package parser

import (
	"strconv"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

// Binary precedence table: higher binds tighter.
var binPrec = map[string]int{
	"^": 14, "*": 12, "/": 12, "\\": 11, "mod": 10, "+": 9, "-": 9, "&": 8,
	"=": 7, "<>": 7, "<": 7, ">": 7, "<=": 7, ">=": 7, "like": 7, "is": 7,
	"and": 5, "or": 4, "xor": 3, "eqv": 2, "imp": 1,
}

func opText(t lexer.Token) string {
	if t.Kind != lexer.Op {
		return ""
	}
	return strings.ToLower(t.Text)
}

func (p *parser) parseExpr() ast.Expr {
	return p.parseBinary(0)
}

func (p *parser) parseBinary(minPrec int) ast.Expr {
	left := p.parseUnary()
	for {
		t := p.cur()
		op := opText(t)
		prec, ok := binPrec[op]
		if !ok || prec < minPrec {
			break
		}
		p.advance()
		nextMin := prec + 1
		if op == "^" { // right associative
			nextMin = prec
		}
		right := p.parseBinary(nextMin)
		left = &ast.Binary{At: ast.At{P: t.Pos}, Op: op, Left: left, Right: right}
	}
	return left
}

func (p *parser) parseUnary() ast.Expr {
	t := p.cur()
	op := opText(t)
	if op == "-" || op == "+" || op == "not" {
		p.advance()
		prec := 13
		if op == "not" {
			prec = 6
		}
		return &ast.Unary{At: ast.At{P: t.Pos}, Op: op, X: p.parseBinary(prec)}
	}
	return p.parsePostfix()
}

func (p *parser) parsePostfix() ast.Expr {
	e := p.parsePrimary()
	for {
		t := p.cur()
		if t.Kind == lexer.Op && t.Text == "." {
			p.advance()
			name := p.expectIdent()
			e = &ast.Member{At: ast.At{P: t.Pos}, Obj: e, Name: name}
			continue
		}
		if t.Kind == lexer.Op && t.Text == "!" {
			p.advance()
			name := p.expectIdent()
			e = &ast.Member{At: ast.At{P: t.Pos}, Obj: e, Name: name}
			continue
		}
		if t.Kind == lexer.Op && t.Text == "(" {
			args := p.parseParenArgs()
			e = &ast.Call{At: ast.At{P: t.Pos}, Fn: e, Args: args}
			continue
		}
		break
	}
	return e
}

// parseParenArgs parses a parenthesised, possibly empty argument list.
func (p *parser) parseParenArgs() []ast.Expr {
	p.advance() // '('
	var args []ast.Expr
	if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
		p.advance()
		return args
	}
	for {
		args = append(args, p.parseArg())
		t := p.cur()
		if t.Kind == lexer.Op && t.Text == "," {
			p.advance()
			continue
		}
		if t.Kind == lexer.Op && t.Text == ")" {
			p.advance()
			break
		}
		break
	}
	return args
}

// parseArg parses one call argument, which may be named (Name:=expr).
func (p *parser) parseArg() ast.Expr {
	if t := p.cur(); t.Kind == lexer.Ident {
		if n := p.peek(1); n.Kind == lexer.Op && n.Text == ":=" {
			p.advance()
			p.advance()
			return &ast.NamedArg{At: ast.At{P: t.Pos}, Name: t.Text, Value: p.parseExpr()}
		}
	}
	return p.parseExpr()
}

func (p *parser) expectIdent() string {
	t := p.cur()
	if t.Kind == lexer.Ident {
		p.advance()
		return t.Text
	}
	// tolerate missing name (diagnostic-driven recovery)
	return ""
}

// parseArgList parses arguments for a bare (paren-less) call statement.
func (p *parser) parseArgList() []ast.Expr {
	var args []ast.Expr
	for !p.eof() && p.cur().Kind != lexer.Newline {
		args = append(args, p.parseArg())
		if p.cur().Kind == lexer.Op && p.cur().Text == "," {
			p.advance()
			continue
		}
		break
	}
	return args
}

func (p *parser) parsePrimary() ast.Expr {
	t := p.cur()
	switch t.Kind {
	case lexer.Number:
		p.advance()
		return parseNumLit(t)
	case lexer.String:
		p.advance()
		return &ast.StrLit{At: ast.At{P: t.Pos}, Value: t.Value}
	case lexer.Ident:
		p.advance()
		switch strings.ToLower(t.Text) {
		case "true":
			return &ast.BoolLit{At: ast.At{P: t.Pos}, Value: true}
		case "false":
			return &ast.BoolLit{At: ast.At{P: t.Pos}, Value: false}
		case "null":
			return &ast.NullLit{At: ast.At{P: t.Pos}}
		case "nothing":
			return &ast.NothingLit{At: ast.At{P: t.Pos}}
		case "new":
			n := p.expectIdent()
			return &ast.NewExpr{At: ast.At{P: t.Pos}, Name: n}
		default:
			return &ast.Ident{At: ast.At{P: t.Pos}, Name: t.Text}
		}
	case lexer.Op:
		if t.Text == "." || t.Text == "!" {
			// ".Member" inside a With block.
			p.advance()
			name := p.expectIdent()
			return &ast.Member{At: ast.At{P: t.Pos}, Obj: &ast.WithObj{At: ast.At{P: t.Pos}}, Name: name}
		}
		if t.Text == "(" {
			p.advance()
			x := p.parseExpr()
			if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
				p.advance()
			}
			return &ast.Paren{At: ast.At{P: t.Pos}, X: x}
		}
	}
	p.mod.Errors = append(p.mod.Errors, &lexer.SyntaxError{Pos: t.Pos, Msg: "unexpected expression token: " + t.Text})
	p.advance()
	return &ast.Ident{At: ast.At{P: t.Pos}, Name: "<error>"}
}

func parseNumLit(t lexer.Token) ast.Expr {
	s := t.Text
	n := &ast.NumLit{At: ast.At{P: t.Pos}, Text: s}
	switch {
	case strings.HasPrefix(strings.ToLower(s), "&h"):
		v, err := strconv.ParseInt(s[2:], 16, 64)
		if err == nil {
			n.Int = v
		}
	case strings.HasPrefix(strings.ToLower(s), "&o"):
		v, err := strconv.ParseInt(s[2:], 8, 64)
		if err == nil {
			n.Int = v
		}
	default:
		trimmed := strings.TrimRight(s, "%&!#@^")
		trimmed = strings.TrimSuffix(trimmed, ".")
		if v, err := strconv.ParseInt(trimmed, 0, 64); err == nil && !strings.ContainsAny(trimmed, ".eEdD") {
			n.Int = v
		} else if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
			n.IsFloat = true
			n.Float = f
		} else {
			n.Int = 0
		}
	}
	return n
}
