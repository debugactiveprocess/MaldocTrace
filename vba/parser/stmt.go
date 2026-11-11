package parser

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

func startsExpr(t lexer.Token) bool {
	if t.Kind == lexer.Ident || t.Kind == lexer.Number || t.Kind == lexer.String {
		return true
	}
	if t.Kind == lexer.Op && (t.Text == "(" || strings.EqualFold(t.Text, "new")) {
		return true
	}
	return false
}

func (p *parser) parseStmt() ast.Stmt {
	t := p.cur()
	if t.Kind == lexer.Ident {
		low := strings.ToLower(t.Text)
		// Label detection: "Name:" followed by separator.
		if p.peek(1).Kind == lexer.Newline && p.peek(1).Text == ":" {
			p.advance()
			p.advance()
			return &ast.Label{At: ast.At{P: t.Pos}, Name: t.Text}
		}
		switch low {
		case "dim", "redim", "static":
			return p.parseDim()
		case "const":
			return p.parseConst()
		case "if":
			return p.parseIf()
		case "select":
			return p.parseSelect()
		case "for":
			return p.parseFor()
		case "while":
			return p.parseWhile()
		case "do":
			return p.parseDo()
		case "exit":
			return p.parseExit()
		case "on":
			return p.parseOnError()
		case "with":
			return p.parseWith()
		case "set":
			return p.parseSet()
		case "end":
			return p.parseEnd()
		case "stop":
			p.advance()
			return &ast.Stop{At: ast.At{P: t.Pos}}
		case "goto":
			p.advance()
			return &ast.Goto{At: ast.At{P: t.Pos}, Label: p.expectIdent()}
		case "resume":
			p.advance()
			r := &ast.Resume{At: ast.At{P: t.Pos}}
			if isWord(p.cur(), "Next") {
				p.advance()
				r.Next = true
			} else if p.cur().Kind == lexer.Ident {
				r.Label = p.advance().Text
			}
			return r
		case "call":
			p.advance()
			return p.parseCallStmt()
		default:
			if isUnrecognisedStatementKeyword(low) {
				p.skipLine()
				return &ast.Noop{At: ast.At{P: t.Pos}, Text: low}
			}
		}
	}
	return p.parseAssignOrCall()
}

func isUnrecognisedStatementKeyword(low string) bool {
	switch low {
	case "open", "close", "print", "write", "input", "line", "name", "mkdir",
		"rmdir", "chdir", "chdrive", "kill", "filecopy", "lock", "unlock",
		"width", "seek", "lset", "rset", "mid", "erase", "type", "enum",
		"option", "get", "put", "reopen":
		return true
	}
	return false
}

func (p *parser) parseCallStmt() ast.Stmt {
	t := p.cur()
	var fn ast.Expr
	if t.Kind == lexer.Ident {
		p.advance()
		fn = &ast.Ident{At: ast.At{P: t.Pos}, Name: t.Text}
		if p.cur().Kind == lexer.Op && p.cur().Text == "." {
			p.advance()
			fn = &ast.Member{At: ast.At{P: t.Pos}, Obj: fn, Name: p.expectIdent()}
		}
	} else {
		p.skipLine()
		return &ast.Noop{At: ast.At{P: t.Pos}, Text: "call"}
	}
	var args []ast.Expr
	if p.cur().Kind == lexer.Op && p.cur().Text == "(" {
		args = p.parseParenArgs()
	} else {
		args = p.parseArgList()
	}
	return &ast.CallStmt{At: ast.At{P: t.Pos}, CallExpr: &ast.Call{At: ast.At{P: t.Pos}, Fn: fn, Args: args}}
}

func (p *parser) parseAssignOrCall() ast.Stmt {
	start := p.cur().Pos
	lhs := p.parsePostfix()
	if p.cur().Kind == lexer.Op && p.cur().Text == "=" {
		p.advance()
		return &ast.Assign{At: ast.At{P: start}, LHS: lhs, RHS: p.parseExpr()}
	}
	switch e := lhs.(type) {
	case *ast.Call:
		return &ast.CallStmt{At: ast.At{P: start}, CallExpr: e}
	case *ast.Ident:
		// Bare Sub call (with or without parens / arguments).
		var args []ast.Expr
		if p.cur().Kind != lexer.Newline && startsExpr(p.cur()) {
			args = p.parseArgList()
		}
		return &ast.CallStmt{At: ast.At{P: start}, CallExpr: &ast.Call{At: ast.At{P: start}, Fn: e, Args: args}}
	case *ast.Member:
		// Member call (with or without parens / arguments).
		var args []ast.Expr
		if p.cur().Kind != lexer.Newline && startsExpr(p.cur()) {
			args = p.parseArgList()
		}
		return &ast.CallStmt{At: ast.At{P: start}, CallExpr: &ast.Call{At: ast.At{P: start}, Fn: e, Args: args}}
	case *ast.Paren:
		return p.parseAssignOrCall()
	default:
		p.skipLine()
		return &ast.Noop{At: ast.At{P: start}, Text: "expression"}
	}
}
