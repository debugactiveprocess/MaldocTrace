package parser

import (
	"strings"

	"maldoctrace/vba/ast"
	"maldoctrace/vba/lexer"
)

func (p *parser) parseBlock(stops ...string) []ast.Stmt {
	var body []ast.Stmt
	for {
		p.skipSep()
		if p.eof() {
			return body
		}
		if p.cur().Kind == lexer.Ident && matchesStop(p, stops) {
			return body
		}
		before := p.pos
		if st := p.parseStmt(); st != nil {
			body = append(body, st)
		}
		if p.pos == before {
			p.advance()
		}
		p.skipSep()
	}
}

func matchesStop(p *parser, stops []string) bool {
	t := p.cur()
	for _, s := range stops {
		words := strings.Fields(s)
		if len(words) == 0 || !strings.EqualFold(t.Text, words[0]) {
			continue
		}
		ok := true
		for i, w := range words[1:] {
			if !isWord(p.peek(i+1), w) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// skipEndTerm consumes "End <word>" (or a bare "End").
func (p *parser) skipEndTerm(words ...string) {
	p.advance() // "End"
	if p.cur().Kind == lexer.Ident {
		for _, w := range words {
			if strings.EqualFold(p.cur().Text, w) {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) parseProc(kind ast.ProcKind) *ast.Proc {
	t := p.advance()
	if kind == ast.ProcProperty && (isWord(p.cur(), "Get") || isWord(p.cur(), "Let") || isWord(p.cur(), "Set")) {
		p.advance()
	}
	proc := &ast.Proc{At: ast.At{P: t.Pos}, Kind: kind}
	if p.cur().Kind == lexer.Ident {
		proc.Name = p.advance().Text
	}
	if p.cur().Kind == lexer.Op && p.cur().Text == "(" {
		proc.Params = p.parseParams()
	}
	if isWord(p.cur(), "As") {
		p.advance()
		proc.ReturnType = p.parseTypeName()
	}
	p.skipSep()
	switch kind {
	case ast.ProcSub:
		proc.Body = p.parseBlock("end sub", "end function", "end property")
		p.skipEndTerm("sub", "function", "property")
	case ast.ProcFunction:
		proc.Body = p.parseBlock("end function", "end sub", "end property")
		p.skipEndTerm("function", "sub", "property")
	default:
		proc.Body = p.parseBlock("end property", "end sub", "end function")
		p.skipEndTerm("property", "sub", "function")
	}
	return proc
}

func (p *parser) parseTypeName() string {
	t := p.cur()
	if t.Kind != lexer.Ident {
		return ""
	}
	if strings.EqualFold(t.Text, "new") {
		p.advance()
		n := ""
		if p.cur().Kind == lexer.Ident {
			n = p.advance().Text
		}
		return "New " + n
	}
	p.advance()
	return t.Text
}

func (p *parser) parseParams() []*ast.Param {
	p.advance() // '('
	var params []*ast.Param
	for {
		if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
			p.advance()
			return params
		}
		if p.eof() {
			return params
		}
		param := &ast.Param{At: ast.At{P: p.cur().Pos}}
		for p.cur().Kind == lexer.Ident {
			switch strings.ToLower(p.cur().Text) {
			case "optional":
				param.Optional = true
				p.advance()
			case "byval":
				param.ByVal = true
				p.advance()
			case "byref":
				param.ByRef = true
				p.advance()
			case "paramarray":
				param.ParamArray = true
				p.advance()
			default:
				goto name
			}
		}
	name:
		if p.cur().Kind == lexer.Ident {
			param.Name = p.advance().Text
		}
		if p.cur().Kind == lexer.Op && p.cur().Text == "(" {
			p.advance()
			if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
				p.advance()
			}
		}
		if isWord(p.cur(), "As") {
			p.advance()
			param.Type = p.parseTypeName()
		}
		params = append(params, param)
		if p.cur().Kind == lexer.Op && p.cur().Text == "," {
			p.advance()
			continue
		}
		if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
			p.advance()
			return params
		}
		return params
	}
}
