package parser

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

func (p *parser) parseDeclare() *ast.Declare {
	t := p.advance() // "Declare"
	d := &ast.Declare{At: ast.At{P: t.Pos}}
	if isWord(p.cur(), "PtrSafe") {
		p.advance()
		d.PtrSafe = true
	}
	if isWord(p.cur(), "Function") {
		d.IsFunc = true
	} else if isWord(p.cur(), "Sub") {
		d.IsFunc = false
	} else {
		p.skipLine()
		return nil
	}
	p.advance()
	if p.cur().Kind == lexer.Ident {
		d.Name = p.advance().Text
	}
	if isWord(p.cur(), "Lib") {
		p.advance()
		if p.cur().Kind == lexer.String {
			d.Lib = p.advance().Value
		}
	}
	if isWord(p.cur(), "Alias") {
		p.advance()
		if p.cur().Kind == lexer.String {
			d.Alias = p.advance().Value
		}
	}
	if p.cur().Kind == lexer.Op && p.cur().Text == "(" {
		d.Params = p.parseParams()
	}
	if isWord(p.cur(), "As") {
		p.advance()
		d.Return = p.parseTypeName()
	}
	return d
}

func (p *parser) parseDim() ast.Stmt {
	kw := p.advance()
	d := &ast.Dim{At: ast.At{P: kw.Pos}}
	switch strings.ToLower(kw.Text) {
	case "redim":
		d.ReDim = true
	case "static":
		d.Static = true
	}
	if p.cur().Kind == lexer.Ident {
		d.Name = p.advance().Text
	}
	if p.cur().Kind == lexer.Op && p.cur().Text == "(" {
		d.Bounds = p.parseBounds()
	}
	if isWord(p.cur(), "As") {
		p.advance()
		d.Type = p.parseTypeName()
	}
	p.skipLine()
	return d
}

func (p *parser) parseBounds() []ast.Expr {
	p.advance() // '('
	var bounds []ast.Expr
	for {
		if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
			p.advance()
			return bounds
		}
		if p.eof() {
			return bounds
		}
		bounds = append(bounds, p.parseExpr())
		if isWord(p.cur(), "To") {
			p.advance()
			bounds = append(bounds, p.parseExpr())
		}
		if p.cur().Kind == lexer.Op && p.cur().Text == ")" {
			p.advance()
			return bounds
		}
		return bounds
	}
}

func (p *parser) parseConst() ast.Stmt {
	t := p.advance() // "Const"
	c := &ast.Const{At: ast.At{P: t.Pos}}
	if p.cur().Kind == lexer.Ident {
		c.Name = p.advance().Text
	}
	if isWord(p.cur(), "As") {
		p.advance()
		c.Type = p.parseTypeName()
	}
	if p.cur().Kind == lexer.Op && p.cur().Text == "=" {
		p.advance()
		c.Val = p.parseExpr()
	}
	p.skipLine()
	return c
}

func (p *parser) parseIf() ast.Stmt {
	t := p.advance() // "If"
	cond := p.parseExpr()
	if !isWord(p.cur(), "Then") {
		p.skipLine()
		return &ast.Noop{At: ast.At{P: t.Pos}, Text: "if"}
	}
	p.advance() // "Then"
	s := &ast.If{At: ast.At{P: t.Pos}}
	if p.cur().Kind != lexer.Newline {
		if st := p.parseStmt(); st != nil {
			s.Branches = append(s.Branches, ast.IfBranch{Cond: cond, Body: []ast.Stmt{st}})
		}
		return s
	}
	s.Branches = append(s.Branches, ast.IfBranch{Cond: cond, Body: p.parseBlock("elseif", "else", "end if")})
	for isWord(p.cur(), "ElseIf") {
		p.advance()
		c := p.parseExpr()
		if isWord(p.cur(), "Then") {
			p.advance()
		}
		s.Branches = append(s.Branches, ast.IfBranch{Cond: c, Body: p.parseBlock("elseif", "else", "end if")})
	}
	if isWord(p.cur(), "Else") {
		p.advance()
		s.Else = p.parseBlock("end if")
	}
	p.skipEndTerm("if")
	return s
}

func (p *parser) parseSelect() ast.Stmt {
	t := p.advance() // "Select"
	if !isWord(p.cur(), "Case") {
		p.skipLine()
		return &ast.Noop{At: ast.At{P: t.Pos}, Text: "select"}
	}
	p.advance() // "Case"
	s := &ast.Select{At: ast.At{P: t.Pos}, Test: p.parseExpr()}
	p.skipSep()
	for {
		if p.eof() || isWord(p.cur(), "End") {
			break
		}
		if !isWord(p.cur(), "Case") {
			p.advance()
			continue
		}
		p.advance() // "Case"
		clause := ast.CaseClause{}
		if isWord(p.cur(), "Else") {
			p.advance()
		} else {
			for p.cur().Kind != lexer.Newline {
				clause.Exprs = append(clause.Exprs, p.parseExpr())
				if p.cur().Kind == lexer.Op && p.cur().Text == "," {
					p.advance()
					continue
				}
				break
			}
		}
		p.skipSep()
		clause.Body = p.parseBlock("case", "end select")
		s.Cases = append(s.Cases, clause)
	}
	p.advance() // "End"
	if isWord(p.cur(), "Select") {
		p.advance()
	}
	return s
}
