package parser

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

func (p *parser) parseFor() ast.Stmt {
	t := p.advance() // "For"
	if isWord(p.cur(), "Each") {
		p.advance()
		f := &ast.ForEach{At: ast.At{P: t.Pos}}
		if p.cur().Kind == lexer.Ident {
			f.Var = p.advance().Text
		}
		if isWord(p.cur(), "In") {
			p.advance()
		}
		f.In = p.parseExpr()
		p.skipSep()
		f.Body = p.parseBlock("next")
		p.advance() // Next
		if p.cur().Kind == lexer.Ident {
			p.advance()
		}
		return f
	}
	f := &ast.For{At: ast.At{P: t.Pos}}
	if p.cur().Kind == lexer.Ident {
		f.Var = p.advance().Text
	}
	if p.cur().Kind == lexer.Op && p.cur().Text == "=" {
		p.advance()
	}
	f.Start = p.parseExpr()
	if isWord(p.cur(), "To") {
		p.advance()
		f.Stop = p.parseExpr()
	}
	if isWord(p.cur(), "Step") {
		p.advance()
		f.Step = p.parseExpr()
	}
	p.skipSep()
	f.Body = p.parseBlock("next")
	p.advance() // Next
	if p.cur().Kind == lexer.Ident {
		p.advance()
	}
	return f
}

func (p *parser) parseWhile() ast.Stmt {
	t := p.advance() // "While"
	w := &ast.While{At: ast.At{P: t.Pos}, Cond: p.parseExpr()}
	p.skipSep()
	w.Body = p.parseBlock("wend", "end while")
	p.advance()
	return w
}

func (p *parser) parseDo() ast.Stmt {
	t := p.advance() // "Do"
	d := &ast.DoLoop{At: ast.At{P: t.Pos}}
	if isWord(p.cur(), "While") {
		p.advance()
		d.PreWhile = true
		d.PreCond = p.parseExpr()
	} else if isWord(p.cur(), "Until") {
		p.advance()
		d.PreWhile = false
		d.PreCond = p.parseExpr()
	}
	p.skipSep()
	d.Body = p.parseBlock("loop")
	p.advance() // "Loop"
	if isWord(p.cur(), "While") {
		p.advance()
		d.PreWhile = true
		d.PostCond = p.parseExpr()
	} else if isWord(p.cur(), "Until") {
		p.advance()
		d.PreWhile = false
		d.PostCond = p.parseExpr()
	}
	return d
}

func (p *parser) parseWith() ast.Stmt {
	t := p.advance() // "With"
	w := &ast.With{At: ast.At{P: t.Pos}, Obj: p.parseExpr()}
	p.skipSep()
	w.Body = p.parseBlock("end with")
	p.skipEndTerm("with")
	return w
}

func (p *parser) parseSet() ast.Stmt {
	t := p.advance() // "Set"
	lhs := p.parsePostfix()
	if p.cur().Kind == lexer.Op && p.cur().Text == "=" {
		p.advance()
		return &ast.Set{At: ast.At{P: t.Pos}, LHS: lhs, RHS: p.parseExpr()}
	}
	p.skipLine()
	return &ast.Noop{At: ast.At{P: t.Pos}, Text: "set"}
}

func (p *parser) parseExit() ast.Stmt {
	t := p.advance() // "Exit"
	e := &ast.Exit{At: ast.At{P: t.Pos}, What: ""}
	if p.cur().Kind == lexer.Ident {
		e.What = strings.ToLower(p.advance().Text)
	}
	return e
}

func (p *parser) parseOnError() ast.Stmt {
	t := p.advance() // "On"
	o := &ast.OnError{At: ast.At{P: t.Pos}}
	if !isWord(p.cur(), "Error") {
		p.skipLine()
		return &ast.Noop{At: ast.At{P: t.Pos}, Text: "on"}
	}
	p.advance()
	if isWord(p.cur(), "Resume") {
		p.advance()
		if isWord(p.cur(), "Next") {
			p.advance()
		}
		o.ResumeNext = true
	} else if isWord(p.cur(), "Goto") || isWord(p.cur(), "GoTo") {
		p.advance()
		if p.cur().Kind == lexer.Number || p.cur().Kind == lexer.Ident {
			lbl := p.advance()
			if lbl.Text == "0" {
				o.GotoZero = true
			} else {
				o.GotoLabel = lbl.Text
			}
		}
	}
	return o
}

func (p *parser) parseEnd() ast.Stmt {
	t := p.advance() // "End"
	if p.cur().Kind == lexer.Ident {
		p.advance()
	}
	return &ast.End{At: ast.At{P: t.Pos}}
}
