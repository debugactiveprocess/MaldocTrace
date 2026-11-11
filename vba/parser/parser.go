// Package parser implements a recursive-descent parser for the supported VBA
// subset. It produces an *ast.Module and records diagnostics for recognised
// but unsupported construct.
package parser

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

// Parse parses VBA source into an AST. Positions refer to the conditionally
// compiled text (see condCompile).
func Parse(code string) *ast.Module {
	compiled, diags := condCompile(code)
	toks, err := lexer.New(compiled).Tokenize()
	mod := &ast.Module{}
	if err != nil {
		if se, ok := err.(*lexer.SyntaxError); ok {
			mod.Errors = append(mod.Errors, se)
			return mod
		}
		mod.Errors = append(mod.Errors, &lexer.SyntaxError{Msg: err.Error()})
		return mod
	}
	p := &parser{toks: toks, mod: mod}
	p.parseModule()
	for _, d := range diags {
		mod.Errors = append(mod.Errors, &lexer.SyntaxError{Msg: d})
	}
	return mod
}

type parser struct {
	toks []lexer.Token
	pos  int
	mod  *ast.Module
}

func (p *parser) cur() lexer.Token     { return p.toks[p.pos] }
func (p *parser) at(k lexer.Kind) bool { return p.cur().Kind == k }
func (p *parser) peek(n int) lexer.Token {
	i := p.pos + n
	if i >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[i]
}
func (p *parser) advance() lexer.Token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}
func (p *parser) eof() bool { return p.cur().Kind == lexer.EOF }

func isWord(t lexer.Token, w string) bool {
	return t.Kind == lexer.Ident && strings.EqualFold(t.Text, w)
}

// skipSep advances over statement separators (newlines and colons).
func (p *parser) skipSep() {
	for !p.eof() && p.cur().Kind == lexer.Newline {
		p.advance()
	}
}

// skipLine consumes tokens until the next statement separator, then the sep.
func (p *parser) skipLine() {
	for !p.eof() && p.cur().Kind != lexer.Newline {
		p.advance()
	}
	p.skipSep()
}

func (p *parser) parseModule() {
	for !p.eof() {
		p.skipSep()
		if p.eof() {
			return
		}
		t := p.cur()
		if t.Kind == lexer.Ident {
			low := strings.ToLower(t.Text)
			// Skip access/scope modifiers.
			hadModifier := false
			for isModifier(low) || (hadModifier && low == "withevents") {
				hadModifier = true
				p.advance()
				if p.cur().Kind != lexer.Ident {
					break
				}
				t = p.cur()
				low = strings.ToLower(t.Text)
			}
			switch low {
			case "attribute":
				p.skipLine()
				continue
			case "sub":
				p.mod.Procs = append(p.mod.Procs, p.parseProc(ast.ProcSub))
				continue
			case "function":
				p.mod.Procs = append(p.mod.Procs, p.parseProc(ast.ProcFunction))
				continue
			case "property":
				p.mod.Procs = append(p.mod.Procs, p.parseProc(ast.ProcProperty))
				continue
			case "declare":
				if d := p.parseDeclare(); d != nil {
					p.mod.Decls = append(p.mod.Decls, d)
				}
				continue
			case "option":
				p.parseOption()
				continue
			case "end":
				p.skipLine()
				continue
			case "const", "dim", "enum", "type", "event", "implements":
			default:
				if hadModifier {
					// "Private x As String": a module-level variable
					// declaration whose keyword is the modifier itself.
					p.pos--
					p.mod.Body = append(p.mod.Body, p.parseDim())
					p.skipSep()
					continue
				}
			}
		}
		if st := p.parseStmt(); st != nil {
			p.mod.Body = append(p.mod.Body, st)
		}
		p.skipSep()
	}
}

func isModifier(low string) bool {
	switch low {
	case "private", "public", "friend", "static", "default":
		return true
	}
	return false
}

func (p *parser) parseOption() {
	// Consume the whole statement; nothing semantically needed for analysis.
	for !p.eof() && p.cur().Kind != lexer.Newline {
		p.advance()
	}
}
