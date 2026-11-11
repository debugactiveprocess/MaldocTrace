package lexer

import (
	"strings"
)

// Lexer tokenizes VBA source.
type Lexer struct {
	src  string
	pos  int // byte offset
	line int
	col  int
}

// New creates a Lexer over src.
func New(src string) *Lexer {
	return &Lexer{src: src, line: 1, col: 1}
}

func toLower(s string) string { return strings.ToLower(s) }

// Tokenize returns all tokens up to and including EOF.
func (l *Lexer) Tokenize() ([]Token, error) {
	var toks []Token
	for {
		t, err := l.Next()
		if err != nil {
			return toks, err
		}
		toks = append(toks, t)
		if t.Kind == EOF {
			return toks, nil
		}
	}
}

// Next produces the next token.
func (l *Lexer) Next() (Token, error) {
	l.skipSpaceAndComments()
	start := l.mark()
	if l.eof() {
		return Token{Kind: EOF, Pos: start}, nil
	}
	// Line continuation: '_' + (spaces) + newline.
	for l.peek() == '_' && l.nextIsContinuation() {
		l.advance()
		for l.peek() == ' ' || l.peek() == '\t' {
			l.advance()
		}
		l.consumeNewline()
		start = l.mark()
		for l.peek() == ' ' || l.peek() == '\t' {
			l.advance()
		}
	}
	// A trailing continuation may consume the rest of the input.
	if l.eof() {
		return Token{Kind: EOF, Pos: start}, nil
	}
	c := l.peek()
	switch {
	case c == '\r' || c == '\n':
		l.consumeNewline()
		return Token{Kind: Newline, Text: "\n", Pos: start}, nil
	case c == ':' && l.peekN(1) == '=':
		l.advance()
		l.advance()
		return Token{Kind: Op, Text: ":=", Pos: start}, nil
	case c == ':':
		l.advance()
		return Token{Kind: Newline, Text: ":", Pos: start}, nil
	case c == '"':
		return l.lexString()
	case c == '#':
		return l.lexDateLiteral()
	case isDigit(c):
		return l.lexNumber()
	case c == '&' && isHexOctal(l.peekN(1)):
		return l.lexNumber()
	case isIdentStart(c):
		return l.lexIdent()
	default:
		return l.lexOp()
	}
}

func (l *Lexer) mark() Pos { return Pos{Offset: l.pos, Line: l.line, Col: l.col} }

func (l *Lexer) eof() bool { return l.pos >= len(l.src) }

func (l *Lexer) peek() byte {
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *Lexer) peekN(n int) byte {
	if l.pos+n >= len(l.src) {
		return 0
	}
	return l.src[l.pos+n]
}

func (l *Lexer) advance() byte {
	c := l.src[l.pos]
	l.pos++
	if c == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return c
}

func (l *Lexer) consumeNewline() {
	if l.peek() == '\r' {
		l.advance()
	}
	if l.peek() == '\n' {
		l.advance()
	}
}

func (l *Lexer) nextIsContinuation() bool {
	i := l.pos + 1
	for i < len(l.src) && (l.src[i] == ' ' || l.src[i] == '\t') {
		i++
	}
	return i < len(l.src) && (l.src[i] == '\r' || l.src[i] == '\n')
}

func (l *Lexer) skipSpaceAndComments() {
	for {
		for l.peek() == ' ' || l.peek() == '\t' {
			l.advance()
		}
		if l.peek() == '\'' {
			for l.pos < len(l.src) && l.peek() != '\r' && l.peek() != '\n' {
				l.advance()
			}
			continue
		}
		rest := l.src[l.pos:]
		if len(rest) >= 4 && (rest[0] == 'R' || rest[0] == 'r') && strings.EqualFold(rest[:4], "Rem ") {
			for l.pos < len(l.src) && l.peek() != '\r' && l.peek() != '\n' {
				l.advance()
			}
			continue
		}
		return
	}
}

func (l *Lexer) lexString() (Token, error) {
	start := l.mark()
	l.advance()
	var sb strings.Builder
	for {
		if l.eof() {
			return Token{}, &SyntaxError{Pos: start, Msg: "unterminated string"}
		}
		c := l.peek()
		if c == '"' {
			l.advance()
			if l.peek() == '"' {
				l.advance()
				sb.WriteByte('"')
				continue
			}
			break
		}
		sb.WriteByte(l.advance())
	}
	return Token{Kind: String, Text: l.src[start.Offset:l.pos], Value: sb.String(), Pos: start}, nil
}

func (l *Lexer) lexDateLiteral() (Token, error) {
	start := l.mark()
	l.advance()
	var sb strings.Builder
	for !l.eof() && l.peek() != '#' && l.peek() != '\r' && l.peek() != '\n' {
		sb.WriteByte(l.advance())
	}
	if l.peek() == '#' {
		l.advance()
	}
	return Token{Kind: String, Text: l.src[start.Offset:l.pos], Value: sb.String(), Pos: start}, nil
}

// SyntaxError carries a position for parse/lex diagnostics.
type SyntaxError struct {
	Pos Pos
	Msg string
}

func (e *SyntaxError) Error() string { return e.Pos.String() + ": " + e.Msg }
