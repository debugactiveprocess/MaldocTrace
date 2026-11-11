package lexer

import (
	"unicode"
)

func (l *Lexer) lexNumber() (Token, error) {
	start := l.mark()
	if l.peek() == '&' {
		l.advance()
		prefix := byte('H')
		if c := l.peek(); c == 'H' || c == 'h' || c == 'O' || c == 'o' {
			prefix = byte(unicode.ToUpper(rune(c)))
			l.advance()
		}
		if prefix == 'H' {
			for isHexDigit(l.peek()) {
				l.advance()
			}
		} else {
			for l.peek() >= '0' && l.peek() <= '7' {
				l.advance()
			}
		}
		l.eatSuffix()
		return Token{Kind: Number, Text: l.src[start.Offset:l.pos], Value: l.src[start.Offset:l.pos], Pos: start}, nil
	}
	for isDigit(l.peek()) {
		l.advance()
	}
	if l.peek() == '.' && isDigit(l.peekN(1)) {
		l.advance()
		for isDigit(l.peek()) {
			l.advance()
		}
	}
	if c := l.peek(); c == 'e' || c == 'E' || c == 'd' || c == 'D' {
		save := l.pos
		l.advance()
		if l.peek() == '+' || l.peek() == '-' {
			l.advance()
		}
		if isDigit(l.peek()) {
			for isDigit(l.peek()) {
				l.advance()
			}
		} else {
			l.pos = save
		}
	}
	l.eatSuffix()
	return Token{Kind: Number, Text: l.src[start.Offset:l.pos], Value: l.src[start.Offset:l.pos], Pos: start}, nil
}

func (l *Lexer) eatSuffix() {
	switch l.peek() {
	case '%', '&', '!', '#', '@', '^':
		l.advance()
	}
}

func (l *Lexer) lexIdent() (Token, error) {
	start := l.mark()
	for isIdentPart(l.peek()) {
		l.advance()
	}
	if l.peek() == '$' {
		l.advance()
	}
	text := l.src[start.Offset:l.pos]
	if isOperatorKeyword(text) {
		return Token{Kind: Op, Text: text, Pos: start}, nil
	}
	return Token{Kind: Ident, Text: text, Pos: start}, nil
}

func (l *Lexer) lexOp() (Token, error) {
	start := l.mark()
	text := string(l.peek())
	l.advance()
	if l.pos < len(l.src) {
		switch l.src[l.pos-1 : l.pos+1] {
		case "<=", ">=", "<>":
			text = l.src[l.pos-1 : l.pos+1]
			l.advance()
		}
	}
	return Token{Kind: Op, Text: text, Pos: start}, nil
}

func isDigit(c byte) bool    { return c >= '0' && c <= '9' }
func isHexDigit(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }
func isHexOctal(c byte) bool { return c == 'H' || c == 'h' || c == 'O' || c == 'o' }
func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}
func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }
