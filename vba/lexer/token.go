// Package lexer tokenizes VBA source into a token stream. It is case
// preserving; keyword matching is done case-insensitively by the parser.
package lexer

import "fmt"

// Kind classifies a token.
type Kind int

const (
	EOF     Kind = iota
	Newline      // statement separator (end of a logical line or ':')
	Ident
	Number
	String
	Op // operator or punctuation (includes keyword operators And/Or/Not/...)
)

func (k Kind) String() string {
	switch k {
	case EOF:
		return "EOF"
	case Newline:
		return "NEWLINE"
	case Ident:
		return "IDENT"
	case Number:
		return "NUMBER"
	case String:
		return "STRING"
	case Op:
		return "OP"
	default:
		return "UNKNOWN"
	}
}

// Pos is a 0-based byte offset with 1-based line/column.
type Pos struct {
	Offset int
	Line   int
	Col    int
}

func (p Pos) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Col) }

// Token is a single lexical token.
type Token struct {
	Kind  Kind
	Text  string // raw text (case preserved)
	Value string // decoded value for strings; raw for numbers
	Pos   Pos
}

// Keywords that act as expression operators and are lexed as Op tokens.
var operatorKeywords = map[string]bool{
	"and": true, "or": true, "not": true, "xor": true, "eqv": true,
	"imp": true, "mod": true, "like": true, "is": true,
}

func isOperatorKeyword(s string) bool { return operatorKeywords[toLower(s)] }
