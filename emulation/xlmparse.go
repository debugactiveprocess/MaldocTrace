package emulation

import (
	"fmt"
	"strconv"
	"strings"

	"maldoctrace/extractor"
)

// XLM formula AST. Formulas are parsed from their A1 text (OOXML stores
// text; BIFF8 tokens are decompiled to text by the extractor), so one parser
// serves both formats and formulas written at run time by FORMULA().

type xNode interface{}

type (
	xNum  float64
	xStr  string
	xBool bool
	xErr  string
	xMiss struct{}
	xName string
	xRef  struct {
		sheet          string
		r1, c1, r2, c2 int
		area           bool
	}
	xCall struct {
		name string
		args []xNode
	}
	xUnary struct {
		op string
		x  xNode
	}
	xBinary struct {
		op   string
		l, r xNode
	}
)

type xParser struct {
	s     string
	p     int
	depth int
}

// parseXLM parses formula text (with or without the leading "=").
func parseXLM(text string) (n xNode, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = nil, fmt.Errorf("%v", r)
		}
	}()
	ps := &xParser{s: strings.TrimPrefix(strings.TrimSpace(text), "=")}
	n = ps.expr()
	ps.space()
	if ps.p < len(ps.s) {
		return n, fmt.Errorf("unexpected %q at %d", ps.s[ps.p:], ps.p)
	}
	return n, nil
}

func (ps *xParser) fail(msg string) { panic(fmt.Sprintf("%s at %d", msg, ps.p)) }

func (ps *xParser) space() {
	for ps.p < len(ps.s) && (ps.s[ps.p] == ' ' || ps.s[ps.p] == '\n' || ps.s[ps.p] == '\r' || ps.s[ps.p] == '\t') {
		ps.p++
	}
}

func (ps *xParser) peek(tok string) bool {
	ps.space()
	return strings.HasPrefix(ps.s[ps.p:], tok)
}

func (ps *xParser) eat(tok string) bool {
	if ps.peek(tok) {
		ps.p += len(tok)
		return true
	}
	return false
}

func (ps *xParser) expr() xNode {
	ps.depth++
	if ps.depth > 200 {
		ps.fail("formula nesting too deep")
	}
	defer func() { ps.depth-- }()
	return ps.compare()
}

func (ps *xParser) compare() xNode {
	l := ps.concat()
	for {
		var op string
		for _, o := range []string{"<>", "<=", ">=", "=", "<", ">"} {
			if ps.eat(o) {
				op = o
				break
			}
		}
		if op == "" {
			return l
		}
		l = xBinary{op, l, ps.concat()}
	}
}

func (ps *xParser) concat() xNode {
	l := ps.additive()
	for ps.eat("&") {
		l = xBinary{"&", l, ps.additive()}
	}
	return l
}

func (ps *xParser) additive() xNode {
	l := ps.mult()
	for {
		switch {
		case ps.eat("+"):
			l = xBinary{"+", l, ps.mult()}
		case ps.eat("-"):
			l = xBinary{"-", l, ps.mult()}
		default:
			return l
		}
	}
}

func (ps *xParser) mult() xNode {
	l := ps.power()
	for {
		switch {
		case ps.eat("*"):
			l = xBinary{"*", l, ps.power()}
		case ps.eat("/"):
			l = xBinary{"/", l, ps.power()}
		default:
			return l
		}
	}
}

func (ps *xParser) power() xNode {
	l := ps.unary()
	for ps.eat("^") {
		l = xBinary{"^", l, ps.unary()}
	}
	return l
}

func (ps *xParser) unary() xNode {
	switch {
	case ps.eat("-"):
		return xUnary{"-", ps.unary()}
	case ps.eat("+"):
		return ps.unary()
	}
	x := ps.primary()
	for ps.eat("%") {
		x = xUnary{"%", x}
	}
	return x
}

func isNameChar(c byte) bool {
	return c == '_' || c == '.' || c == '$' || c == '\\' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= 0x80
}

func (ps *xParser) primary() xNode {
	ps.space()
	if ps.p >= len(ps.s) {
		ps.fail("unexpected end of formula")
	}
	c := ps.s[ps.p]
	switch {
	case c == '(':
		ps.p++
		x := ps.expr()
		if !ps.eat(")") {
			ps.fail("missing )")
		}
		return x
	case c == '"':
		ps.p++
		var b strings.Builder
		for {
			if ps.p >= len(ps.s) {
				ps.fail("unterminated string")
			}
			if ps.s[ps.p] == '"' {
				if ps.p+1 < len(ps.s) && ps.s[ps.p+1] == '"' {
					b.WriteByte('"')
					ps.p += 2
					continue
				}
				ps.p++
				return xStr(b.String())
			}
			b.WriteByte(ps.s[ps.p])
			ps.p++
		}
	case c == '#':
		for _, e := range []string{"#NULL!", "#DIV/0!", "#VALUE!", "#REF!", "#NAME?", "#NUM!", "#N/A"} {
			if strings.HasPrefix(strings.ToUpper(ps.s[ps.p:]), e) {
				ps.p += len(e)
				return xErr(e)
			}
		}
		ps.fail("bad error literal")
	case c == '{':
		end := strings.IndexByte(ps.s[ps.p:], '}')
		if end < 0 {
			ps.fail("unterminated array")
		}
		ps.p += end + 1
		return xErr("#VALUE!")
	case c == '\'':
		end := ps.p + 1
		for end < len(ps.s) && !(ps.s[end] == '\'' && (end+1 >= len(ps.s) || ps.s[end+1] != '\'')) {
			if ps.s[end] == '\'' {
				end++
			}
			end++
		}
		if end >= len(ps.s) {
			ps.fail("unterminated sheet name")
		}
		sheet := strings.ReplaceAll(ps.s[ps.p+1:end], "''", "'")
		ps.p = end + 1
		if !ps.eat("!") {
			ps.fail("missing ! after sheet name")
		}
		return ps.ref(sheet)
	case c >= '0' && c <= '9' || c == '.':
		start := ps.p
		for ps.p < len(ps.s) && (ps.s[ps.p] >= '0' && ps.s[ps.p] <= '9' || ps.s[ps.p] == '.') {
			ps.p++
		}
		if ps.p < len(ps.s) && (ps.s[ps.p] == 'E' || ps.s[ps.p] == 'e') {
			q := ps.p + 1
			if q < len(ps.s) && (ps.s[q] == '+' || ps.s[q] == '-') {
				q++
			}
			if q < len(ps.s) && ps.s[q] >= '0' && ps.s[q] <= '9' {
				ps.p = q
				for ps.p < len(ps.s) && ps.s[ps.p] >= '0' && ps.s[ps.p] <= '9' {
					ps.p++
				}
			}
		}
		// A row range like 1:1 or a name starting with digits is not
		// supported; plain numbers are.
		if ps.p < len(ps.s) && isNameChar(ps.s[ps.p]) && ps.s[ps.p] != '.' {
			ps.fail("unsupported token")
		}
		f, err := strconv.ParseFloat(ps.s[start:ps.p], 64)
		if err != nil {
			ps.fail("bad number")
		}
		return xNum(f)
	case isNameChar(c):
		start := ps.p
		for ps.p < len(ps.s) && isNameChar(ps.s[ps.p]) {
			ps.p++
		}
		word := ps.s[start:ps.p]
		if ps.p < len(ps.s) && ps.s[ps.p] == '!' {
			ps.p++
			return ps.ref(word)
		}
		if ps.p < len(ps.s) && ps.s[ps.p] == '(' {
			ps.p++
			return xCall{name: strings.ToUpper(word), args: ps.args()}
		}
		ps.p = start
		if r, ok := ps.tryRef(""); ok {
			return r
		}
		ps.p = start + len(word)
		switch strings.ToUpper(word) {
		case "TRUE":
			return xBool(true)
		case "FALSE":
			return xBool(false)
		}
		return xName(word)
	}
	ps.fail(fmt.Sprintf("unexpected %q", c))
	return nil
}

func (ps *xParser) args() []xNode {
	var out []xNode
	if ps.eat(")") {
		return out
	}
	for {
		if ps.peek(",") || ps.peek(")") {
			out = append(out, xMiss{})
		} else {
			out = append(out, ps.expr())
		}
		if ps.eat(",") {
			continue
		}
		if ps.eat(")") {
			return out
		}
		ps.fail("expected , or )")
	}
}

// cellToken reads a single A1 or R1C1 cell token at the current position.
func (ps *xParser) cellToken() (int, int, bool) {
	start := ps.p
	for ps.p < len(ps.s) && isNameChar(ps.s[ps.p]) && ps.s[ps.p] != '.' {
		ps.p++
	}
	r, c, ok := extractor.ParseCellRef(ps.s[start:ps.p])
	if !ok {
		ps.p = start
	}
	return r, c, ok
}

func (ps *xParser) tryRef(sheet string) (xNode, bool) {
	start := ps.p
	r1, c1, ok := ps.cellToken()
	if !ok {
		return nil, false
	}
	if ps.p < len(ps.s) && (ps.s[ps.p] == '(' || ps.s[ps.p] == '.') {
		ps.p = start
		return nil, false
	}
	ref := xRef{sheet: sheet, r1: r1, c1: c1, r2: r1, c2: c1}
	if ps.p < len(ps.s) && ps.s[ps.p] == ':' {
		save := ps.p
		ps.p++
		if r2, c2, ok := ps.cellToken(); ok {
			ref.r2, ref.c2, ref.area = r2, c2, true
		} else {
			ps.p = save
		}
	}
	return ref, true
}

func (ps *xParser) ref(sheet string) xNode {
	if r, ok := ps.tryRef(sheet); ok {
		return r
	}
	// Sheet-qualified name (Sheet1!MyName): treat as a workbook name.
	start := ps.p
	for ps.p < len(ps.s) && isNameChar(ps.s[ps.p]) {
		ps.p++
	}
	if ps.p == start {
		ps.fail("bad reference")
	}
	return xName(ps.s[start:ps.p])
}
