package parser

import (
	"strconv"
	"strings"
)

type boolVal struct {
	val   bool
	known bool
}

var unknownVal = boolVal{known: false}

func evalGuard(s string, consts map[string]bool) (bool, bool) {
	v, _ := parseBoolOr(tokenizeGuard(s), consts)
	return v.val, v.known
}

func tokenizeGuard(s string) []boolTok {
	var toks []boolTok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			toks = append(toks, boolTok{kind: string(c)})
			i++
		case c == '=' || c == '<' || c == '>':
			toks = append(toks, boolTok{kind: "op", text: string(c)})
			i++
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			toks = append(toks, boolTok{kind: "ident", text: s[i+1 : j]})
			i = j + 1
		case isAlpha(c):
			j := i
			for j < len(s) && isAlphaNum(s[j]) {
				j++
			}
			toks = append(toks, boolTok{kind: "ident", text: s[i:j]})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (isAlphaNum(s[j]) || s[j] == '&') {
				j++
			}
			toks = append(toks, boolTok{kind: "num", text: s[i:j]})
			i = j
		default:
			i++
		}
	}
	toks = append(toks, boolTok{kind: "eof"})
	return toks
}

func isAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
func isAlphaNum(c byte) bool { return isAlpha(c) || c >= '0' && c <= '9' }

type boolTok struct {
	kind string
	text string
}

func parseBoolOr(toks []boolTok, consts map[string]bool) (boolVal, int) {
	return parseOr(toks, 0, consts)
}

func parseOr(toks []boolTok, pos int, c map[string]bool) (boolVal, int) {
	lhs, pos := parseAnd(toks, pos, c)
	for pos < len(toks) && toks[pos].kind == "ident" {
		op := strings.ToLower(toks[pos].text)
		if op != "or" && op != "xor" && op != "eqv" && op != "imp" {
			break
		}
		pos++
		rhs, np := parseAnd(toks, pos, c)
		pos = np
		if !lhs.known || !rhs.known {
			lhs = unknownVal
			continue
		}
		switch op {
		case "or":
			lhs.val = lhs.val || rhs.val
		case "xor":
			lhs.val = lhs.val != rhs.val
		case "eqv":
			lhs.val = lhs.val == rhs.val
		case "imp":
			lhs.val = !lhs.val || rhs.val
		}
	}
	return lhs, pos
}

func parseAnd(toks []boolTok, pos int, c map[string]bool) (boolVal, int) {
	lhs, pos := parseUnary(toks, pos, c)
	for pos < len(toks) && toks[pos].kind == "ident" && strings.EqualFold(toks[pos].text, "and") {
		pos++
		rhs, np := parseUnary(toks, pos, c)
		pos = np
		if !lhs.known || !rhs.known {
			lhs = unknownVal
			continue
		}
		lhs.val = lhs.val && rhs.val
	}
	return lhs, pos
}

func parseUnary(toks []boolTok, pos int, c map[string]bool) (boolVal, int) {
	if pos < len(toks) && toks[pos].kind == "ident" && strings.EqualFold(toks[pos].text, "not") {
		v, np := parseUnary(toks, pos+1, c)
		if v.known {
			v.val = !v.val
		}
		return v, np
	}
	return parseAtomic(toks, pos, c)
}

func parseAtomic(toks []boolTok, pos int, c map[string]bool) (boolVal, int) {
	if pos >= len(toks) {
		return unknownVal, pos
	}
	t := toks[pos]
	switch t.kind {
	case "(":
		v, np := parseOr(toks, pos+1, c)
		if np < len(toks) && toks[np].kind == ")" {
			np++
		}
		return v, np
	case "ident":
		if v, ok := c[strings.ToLower(t.text)]; ok {
			return boolVal{val: v, known: true}, pos + 1
		}
		return unknownVal, pos + 1
	case "num":
		n, err := strconv.ParseInt(strings.TrimSuffix(t.text, "&"), 0, 64)
		if err == nil {
			return boolVal{val: n != 0, known: true}, pos + 1
		}
		return unknownVal, pos + 1
	default:
		return unknownVal, pos + 1
	}
}
