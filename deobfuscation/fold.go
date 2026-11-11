package deobfuscation

import (
	"strconv"
	"strings"

	"maldoctrace/vba/ast"
)

// Fold statically evaluates a side-effect-free expression to a string and
// reports whether the value could be fully determined.
func Fold(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.NumLit:
		if x.IsFloat {
			return strconv.FormatFloat(x.Float, 'g', -1, 64), true
		}
		return strconv.FormatInt(x.Int, 10), true
	case *ast.StrLit:
		return x.Value, true
	case *ast.Paren:
		return Fold(x.X)
	case *ast.Unary:
		if s, ok := Fold(x.X); ok && x.Op == "+" {
			return s, true
		}
		return "", false
	case *ast.Binary:
		l, lok := Fold(x.Left)
		r, rok := Fold(x.Right)
		if !lok || !rok {
			return "", false
		}
		switch x.Op {
		case "&":
			return l + r, true
		case "+":
			// Only concatenate provably string operands; numeric arithmetic is
			// left to the typed interpreter rather than guessed from text.
			if stringExpr(x.Left) && stringExpr(x.Right) {
				return l + r, true
			}
		}
		return "", false
	case *ast.Call:
		return foldCall(x)
	}
	return "", false
}

func foldCall(c *ast.Call) (string, bool) {
	id, ok := c.Fn.(*ast.Ident)
	if !ok {
		return "", false
	}
	name := strings.ToLower(id.Name)
	arg := func(i int) (string, bool) {
		if i >= len(c.Args) {
			return "", false
		}
		return Fold(c.Args[i])
	}
	switch name {
	case "chr", "chrb":
		if s, ok := arg(0); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64); err == nil {
				if n < 0 {
					n += 256
				}
				return string([]byte{byte(n & 0xFF)}), true
			}
		}
	case "chrw":
		if s, ok := arg(0); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64); err == nil {
				if n < 0 {
					n += 65536
				}
				return string(rune(n)), true
			}
		}
	case "strreverse":
		if s, ok := arg(0); ok {
			rr := []rune(s)
			for i, j := 0, len(rr)-1; i < j; i, j = i+1, j-1 {
				rr[i], rr[j] = rr[j], rr[i]
			}
			return string(rr), true
		}
	case "replace":
		s, ok := arg(0)
		if !ok {
			return "", false
		}
		f, ok := arg(1)
		if !ok {
			return "", false
		}
		r, ok := arg(2)
		if !ok {
			return "", false
		}
		return strings.Replace(s, f, r, -1), true
	case "lcase":
		if s, ok := arg(0); ok {
			return strings.ToLower(s), true
		}
	case "ucase":
		if s, ok := arg(0); ok {
			return strings.ToUpper(s), true
		}
	case "trim", "ltrim", "rtrim":
		s, ok := arg(0)
		if !ok {
			return "", false
		}
		switch name {
		case "ltrim":
			return strings.TrimLeft(s, " \t"), true
		case "rtrim":
			return strings.TrimRight(s, " \t"), true
		}
		return strings.TrimSpace(s), true
	case "left", "right":
		s, ok := arg(0)
		if !ok {
			return "", false
		}
		n, ok := arg(1)
		if !ok {
			return "", false
		}
		ni, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil || ni < 0 {
			return "", false
		}
		rr := []rune(s)
		if ni > len(rr) {
			ni = len(rr)
		}
		if name == "left" {
			return string(rr[:ni]), true
		}
		return string(rr[len(rr)-ni:]), true
	case "mid":
		s, ok := arg(0)
		if !ok {
			return "", false
		}
		st, ok := arg(1)
		if !ok {
			return "", false
		}
		si, err := strconv.Atoi(strings.TrimSpace(st))
		if err != nil {
			return "", false
		}
		rr := []rune(s)
		if si < 1 {
			si = 1
		}
		si--
		if si >= len(rr) {
			return "", true
		}
		if ln, ok := arg(2); ok {
			if li, err := strconv.Atoi(strings.TrimSpace(ln)); err == nil && li >= 0 && li < len(rr)-si {
				return string(rr[si : si+li]), true
			}
		}
		return string(rr[si:]), true
	case "cstr":
		if s, ok := arg(0); ok {
			return s, true
		}
	case "space":
		if s, ok := arg(0); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n < 1<<16 {
				return strings.Repeat(" ", n), true
			}
		}
	case "string":
		if s, ok := arg(0); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n < 1<<16 {
				if cs, ok2 := arg(1); ok2 && len(cs) > 0 {
					return strings.Repeat(cs[:1], n), true
				}
			}
		}
	}
	return "", false
}

func stringExpr(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.StrLit:
		return true
	case *ast.Paren:
		return stringExpr(x.X)
	case *ast.Binary:
		return x.Op == "&" || (x.Op == "+" && stringExpr(x.Left) && stringExpr(x.Right))
	case *ast.Call:
		_, ok := foldCall(x)
		return ok
	}
	return false
}

// Method describes how a folded expression was reconstructed, e.g. "literal",
// "concatenation", "concatenation+Chr+StrReverse". The order is stable.
func Method(e ast.Expr) string {
	seen := map[string]bool{}
	var order []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			order = append(order, s)
		}
	}
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch x := e.(type) {
		case *ast.Paren:
			walk(x.X)
		case *ast.Unary:
			walk(x.X)
		case *ast.Binary:
			add("concatenation")
			walk(x.Left)
			walk(x.Right)
		case *ast.Call:
			if id, ok := x.Fn.(*ast.Ident); ok {
				name := id.Name
				if c, ok := canonicalBuiltins[strings.ToLower(name)]; ok {
					name = c
				}
				add(name)
			}
			for _, a := range x.Args {
				walk(a)
			}
		}
	}
	walk(e)
	if len(order) == 0 {
		if _, ok := e.(*ast.StrLit); ok {
			return "literal"
		}
		return "constant"
	}
	return strings.Join(order, "+")
}

var canonicalBuiltins = map[string]string{
	"chr": "Chr", "chrb": "ChrB", "chrw": "ChrW", "strreverse": "StrReverse",
	"replace": "Replace", "lcase": "LCase", "ucase": "UCase", "trim": "Trim",
	"ltrim": "LTrim", "rtrim": "RTrim", "mid": "Mid", "left": "Left", "right": "Right",
	"space": "Space", "string": "String", "join": "Join", "split": "Split",
}
