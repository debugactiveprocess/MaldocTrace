package runtime

import (
	"math"
	"regexp"
	"strings"

	"maldoctrace/vba/ast"
)

func numericResult(f float64, l, r Value) Value {
	if l.Kind == KindInt && r.Kind == KindInt && f == math.Trunc(f) {
		return VInt(int64(f))
	}
	return VFloat(f)
}

func (rt *Interp) evalBinary(b *ast.Binary) Value {
	l := rt.eval(b.Left)
	r := rt.eval(b.Right)
	if l.Kind == KindObject {
		if o, ok := l.Obj.(interface{ DefaultValue() Value }); ok {
			l = o.DefaultValue()
		}
	}
	if r.Kind == KindObject {
		if o, ok := r.Obj.(interface{ DefaultValue() Value }); ok {
			r = o.DefaultValue()
		}
	}
	op := b.Op
	if l.Kind == KindNull || r.Kind == KindNull {
		switch op {
		case "=", "<>", "<", ">", "<=", ">=", "and", "or":
			return VNull
		}
	}
	if l.IsUnknown() || r.IsUnknown() {
		return NewUnknown("binary op " + op + " with unknown operand")
	}
	switch op {
	case "&":
		return VString(l.CoerceString() + r.CoerceString())
	case "+":
		if l.Kind == KindString && r.Kind == KindString {
			return VString(l.Str + r.Str)
		}
		if ln, lok := l.CoerceFloat(); lok {
			if rn, rok := r.CoerceFloat(); rok {
				return numericResult(ln+rn, l, r)
			}
		}
		return VString(l.CoerceString() + r.CoerceString())
	case "-":
		if ln, lok := l.CoerceFloat(); lok {
			if rn, rok := r.CoerceFloat(); rok {
				return numericResult(ln-rn, l, r)
			}
		}
	case "*":
		if ln, lok := l.CoerceFloat(); lok {
			if rn, rok := r.CoerceFloat(); rok {
				return numericResult(ln*rn, l, r)
			}
		}
	case "/":
		if ln, lok := l.CoerceFloat(); lok {
			if rn, rok := r.CoerceFloat(); rok && rn != 0 {
				return VFloat(ln / rn)
			}
		}
	case "\\":
		li, _ := l.CoerceInt()
		ri, _ := r.CoerceInt()
		if ri != 0 {
			return VInt(li / ri)
		}
	case "mod":
		li, _ := l.CoerceInt()
		ri, _ := r.CoerceInt()
		if ri != 0 {
			return VInt(li % ri)
		}
	case "^":
		if ln, lok := l.CoerceFloat(); lok {
			if rn, rok := r.CoerceFloat(); rok {
				return VFloat(math.Pow(ln, rn))
			}
		}
	case "and", "or", "xor", "eqv", "imp":
		return rt.evalLogical(op, l, r)
	case "like":
		return VBool(vbaLike(l.CoerceString(), r.CoerceString()))
	case "is":
		return VBool((l.Kind == KindNothing) == (r.Kind == KindNothing))
	case "=", "<>", "<", ">", "<=", ">=":
		return rt.evalCompare(op, l, r)
	}
	return NewUnknown("unsupported operator " + op)
}

func (rt *Interp) evalLogical(op string, l, r Value) Value {
	if l.Kind == KindBool || r.Kind == KindBool {
		a, b := l.Truthy(), r.Truthy()
		switch op {
		case "and":
			return VBool(a && b)
		case "or":
			return VBool(a || b)
		case "xor":
			return VBool(a != b)
		case "eqv":
			return VBool(a == b)
		case "imp":
			return VBool(!a || b)
		}
	}
	li, _ := l.CoerceInt()
	ri, _ := r.CoerceInt()
	switch op {
	case "and":
		return VInt(li & ri)
	case "or":
		return VInt(li | ri)
	case "xor":
		return VInt(li ^ ri)
	case "eqv":
		return VInt(^(li ^ ri))
	case "imp":
		return VInt(^li | ri)
	}
	return VUnknown
}

func (rt *Interp) evalCompare(op string, l, r Value) Value {
	if lf, lok := l.CoerceFloat(); lok {
		if rf, rok := r.CoerceFloat(); rok {
			return VBool(compareFloats(op, lf, rf))
		}
	}
	c := strings.Compare(l.CoerceString(), r.CoerceString())
	switch op {
	case "=":
		return VBool(c == 0)
	case "<>":
		return VBool(c != 0)
	case "<":
		return VBool(c < 0)
	case ">":
		return VBool(c > 0)
	case "<=":
		return VBool(c <= 0)
	case ">=":
		return VBool(c >= 0)
	}
	return VBool(false)
}

func compareFloats(op string, a, b float64) bool {
	switch op {
	case "=":
		return a == b
	case "<>":
		return a != b
	case "<":
		return a < b
	case ">":
		return a > b
	case "<=":
		return a <= b
	case ">=":
		return a >= b
	}
	return false
}

var likeReplacer = strings.NewReplacer(
	`\`, `\\`,
	`*`, `.*`,
	`?`, `.`,
	`#`, `[0-9]`,
)

// vbaLike implements a basic subset of VBA Like (wildcards *, ?, #).
func vbaLike(s, pattern string) bool {
	re := likeReplacer.Replace(pattern)
	matched, err := regexp.MatchString(`(?is)^`+re+`$`, s)
	return err == nil && matched
}
