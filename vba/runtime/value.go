// Package runtime implements a small, documented VBA interpreter. It evaluates
// the AST produced by vba/parser over a virtual, isolated environment: external
// effects (Shell, COM objects, files, network, declared APIs) go through the
// Host interface and are simulated, never executed for real.
package runtime

import (
	"math"
	"strconv"
	"strings"
)

// Kind discriminates a Value.
type Kind int

const (
	KindUnknown Kind = iota
	KindEmpty
	KindNull
	KindNothing
	KindError
	KindBool
	KindInt
	KindFloat
	KindString
	KindArray
	KindObject
)

func (k Kind) String() string {
	switch k {
	case KindUnknown:
		return "unknown"
	case KindEmpty:
		return "empty"
	case KindNull:
		return "null"
	case KindNothing:
		return "nothing"
	case KindError:
		return "error"
	case KindBool:
		return "bool"
	case KindInt:
		return "int"
	case KindFloat:
		return "float"
	case KindString:
		return "string"
	case KindArray:
		return "array"
	case KindObject:
		return "object"
	}
	return "unknown"
}

// Value is a VBA runtime value. Unknown values are propagated, never silently
// coerced to zero or empty string.
type Value struct {
	Kind    Kind
	Int     int64
	Float   float64
	Str     string
	B       bool
	Arr     []Value
	Obj     Object
	ErrNum  int
	Unknown string // recorded uncertainty note when Kind == KindUnknown
}

// Object is the interface implemented by virtual COM objects (emulation).
type Object interface {
	TypeName() string
	Get(name string) Value
	Set(name string, v Value)
	Call(name string, args []Value) Value
}

var (
	VUnknown = Value{Kind: KindUnknown}
	VEmpty   = Value{Kind: KindEmpty}
	VNull    = Value{Kind: KindNull}
	VNothing = Value{Kind: KindNothing}
)

func VBool(b bool) Value       { return Value{Kind: KindBool, B: b} }
func VInt(n int64) Value       { return Value{Kind: KindInt, Int: n} }
func VFloat(f float64) Value   { return Value{Kind: KindFloat, Float: f} }
func VString(s string) Value   { return Value{Kind: KindString, Str: s} }
func VArray(arr []Value) Value { return Value{Kind: KindArray, Arr: arr} }
func VObject(o Object) Value   { return Value{Kind: KindObject, Obj: o} }
func VError(n int) Value       { return Value{Kind: KindError, ErrNum: n} }

func NewUnknown(note string) Value { return Value{Kind: KindUnknown, Unknown: note} }

// IsUnknown reports whether v is unknown.
func (v Value) IsUnknown() bool { return v.Kind == KindUnknown }

// IsEmpty reports Empty (distinct from Null, Nothing, default 0/"").
func (v Value) IsEmpty() bool { return v.Kind == KindEmpty }

// CoerceString renders v as a string, preserving unknown-ness at the caller's
// discretion. Empty -> "", Null -> "Null" (VBA renders Null). Nothing -> "".
func (v Value) CoerceString() string {
	switch v.Kind {
	case KindString:
		return v.Str
	case KindInt:
		return strconv.FormatInt(v.Int, 10)
	case KindFloat:
		return strconv.FormatFloat(v.Float, 'g', -1, 64)
	case KindBool:
		if v.B {
			return "True"
		}
		return "False"
	case KindEmpty, KindNothing:
		return ""
	case KindNull:
		return "Null"
	case KindObject:
		if o, ok := v.Obj.(interface{ DefaultValue() Value }); ok {
			return o.DefaultValue().CoerceString()
		}
		return v.Obj.TypeName()
	case KindUnknown:
		return "<unknown: " + v.Unknown + ">"
	default:
		return ""
	}
}

// CoerceFloat returns a numeric interpretation and whether v was numeric.
func (v Value) CoerceFloat() (float64, bool) {
	switch v.Kind {
	case KindInt:
		return float64(v.Int), true
	case KindFloat:
		return v.Float, true
	case KindBool:
		if v.B {
			return -1, true
		}
		return 0, true
	case KindString:
		f, err := strconv.ParseFloat(strings.TrimSpace(v.Str), 64)
		return f, err == nil
	case KindEmpty:
		return 0, true
	default:
		return 0, false
	}
}

// roundBankers rounds to nearest integer with ties to even (VBA CInt semantics).
func roundBankers(f float64) int64 {
	i := int64(math.Floor(f + 0.5))
	if m := math.Mod(f, 1); math.Abs(m) == 0.5 {
		if i%2 != 0 {
			i--
		}
	}
	return i
}

// CoerceInt returns VBA integer coercion (banker's rounding for floats).
func (v Value) CoerceInt() (int64, bool) {
	switch v.Kind {
	case KindInt:
		return v.Int, true
	case KindBool:
		if v.B {
			return -1, true
		}
		return 0, true
	case KindFloat:
		return roundBankers(v.Float), true
	case KindString:
		n, err := strconv.ParseInt(strings.TrimSpace(v.Str), 10, 64)
		if err == nil {
			return n, true
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(v.Str), 64); err == nil {
			return roundBankers(f), true
		}
		return 0, false
	case KindEmpty:
		return 0, true
	default:
		return 0, false
	}
}

// Truthy reports the boolean value; unknown-ness is the caller's concern.
func (v Value) Truthy() bool {
	switch v.Kind {
	case KindBool:
		return v.B
	case KindInt:
		return v.Int != 0
	case KindFloat:
		return v.Float != 0
	case KindString:
		return false
	case KindEmpty:
		return false
	default:
		return false
	}
}
