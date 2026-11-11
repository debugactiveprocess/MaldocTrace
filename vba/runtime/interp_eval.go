package runtime

import (
	"strings"

	"maldoctrace/vba/ast"
	"maldoctrace/vba/lexer"
)

func (rt *Interp) eval(e ast.Expr) Value {
	if !rt.tick() {
		return NewUnknown("execution budget or context exhausted")
	}
	switch x := e.(type) {
	case *ast.Ident:
		return rt.resolveIdent(x.Name)
	case *ast.NumLit:
		if x.IsFloat {
			return VFloat(x.Float)
		}
		return VInt(x.Int)
	case *ast.StrLit:
		return VString(x.Value)
	case *ast.BoolLit:
		return VBool(x.Value)
	case *ast.NullLit:
		return VNull
	case *ast.NothingLit:
		return VNothing
	case *ast.EmptyLit:
		return VEmpty
	case *ast.Unary:
		return rt.evalUnary(x)
	case *ast.Binary:
		return rt.evalBinary(x)
	case *ast.Call:
		return rt.evalCall(x)
	case *ast.Member:
		return rt.evalMember(x)
	case *ast.Index:
		return rt.evalIndex(x)
	case *ast.ArrayLit:
		var arr []Value
		for _, el := range x.Elems {
			arr = append(arr, rt.eval(el))
		}
		return VArray(arr)
	case *ast.Paren:
		return rt.eval(x.X)
	case *ast.NamedArg:
		return rt.eval(x.Value)
	case *ast.NewExpr:
		if rt.host != nil {
			return rt.host.CreateObject(x.Name)
		}
		return VNothing
	}
	return VUnknown
}

func (rt *Interp) resolveIdent(name string) Value {
	if v, ok := rt.getVar(name); ok {
		return v
	}
	if arr, ok := rt.arrays[strings.ToLower(name)]; ok {
		return VArray(arr.elems)
	}
	if p := rt.procs[strings.ToLower(name)]; p != nil {
		return rt.callProc(p, nil)
	}
	switch strings.ToLower(name) {
	case "vbcrlf":
		return VString("\r\n")
	case "vbnullstring":
		return VString("")
	case "vbtab":
		return VString("\t")
	}
	for i := len(rt.withStack) - 1; i >= 0; i-- {
		o := rt.withStack[i]
		if o.Kind == KindObject {
			if v := o.Obj.Get(name); v.Kind != KindEmpty {
				return v
			}
		}
	}
	if rt.host != nil {
		if v := rt.host.GetObject(name); v.Kind != KindEmpty && !v.IsUnknown() {
			return v
		}
	}
	if !rt.optionExplicit && name != "<error>" {
		rt.setVar(name, VEmpty)
		return VEmpty
	}
	return NewUnknown("unresolved identifier " + name)
}

func (rt *Interp) evalMember(m *ast.Member) Value {
	obj := rt.eval(m.Obj)
	if obj.IsUnknown() {
		return NewUnknown("member on unknown " + m.Name)
	}
	if obj.Kind == KindObject {
		return obj.Obj.Get(m.Name)
	}
	return NewUnknown("member " + m.Name + " on non-object")
}

func (rt *Interp) evalIndex(ix *ast.Index) Value {
	base := rt.eval(ix.Base)
	idx, _ := rt.eval(ix.Idx).CoerceInt()
	if base.Kind == KindArray {
		if idx >= 0 && int(idx) < len(base.Arr) {
			return base.Arr[idx]
		}
		return NewUnknown("array index out of range")
	}
	return NewUnknown("index on non-array")
}

func (rt *Interp) evalUnary(u *ast.Unary) Value {
	v := rt.eval(u.X)
	if v.IsUnknown() {
		return v
	}
	switch u.Op {
	case "not":
		if n, ok := v.CoerceInt(); ok {
			return VInt(^n)
		}
		return VBool(!v.Truthy())
	case "-":
		if n, ok := v.CoerceFloat(); ok {
			return VFloat(-n)
		}
	case "+":
		if n, ok := v.CoerceFloat(); ok {
			return VFloat(n)
		}
	}
	return v
}

func (rt *Interp) assign(lhs ast.Expr, v Value) {
	switch l := lhs.(type) {
	case *ast.Ident:
		rt.setVar(l.Name, v)
	case *ast.Call:
		if id, ok := l.Fn.(*ast.Ident); ok && len(l.Args) == 1 {
			if arr, ok := rt.arrays[strings.ToLower(id.Name)]; ok {
				idx, _ := rt.eval(l.Args[0]).CoerceInt()
				pos := int(idx - arr.lower)
				if pos >= 0 && pos < len(arr.elems) {
					arr.elems[pos] = v
					return
				}
			}
		}
		obj := rt.eval(l.Fn)
		if obj.Kind != KindObject {
			return
		}
		// Assignment to an object's default member: Range("A1") = x,
		// ActiveDocument.Variables("k") = x.
		if target := rt.eval(l); target.Kind == KindObject {
			if d, ok := target.Obj.(interface{ SetDefaultValue(Value) }); ok {
				d.SetDefaultValue(v)
				return
			}
		}
		if len(l.Args) == 1 {
			if id, ok := l.Args[0].(*ast.Ident); ok {
				obj.Obj.Set(id.Name, v)
			}
		}
	case *ast.Member:
		if obj := rt.eval(l.Obj); obj.Kind == KindObject {
			// Give events raised by property setters (e.g. Range.Text = ...)
			// the location of the assignment.
			if h, ok := rt.host.(CallContextHost); ok {
				done := h.PushCall(&Event{Module: rt.curModule, Proc: rt.curProc, Line: l.Pos().Line, Col: l.Pos().Col,
					Receiver: obj.Obj.TypeName(), Method: l.Name, Simulated: true})
				defer done()
			}
			obj.Obj.Set(l.Name, v)
		}
	}
}

func (rt *Interp) recordAPICall(d *ast.Declare, args []Value, pos lexer.Pos) {
	res := make([]string, len(args))
	for i, a := range args {
		res[i] = a.CoerceString()
	}
	extra := map[string]string{"lib": d.Lib, "alias": d.Alias, "name": d.Name}
	rt.annotateAPIBuffer(d, args, extra)
	rt.event(&Event{
		Type:      "api_call",
		Line:      pos.Line,
		Col:       pos.Col,
		Raw:       res,
		Resolved:  res,
		Simulated: true,
		Extra:     extra,
	})
}

func (rt *Interp) withMember(name string) Value {
	for i := len(rt.withStack) - 1; i >= 0; i-- {
		o := rt.withStack[i]
		if o.Kind == KindObject {
			if v := o.Obj.Get(name); v.Kind != KindEmpty {
				return v
			}
		}
	}
	return VUnknown
}

// __EVAL_CALL__
