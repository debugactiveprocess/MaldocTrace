package runtime

import (
	"strings"

	"maldoctrace/vba/ast"
	"maldoctrace/vba/lexer"
)

type builtinFunc func(rt *Interp, args []Value, pos lexer.Pos) Value

func (rt *Interp) evalArgs(args []ast.Expr) []Value {
	out := make([]Value, len(args))
	for i, a := range args {
		out[i] = rt.eval(a)
	}
	return out
}

func (rt *Interp) evalCall(c *ast.Call) Value {
	if id, ok := c.Fn.(*ast.Ident); ok && len(c.Args) == 1 {
		switch strings.ToLower(id.Name) {
		case "varptr", "strptr", "objptr":
			if rt.procs[strings.ToLower(id.Name)] == nil && rt.decls[strings.ToLower(id.Name)] == nil {
				return rt.evalPointer(c.Args[0])
			}
		}
	}
	args := rt.evalArgs(c.Args)
	switch fn := c.Fn.(type) {
	case *ast.Ident:
		name := strings.ToLower(fn.Name)
		if arr, ok := rt.arrays[name]; ok && len(args) == 1 {
			idx, _ := args[0].CoerceInt()
			pos := int(idx - arr.lower)
			if pos >= 0 && pos < len(arr.elems) {
				return arr.elems[pos]
			}
			return NewUnknown("array index out of range")
		}
		if b, ok := builtins[name]; ok {
			_, done := rt.callContext(c, args, "VBA", fn.Name)
			defer done()
			if name != "shell" && name != "createobject" && name != "getobject" {
				for _, a := range args {
					if a.IsUnknown() {
						return a
					}
				}
			}
			if len(args) == 0 && name != "doevents" && name != "array" {
				return NewUnknown("missing arguments for " + name)
			}
			return b(rt, args, c.Pos())
		}
		if proc := rt.procs[name]; proc != nil {
			if proc.Kind == ast.ProcFunction {
				return rt.callProcRef(proc, args, c.Args)
			}
			rt.callProcRef(proc, args, c.Args)
			return VEmpty
		}
		if d := rt.decls[name]; d != nil {
			rt.recordAPICall(d, args, c.Pos())
			return VUnknown
		}
		if v, ok := rt.getVar(name); ok && v.Kind == KindArray && len(args) == 1 {
			if n, ok := args[0].CoerceInt(); ok && n >= 0 && n < int64(len(v.Arr)) {
				return v.Arr[n]
			}
			return NewUnknown("array index out of range")
		}
		return rt.unresolved(c, args, "", fn.Name, "unresolved call "+fn.Name)
	case *ast.Member:
		obj := rt.eval(fn.Obj)
		if obj.Kind == KindObject {
			_, done := rt.callContext(c, args, obj.Obj.TypeName(), fn.Name)
			defer done()
			var v Value
			if nc, ok := obj.Obj.(NamedCaller); ok && hasNamedArgs(c.Args) {
				v = nc.CallNamed(fn.Name, args, argNames(c.Args))
			} else {
				v = obj.Obj.Call(fn.Name, args)
			}
			if m, ok := obj.Obj.(MethodModeler); ok && m.ModelsMethod(fn.Name) {
				return v // the host recorded the call; an unknown result is expected
			}
			if v.IsUnknown() {
				return rt.unresolved(c, args, obj.Obj.TypeName(), fn.Name, "unsupported method "+obj.Obj.TypeName()+"."+fn.Name)
			}
			return v
		}
		return rt.unresolved(c, args, ExprText(fn.Obj), fn.Name, "receiver unresolved: "+obj.CoerceString())
	}
	return VUnknown
}

func arg(args []Value, i int, def Value) Value {
	if i < len(args) {
		return args[i]
	}
	return def
}

func argStr(args []Value, i int) string {
	if i < len(args) {
		return args[i].CoerceString()
	}
	return ""
}

func argInt(args []Value, i int) (int64, bool) {
	if i < len(args) {
		return args[i].CoerceInt()
	}
	return 0, false
}

func builtinChr(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, _ := argInt(args, 0)
	n &= 0xFF
	if n < 0 {
		n += 256
	}
	return VString(string([]byte{byte(n)}))
}

func builtinChrW(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, _ := argInt(args, 0)
	if n < 0 {
		n += 65536
	}
	return VString(string(rune(n)))
}

func builtinAsc(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	if s == "" {
		return VError(5)
	}
	return VInt(int64(s[0]))
}

func builtinAscW(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	rr := []rune(s)
	if len(rr) == 0 {
		return VError(5)
	}
	return VInt(int64(rr[0]))
}

func builtinStrReverse(rt *Interp, args []Value, _ lexer.Pos) Value {
	rr := []rune(argStr(args, 0))
	for i, j := 0, len(rr)-1; i < j; i, j = i+1, j-1 {
		rr[i], rr[j] = rr[j], rr[i]
	}
	return VString(string(rr))
}

func builtinReplace(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	find := argStr(args, 1)
	rep := argStr(args, 2)
	count := int64(-1)
	if c, ok := argInt(args, 4); ok && c >= 0 {
		count = c
	}
	if find == "" {
		return VString(s)
	}
	return VString(strings.Replace(s, find, rep, int(count)))
}

func builtinSplit(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	delim := argStr(args, 1)
	if delim == "" {
		delim = " "
	}
	parts := strings.Split(s, delim)
	arr := make([]Value, len(parts))
	for i, p := range parts {
		arr[i] = VString(p)
	}
	return VArray(arr)
}

func builtinJoin(rt *Interp, args []Value, _ lexer.Pos) Value {
	delim := argStr(args, 1)
	var sb strings.Builder
	if len(args) > 0 && args[0].Kind == KindArray {
		for i, e := range args[0].Arr {
			if i > 0 {
				sb.WriteString(delim)
			}
			sb.WriteString(e.CoerceString())
		}
	}
	return VString(sb.String())
}

// __BUILTINS_STR__

func hasNamedArgs(args []ast.Expr) bool {
	for _, a := range args {
		if _, ok := a.(*ast.NamedArg); ok {
			return true
		}
	}
	return false
}

func argNames(args []ast.Expr) []string {
	names := make([]string, len(args))
	for i, a := range args {
		if n, ok := a.(*ast.NamedArg); ok {
			names[i] = n.Name
		}
	}
	return names
}
