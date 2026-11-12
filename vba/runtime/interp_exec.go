package runtime

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
)

func (rt *Interp) exec(s ast.Stmt) {
	if !rt.tick() {
		return
	}
	switch st := s.(type) {
	case *ast.Assign:
		rt.assign(st.LHS, rt.eval(st.RHS))
	case *ast.Set:
		rt.assign(st.LHS, rt.eval(st.RHS))
	case *ast.CallStmt:
		rt.eval(st.CallExpr)
	case *ast.Dim:
		rt.execDim(st)
	case *ast.Const:
		rt.execConst(st)
	case *ast.If:
		for _, b := range st.Branches {
			if rt.condTruth(b.Cond) {
				for _, x := range b.Body {
					rt.exec(x)
				}
				return
			}
		}
		for _, x := range st.Else {
			rt.exec(x)
		}
	case *ast.Select:
		rt.execSelect(st)
	case *ast.For:
		rt.execFor(st)
	case *ast.ForEach:
		rt.execForEach(st)
	case *ast.While:
		rt.execWhile(st)
	case *ast.DoLoop:
		rt.execDo(st)
	case *ast.Exit:
		rt.exited = true
	case *ast.OnError:
		rt.onErr = st.ResumeNext
	case *ast.With:
		rt.withStack = append(rt.withStack, rt.eval(st.Obj))
		for _, x := range st.Body {
			rt.exec(x)
		}
		rt.withStack = rt.withStack[:len(rt.withStack)-1]
	case *ast.End:
		rt.exited = true
	case *ast.Goto, *ast.Resume, *ast.Label:
		rt.note("unsupported control flow (GoTo/Resume/label) ignored")
	case *ast.Stop:
	case *ast.Noop:
		rt.note("unsupported statement encountered")
	}
}

func (rt *Interp) condTruth(e ast.Expr) bool {
	v := rt.eval(e)
	if v.IsUnknown() {
		rt.note("conditional expression unresolved: " + v.Unknown)
		return false
	}
	return v.Truthy()
}

func (rt *Interp) execDim(d *ast.Dim) {
	if d.ReDim && len(d.Bounds) == 0 {
		return
	}
	name := strings.ToLower(d.Name)
	if len(d.Bounds) > 0 {
		lower := int64(0)
		upper := int64(0)
		if len(d.Bounds) == 2 {
			if lv, ok := rt.eval(d.Bounds[0]).CoerceInt(); ok {
				lower = lv
			}
			if uv, ok := rt.eval(d.Bounds[1]).CoerceInt(); ok {
				upper = uv
			}
		} else if len(d.Bounds) == 1 {
			if uv, ok := rt.eval(d.Bounds[0]).CoerceInt(); ok {
				upper = uv
			}
		}
		n := upper - lower + 1
		if n < 0 || n > 10_000_000 {
			rt.note("array bounds out of range for " + d.Name)
			return
		}
		elems := make([]Value, n)
		for i := range elems {
			elems[i] = VEmpty
		}
		if old, ok := rt.arrays[name]; ok && d.Preserve {
			copy(elems, old.elems)
		}
		rt.arrays[name] = &arrayData{lower: lower, elems: elems}
		if d.ReDim {
			// A variable declared without bounds (Dim x / Dim x()) now
			// holds the array; it shares the element slice, so element
			// assignments are visible through the variable too.
			if _, ok := rt.getVar(name); ok {
				rt.setVar(name, VArray(elems))
			}
		}
		return
	}
	if d.Init != nil {
		rt.setVar(name, rt.eval(d.Init))
	} else {
		rt.setVar(name, VEmpty)
	}
}

func (rt *Interp) execConst(c *ast.Const) {
	rt.setVar(strings.ToLower(c.Name), rt.eval(c.Val))
}

func (rt *Interp) execFor(f *ast.For) {
	start, _ := rt.eval(f.Start).CoerceFloat()
	stop, _ := rt.eval(f.Stop).CoerceFloat()
	step := 1.0
	if f.Step != nil {
		if sv, ok := rt.eval(f.Step).CoerceFloat(); ok && sv != 0 {
			step = sv
		}
	}
	name := strings.ToLower(f.Var)
	i := start
	iters := 0
	for !rt.halted {
		if step > 0 && i > stop || step < 0 && i < stop {
			break
		}
		if iters >= rt.lim.MaxLoopIterations {
			rt.note("loop iteration limit reached")
			break
		}
		iters++
		rt.setVar(name, VFloat(i))
		for _, s := range f.Body {
			rt.exec(s)
			if rt.exited {
				rt.exited = false
				return
			}
		}
		i += step
	}
}

func (rt *Interp) execForEach(f *ast.ForEach) {
	col := rt.eval(f.In)
	var elems []Value
	switch col.Kind {
	case KindArray:
		elems = col.Arr
	case KindObject:
		if v := col.Obj.Get("_items"); v.Kind == KindArray {
			elems = v.Arr
		}
	default:
		return
	}
	for _, e := range elems {
		if rt.halted {
			break
		}
		rt.setVar(strings.ToLower(f.Var), e)
		for _, s := range f.Body {
			rt.exec(s)
			if rt.exited {
				rt.exited = false
				return
			}
		}
	}
}

func (rt *Interp) execWhile(w *ast.While) {
	iters := 0
	for rt.condTruth(w.Cond) {
		if iters >= rt.lim.MaxLoopIterations {
			rt.note("loop iteration limit reached")
			break
		}
		iters++
		for _, s := range w.Body {
			rt.exec(s)
			if rt.exited {
				rt.exited = false
				return
			}
		}
	}
}

func (rt *Interp) execDo(d *ast.DoLoop) {
	iters := 0
	for !rt.halted {
		if iters >= rt.lim.MaxLoopIterations {
			rt.note("loop iteration limit reached")
			break
		}
		iters++
		if d.PreCond != nil {
			v := rt.condTruth(d.PreCond)
			if d.PreWhile && !v || !d.PreWhile && v {
				break
			}
		}
		loopExit := false
		for _, s := range d.Body {
			rt.exec(s)
			if rt.exited {
				rt.exited = false
				loopExit = true
				break
			}
		}
		if loopExit {
			break
		}
		if d.PostCond != nil {
			v := rt.condTruth(d.PostCond)
			if d.PreWhile && !v || !d.PreWhile && v {
				break
			}
		}
	}
}

func (rt *Interp) execSelect(sel *ast.Select) {
	test := rt.eval(sel.Test)
	for _, c := range sel.Cases {
		if len(c.Exprs) == 0 {
			for _, s := range c.Body {
				rt.exec(s)
			}
			return
		}
		for _, ce := range c.Exprs {
			if rt.valuesEqual(test, rt.eval(ce)) {
				for _, s := range c.Body {
					rt.exec(s)
				}
				return
			}
		}
	}
}

func (rt *Interp) valuesEqual(a, b Value) bool {
	if a.IsUnknown() || b.IsUnknown() || a.Kind == KindNull || b.Kind == KindNull {
		return false
	}
	if af, aok := a.CoerceFloat(); aok {
		if bf, bok := b.CoerceFloat(); bok {
			return af == bf
		}
	}
	return strings.EqualFold(a.CoerceString(), b.CoerceString())
}
