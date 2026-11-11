package runtime

import (
	"context"
	"fmt"
	"maldoctrace/vba/ast"
	"strconv"
	"strings"
)

type Argument struct {
	Original      string `json:"original"`
	Value         string `json:"value"`
	Kind          string `json:"kind"`
	UnknownReason string `json:"unknown_reason,omitempty"`
}

// CallContextHost brackets virtual effects so nested calls retain their origin.
type CallContextHost interface{ PushCall(*Event) func() }

func (rt *Interp) SetContext(ctx context.Context) { rt.ctx = ctx }
func (rt *Interp) SetOptionExplicit(v bool)       { rt.optionExplicit = v }
func (rt *Interp) tick() bool {
	if rt.halted {
		return false
	}
	if rt.ctx != nil && rt.ctx.Err() != nil {
		rt.note("execution cancelled: " + rt.ctx.Err().Error())
		rt.halted = true
		return false
	}
	if rt.steps >= rt.lim.MaxSteps {
		rt.note("max step budget reached")
		rt.halted = true
		return false
	}
	rt.steps++
	return true
}

func ExprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StrLit:
		return `"` + strings.ReplaceAll(x.Value, `"`, `""`) + `"`
	case *ast.NumLit:
		return x.Text
	case *ast.Member:
		return ExprText(x.Obj) + "." + x.Name
	case *ast.Call:
		a := make([]string, len(x.Args))
		for i, v := range x.Args {
			a[i] = ExprText(v)
		}
		return ExprText(x.Fn) + "(" + strings.Join(a, ", ") + ")"
	case *ast.Binary:
		return "(" + ExprText(x.Left) + " " + x.Op + " " + ExprText(x.Right) + ")"
	case *ast.Unary:
		return x.Op + " " + ExprText(x.X)
	case *ast.Paren:
		return "(" + ExprText(x.X) + ")"
	case *ast.NamedArg:
		return x.Name + ":=" + ExprText(x.Value)
	case *ast.BoolLit:
		return strconv.FormatBool(x.Value)
	case *ast.NothingLit:
		return "Nothing"
	case *ast.EmptyLit:
		return "Empty"
	case *ast.NullLit:
		return "Null"
	}
	return fmt.Sprintf("<%T>", e)
}

func (rt *Interp) callContext(c *ast.Call, args []Value, receiver, method string) (*Event, func()) {
	e := &Event{Module: rt.curModule, Proc: rt.curProc, Line: c.Pos().Line, Col: c.Pos().Col, Receiver: receiver, Method: method, Simulated: true}
	for i, v := range args {
		raw := ExprText(c.Args[i])
		value := v.CoerceString()
		e.Raw = append(e.Raw, raw)
		e.Resolved = append(e.Resolved, value)
		e.Arguments = append(e.Arguments, Argument{Original: raw, Value: value, Kind: v.Kind.String(), UnknownReason: v.Unknown})
	}
	if h, ok := rt.host.(CallContextHost); ok {
		return e, h.PushCall(e)
	}
	return e, func() {}
}

func (rt *Interp) unresolved(c *ast.Call, args []Value, receiver, method, reason string) Value {
	e, done := rt.callContext(c, args, receiver, method)
	defer done()
	e.Type = "unresolved_call"
	e.Extra = map[string]string{"reason": reason}
	rt.event(e)
	rt.note(reason)
	return NewUnknown(reason)
}
