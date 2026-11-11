package runtime

import (
	"context"
	"strings"

	"maldoctrace/vba/ast"
	"maldoctrace/vba/lexer"
)

// Event records a simulated external action or an observed operation.
type Event struct {
	Receiver          string            `json:"receiver,omitempty"`
	Method            string            `json:"method,omitempty"`
	Arguments         []Argument        `json:"arguments,omitempty"`
	CallChain         []string          `json:"call_chain,omitempty"`
	LocationInherited bool              `json:"location_inherited,omitempty"`
	Type              string            `json:"type"`
	Module            string            `json:"module,omitempty"`
	Proc              string            `json:"proc,omitempty"`
	Line              int               `json:"line,omitempty"`
	Col               int               `json:"col,omitempty"`
	Raw               []string          `json:"raw,omitempty"`
	Resolved          []string          `json:"resolved,omitempty"`
	Simulated         bool              `json:"simulated"`
	Speculative       bool              `json:"speculative"`
	Extra             map[string]string `json:"extra,omitempty"`
}

// NamedCaller is implemented by simulated objects that understand named
// arguments (Name:=Value). names[i] is "" for a positional argument.
type NamedCaller interface {
	CallNamed(name string, args []Value, names []string) Value
}

// MethodModeler is implemented by simulated objects whose methods are
// recorded by the host but return a deliberately unknown value (for example
// ScriptControl.Run, whose result would require executing script code). Such
// calls are not reported as unsupported.
type MethodModeler interface{ ModelsMethod(name string) bool }

// Host is the boundary between the interpreter and the virtual outside world.
// Implementations must not perform real effects.
type Host interface {
	CreateObject(progID string) Value
	GetObject(name string) Value
	Record(e *Event)
	Note(msg string)
}

// Limits bounds interpreter execution.
type Limits struct {
	MaxSteps          int
	MaxLoopIterations int
	MaxCallDepth      int
}

// DefaultLimits returns interpreter limits for interactive use.
func DefaultLimits() Limits {
	return Limits{MaxSteps: 1_000_000, MaxLoopIterations: 100_000, MaxCallDepth: 200}
}

type arrayData struct {
	lower int64
	elems []Value
}

// Interp is a per-module interpreter instance.
type Interp struct {
	ctx            context.Context
	halted         bool
	optionExplicit bool
	host           Host
	procs          map[string]*ast.Proc
	decls          map[string]*ast.Declare
	globals        map[string]Value
	arrays         map[string]*arrayData
	pointers       map[int64]pointerRef
	called         map[string]bool
	scopes         []map[string]Value
	withStack      []Value
	lim            Limits
	steps          int
	depth          int
	curModule      string
	curProc        string
	speculate      bool
	onErr          bool
	exited         bool
	notes          []string
}

// New creates an interpreter for one module's parsed AST.
func New(mod *ast.Module, moduleName string, host Host, lim Limits) *Interp {
	defaults := DefaultLimits()
	if lim.MaxSteps <= 0 {
		lim.MaxSteps = defaults.MaxSteps
	}
	if lim.MaxLoopIterations <= 0 {
		lim.MaxLoopIterations = defaults.MaxLoopIterations
	}
	if lim.MaxCallDepth <= 0 {
		lim.MaxCallDepth = defaults.MaxCallDepth
	}
	rt := &Interp{
		host:      host,
		procs:     map[string]*ast.Proc{},
		decls:     map[string]*ast.Declare{},
		globals:   map[string]Value{},
		arrays:    map[string]*arrayData{},
		lim:       lim,
		curModule: moduleName,
	}
	for _, p := range mod.Procs {
		rt.procs[strings.ToLower(p.Name)] = p
	}
	for _, d := range mod.Decls {
		rt.decls[strings.ToLower(d.Name)] = d
	}
	return rt
}

// StepExceeded reports whether the instruction budget is exhausted.
func (rt *Interp) StepExceeded() bool { return rt.steps >= rt.lim.MaxSteps }

// Steps returns the number of executed statements/expressions.
func (rt *Interp) Steps() int { return rt.steps }

// Notes returns accumulated uncertainty diagnostics.
func (rt *Interp) Notes() []string { return rt.notes }

func (rt *Interp) note(msg string) { rt.notes = appendUnique(rt.notes, msg) }

// RunModule executes module-level statements.
func (rt *Interp) RunModule(body []ast.Stmt) {
	for _, s := range body {
		rt.exec(s)
	}
}

// WasCalled reports whether a procedure of this module has already run.
func (rt *Interp) WasCalled(name string) bool { return rt.called[strings.ToLower(name)] }

// CallProc invokes a named procedure with arguments.
func (rt *Interp) CallProc(name string, args []Value) Value {
	proc := rt.procs[strings.ToLower(name)]
	if proc == nil {
		return VUnknown
	}
	return rt.callProc(proc, args)
}

func (rt *Interp) setVar(name string, v Value) {
	name = strings.ToLower(name)
	for i := len(rt.scopes) - 1; i >= 0; i-- {
		if _, ok := rt.scopes[i][name]; ok {
			rt.scopes[i][name] = v
			return
		}
	}
	if len(rt.scopes) > 0 {
		rt.scopes[len(rt.scopes)-1][name] = v
		return
	}
	rt.globals[name] = v
}

func (rt *Interp) getVar(name string) (Value, bool) {
	name = strings.ToLower(name)
	for i := len(rt.scopes) - 1; i >= 0; i-- {
		if v, ok := rt.scopes[i][name]; ok {
			return v, true
		}
	}
	if v, ok := rt.globals[name]; ok {
		return v, true
	}
	return Value{}, false
}

func (rt *Interp) getArray(name string) (*arrayData, bool) {
	a, ok := rt.arrays[strings.ToLower(name)]
	return a, ok
}

func (rt *Interp) callProc(proc *ast.Proc, args []Value) Value {
	return rt.callProcRef(proc, args, nil)
}

// callProcRef invokes a procedure. argExprs, when given, are the caller's
// argument expressions: parameters not declared ByVal are ByRef in VBA, so a
// value assigned to such a parameter is written back to a plain variable
// passed in that position (e.g. "Set p = CreateObject(...)" in a helper Sub).
func (rt *Interp) callProcRef(proc *ast.Proc, args []Value, argExprs []ast.Expr) Value {
	if rt.halted {
		return NewUnknown("execution halted")
	}
	if rt.depth >= rt.lim.MaxCallDepth {
		rt.note("max call depth reached")
		return VUnknown
	}
	rt.depth++
	if rt.called == nil {
		rt.called = map[string]bool{}
	}
	rt.called[strings.ToLower(proc.Name)] = true
	savedProc := rt.curProc
	rt.curProc = proc.Name
	scope := map[string]Value{}
	scope[strings.ToLower(proc.Name)] = VEmpty
	for i, p := range proc.Params {
		if i < len(args) {
			scope[strings.ToLower(p.Name)] = args[i]
		} else {
			scope[strings.ToLower(p.Name)] = VEmpty
		}
	}
	rt.scopes = append(rt.scopes, scope)
	for _, s := range proc.Body {
		if rt.halted {
			break
		}
		rt.exec(s)
		if rt.exited {
			rt.exited = false
			break
		}
	}
	ret := VEmpty
	if proc.Kind == ast.ProcFunction {
		if v, ok := scope[strings.ToLower(proc.Name)]; ok {
			ret = v
		}
	}
	rt.scopes = rt.scopes[:len(rt.scopes)-1]
	for i, p := range proc.Params {
		if p.ByVal || p.ParamArray || i >= len(argExprs) {
			continue
		}
		id, ok := argExprs[i].(*ast.Ident)
		if !ok {
			continue
		}
		low := strings.ToLower(id.Name)
		if rt.procs[low] != nil || rt.arrays[low] != nil {
			continue
		}
		if v, ok := scope[strings.ToLower(p.Name)]; ok {
			rt.setVar(id.Name, v)
		}
	}
	rt.curProc = savedProc
	rt.depth--
	return ret
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func (rt *Interp) event(e *Event) {
	e.Module = rt.curModule
	e.Proc = rt.curProc
	e.Speculative = rt.speculate
	if rt.host != nil {
		rt.host.Record(e)
	}
}

func (rt *Interp) posOf(e ast.Expr) lexer.Pos { return e.Pos() }

// __INTERP_EXEC__
