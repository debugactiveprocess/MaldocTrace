package runtime

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/parser"
)

// maxExecuteDepth bounds nested Execute calls (code that executes code
// that executes code ...).
const maxExecuteDepth = 8

// SplitVBScriptStatements returns VBScript source with the statements that
// share a line (a : b : c) on separate lines. VBScript has no line labels,
// so "name:" at the start of a line is a call followed by a separator, not
// a label as it would be in VBA. Colons inside string literals and comments
// are kept.
func SplitVBScriptStatements(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	inStr, comment := false, false
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '\n' || c == '\r':
			inStr, comment = false, false
		case comment:
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '\'':
			comment = true
		case c == ':' && (i+1 >= len(code) || code[i+1] != '='):
			b.WriteByte('\n')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// isExecute reports a call to VBScript's Execute / ExecuteGlobal statement
// that the module does not define itself.
func (rt *Interp) isExecute(name string) bool {
	return (name == "execute" || name == "executeglobal") && rt.procs[name] == nil
}

// execute runs VBScript source built at run time, as Execute and
// ExecuteGlobal do: its procedures join the module and its statements run
// in the current scope (ExecuteGlobal: the global one).
func (rt *Interp) execute(name string, c *ast.Call, args []Value) Value {
	e, done := rt.callContext(c, args, "VBScript", name)
	defer done()
	e.Type = "script_execute_statement"
	e.Simulated = true
	e.Extra = map[string]string{"language": "VBScript"}
	rt.event(e)
	if len(args) != 1 || args[0].IsUnknown() {
		rt.note(name + " of an unresolved string not emulated")
		return VEmpty
	}
	if rt.execDepth >= maxExecuteDepth {
		rt.note(name + " nesting limit reached")
		return VEmpty
	}
	mod := parser.Parse(SplitVBScriptStatements(args[0].CoerceString()))
	for _, p := range mod.Procs {
		rt.procs[strings.ToLower(p.Name)] = p
	}
	for _, d := range mod.Decls {
		rt.decls[strings.ToLower(d.Name)] = d
	}
	rt.execDepth++
	defer func() { rt.execDepth-- }()
	scopes := rt.scopes
	if name == "executeglobal" {
		rt.scopes = nil
	}
	for _, s := range mod.Body {
		if rt.halted || rt.exited {
			break
		}
		rt.exec(s)
	}
	rt.scopes = scopes
	return VEmpty
}
