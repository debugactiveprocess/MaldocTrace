package emulation

import (
	"regexp"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// scriptControl models MSScriptControl.ScriptControl. Code passed to AddCode
// is recorded as a recovered script (never executed); Run/Eval/
// ExecuteStatement are recorded as script-engine invocations, which are
// distinct from operating-system command execution.
type scriptControl struct {
	h         *Host
	language  string
	functions map[string]bool
}

var (
	reJSFunction = regexp.MustCompile(`\bfunction\s+([A-Za-z_$][\w$]*)\s*\(`)
	reVBSProc    = regexp.MustCompile(`(?im)^\s*(?:(?:public|private)\s+)?(?:sub|function)\s+([A-Za-z_]\w*)`)
)

// ScriptFunctions returns the procedure names a script defines, in order.
func ScriptFunctions(code string) []string {
	var out []string
	seen := map[string]bool{}
	for _, re := range []*regexp.Regexp{reJSFunction, reVBSProc} {
		for _, m := range re.FindAllStringSubmatch(code, -1) {
			if k := strings.ToLower(m[1]); !seen[k] {
				seen[k] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}

func (o *scriptControl) lang() string {
	if o.language == "" {
		return "unspecified"
	}
	return o.language
}

func (o *scriptControl) TypeName() string { return "ScriptControl" }

// ModelsMethod implements runtime.MethodModeler.
func (o *scriptControl) ModelsMethod(name string) bool {
	switch strings.ToLower(name) {
	case "run", "eval", "executestatement", "addcode", "addobject", "reset":
		return true
	}
	return false
}
func (o *scriptControl) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "language":
		return runtime.VString(o.language)
	}
	return runtime.NewUnknown("unsupported ScriptControl property " + name)
}
func (o *scriptControl) Set(name string, v runtime.Value) {
	if strings.EqualFold(name, "Language") {
		o.language = v.CoerceString()
	}
}
func (o *scriptControl) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "addcode":
		code := argString(args, 0)
		fns := ScriptFunctions(code)
		if o.functions == nil {
			o.functions = map[string]bool{}
		}
		for _, f := range fns {
			o.functions[strings.ToLower(f)] = true
		}
		o.h.rec("script_add_code", args, map[string]string{"language": o.lang(), "functions": strings.Join(fns, ",")})
		return runtime.VEmpty
	case "run":
		fn := argString(args, 0)
		defined := "false"
		if o.functions[strings.ToLower(fn)] {
			defined = "true"
		}
		o.h.rec("script_run", args, map[string]string{"language": o.lang(), "function": fn, "defined_in_script": defined})
		return runtime.NewUnknown("ScriptControl.Run result is not emulated")
	case "eval":
		o.h.rec("script_eval", args, map[string]string{"language": o.lang()})
		return runtime.NewUnknown("ScriptControl.Eval result is not emulated")
	case "executestatement":
		o.h.rec("script_execute_statement", args, map[string]string{"language": o.lang()})
		return runtime.VEmpty
	case "addobject", "reset":
		return runtime.VEmpty
	}
	o.h.Note("unsupported ScriptControl method " + name)
	return runtime.NewUnknown("unsupported ScriptControl method " + name)
}
