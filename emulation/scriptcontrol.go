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
	objects   map[string]runtime.Value // AddObject name -> object
}

// reScriptShellCall matches "<obj>.Run(" / ".Exec(" calls on a host object
// with a string-literal command, in JScript or VBScript.
var reScriptShellCall = regexp.MustCompile(`(?i)\b([A-Za-z_$][\w$]*)\.(run|exec)\s*\(?\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`)

const backslash = byte(92)

// jsUnquote decodes a JScript/VBScript string literal.
func jsUnquote(lit string) string {
	body := lit[1 : len(lit)-1]
	if strings.IndexByte(body, backslash) < 0 {
		return strings.ReplaceAll(body, `""`, `"`) // VBScript doubling
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != backslash || i+1 == len(body) {
			b.WriteByte(c)
			continue
		}
		i++
		switch body[i] {
		case 'n':
			b.WriteByte(10)
		case 'r':
			b.WriteByte(13)
		case 't':
			b.WriteByte(9)
		default:
			b.WriteByte(body[i])
		}
	}
	return b.String()
}

// shellCommands records OS commands that script code runs through a
// WScript.Shell object the macro exposed with AddObject. The script is not
// executed; only literal command strings are recovered.
func (o *scriptControl) shellCommands(code string) {
	for _, m := range reScriptShellCall.FindAllStringSubmatch(code, -1) {
		obj, ok := o.objects[strings.ToLower(m[1])]
		if !ok || obj.Kind != runtime.KindObject {
			continue
		}
		if _, isShell := obj.Obj.(*wshShell); !isShell {
			continue
		}
		typ := "wscript_shell_run"
		if strings.EqualFold(m[2], "exec") {
			typ = "wscript_shell_exec"
		}
		cmd := jsUnquote(m[3])
		method := "Run"
		if typ == "wscript_shell_exec" {
			method = "Exec"
		}
		// The event names its own receiver so it does not inherit the
		// ExecuteStatement call's arguments.
		o.h.Record(&runtime.Event{
			Type: typ, Receiver: "WScript.Shell", Method: method,
			Raw: []string{m[3]}, Resolved: []string{cmd}, Simulated: true,
			Arguments: []runtime.Argument{{Original: m[3], Value: cmd, Kind: "string"}},
			Extra:     map[string]string{"via": "ScriptControl (" + o.lang() + ") code, object " + m[1]},
		})
	}
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
		o.shellCommands(argString(args, 0))
		return runtime.VEmpty
	case "addobject":
		if len(args) >= 2 {
			if o.objects == nil {
				o.objects = map[string]runtime.Value{}
			}
			o.objects[strings.ToLower(argString(args, 0))] = args[1]
		}
		return runtime.VEmpty
	case "reset":
		return runtime.VEmpty
	}
	o.h.Note("unsupported ScriptControl method " + name)
	return runtime.NewUnknown("unsupported ScriptControl method " + name)
}
