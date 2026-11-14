package emulation

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

func (h *Host) rec(t string, args []runtime.Value, extra map[string]string) {
	res := make([]string, len(args))
	for i, a := range args {
		res[i] = a.CoerceString()
	}
	h.Record(&runtime.Event{Type: t, Raw: res, Resolved: res, Simulated: true, Extra: extra})
}

func (h *Host) recStr(t string, s string, extra map[string]string) {
	h.Record(&runtime.Event{Type: t, Raw: []string{s}, Resolved: []string{s}, Simulated: true, Extra: extra})
}

type wshShell struct{ h *Host }

func (o *wshShell) TypeName() string { return "WScript.Shell" }
func (o *wshShell) Get(name string) runtime.Value {
	if strings.EqualFold(name, "Environment") {
		return runtime.VObject(&wshEnvironment{h: o.h})
	}
	return runtime.VEmpty
}
func (o *wshShell) Set(name string, v runtime.Value) {}
func (o *wshShell) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "run":
		o.h.recStr("wscript_shell_run", argString(args, 0), nil)
		return runtime.VInt(0)
	case "exec":
		o.h.recStr("wscript_shell_exec", argString(args, 0), nil)
		return runtime.VObject(&execProcess{h: o.h})
	case "expandenvironmentstrings":
		s := argString(args, 0)
		o.h.recStr("expand_environment", s, nil)
		return runtime.VString(s)
	case "regread":
		o.h.recStr("registry_read", argString(args, 0), nil)
		return runtime.VString("")
	case "regwrite":
		o.h.rec("registry_write", args, nil)
		return runtime.VEmpty
	case "regdelete":
		o.h.recStr("registry_delete", argString(args, 0), nil)
		return runtime.VEmpty
	case "popup":
		o.h.recStr("wscript_popup", argString(args, 0), nil)
		return runtime.VInt(0)
	case "sendkeys":
		o.h.recStr("wscript_sendkeys", argString(args, 0), nil)
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

type wshEnvironment struct{ h *Host }

func (o *wshEnvironment) TypeName() string { return "WshEnvironment" }
func (o *wshEnvironment) Get(name string) runtime.Value {
	o.h.recStr("environ_read", name, nil)
	return runtime.VString("")
}
func (o *wshEnvironment) Set(name string, v runtime.Value) {}
func (o *wshEnvironment) Call(name string, args []runtime.Value) runtime.Value {
	return runtime.VUnknown
}

type wshNetwork struct{ h *Host }

func (o *wshNetwork) TypeName() string { return "WshNetwork" }
func (o *wshNetwork) Get(name string) runtime.Value {
	o.h.recStr("network_property", name, nil)
	return runtime.VString("")
}
func (o *wshNetwork) Set(name string, v runtime.Value) {}
func (o *wshNetwork) Call(name string, args []runtime.Value) runtime.Value {
	return runtime.VUnknown
}

type execProcess struct{ h *Host }

func (o *execProcess) TypeName() string { return "Exec" }
func (o *execProcess) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "stdout", "stderr":
		return runtime.VObject(&textStream{h: o.h})
	case "status", "exitcode":
		return runtime.VInt(0)
	}
	return runtime.VEmpty
}
func (o *execProcess) Set(name string, v runtime.Value) {}
func (o *execProcess) Call(name string, args []runtime.Value) runtime.Value {
	return runtime.VUnknown
}

// fso simulates Scripting.FileSystemObject.
type fso struct{ h *Host }

func (o *fso) TypeName() string { return "FileSystemObject" }
func (o *fso) Get(name string) runtime.Value {
	// Methods without arguments are often written without parentheses
	// (fso.GetTempName), which reads them as properties.
	if strings.EqualFold(name, "gettempname") {
		return o.Call(name, nil)
	}
	return runtime.VEmpty
}
func (o *fso) Set(name string, v runtime.Value) {}
func (o *fso) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "fileexists":
		o.h.recStr("file_exists", argString(args, 0), nil)
		return runtime.VBool(false)
	case "folderexists":
		o.h.recStr("folder_exists", argString(args, 0), nil)
		return runtime.VBool(false)
	case "getfile", "getfolder":
		o.h.recStr("get_file", argString(args, 0), nil)
		return runtime.VObject(&folderObject{h: o.h, path: argString(args, 0)})
	case "opentextfile", "createtextfile":
		o.h.recStr("file_open", argString(args, 0), nil)
		return runtime.VObject(&textStream{h: o.h, path: argString(args, 0)})
	case "copyfile":
		o.h.rec("file_copy", args, nil)
		return runtime.VEmpty
	case "movefile":
		o.h.rec("file_move", args, nil)
		return runtime.VEmpty
	case "deletefile":
		o.h.rec("file_delete", args, nil)
		return runtime.VEmpty
	case "deletefolder":
		o.h.rec("folder_delete", args, nil)
		return runtime.VEmpty
	case "copyfolder":
		o.h.rec("folder_copy", args, nil)
		return runtime.VEmpty
	case "createfolder":
		o.h.rec("folder_create", args, nil)
		return runtime.VEmpty
	case "buildpath":
		return runtime.VString(argString(args, 0) + "\\" + argString(args, 1))
	case "getspecialfolder":
		return runtime.VString("%TEMP%")
	case "getparentfoldername", "getfilename", "getbasename", "getextensionname", "getabsolutepathname":
		return runtime.VString(fsoPathPart(strings.ToLower(name), argString(args, 0)))
	case "gettempname":
		// Windows returns a bare name such as "radB93F1.tmp".
		return runtime.VString("rad5F3A1.tmp")
	case "driveexists":
		return runtime.VBool(false)
	}
	return runtime.VUnknown
}

// __EMU_OBJECTS2__

// fsoPathPart implements the FileSystemObject path helpers on Windows paths.
func fsoPathPart(method, p string) string {
	p = strings.TrimRight(p, `\/`)
	i := strings.LastIndexAny(p, `\/`)
	base := p[i+1:]
	switch method {
	case "getparentfoldername":
		if i < 0 {
			return ""
		}
		return p[:i]
	case "getfilename":
		return base
	case "getbasename":
		if j := strings.LastIndexByte(base, '.'); j > 0 {
			return base[:j]
		}
		return base
	case "getextensionname":
		if j := strings.LastIndexByte(base, '.'); j >= 0 {
			return base[j+1:]
		}
		return ""
	}
	return p
}
