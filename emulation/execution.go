package emulation

import (
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
	"strings"
)

type shellApplication struct{ h *Host }

func (o *shellApplication) TypeName() string { return "Shell.Application" }
func (o *shellApplication) Get(n string) runtime.Value {
	return runtime.NewUnknown("unsupported Shell.Application property " + n)
}
func (o *shellApplication) Set(n string, v runtime.Value) {}
func (o *shellApplication) Call(n string, a []runtime.Value) runtime.Value {
	if strings.EqualFold(n, "ShellExecute") {
		o.h.rec("shell_execute", a, nil)
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

type wmiObject struct {
	h       *Host
	process bool
}

func (o *wmiObject) TypeName() string {
	if o.process {
		return "Win32_Process"
	}
	return "WMI.Services"
}
func (o *wmiObject) Get(n string) runtime.Value {
	return runtime.NewUnknown("unsupported WMI property " + n)
}
func (o *wmiObject) Set(n string, v runtime.Value) {}
func (o *wmiObject) Call(n string, a []runtime.Value) runtime.Value {
	if !o.process && strings.EqualFold(n, "Get") && strings.EqualFold(argString(a, 0), "Win32_Process") {
		return runtime.VObject(&wmiObject{h: o.h, process: true})
	}
	if o.process && strings.EqualFold(n, "Create") {
		o.h.rec("wmi_process_create", a, nil)
		return runtime.VInt(0)
	}
	return runtime.VUnknown
}
