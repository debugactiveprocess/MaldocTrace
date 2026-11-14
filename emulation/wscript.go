package emulation

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// wscriptObject is the WScript object of the Windows Script Host, global in
// a .vbs file run by wscript.exe or cscript.exe.
type wscriptObject struct{ h *Host }

func (o *wscriptObject) TypeName() string { return "WScript" }
func (o *wscriptObject) Get(n string) runtime.Value {
	switch strings.ToLower(n) {
	case "scriptfullname":
		return runtime.VString(`C:\Users\user\AppData\Local\Temp\script.vbs`)
	case "scriptname":
		return runtime.VString("script.vbs")
	case "fullname":
		return runtime.VString(`C:\Windows\System32\wscript.exe`)
	case "path":
		return runtime.VString(`C:\Windows\System32`)
	case "name":
		return runtime.VString("Windows Script Host")
	case "version":
		return runtime.VString("5.812")
	case "arguments":
		return runtime.VObject(&wscriptArgs{})
	case "stdout", "stderr", "stdin":
		return runtime.VObject(&debugObject{})
	}
	return runtime.NewUnknown("unsupported WScript property " + n)
}
func (o *wscriptObject) Set(n string, v runtime.Value) {}
func (o *wscriptObject) Call(n string, a []runtime.Value) runtime.Value {
	switch strings.ToLower(n) {
	case "createobject":
		return o.h.CreateObject(argString(a, 0))
	case "getobject":
		return o.h.GetObject(argString(a, 0))
	case "sleep", "echo", "quit", "disconnectobject", "connectobject":
		return runtime.VEmpty
	}
	return o.Get(n)
}

// wscriptArgs is an empty WScript.Arguments collection.
type wscriptArgs struct{}

func (o *wscriptArgs) TypeName() string { return "WshArguments" }
func (o *wscriptArgs) Get(n string) runtime.Value {
	switch strings.ToLower(n) {
	case "count", "length":
		return runtime.VInt(0)
	}
	return runtime.VEmpty
}
func (o *wscriptArgs) Set(n string, v runtime.Value) {}
func (o *wscriptArgs) Call(n string, a []runtime.Value) runtime.Value {
	return o.Get(n)
}

// errObject is the VBA/VBScript Err object. Simulated calls succeed, so
// Err.Number is 0: the "no error" path is the one the code takes when its
// download or file operation works.
type errObject struct{}

func (o *errObject) TypeName() string { return "ErrObject" }
func (o *errObject) Get(n string) runtime.Value {
	switch strings.ToLower(n) {
	case "number", "lastdllerror", "helpcontext":
		return runtime.VInt(0)
	}
	return runtime.VString("")
}
func (o *errObject) Set(n string, v runtime.Value) {}
func (o *errObject) Call(n string, a []runtime.Value) runtime.Value {
	switch strings.ToLower(n) {
	case "clear", "raise":
		return runtime.VEmpty
	}
	return o.Get(n)
}
