package emulation

import (
	"strings"

	"maldoctrace/vba/runtime"
)

// httpReq simulates MSXML2.XMLHTTP / WinHttp.WinHttpRequest.
type httpReq struct {
	h      *Host
	method string
	url    string
}

func (o *httpReq) TypeName() string { return "XMLHTTP" }
func (o *httpReq) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "status":
		return runtime.VInt(200)
	case "statustext":
		return runtime.VString("OK")
	case "responsetext":
		if r, ok := o.h.fixtures.HTTPResponses[o.method+" "+o.url]; ok {
			return runtime.VString(r.Body)
		}
		return runtime.VString("")
	case "responsebody":
		return runtime.VEmpty
	}
	return runtime.VEmpty
}
func (o *httpReq) Set(name string, v runtime.Value) {}
func (o *httpReq) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "open":
		o.method = argString(args, 0)
		o.url = argString(args, 1)
		o.h.recStr("http_open", o.method+" "+o.url, nil)
		return runtime.VEmpty
	case "send":
		o.h.recStr("http_request", o.method+" "+o.url, map[string]string{"simulated": "true"})
		return runtime.VEmpty
	case "setrequestheader", "setproxy", "settimeouts":
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

type debugObject struct{}

func (o *debugObject) TypeName() string { return "Debug" }
func (o *debugObject) Get(name string) runtime.Value {
	return runtime.VEmpty
}
func (o *debugObject) Set(name string, v runtime.Value) {}
func (o *debugObject) Call(name string, args []runtime.Value) runtime.Value {
	return runtime.VEmpty
}

type appObject struct {
	h    *Host
	name string
}

func (o *appObject) TypeName() string { return "Application" }
func (o *appObject) Get(name string) runtime.Value {
	if strings.EqualFold(name, "visible") || strings.EqualFold(name, "displayalerts") {
		return runtime.VBool(false)
	}
	switch strings.ToLower(name) {
	case "activesheet":
		return runtime.VObject(&sheetObject{h: o.h, s: o.h.workbook().active()})
	case "sheets", "worksheets":
		return runtime.VObject(&sheetsCollection{h: o.h, onlyWorksheets: strings.EqualFold(name, "worksheets")})
	case "activeworkbook", "thisworkbook", "activedocument":
		return runtime.VObject(&documentObject{h: o.h, name: name})
	}
	return runtime.VEmpty
}
func (o *appObject) Set(name string, v runtime.Value) {
	o.h.recStr("set_application_property", name, nil)
}
func (o *appObject) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "run":
		if v, ok := o.h.runXLMMacro(argString(args, 0)); ok {
			return v
		}
		o.h.rec("application_run", args, nil)
		return runtime.VEmpty
	case "executeexcel4macro":
		return o.h.ExecuteExcel4Macro(argString(args, 0))
	case "range", "cells", "sheets", "worksheets":
		return (&globalExcel{h: o.h, name: strings.ToLower(name)}).Call("", args)
	case "quit":
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

// genericObject captures method calls on unknown ProgIDs rather than failing.
type genericObject struct {
	h      *Host
	progID string
}

func (o *genericObject) TypeName() string { return o.progID }
func (o *genericObject) Get(name string) runtime.Value {
	return runtime.NewUnknown("unsupported property " + o.progID + "." + name)
}
func (o *genericObject) Set(name string, v runtime.Value) {}
func (o *genericObject) Call(name string, args []runtime.Value) runtime.Value {
	o.h.rec("unresolved_call", args, map[string]string{"reason": "unsupported receiver model: " + o.progID})
	o.h.Note("unsupported receiver model: " + o.progID + "." + name)
	return runtime.VEmpty
}
