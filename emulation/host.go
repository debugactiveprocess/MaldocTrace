// Package emulation provides the virtual environment in which VBA macros run.
// Every external action (Shell, WScript.Shell, FileSystemObject, ADODB.Stream,
// XMLHTTP, WinHttp, declared APIs) is simulated: intent and resolved arguments
// are recorded as events, but no process is launched, no network request is
// made, no COM object is instantiated, no DLL is loaded and the host system is
// never modified.
package emulation

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// Dispatcher runs a procedure of a named module and returns its value. It is
// implemented by the analyzer to wire cross-module calls.
type Dispatcher interface {
	CallProc(module, proc string, args []runtime.Value) runtime.Value
}

// Fixtures provides simulated external responses (HTTP and document content).
type Fixtures struct {
	HTTPResponses map[string]HTTPResponse // key: method+" "+url
}

// HTTPResponse simulates an HTTP response body and status.
type HTTPResponse struct {
	Status int
	Body   string
}

// Host is the virtual environment shared by all modules of one file.
type Host struct {
	formControls map[string]map[string]*formObject
	contexts     []*runtime.Event
	dispatcher   Dispatcher
	fixtures     Fixtures
	events       []*runtime.Event
	notes        []string
	modules      map[string]bool // module names that exist (for GetObject)
	doc          *wordDoc
	wb           *workbook
	props        []*docProp
	xlm          *xlmEngine
	xlmWrites    []XLMWrite
}

// NewHost creates an emulation host.
func NewHost(d Dispatcher) *Host {
	return &Host{dispatcher: d, modules: map[string]bool{}, formControls: map[string]map[string]*formObject{}}
}

// SetFixtures configures simulated external responses.
func (h *Host) SetFixtures(f Fixtures) { h.fixtures = f }

// RegisterModule marks a module name so GetObject can resolve it.
func (h *Host) RegisterModule(name string) { h.modules[strings.ToLower(name)] = true }

// Events returns recorded events in order.
func (h *Host) Events() []*runtime.Event { return h.events }

// Notes returns uncertainty diagnostics.
func (h *Host) Notes() []string { return h.notes }

// Record implements runtime.Host.
func (h *Host) PushCall(e *runtime.Event) func() {
	h.contexts = append(h.contexts, e)
	return func() { h.contexts = h.contexts[:len(h.contexts)-1] }
}
func (h *Host) Record(e *runtime.Event) {
	if len(h.contexts) > 0 {
		c := h.contexts[len(h.contexts)-1]
		if e.Line == 0 {
			e.Line = c.Line
			e.Col = c.Col
			e.LocationInherited = true
		}
		if e.Module == "" {
			e.Module = c.Module
			e.Proc = c.Proc
		}
		// Events that describe their own call (XLM functions reached from
		// VBA through ExecuteExcel4Macro) keep it; others take the VBA call.
		if e.Receiver == "" {
			e.Receiver = c.Receiver
			e.Method = c.Method
			e.Raw = c.Raw
			e.Arguments = c.Arguments
		}
		for _, frame := range h.contexts {
			e.CallChain = append(e.CallChain, frame.Module+"."+frame.Proc)
		}
	}
	h.events = append(h.events, e)
}

// Note implements runtime.Host.
func (h *Host) Note(msg string) { h.notes = append(h.notes, msg) }

// CreateObject implements runtime.Host and returns a simulated COM object.
func (h *Host) CreateObject(progID string) runtime.Value {
	key := strings.ToLower(progID)
	if strings.HasPrefix(purge(key), "winmgmts:") {
		// CreateObject("winmgmts:...") binds a moniker exactly like GetObject.
		return h.GetObject(purge(progID))
	}
	switch purge(key) {
	case "wscript.shell":
		return runtime.VObject(&wshShell{h: h})
	case "shell.application":
		return runtime.VObject(&shellApplication{h: h})
	case "scripting.filesystemobject":
		return runtime.VObject(&fso{h: h})
	case "adodb.stream":
		return runtime.VObject(&adodbStream{h: h, buf: newBuf()})
	case "msxml2.xmlhttp", "msxml2.xmlhttp.3.0", "msxml2.xmlhttp.6.0", "msxml2.serverxmlhttp",
		"microsoft.xmlhttp", "winhttp.winhttprequest", "winhttp.winhttprequest.5.1":
		return runtime.VObject(&httpReq{h: h})
	case "wscript.network":
		return runtime.VObject(&wshNetwork{h: h})
	case "msxml2.domdocument", "msxml2.domdocument.3.0", "msxml2.domdocument.6.0", "microsoft.xmldom", "msxml.domdocument":
		return runtime.VObject(&xmlDOM{h: h})
	case "msscriptcontrol.scriptcontrol", "msscriptcontrol.scriptcontrol.1", "scriptcontrol":
		return runtime.VObject(&scriptControl{h: h})
	}
	// Unknown ProgID: record an observation and return a generic object that
	// still captures method calls (so nothing is silently swallowed).
	h.Note("unsupported CreateObject identifier: " + progID)
	return runtime.VObject(&genericObject{h: h, progID: progID})
}

// GetObject implements runtime.Host. It resolves module objects (for
// cross-module member calls) and well-known application globals.
func (h *Host) GetObject(name string) runtime.Value {
	low := strings.ToLower(name)
	if strings.HasPrefix(low, "winmgmts:") {
		return runtime.VObject(&wmiObject{h: h, process: strings.HasSuffix(low, "win32_process")})
	}
	if h.modules[low] {
		m := &moduleObject{name: name, d: h.dispatcher, controls: h.formControls[low]}
		switch low {
		case "thisdocument", "thisworkbook":
			// The document module is also the Document/Workbook object:
			// ThisDocument.Variables(...) reaches the document when the
			// module defines no procedure of that name.
			m.doc = &documentObject{h: h, name: name}
		}
		return runtime.VObject(m)
	}
	if n, ok := wordConstants[low]; ok {
		return runtime.VInt(n)
	}
	switch low {
	case "debug":
		return runtime.VObject(&debugObject{})
	case "activesheet":
		return runtime.VObject(&sheetObject{h: h, s: h.workbook().active()})
	case "range", "cells", "sheets", "worksheets", "executeexcel4macro":
		return runtime.VObject(&globalExcel{h: h, name: low})
	case "thisdocument", "activedocument", "thisworkbook", "activeworkbook", "workbook":
		return runtime.VObject(&documentObject{h: h, name: name})
	case "application", "excel", "word", "powerpoint":
		return runtime.VObject(&appObject{h: h, name: name})
	}
	return runtime.VEmpty
}

func purge(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\u0000", "")
}

// moduleObject represents another VBA module as a callable object so that
// class module methods (Module.Method) can be invoked across modules.
type moduleObject struct {
	controls map[string]*formObject
	name     string
	d        Dispatcher
	prop     map[string]runtime.Value
	doc      *documentObject
}

// procChecker is implemented by dispatchers that can tell whether a module
// defines a procedure.
type procChecker interface {
	HasProc(module, proc string) bool
}

func (m *moduleObject) TypeName() string { return m.name }
func (m *moduleObject) Get(name string) runtime.Value {
	if o := m.controls[strings.ToLower(name)]; o != nil {
		return runtime.VObject(o)
	}
	if m.prop != nil {
		if v, ok := m.prop[name]; ok {
			return v
		}
	}
	if m.doc != nil && !m.hasProc(name) {
		if v := m.doc.Get(name); v.Kind != runtime.KindEmpty {
			return v
		}
	}
	// Property access on a module: return a simulated numeric property.
	if strings.EqualFold(name, "HelpContextId") || strings.EqualFold(name, "Index") {
		return runtime.VInt(0)
	}
	return runtime.NewUnknown("module property " + name)
}
func (m *moduleObject) Set(name string, v runtime.Value) {
	if m.prop == nil {
		m.prop = map[string]runtime.Value{}
	}
	m.prop[name] = v
}
func (m *moduleObject) hasProc(name string) bool {
	pc, ok := m.d.(procChecker)
	return ok && pc.HasProc(m.name, name)
}

func (m *moduleObject) Call(name string, args []runtime.Value) runtime.Value {
	if m.doc != nil && !m.hasProc(name) {
		return m.doc.Call(name, args)
	}
	if m.d != nil {
		return m.d.CallProc(m.name, name, args)
	}
	return runtime.VUnknown
}

// __EMU_OBJECTS__
