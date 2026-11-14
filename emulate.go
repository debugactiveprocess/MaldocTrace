package maldoctrace

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/deobfuscation"
	"github.com/debugactiveprocess/MaldocTrace/emulation"
	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/indicators"
	"github.com/debugactiveprocess/MaldocTrace/report"
	"github.com/debugactiveprocess/MaldocTrace/vba/ast"
	"github.com/debugactiveprocess/MaldocTrace/vba/parser"
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

type procDispatcher struct{ ints map[string]*runtime.Interp }

func (d *procDispatcher) CallProc(m, p string, args []runtime.Value) runtime.Value {
	it := d.ints[strings.ToLower(m)]
	if it == nil {
		return runtime.VUnknown
	}
	return it.CallProc(p, args)
}

func (d *procDispatcher) HasProc(m, p string) bool {
	it := d.ints[strings.ToLower(m)]
	return it != nil && it.HasProc(p)
}

type entryProc struct {
	module  string
	proc    string
	trigger string
}

type parsedMod struct {
	ext *extractor.Module
	mod *ast.Module
}

func runEmulation(ctx context.Context, res *extractor.Result, r *report.Report, opts Options) {
	d := &procDispatcher{ints: map[string]*runtime.Interp{}}
	host := emulation.NewHost(d)
	host.SetFixtures(opts.Fixtures)
	if res.DocumentText != "" {
		host.SetDocumentText(res.DocumentText)
	}
	host.SetWorkbook(res.Sheets, res.Names)
	host.SetProperties(res.Properties)
	for _, f := range res.Forms {
		host.RegisterForm(f.Module, f.Name, f.Properties, f.Stream, f.Offset)
		for _, value := range f.Properties {
			scanEvidence(r, value, "literal", "form:"+f.Stream, report.Source{Module: f.Module})
		}
	}

	var parsed []parsedMod
	for i := range res.Modules {
		m := res.Modules[i]
		am := parser.Parse(m.Code)
		parsed = append(parsed, parsedMod{ext: m, mod: am})
		host.RegisterModule(m.Name)
		r.Coverage.ParsedProcedures += len(am.Procs)
		for _, e := range am.Errors {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "parse", Module: m.Name, Line: e.Pos.Line, Message: e.Msg})
		}
	}

	for _, pm := range parsed {
		for _, ds := range deobfuscation.DecodeModule(pm.mod, pm.ext.Name) {
			r.Decoded = append(r.Decoded, report.DecodedStr{Value: ds.Value, Kind: "static", Method: ds.Method, Module: ds.Module, Proc: ds.Proc, Line: ds.Line, Col: ds.Col})
			scanEvidence(r, ds.Value, "static", fmt.Sprintf("static-%d", len(r.Decoded)), report.Source{Module: ds.Module, Proc: ds.Proc, Line: ds.Line, Col: ds.Col})
		}
	}

	for _, pm := range parsed {
		for _, f := range indicators.ScanValue(pm.ext.Code) {
			line, col := lineCol(pm.ext.Code, strings.Index(pm.ext.Code, f.Evidence))
			r.IOCs = append(r.IOCs, report.IOC{Type: f.Type, Value: f.Value, Discovery: "literal", Occurrences: []report.Occurrence{{Module: pm.ext.Name, Line: line, Col: col, Evidence: f.Evidence}}})
		}
	}

	for _, pm := range parsed {
		d.ints[strings.ToLower(pm.ext.Name)] = runtime.New(pm.mod, pm.ext.Name, host, opts.RuntimeLimits)
		d.ints[strings.ToLower(pm.ext.Name)].SetContext(ctx)
		d.ints[strings.ToLower(pm.ext.Name)].SetSpeculative(opts.Speculative)
		d.ints[strings.ToLower(pm.ext.Name)].SetOptionExplicit(strings.Contains(strings.ToLower(pm.ext.Code), "option explicit"))
	}

	var entries []entryProc
	for _, pm := range parsed {
		it := d.ints[strings.ToLower(pm.ext.Name)]
		it.RunModule(pm.mod.Body)
		for _, p := range pm.mod.Procs {
			if trigger, ok := autoexecTrigger(p.Name); ok {
				entries = append(entries, entryProc{module: pm.ext.Name, proc: p.Name, trigger: trigger})
				r.EntryPoints = append(r.EntryPoints, report.EntryPoint{Module: pm.ext.Name, Proc: p.Name, Trigger: trigger, Line: p.Pos().Line})
			}
		}
	}
	for _, ep := range entries {
		if ctx.Err() != nil {
			break
		}
		if d.ints[strings.ToLower(ep.module)].WasCalled(ep.proc) {
			// Already executed as part of an earlier entry point (e.g. a
			// "Form_Close" helper called from Document_Close). Running it
			// again would replay side effects on an already-modified state.
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "info", Stage: "emulation", Module: ep.module,
				Message: "entry point " + ep.proc + " already executed via another entry point; not run again"})
			continue
		}
		d.ints[strings.ToLower(ep.module)].CallProc(ep.proc, nil)
		r.Coverage.EmulatedProcedures++
	}

	for _, ep := range host.XLMEntries() {
		if ctx.Err() != nil {
			break
		}
		r.EntryPoints = append(r.EntryPoints, report.EntryPoint{Module: ep.Sheet, Proc: ep.Cell, Trigger: "XLM " + ep.Name})
		host.RunXLM(ctx, ep.Sheet, ep.Cell)
		r.Coverage.EmulatedProcedures++
	}
	for _, w := range host.XLMWrites() {
		r.Decoded = append(r.Decoded, report.DecodedStr{Value: w.Text, Kind: "observed", Method: "XLM " + w.Via + " → " + w.Sheet + "!" + w.Cell, Module: w.Sheet, Proc: w.Cell})
		scanEvidence(r, w.Text, "observed", "xlm-write:"+w.Sheet+"!"+w.Cell, report.Source{Module: w.Sheet, Proc: w.Cell})
	}

	for i, e := range host.Events() {
		r.Events = append(r.Events, report.Event{
			Receiver: e.Receiver, Method: e.Method, Arguments: e.Arguments, CallChain: e.CallChain, LocationInherited: e.LocationInherited,
			ID: i + 1, Type: e.Type, Module: e.Module, Proc: e.Proc, Line: e.Line, Col: e.Col,
			Raw: e.Raw, Resolved: e.Resolved, Simulated: e.Simulated, Speculative: e.Speculative, Extra: e.Extra,
		})
		for _, v := range e.Resolved {
			for _, f := range indicators.ScanValue(v) {
				if f.Type == "command" && isScriptEvent(e.Type) {
					continue // script source is a payload, not a command line
				}
				r.IOCs = append(r.IOCs, report.IOC{Type: f.Type, Value: f.Value, Discovery: "observed", Occurrences: []report.Occurrence{{Module: e.Module, Proc: e.Proc, Line: e.Line, Evidence: f.Evidence, FromEvent: true}}})
			}
		}
		if e.Extra != nil && e.Extra["content_sha256"] != "" {
			content, _ := hex.DecodeString(e.Extra["content_hex"])
			r.Artifacts = append(r.Artifacts, report.Artifact{
				Raw:  content,
				Path: firstOf(e.Resolved...), SHA256: e.Extra["content_sha256"], Size: len(e.Extra["content_hex"]) / 2,
				Discovery: "observed", Module: e.Module, Proc: e.Proc,
			})
		}
	}

	for _, pm := range parsed {
		it := d.ints[strings.ToLower(pm.ext.Name)]
		for _, n := range it.Notes() {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "runtime", Module: pm.ext.Name, Message: n})
		}
	}
	for _, n := range host.Notes() {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "emulation", Message: n})
	}

	r.IOCs = dedupeIOCs(r.IOCs)
	r.Stats = report.Stats{EventsRecorded: len(r.Events), IOCCount: len(r.IOCs), DecodedStringCount: len(r.Decoded)}
	r.Coverage.FormatsSupported = []string{"doc", "docm", "dotm", "docx", "xls", "xlsm", "xlsx", "ppt", "pptm", "rtf", "vba text", "xlm (excel 4.0)", "word 2003 xml", "flat opc", "mht/activemime", "sylk", "iqy", "csv (dde)"}
	r.Coverage.SupportedFeatures = []string{
		"Sub/Function", "Dim/Const", "If/Select", "For/ForEach/Do/While",
		"Chr/ChrW/StrReverse/Replace/Split/Join/Mid/Left/Right/InStr",
		"CreateObject/Shell", "WScript.Shell", "FileSystemObject",
		"ADODB.Stream", "MSXML2.XMLHTTP/WinHttp",
	}
}
