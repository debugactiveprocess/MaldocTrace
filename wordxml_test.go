package maldoctrace

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

const autoOpenShell = "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nShell \"cmd.exe /c calc.exe\"\r\nEnd Sub\r\n"

func vbaProjectBin() []byte {
	return cfbtest.BuildExact(cfbtest.VBAProject("", map[string]string{"Module1": autoOpenShell})...)
}

// activeMime wraps a CFB the way Word stores editdata.mso.
func activeMime(cfb []byte) []byte {
	hdr := make([]byte, 0x32)
	copy(hdr, "ActiveMime")
	binary.LittleEndian.PutUint16(hdr[0x1E:], 0x32-46)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(cfb)
	w.Close()
	return append(hdr, z.Bytes()...)
}

func b64Lines(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(s) > 76 {
		out.WriteString(s[:76] + "\n")
		s = s[76:]
	}
	return out.String() + s
}

func checkMacroCommand(t *testing.T, name string, data []byte, format string) {
	t.Helper()
	r := AnalyzeFromBytes(context.Background(), data, name, Options{})
	if r.Format != format || r.Macros != "present" || len(r.Commands) == 0 || !strings.Contains(r.Commands[0].CommandLine, "calc.exe") || r.Verdict != "malicious" {
		t.Fatalf("%s: format %s macros %s commands %+v verdict %s diags %+v", name, r.Format, r.Macros, r.Commands, r.Verdict, r.Diagnostics)
	}
}

func TestWord2003XML(t *testing.T) {
	doc := `<?xml version="1.0"?><?mso-application progid="Word.Document"?>` +
		`<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">` +
		`<w:docPr><w:attachedTemplate w:val="http://example.invalid/t.dot"/></w:docPr>` +
		`<w:binData w:name="editdata.mso">` + b64Lines(activeMime(vbaProjectBin())) + `</w:binData>` +
		`<w:body><w:p><w:r><w:t>Enable content</w:t></w:r></w:p></w:body></w:wordDocument>`
	checkMacroCommand(t, "a.xml", []byte(doc), "word2003xml")
	r := AnalyzeFromBytes(context.Background(), []byte(doc), "a.xml", Options{})
	if !hasFindingSev(r, "template_injection", "high") {
		t.Fatalf("template: %+v", r.StaticFindings)
	}
}

func TestFlatOPC(t *testing.T) {
	doc := `<?xml version="1.0"?><?mso-application progid="Word.Document"?>` +
		`<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">` +
		`<pkg:part pkg:name="/_rels/.rels" pkg:contentType="application/vnd.openxmlformats-package.relationships+xml"><pkg:xmlData>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>` +
		`</pkg:xmlData></pkg:part>` +
		`<pkg:part pkg:name="/word/document.xml" pkg:contentType="application/vnd.ms-word.document.macroEnabled.main+xml"><pkg:xmlData>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:fldSimple w:instr="DDEAUTO c:\windows\system32\cmd.exe &quot;/k calc.exe&quot;"/></w:p></w:body></w:document>` +
		`</pkg:xmlData></pkg:part>` +
		`<pkg:part pkg:name="/word/vbaProject.bin" pkg:contentType="application/vnd.ms-office.vbaProject"><pkg:binaryData>` + b64Lines(vbaProjectBin()) + `</pkg:binaryData></pkg:part>` +
		`</pkg:package>`
	checkMacroCommand(t, "a.xml", []byte(doc), "flatopc")
	r := AnalyzeFromBytes(context.Background(), []byte(doc), "a.xml", Options{})
	if !hasFindingSev(r, "dde", "high") {
		t.Fatalf("dde: %+v", r.StaticFindings)
	}
}

func TestMHTActiveMime(t *testing.T) {
	doc := "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"----=_NextPart_01\"\r\n\r\n" +
		"------=_NextPart_01\r\nContent-Location: file:///C:/doc.htm\r\nContent-Type: text/html; charset=\"utf-8\"\r\n\r\n" +
		"<html xmlns:w=\"urn:schemas-microsoft-com:office:word\"><body><p>Invoice</p></body></html>\r\n" +
		"------=_NextPart_01\r\nContent-Location: file:///C:/doc_files/editdata.mso\r\nContent-Transfer-Encoding: base64\r\nContent-Type: application/x-mso\r\n\r\n" +
		b64Lines(activeMime(vbaProjectBin())) + "\r\n------=_NextPart_01--\r\n"
	if extractor.DetectContainer([]byte(doc)) != "" {
		t.Fatal("MHT taken for an email")
	}
	checkMacroCommand(t, "a.mht", []byte(doc), "mht")
}

func FuzzEvasiveWord(f *testing.F) {
	f.Add([]byte(`<w:wordDocument><w:binData w:name="editdata.mso">QWN0aXZlTWltZQAAAA==</w:binData></w:wordDocument>`))
	f.Add([]byte(`<pkg:package><pkg:part pkg:name="/a"><pkg:binaryData>AAAA</pkg:binaryData></pkg:part></pkg:package>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		extractor.Extract(context.Background(), b, nil)
		extractor.DecodeActiveMime(b)
	})
}
