package maldoctrace

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

// clsidShellExplorer1 is {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} as stored
// in a CFB directory entry.
var clsidShellExplorer1 = [16]byte{0xC3, 0x2A, 0xB2, 0xEA, 0xC1, 0x30, 0xCF, 0x11, 0xA7, 0xEB, 0x00, 0x00, 0xC0, 0x5B, 0xAE, 0x0B}

const browserURL = "https://tunnel.example.invalid/f00d/Proposal.pdf.lnk"

// shellExplorerContents mimics the CONTENTS stream Shell.Explorer persists:
// a binary header followed by the location as UTF-16.
func shellExplorerContents(url string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 0x4C)
	b = append(b, make([]byte, 0xB2)...)
	for _, c := range utf16.Encode([]rune(url)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return append(b, 0, 0)
}

// shellExplorerObject builds an oleObject*.bin: the root storage has the
// Shell.Explorer.1 CLSID, optionally a (forged) CompObj, and the CONTENTS.
func shellExplorerObject(compObj []byte) []byte {
	streams := []cfbtest.Stream{
		{Name: "\x03ObjInfo", Data: []byte{0, 0, 3, 0, 4, 0}},
		{Name: "CONTENTS", Data: shellExplorerContents(browserURL)},
	}
	if compObj != nil {
		streams = append(streams, cfbtest.Stream{Name: "\x01CompObj", Data: compObj})
	}
	return cfbtest.SetRootCLSID(cfbtest.Build(streams...), clsidShellExplorer1)
}

func browserDocx(t *testing.T, obj []byte) []byte {
	return zipBytes(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types/>`),
		"word/document.xml": []byte(`<w:document xmlns:w="w" xmlns:o="o"><w:body><w:p><w:r>` +
			`<w:object><o:OLEObject Type="Embed" ProgID="Shell.Explorer.1" r:id="rId7"/></w:object></w:r></w:p></w:body></w:document>`),
		"word/embeddings/oleObject1.bin": obj,
	})
}

// CVE-2026-21509: a .docx whose embedded object has no CompObj stream and
// is identified only by its storage CLSID (the shape of the samples seen
// in the wild), or carries a CompObj that pretends to be something else.
func TestShellExplorerObject(t *testing.T) {
	for name, compObj := range map[string][]byte{
		"clsid only":    nil,
		"forged progid": compObjT("Microsoft Word Document", "Word.Document.8"),
	} {
		t.Run(name, func(t *testing.T) {
			r := AnalyzeFromBytes(context.Background(), browserDocx(t, shellExplorerObject(compObj)), "proposal.docx", Options{})
			if r.Verdict != "malicious" {
				t.Fatalf("verdict %s %v", r.Verdict, r.VerdictReasons)
			}
			var url, obj bool
			for _, f := range r.StaticFindings {
				switch {
				case f.Kind == "browser_object_url" && f.Severity == "high" && f.Target == browserURL:
					url = strings.Contains(f.Detail, "CVE-2026-21509") && strings.Contains(f.Detail, ".lnk")
				case f.Kind == "embedded_ole" && f.Severity == "high":
					obj = strings.Contains(f.Detail, "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}")
				}
			}
			if !url || !obj {
				t.Fatalf("findings %+v", r.StaticFindings)
			}
			if !hasIOCType(r, "url", browserURL) {
				t.Fatalf("URL not an IOC: %+v", r.Indicators)
			}
		})
	}
}

// The same object inside a password-protected ZIP, as samples are shared.
func TestShellExplorerInArchive(t *testing.T) {
	zipped := zipBytes(t, map[string][]byte{"proposal.docx": browserDocx(t, shellExplorerObject(nil))})
	r := AnalyzeFromBytes(context.Background(), zipped, "sample.zip", Options{})
	if r.Verdict != "malicious" || len(r.Children) != 1 || r.Children[0].Report.Verdict != "malicious" {
		t.Fatalf("verdict %s %v children %+v", r.Verdict, r.VerdictReasons, r.Children)
	}
}

// An unrelated object (no known CLSID, no URL) stays a medium finding.
func TestPlainEmbeddedObjectNotBrowser(t *testing.T) {
	obj := cfbtest.Build(
		cfbtest.Stream{Name: "\x01CompObj", Data: compObjT("Bitmap Image", "Paint.Picture")},
		cfbtest.Stream{Name: "CONTENTS", Data: []byte("BM")},
	)
	r := AnalyzeFromBytes(context.Background(), browserDocx(t, obj), "image.docx", Options{})
	for _, f := range r.StaticFindings {
		if f.Kind == "browser_object_url" || (f.Kind == "embedded_ole" && f.Severity == "high") {
			t.Fatalf("false positive: %+v", f)
		}
	}
	if r.Verdict == "malicious" {
		t.Fatalf("verdict %s %v", r.Verdict, r.VerdictReasons)
	}
}
