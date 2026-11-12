package maldoctrace

import (
	"context"
	"encoding/hex"
	"testing"
)

func templateDocx(t *testing.T) []byte {
	return zipBytes(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types/>`),
		"word/document.xml":   []byte(`<w:document xmlns:w="w"><w:body><w:p/></w:body></w:document>`),
		"word/_rels/settings.xml.rels": []byte(`<Relationships><Relationship Id="rId1" ` +
			`Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" ` +
			`Target="http://example.invalid/t.dotm" TargetMode="External"/></Relationships>`),
	})
}

func TestArchiveMembersAnalysed(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{"nested/invoice.docx": templateDocx(t)})
	data := zipBytes(t, map[string][]byte{
		"readme.txt":  []byte("nothing here"),
		"invoice.zip": inner,
	})
	r := AnalyzeFromBytes(context.Background(), data, "sample.zip", Options{})
	if r.Format != "zip" || r.Verdict != "malicious" {
		t.Fatalf("format %s verdict %s %v", r.Format, r.Verdict, r.VerdictReasons)
	}
	if len(r.Artifacts) != 2 || len(r.Children) != 1 {
		t.Fatalf("artifacts %d children %d", len(r.Artifacts), len(r.Children))
	}
	nested := r.Children[0].Report
	if nested.Format != "zip" || len(nested.Children) != 1 || nested.Children[0].Report.Format != "ooxml" ||
		!hasFindingSev(nested.Children[0].Report, "template_injection", "high") {
		t.Fatalf("nested archive not analysed: %+v", nested)
	}
}

func TestSevenZipInput(t *testing.T) {
	// 7-Zip archive (encrypted names, password "infected") holding a
	// synthetic one-line VBScript.
	data, _ := hex.DecodeString("377abcaf271c0004eedf5ef0c0000000000000002f000000000000007444d4f085863ecdb09d1a31c23a03f4717ced972cd5183314f07e24e3bf63d0aec6305f249646860c7b2c8887203ec6f18545f9691df57e1e0cbf4ccbdd34796d63b64e4a8af17455cfcd54b08b111b51d479dd2ce4d01076428b68e56676f93837f70e871cf1b327ae4a65679ba0e15d085a506d2cf0dd890ef48d80f77cf0be38cf7dac516ebb1d6f17342ced079d83b93e6f2fc745ff4c523f4b6c3eb495b38d3f268aec5f51b822a3e09c825744d636b3d680980a9d5a21c8d45056c587d249078a1706400109808000070b0100012406f1070112530fa16b49363cd37cf19a55e72aa1051d6e0c720a0153509f650000")
	r := AnalyzeFromBytes(context.Background(), data, "sample.7z", Options{})
	if r.Format != "7z" || !r.Encrypted || r.Decryption == nil || r.Decryption.Password != "infected" {
		t.Fatalf("format %s decryption %+v", r.Format, r.Decryption)
	}
	if r.Verdict != "malicious" || len(r.Commands) == 0 || !hasFindingSev(r, "embedded_script", "high") {
		t.Fatalf("verdict %s commands %+v findings %+v", r.Verdict, r.Commands, r.StaticFindings)
	}
}

// An archive that cannot be opened is unknown, not clean.
func TestArchiveUnreadable(t *testing.T) {
	r := AnalyzeFromBytes(context.Background(), []byte("7z\xbc\xaf\x27\x1c garbage"), "bad.7z", Options{})
	if r.Verdict != "unknown" {
		t.Fatalf("verdict %s", r.Verdict)
	}
}
