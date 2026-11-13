package extractor

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

// mtefRandomHeader builds MTEF data the way current exploit builders do:
// a 5-byte header with random bytes (version included), a junk first
// record, then LINE and the overflowing record.
func mtefRandomHeader(record []byte) []byte {
	return append([]byte{0x02, 0x7E, 0x0A, 0xEB, 0x47, 0xDC, 0x01}, record...)
}

func fontOverflow() []byte {
	return append(append([]byte{0x08, 0x5A, 0x5A}, bytes.Repeat([]byte{0x90}, 47)...), 0)
}

func TestMTEFRandomizedHeader(t *testing.T) {
	if x := mtefExploit(mtefRandomHeader(fontOverflow())); !strings.Contains(x.detail, "CVE-2017-11882") || len(x.payload) != 47 {
		t.Errorf("font: %+v", x)
	}
	matrix := []byte{0x05, 0x9B, 0xD2, 0x7E, 0xEC, 0x91, 0xCC, 0xCC}
	if x := mtefExploit(mtefRandomHeader(matrix)); !strings.Contains(x.detail, "236 rows x 145 columns") {
		t.Errorf("matrix: %+v", x)
	}
	// OLE1 native stream: 4-byte size, then MTEF.
	wrapped := append(binary.LittleEndian.AppendUint32(nil, 0x04EA672A), mtefRandomHeader(fontOverflow())...)
	if x := mtefExploit(wrapped); x.detail == "" {
		t.Error("size-prefixed MTEF not detected")
	}
	// A legitimate equation (short font name) is not an exploit.
	benign := append([]byte{0x03, 0x01, 0x01, 0x03, 0x0A, 0x01, 0x08, 0x01, 0x00}, []byte("Times New Roman\x00")...)
	if x := mtefExploit(benign); x.detail != "" {
		t.Errorf("false positive: %+v", x)
	}
}

// An Equation Editor object whose MTEF data sits in a case-mangled OLE1
// native stream (no "Equation Native", no CompObj) inside an .xlsx.
func TestEquationInMangledOle10Native(t *testing.T) {
	clsidEquation := [16]byte{0x02, 0xCE, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	stream := append(binary.LittleEndian.AppendUint32(nil, 0x0387886F), mtefRandomHeader(fontOverflow())...)
	obj := cfbtest.SetRootCLSID(cfbtest.Build(
		cfbtest.Stream{Name: "gktZa7idD8FQqRxg6lw", Data: []byte{1, 2, 3}},
		cfbtest.Stream{Name: "\x01olE10naTIVe", Data: stream},
	), clsidEquation)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		"[Content_Types].xml":                 []byte(`<Types/>`),
		"xl/workbook.xml":                     []byte(`<workbook/>`),
		"xl/embeddings/utLyavNu.GxTaxgD":      obj,
		"xl/worksheets/_rels/sheet1.xml.rels": []byte(`<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="../embeddings/utLyavNu.GxTaxgD"/></Relationships>`),
	} {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	zw.Close()
	res, err := Extract(context.Background(), buf.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var exploit, pkg bool
	for _, e := range res.External {
		if e.Kind == "equation_editor_exploit" {
			exploit = true
		}
		if strings.Contains(e.Detail, "OLE Package") {
			pkg = true
		}
	}
	if !exploit || pkg {
		t.Fatalf("exploit=%v package=%v: %+v", exploit, pkg, res.External)
	}
}

// A .docx that imports an RTF through altChunk: the RTF is analysed as an
// embedded file.
func TestAltChunkImport(t *testing.T) {
	rtf := []byte(`{\rtf1{\*\template http://example.invalid/t.dotm}}`)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		"[Content_Types].xml":          []byte(`<Types/>`),
		"word/document.xml":            []byte(`<w:document xmlns:w="w"><w:body><w:altChunk r:id="BMl5"/></w:body></w:document>`),
		"word/itio.rtf":                rtf,
		"word/_rels/document.xml.rels": []byte(`<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" Target="/word/itio.rtf" Id="BMl5"/></Relationships>`),
	} {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	zw.Close()
	res, err := Extract(context.Background(), buf.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var finding bool
	for _, e := range res.External {
		if e.Kind == "altchunk" && e.Target == "word/itio.rtf" {
			finding = true
		}
	}
	if !finding || len(res.Embedded) != 1 || !bytes.Equal(res.Embedded[0].Data, rtf) {
		t.Fatalf("finding=%v embedded=%+v", finding, res.Embedded)
	}
}

// Junk bytes before the OLE1 header of an RTF object are skipped.
func TestRTFObjectJunkBeforeHeader(t *testing.T) {
	var obj []byte
	u32 := func(v uint32) { obj = binary.LittleEndian.AppendUint32(obj, v) }
	u32(0x0501)
	u32(2)
	u32(11)
	obj = append(obj, "Equation.3\x00"...)
	u32(0)
	u32(0)
	native := mtefRandomHeader(fontOverflow())
	u32(uint32(len(native)))
	obj = append(obj, native...)
	junk := bytes.Repeat([]byte{0xAB, 0xED, 0xED, 0xBC}, 16)
	rtf := `{\rtf1{\object\objemb\objupdate{\*\objdata ` + hexString(append(junk, obj...)) + `}}}`
	res, _ := Extract(context.Background(), []byte(rtf), nil)
	var cls, exploit bool
	for _, e := range res.External {
		if e.Kind == "embedded_ole" && e.Target == "Equation.3" && strings.Contains(e.Detail, "64 junk bytes") {
			cls = true
		}
		if e.Kind == "equation_editor_exploit" {
			exploit = true
		}
	}
	if !cls || !exploit {
		t.Fatalf("class=%v exploit=%v %+v", cls, exploit, res.External)
	}
}

func TestReadStreamFold(t *testing.T) {
	lim := DefaultLimits()
	cfb, err := parseCFB(cfbtest.Build(cfbtest.Stream{Name: "\x01oLe10NaTIve", Data: []byte("x")}), &lim)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := cfb.readStreamFold("\x01Ole10Native"); err != nil || len(b) == 0 || b[0] != 'x' {
		t.Fatalf("%v %v", b, err)
	}
}
