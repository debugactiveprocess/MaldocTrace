package emulation

import (
	"context"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

func TestParseXLM(t *testing.T) {
	for _, in := range []string{
		`=EXEC("cmd /c ""x""")`,
		`=IF(GET.WORKSPACE(13)<770,CLOSE(FALSE),)`,
		`=FORMULA(CHAR(61)&"HALT()",'My Sheet'!$B$2)`,
		`=Sheet1!A1:B3`,
		`=-R2C3%+1.5E3^2`,
		`=Run1(s&".exe",0)`,
	} {
		if _, err := parseXLM(in); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, bad := range []string{`=EXEC(`, `="abc`, `=1 2`, `=#BOGUS`, `='x`} {
		if _, err := parseXLM(bad); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
}

func newXLMHost(formulas map[string]string, values map[string]string) *Host {
	h := NewHost(nil)
	s := &extractor.Sheet{Name: "M", Kind: "macrosheet", Visibility: "hidden"}
	for ref, f := range formulas {
		r, c, _ := extractor.ParseCellRef(ref)
		s.Cells = append(s.Cells, extractor.Cell{Row: r, Col: c, Formula: f})
	}
	for ref, v := range values {
		r, c, _ := extractor.ParseCellRef(ref)
		s.Cells = append(s.Cells, extractor.Cell{Row: r, Col: c, Value: v, ValueKind: "string"})
	}
	h.SetWorkbook([]*extractor.Sheet{s}, []extractor.DefinedName{{Name: "Auto_Open_x1", Formula: "=M!$A$1"}})
	return h
}

func TestXLMControlFlow(t *testing.T) {
	h := newXLMHost(map[string]string{
		"A1": `=FOR("n",1,3)`,
		"A2": `=SET.VALUE(B1,B1&n)`,
		"A3": `=NEXT()`,
		"A4": `=RUN(C1)`,
		"A5": `=EXEC("after "&B1&" "&C3)`,
		"A6": `=HALT()`,
		"C1": `=SET.NAME("x","sub")`,
		"C2": `=SET.VALUE(C3,x)`,
		"C4": `=RETURN()`,
		"A9": `=EXEC("never")`,
	}, nil)
	entries := h.XLMEntries()
	if len(entries) != 1 || entries[0].Cell != "A1" {
		t.Fatalf("entries = %+v", entries)
	}
	h.RunXLM(context.Background(), entries[0].Sheet, entries[0].Cell)
	var cmds []string
	for _, e := range h.Events() {
		if e.Type == "shell" {
			cmds = append(cmds, e.Arguments[0].Value)
		}
	}
	if strings.Join(cmds, "|") != "after 123 sub" {
		t.Fatalf("commands = %q, notes = %q", cmds, h.Notes())
	}
}

func TestXLMBudget(t *testing.T) {
	h := newXLMHost(map[string]string{"A1": `=GOTO(A1)`}, nil)
	h.engine(context.Background()).max = 1000
	h.RunXLM(context.Background(), "M", "A1")
	if len(h.Notes()) == 0 || !strings.Contains(h.Notes()[len(h.Notes())-1], "budget") {
		t.Fatalf("notes = %q", h.Notes())
	}
}

func TestXLMFileWrite(t *testing.T) {
	h := newXLMHost(map[string]string{
		"A1": `=FOPEN("C:\Users\Public\a.vbs",3)`,
		"A2": `=FWRITELN(A1,"CreateObject(""WScript.Shell"").Run ""calc""")`,
		"A3": `=FCLOSE(A1)`,
		"A4": `=EXEC("wscript C:\Users\Public\a.vbs")`,
	}, nil)
	h.RunXLM(context.Background(), "M", "A1")
	var write *runtime.Event
	for _, e := range h.Events() {
		if e.Type == "file_write" {
			write = e
		}
	}
	if write == nil || write.Extra["path"] != `C:\Users\Public\a.vbs` || write.Extra["content_sha256"] == "" {
		t.Fatalf("events = %+v", h.Events())
	}
}

func FuzzParseXLM(f *testing.F) {
	for _, s := range []string{`=EXEC("a")`, `=A1:B2&'x y'!C3`, `=IF(1,GOTO(R1C1),)`, `=--1%`, `={1,2}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := parseXLM(s)
		if err != nil {
			return
		}
		// Evaluating any parsed formula must not panic.
		h := newXLMHost(map[string]string{"A1": "=" + strings.TrimPrefix(s, "=")}, nil)
		h.engine(context.Background()).max = 2000
		_ = n
		h.RunXLM(context.Background(), "M", "A1")
	})
}
