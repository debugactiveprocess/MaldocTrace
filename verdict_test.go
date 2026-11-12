package maldoctrace

import (
	"context"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

func TestVerdictLevels(t *testing.T) {
	cases := []struct {
		name string
		r    report.Report
		want string
	}{
		{"nothing found", report.Report{Status: "complete", Macros: "absent"}, "clean"},
		{"partial and nothing found", report.Report{Status: "partial", Macros: "absent"}, "unknown"},
		{"undecrypted", report.Report{Status: "complete", Macros: "unknown", Encrypted: true}, "unknown"},
		{"hyperlinks only", report.Report{Status: "complete", Macros: "absent",
			StaticFindings: []report.StaticFinding{{Kind: "hyperlink", Severity: "low"}},
			Indicators:     []report.IOC{{Type: "url", Value: "https://example.com/"}}}, "clean"},
		{"qr lure", report.Report{Status: "complete", Macros: "absent",
			StaticFindings: []report.StaticFinding{{Kind: "qr_code_lure", Severity: "medium"}}}, "suspicious"},
		{"auto-run macro", report.Report{Status: "complete", Macros: "present",
			EntryPoints: []report.EntryPoint{{Module: "M", Proc: "AutoOpen"}}}, "suspicious"},
		{"remote template", report.Report{Status: "complete", Macros: "absent",
			StaticFindings: []report.StaticFinding{{Kind: "template_injection", Severity: "high"}}}, "malicious"},
		{"command", report.Report{Status: "partial", Macros: "present",
			Commands: []report.Command{{CommandLine: "cmd /c calc"}}}, "malicious"},
		{"executable artifact", report.Report{Status: "complete", Macros: "present",
			Artifacts: []report.Artifact{{FileType: "PE32 executable"}}}, "malicious"},
		{"malicious child", report.Report{Status: "complete", Macros: "absent",
			Children: []report.Child{{Source: "embedded_object", Name: "x", Report: &report.Report{Verdict: "malicious", RiskScore: 60}}}}, "malicious"},
	}
	for _, c := range cases {
		r := c.r
		computeVerdict(&r)
		if r.Verdict != c.want {
			t.Errorf("%s: verdict %s (score %d, %v), want %s", c.name, r.Verdict, r.RiskScore, r.VerdictReasons, c.want)
		}
		if r.RiskScore < 0 || r.RiskScore > 100 {
			t.Errorf("%s: score %d out of range", c.name, r.RiskScore)
		}
	}
}

func TestVerdictAtLeast(t *testing.T) {
	if !VerdictAtLeast("malicious", "suspicious") || VerdictAtLeast("suspicious", "malicious") ||
		VerdictAtLeast("unknown", "suspicious") || VerdictAtLeast("clean", "suspicious") || !VerdictAtLeast("suspicious", "suspicious") {
		t.Fatal("VerdictAtLeast ordering")
	}
}

// The whole pipeline fills the verdict and the checks.
func TestPipelineVerdict(t *testing.T) {
	r := AnalyzeVBA("Sub AutoOpen()\r\nShell \"cmd.exe /c calc.exe\"\r\nEnd Sub\r\n", "m.bas", Options{})
	if r.Verdict != "malicious" || r.RiskScore < scoreMalicious || len(r.VerdictReasons) == 0 {
		t.Fatalf("verdict %s %d %v", r.Verdict, r.RiskScore, r.VerdictReasons)
	}
	r = AnalyzeFromBytes(context.Background(), []byte{0, 1, 2, 3}, "x.bin", Options{})
	if r.Verdict != "unknown" {
		t.Fatalf("unrecognised input: verdict %s", r.Verdict)
	}
}
