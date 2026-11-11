package maldoctrace

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/debugactiveprocess/MaldocTrace/report"
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

func encodedTest(s string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestRecoveredExecutionSinks(t *testing.T) {
	command := "powershell -e " + encodedTest(`Write-Output 'https://example.org/harmless'`)
	for _, sink := range []string{
		`Shell BuildCommand`,
		`Set s = CreateObject("WScript.Shell")` + "\n" + `s.Run BuildCommand`,
		`Set s = CreateObject("WScript.Shell")` + "\n" + `s.Exec BuildCommand`,
		`Set s = GetObject("winmgmts:").Get("Win32_Process")` + "\n" + `s.Create BuildCommand`,
	} {
		t.Run(sink, func(t *testing.T) {
			code := "Function BuildCommand()\nBuildCommand = Chr(112) & \"" + command[1:] + "\"\nEnd Function\nSub AutoOpen()\n" + sink + "\nEnd Sub"
			r := AnalyzeVBA(code, "fixture.bas", Options{})
			if len(r.Commands) != 1 || r.Commands[0].CommandLine != command {
				t.Fatalf("commands=%+v diagnostics=%+v events=%+v", r.Commands, r.Diagnostics, r.Events)
			}
			if len(r.DecodedPayloads) != 1 || !strings.Contains(r.DecodedPayloads[0].Content, "https://example.org/harmless") {
				t.Fatalf("payload=%+v", r.DecodedPayloads)
			}
			if r.Commands[0].Source.Line == 0 || r.Commands[0].Source.Proc != "AutoOpen" {
				t.Fatal(r.Commands[0].Source)
			}
			found := false
			for _, i := range r.Indicators {
				if i.Type == "url" && i.Value == "https://example.org/harmless" {
					for _, o := range i.Occurrences {
						if o.EvidenceID == "payload-1" {
							found = true
						}
					}
				}
			}
			if !found {
				t.Fatal("missing payload IOC")
			}
			b, err := json.Marshal(r)
			if err != nil || !json.Valid(b) {
				t.Fatal(err)
			}
			text := report.RenderText(r)
			if !strings.Contains(text, "-- Recovered commands --") || !strings.Contains(text, "-- Decoded payloads and recovered scripts --") {
				t.Fatal(text)
			}
		})
	}
}

func TestBoundedExecution(t *testing.T) {
	r := AnalyzeVBA("Sub AutoOpen()\nDo\nLoop\nEnd Sub", "limit.bas", Options{RuntimeLimits: runtime.Limits{MaxSteps: 20, MaxLoopIterations: 30, MaxCallDepth: 5}})
	if r.Status != "partial" {
		t.Fatalf("status=%s diagnostics=%+v", r.Status, r.Diagnostics)
	}
}

func TestUnknownReceiverPreservesEvidence(t *testing.T) {
	r := AnalyzeVBA("Option Explicit\nSub AutoOpen()\nx.Create \"harmless argument\"\nEnd Sub", "unknown.bas", Options{})
	if len(r.Commands) != 1 || r.Commands[0].Resolution != "unresolved_receiver" || r.Commands[0].CommandLine != "harmless argument" || r.Status != "partial" {
		t.Fatalf("%+v", r)
	}
}

func TestPrecedenceAndArrays(t *testing.T) {
	r := AnalyzeVBA("Sub AutoOpen()\na = Array(Chr(60 + 5 * 2), StrReverse(\"ko\"))\nShell a(0) & a(1)\nEnd Sub", "expressions.bas", Options{})
	if len(r.Commands) != 1 || r.Commands[0].CommandLine != "Fok" {
		t.Fatalf("commands=%+v diagnostics=%+v", r.Commands, r.Diagnostics)
	}
}
