package maldoctrace

import (
	"testing"
	"time"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
	"github.com/debugactiveprocess/MaldocTrace/vba/parser"
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// FuzzAnalyzeVBA drives lexer, parser, static deobfuscation and emulation
// with arbitrary source. Any panic escaping the pipeline is a bug.
func FuzzAnalyzeVBA(f *testing.F) {
	for _, s := range []string{
		"Sub AutoOpen()\nShell \"cmd /c x\"\nEnd Sub",
		scriptControlFixture,
		"Sub AutoOpen()\nx = Chr(65) & StrReverse(\"cba\")\nIf x Then\nEnd If\nEnd Sub",
		"Function F(a)\nF = F(a)\nEnd Function\nSub AutoOpen()\nF 1\nEnd Sub",
		"#If VBA7 Then\nDeclare PtrSafe Function X Lib \"k\" () As Long\n#End If",
	} {
		f.Add(s)
	}
	opts := Options{Timeout: 2 * time.Second, RuntimeLimits: runtime.Limits{MaxSteps: 5000, MaxLoopIterations: 200, MaxCallDepth: 30}}
	f.Fuzz(func(t *testing.T, src string) {
		// Parser on its own, without the recovering wrapper.
		parser.Parse(src)
		r := AnalyzeVBA(src, "fuzz.bas", opts)
		for _, d := range r.Diagnostics {
			if d.Severity == "error" {
				t.Fatalf("recovered panic: %s", d.Message)
			}
		}
	})
}

// FuzzAnalyzeBytes exercises container extraction (CFB, OOXML, OVBA).
func FuzzAnalyzeBytes(f *testing.F) {
	f.Add([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	f.Add([]byte("PK\x03\x04"))
	f.Add(cfbtest.MacroWorkbook("M", true, 0, 0, "x", []cfbtest.Formula{
		{Row: 0, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr("calc"), cfbtest.PtgFuncVar(1, 110))},
		{Row: 1, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgRef(0, 0), cfbtest.PtgFunc(53))},
	}))
	f.Add([]byte(`{\rtf1{\object\objupdate\objdata 01050000020000000b000000457175617469}{\*\template http://x/t}}`))
	opts := Options{Timeout: 2 * time.Second, RuntimeLimits: runtime.Limits{MaxSteps: 5000, MaxLoopIterations: 200, MaxCallDepth: 30}}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := AnalyzeFromBytes(nil, data, "fuzz.bin", opts)
		for _, d := range r.Diagnostics {
			if d.Severity == "error" {
				t.Fatalf("recovered panic: %s", d.Message)
			}
		}
	})
}
