package maldoctrace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/report"
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// maxScriptStages bounds the chain of scripts that write and launch the
// next script (OneNote .vbs droppers write a second .vbs or .hta, which
// rebuilds the final command with Execute).
const maxScriptStages = 3

// AnalyzeVBScript emulates a Windows Script Host .vbs file with the VBA
// interpreter: its top-level statements run as the module body, WScript is
// a global object, and Execute/ExecuteGlobal run the code they build.
// Nothing is executed on the host; every external action is simulated.
func AnalyzeVBScript(ctx context.Context, text, name string, opts Options) *report.Report {
	opts.fill()
	if opts.RuntimeLimits.MaxSteps == runtime.DefaultLimits().MaxSteps {
		// Script droppers decode the same payload dozens of times in
		// decoy loops before the one Execute that matters; the wall-clock
		// timeout still bounds the run.
		opts.RuntimeLimits.MaxSteps *= 10
	}
	// A dropper's last step usually waits on run-time state (the size of
	// the file it downloaded); explore those branches.
	opts.Speculative = true
	sum := sha256.Sum256([]byte(text))
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   Version,
		File:          report.FileInfo{Path: name, Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(text))},
		Format:        "vbscript",
		Status:        "complete",
		Macros:        "absent",
	}
	code := runtime.SplitVBScriptStatements(text)
	synthetic := &extractor.Result{
		Format:  extractor.FormatVBA,
		Modules: []*extractor.Module{{Name: "Script", FileName: name, TypeName: "procedural", Code: code, CodeRaw: []byte(text)}},
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	runStage(r, "emulation", func() { runEmulation(ctx, synthetic, r, opts) })
	if r.Status != "failed" && (len(r.Diagnostics) > 0 || len(r.LimitsHit) > 0) {
		r.Status = "partial"
	}
	if r.Status != "failed" && ctx.Err() != nil {
		r.Status = "timeout"
	}
	safeFinalize(r)
	return r
}

// isVBScriptSource tells VBScript from JScript and encoded (.vbe) scripts,
// which the VBA interpreter cannot run.
func isVBScriptSource(kind, text string) bool {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "#@~^") {
		return false
	}
	switch kind {
	case "VBScript script":
		return true
	case "VBScript/JScript script":
		low := strings.ToLower(t)
		return !strings.Contains(low, "var ") && !strings.Contains(low, "function(") && !strings.Contains(t, "};")
	}
	return false
}

// emulateScript emulates an embedded VBScript and, stage by stage, the
// scripts it writes to disk and launches, attaching each emulation as a
// child report so its events, commands and indicators reach the verdict.
func emulateScript(ctx context.Context, r *report.Report, f childFile, kind, text string, opts Options) {
	if !isVBScriptSource(kind, text) {
		return
	}
	seen := map[string]bool{}
	var written []report.Artifact // files written by every stage so far
	parent, name, source := r, f.name, "script_emulation"
	for stage := 0; stage < maxScriptStages && text != "" && ctx.Err() == nil; stage++ {
		sum := sha256.Sum256([]byte(text))
		seen[hex.EncodeToString(sum[:])] = true
		cr := AnalyzeVBScript(ctx, text, r.File.Path+"!"+f.location+"!"+name, opts)
		cr.File.Name = name
		parent.Children = append(parent.Children, report.Child{Source: source, Name: name, Report: cr})
		parent, source = cr, "script_stage"
		for _, a := range cr.Artifacts {
			if a.Discovery == "observed" && len(a.Raw) > 0 && !seen[a.SHA256] {
				written = append(written, a)
			}
		}
		text = ""
		if a, ok := nextScriptStage(cr, written, seen); ok {
			seen[a.SHA256] = true
			text, name = scriptText(a.Raw), a.Path
		}
	}
}

// nextScriptStage picks the written file the stage launches as VBScript:
// one named in a wscript/cscript or shell command (an .html or .txt run
// with //E:vbscript counts), else a written .vbs file.
func nextScriptStage(cr *report.Report, written []report.Artifact, seen map[string]bool) (report.Artifact, bool) {
	var launched []string
	for _, e := range cr.Events {
		switch e.Type {
		case "wscript_shell_run", "wscript_shell_exec", "shell", "shell_execute", "wmi_process_create":
			launched = append(launched, strings.ToLower(strings.Join(e.Resolved, " ")))
		}
	}
	for _, a := range written {
		if seen[a.SHA256] || a.Path == "" {
			continue
		}
		p := strings.ToLower(a.Path)
		base := p[strings.LastIndexAny(p, `\/`)+1:]
		for _, l := range launched {
			if base != "" && strings.Contains(l, base) && (strings.Contains(l, "vbscript") || strings.HasSuffix(base, ".vbs") || strings.Contains(l, "wscript") || strings.Contains(l, "cscript")) {
				return a, true
			}
		}
	}
	for _, a := range written {
		if !seen[a.SHA256] && strings.HasSuffix(strings.ToLower(a.Path), ".vbs") {
			return a, true
		}
	}
	return report.Artifact{}, false
}
