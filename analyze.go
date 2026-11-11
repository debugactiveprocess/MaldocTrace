// Package maldoctrace is the reusable public API: it runs the full pipeline
// (extraction, parse, static deobfuscation, emulation, IOC extraction) and
// returns a self-contained report. Steps are independent; a failure in a later
// step never discards evidence recovered by an earlier one.
package maldoctrace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"maldoctrace/emulation"
	"maldoctrace/extractor"
	"maldoctrace/report"
	"maldoctrace/vba/runtime"
)

// Version is the tool version reported in output. Release builds set it
// from the git tag: -ldflags "-X maldoctrace.Version=1.2.3".
var Version = "0.1.0"

// Options configures an analysis run.
type Options struct {
	Limits        extractor.Limits
	RuntimeLimits runtime.Limits
	Timeout       time.Duration
	Speculative   bool
	Fixtures      emulation.Fixtures
	// DocumentText supplies the document body when analysing raw VBA text
	// (container inputs use the text extracted from the file).
	DocumentText string
}

func (o *Options) fill() {
	if o.Limits.MaxInputSize == 0 {
		o.Limits = extractor.DefaultLimits()
	}
	if o.RuntimeLimits.MaxSteps == 0 {
		o.RuntimeLimits = runtime.DefaultLimits()
	}
	if o.Timeout == 0 {
		o.Timeout = 120 * time.Second
	}
}

// AnalyzeFromBytes runs the full pipeline over an in-memory input.
func AnalyzeFromBytes(parent context.Context, data []byte, path string, opts Options) *report.Report {
	opts.fill()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()

	sum := sha256.Sum256(data)
	name := path
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		name = path[i+1:]
	}
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   Version,
		File:          report.FileInfo{Path: path, Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))},
		Status:        "complete",
		Macros:        "absent",
	}
	start := time.Now()

	var res *extractor.Result
	var extractErr error
	if !runStage(r, "extract", func() { res, extractErr = extractor.Extract(ctx, data, &opts.Limits) }) || res == nil {
		r.Macros = "unknown"
		if res == nil {
			res = &extractor.Result{}
		}
	}
	if extractErr != nil {
		r.Status = "partial"
		r.Macros = "unknown"
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "extract", Message: extractErr.Error()})
	}
	r.Format = res.Format.String()
	r.Encrypted = res.Encrypted
	r.Projects = toReportProjects(res)

	if res.Encrypted {
		r.Macros = "unknown"
		r.Status = "partial"
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "extract", Message: "container is encrypted; macro presence is unknown"})
	} else if res.HasModules() {
		r.Macros = "present"
	} else if res.Format == extractor.FormatUnknown {
		r.Macros = "unknown"
		r.Status = "partial"
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "extract", Message: "unrecognised input; no VBA extracted"})
	}

	for _, m := range res.Modules {
		r.Modules = append(r.Modules, report.Module{Name: m.Name, FileName: m.FileName, Type: m.TypeName, Codepage: m.Codepage, SourceFile: m.SourceFile, CodeLen: len(m.Code)})
	}
	for _, d := range res.Diagnostics {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: d.Severity, Stage: d.Stage, Message: d.Message})
	}
	for _, l := range res.LimitsHit {
		r.LimitsHit = append(r.LimitsHit, l)
	}

	if res.HasModules() {
		runStage(r, "emulation", func() { runEmulation(ctx, res, r, opts) })
	}

	if r.Status == "failed" {
		// keep failed: a recovered panic must stay visible in the status
	} else if ctx.Err() != nil {
		r.Status = "timeout"
	} else if r.Status == "complete" && (hasWarnings(r.Diagnostics) || len(r.LimitsHit) > 0) {
		r.Status = "partial"
	}
	safeFinalize(r)
	r.DurationMs = time.Since(start).Milliseconds()
	return r
}

func hasWarnings(ds []report.Diagnostic) bool {
	for _, d := range ds {
		if d.Severity == "warning" || d.Severity == "error" {
			return true
		}
	}
	return false
}

// AnalyzeVBA analyses raw VBA source text (for --input-format vba).
func AnalyzeVBA(text, name string, opts Options) *report.Report {
	opts.fill()
	sum := sha256.Sum256([]byte(text))
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   Version,
		File:          report.FileInfo{Path: name, Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(text))},
		Format:        "vba",
		Status:        "complete",
		Macros:        "present",
	}
	synthetic := &extractor.Result{
		Format:       extractor.FormatVBA,
		Modules:      []*extractor.Module{{Name: "Module1", FileName: "Module1.bas", TypeName: "procedural", Code: text, CodeRaw: []byte(text)}},
		DocumentText: opts.DocumentText,
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
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

func toReportProjects(res *extractor.Result) []report.Project {
	var out []report.Project
	for _, p := range res.Projects {
		out = append(out, report.Project{Name: p.Name, DirStream: p.DirStream, SourceFile: p.SourceFile, Codepage: p.Codepage, SysKind: p.SysKind, LCID: p.LCID})
	}
	return out
}
