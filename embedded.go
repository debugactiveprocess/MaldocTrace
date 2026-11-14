package maldoctrace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/payload"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

// childFile is a file found inside the analysed one, to be described and,
// when it is a supported document, analysed recursively.
type childFile struct {
	source   string // embedded_object | archive_member | email_attachment | onenote_file
	name     string // short file name
	location string // where it was found
	class    string // OLE class, MIME type...
	data     []byte
	// noRecurse is set when the content was already analysed with the
	// parent (an OLE document whose VBA openZip extracted).
	noRecurse bool
}

// recursable reports inputs the pipeline can analyse as documents.
func recursable(data []byte) bool {
	switch extractor.Detect(data) {
	case extractor.FormatCFB, extractor.FormatOOXML, extractor.FormatRTF, extractor.FormatWordXML, extractor.FormatFlatOPC, extractor.FormatMHT:
		return true
	}
	return extractor.DetectContainer(data) != ""
}

// processChildren describes every child file as an artifact, reports active
// PDF content and scripts, and analyses supported documents recursively
// within the depth limit.
func processChildren(ctx context.Context, r *report.Report, files []childFile, opts Options) {
	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		sum := sha256.Sum256(f.data)
		a := report.Artifact{Name: f.name, Path: f.location, SHA256: hex.EncodeToString(sum[:]), Size: len(f.data),
			Discovery: f.source, Raw: f.data}
		kind, script := payload.ClassifyFile(f.name, f.data)
		a.FileType, a.Facts = payload.DescribeBinary(f.data)
		if a.FileType == "" || script || kind == payload.MSIKind || kind == payload.ISOKind || kind == payload.CHMKind {
			a.FileType = kind
		}
		if f.class != "" {
			a.Facts = append([]string{"class " + f.class}, a.Facts...)
		}
		r.Artifacts = append(r.Artifacts, a)
		src := report.Source{Module: f.location}
		switch {
		case a.FileType == "PDF document":
			describePDFChild(r, f, src)
		case script:
			id := addFinding(r, report.StaticFinding{Kind: "embedded_script", Severity: "high", Location: f.location, Target: f.name,
				Detail: fmt.Sprintf("%s carried by the document (%d bytes); it runs when opened", kind, len(f.data))})
			text := scriptText(f.data)
			scanEvidenceOpts(r, text, "static", id, src, true)
			switch kind {
			case "batch script":
				// The commands are assembled from "set" fragments: recover
				// them from the expanded script, as cmd.exe runs it.
				if deob := payload.DeobfuscateBatch(text); deob != "" {
					r.Decoded = append(r.Decoded, report.DecodedStr{Value: cut(deob, 8192), Kind: "static", Method: "batch variable expansion", Module: f.location})
					scanEvidenceOpts(r, deob, "decoded", id, src, true)
					text = deob
				}
			case "VBScript script", "VBScript/JScript script":
				emulateScript(ctx, r, f, kind, text, opts)
			}
			recoverScriptCommands(r, text, id, src)
		case kind == payload.ISOKind:
			addFinding(r, report.StaticFinding{Kind: "embedded_disk_image", Severity: "high", Location: f.location, Target: f.name,
				Detail: "ISO disk image carried by the document; Windows mounts it on a double click and its files (often a shortcut and a DLL) are analysed below"})
		case kind == "Windows shortcut (LNK)" || kind == payload.MSIKind || kind == payload.CHMKind || strings.HasPrefix(a.FileType, "PE"):
			detail := a.FileType + " carried by the document"
			if kind == payload.MSIKind {
				detail = "Windows Installer package carried by the document; installing it runs its custom actions (scripts, DLLs, executables)"
			}
			if kind == payload.CHMKind {
				detail = "Compiled HTML Help file carried by the document; hh.exe renders its pages and runs their script and ActiveX shortcut objects"
			}
			addFinding(r, report.StaticFinding{Kind: "embedded_executable", Severity: "high", Location: f.location, Target: f.name,
				Detail: detail})
			for _, s := range payload.PrintableStrings(f.data, 6, 4096) {
				scanEvidence(r, s, "static", "artifact:"+a.SHA256, src)
			}
		}
		if f.noRecurse || kind == payload.MSIKind || !recursable(f.data) {
			continue
		}
		if opts.depth >= opts.Limits.MaxNestedDepth {
			r.LimitsHit = append(r.LimitsHit, "MaxNestedDepth")
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "embedded",
				Message: "nesting depth limit reached; " + f.location + " was not analysed"})
			continue
		}
		child := opts
		child.depth++
		cr := AnalyzeFromBytes(ctx, f.data, r.File.Path+"!"+f.location, child)
		cr.File.Name = f.name
		r.Children = append(r.Children, report.Child{Source: f.source, Name: f.location, Report: cr})
	}
}

// embeddedFiles converts the extractor's embedded objects to child files.
func embeddedFiles(res *extractor.Result) []childFile {
	var out []childFile
	for _, e := range res.Embedded {
		out = append(out, childFile{source: "embedded_object", name: e.Name, location: e.Location, class: e.Class, data: e.Data, noRecurse: e.HasVBA})
	}
	return out
}

// describePDFChild reports the active content and links of a PDF.
func describePDFChild(r *report.Report, f childFile, src report.Source) {
	b := f.data
	if i := strings.Index(string(b[:min(len(b), 1024)]), "%PDF-"); i > 0 {
		b = b[i:]
	}
	info := payload.DescribePDF(b)
	active := info.Active()
	id := ""
	if len(active) > 0 {
		sev := "medium"
		for _, m := range active {
			if m == "/JavaScript" || m == "/JS" || m == "/Launch" {
				sev = "high"
			}
		}
		id = addFinding(r, report.StaticFinding{Kind: "pdf_active_content", Severity: sev, Location: f.location, Target: f.name,
			Detail: "embedded PDF with " + strings.Join(active, ", ")})
	}
	if len(info.URIs) > 0 && id == "" {
		id = addFinding(r, report.StaticFinding{Kind: "pdf_link", Severity: "low", Location: f.location, Target: f.name,
			Detail: fmt.Sprintf("embedded PDF with %d link(s)", len(info.URIs))})
	}
	for _, u := range info.URIs {
		scanEvidence(r, u, "static", id, src)
	}
}

// scriptText decodes UTF-16 scripts (with a BOM) to text.
func scriptText(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]rune, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, rune(uint16(b[i])|uint16(b[i+1])<<8))
		}
		return string(u)
	}
	return string(b)
}

// scriptLaunchers are programs whose command lines in a script are
// reported as commands.
var scriptLaunchers = []string{"powershell", "pwsh", "cmd.exe", "cmd /c", "cmd /k", "mshta", "rundll32", "regsvr32", "wscript.exe", "cscript.exe", "wscript //", "cscript //",
	"certutil", "bitsadmin", "curl ", "curl.exe", "wget ", "msiexec", "schtasks", "start-process", "invoke-webrequest", "iwr ", "iex"}

// recoverScriptCommands reports the lines of a script that start programs.
func recoverScriptCommands(r *report.Report, text, evidence string, src report.Source) {
	n := 0
	for _, line := range strings.FieldsFunc(text, func(c rune) bool { return c == 10 || c == 13 }) {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if l == "" || strings.HasPrefix(low, "rem ") || strings.HasPrefix(low, "'") || strings.HasPrefix(low, "//") || strings.HasPrefix(low, "#") || strings.HasPrefix(low, "::") {
			continue
		}
		for _, k := range scriptLaunchers {
			if strings.Contains(low, k) {
				r.Commands = append(r.Commands, report.Command{
					ID: fmt.Sprintf("command-%d", len(r.Commands)+1), Kind: "script command", CommandLine: cut(l, 4096),
					Receiver: "script", Method: "line", Source: src, Discovery: "static", Execution: "not executed (static script content)",
					Resolution: "literal", EvidenceIDs: []string{evidence},
				})
				n++
				break
			}
		}
		if n >= 32 {
			return
		}
	}
}
