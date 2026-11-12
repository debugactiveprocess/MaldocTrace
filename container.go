package maldoctrace

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

// analyzeContainer handles inputs that carry documents rather than being
// one: archives (and, later, emails and notebooks). Every member is listed
// and described, and supported documents are analysed as children.
func analyzeContainer(ctx context.Context, kind string, data []byte, r *report.Report, opts Options) {
	switch kind {
	case "zip", "7z":
		analyzeArchive(ctx, kind, data, r, opts)
	case "eml", "msg":
		analyzeEmail(ctx, kind, data, r, opts)
	default:
		r.Status = "partial"
		r.Macros = "unknown"
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "container", Message: "unsupported container " + kind})
	}
}

// analyzeEmail reports the sender, subject and attachments of a message,
// takes indicators from its bodies and analyses every attachment.
func analyzeEmail(ctx context.Context, kind string, data []byte, r *report.Report, opts Options) {
	r.Macros = "absent"
	var e *extractor.Email
	var err error
	if kind == "msg" {
		e, err = extractor.ParseMSG(data, &opts.Limits)
	} else {
		e, err = extractor.ParseEML(data)
	}
	if err != nil {
		r.Status = "partial"
		r.Macros = "unknown"
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: kind, Message: err.Error()})
		return
	}
	for _, d := range e.Diagnostics {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: d.Severity, Stage: d.Stage, Message: d.Message})
	}
	r.LimitsHit = append(r.LimitsHit, e.LimitsHit...)
	for _, h := range []struct{ name, value string }{{"From", e.From}, {"To", e.To}, {"Subject", e.Subject}, {"Date", e.Date}, {"Message-ID", e.MessageID}} {
		if h.value != "" {
			r.Properties = append(r.Properties, report.Property{Name: h.name, Value: h.value, Kind: "email", Source: kind + " header"})
		}
	}
	var files []childFile
	for i, a := range e.Attachments {
		r.Properties = append(r.Properties, report.Property{Name: fmt.Sprintf("Attachment %d", i+1),
			Value: fmt.Sprintf("%s (%s, %d bytes)", a.Name, firstOf(a.ContentType, "unknown type"), len(a.Data)), Kind: "email", Source: kind + " attachment"})
		files = append(files, childFile{source: "email_attachment", name: a.Name, location: a.Name, class: a.ContentType, data: a.Data})
	}
	for i, b := range e.Bodies {
		scanEvidence(r, b, "static", fmt.Sprintf("email-body-%d", i+1), report.Source{Module: kind + " body"})
	}
	r.Checks = append(r.Checks, fmt.Sprintf("%s headers, %d body part(s) for indicators, %d attachment(s)", kind, len(e.Bodies), len(e.Attachments)))
	processChildren(ctx, r, files, opts)
}

func analyzeArchive(ctx context.Context, kind string, data []byte, r *report.Report, opts Options) {
	r.Macros = "absent"
	a, err := extractor.OpenArchive(data, kind, &opts.Limits)
	if err != nil {
		r.Status = "partial"
		r.Macros = "unknown"
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "archive", Message: err.Error()})
		return
	}
	for _, d := range a.Diagnostics {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: d.Severity, Stage: d.Stage, Message: d.Message})
	}
	r.LimitsHit = append(r.LimitsHit, a.LimitsHit...)
	var files []childFile
	passwords := map[string]bool{}
	unread := 0
	for _, m := range a.Members {
		if m.Password != "" {
			passwords[m.Password] = true
		}
		if m.Err != "" {
			unread++
			if m.Encrypted {
				r.Encrypted = true
			}
			continue
		}
		files = append(files, childFile{source: "archive_member", name: path.Base(strings.ReplaceAll(m.Name, `\`, "/")), location: m.Name, data: m.Data})
	}
	if len(passwords) > 0 || r.Encrypted {
		r.Encrypted = true
		var pws []string
		for p := range passwords {
			pws = append(pws, p)
		}
		scheme := "ZIP (ZipCrypto or WinZip AES)"
		if kind == "7z" {
			scheme = "7z AES-256"
		}
		r.Decryption = &report.Decryption{Scheme: scheme, Decrypted: unread == 0, Password: strings.Join(pws, ", ")}
		if unread > 0 {
			r.Decryption.Note = fmt.Sprintf("%d member(s) could not be read", unread)
		}
	}
	if unread > 0 {
		r.Macros = "unknown"
	}
	r.Checks = append(r.Checks, fmt.Sprintf("%s archive members (%d read, %d unreadable), analysed in memory", kind, len(files), unread))
	processChildren(ctx, r, files, opts)
}
