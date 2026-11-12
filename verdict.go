package maldoctrace

import (
	"fmt"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

// Verdict thresholds on the 0-100 risk score.
const (
	scoreMalicious  = 60
	scoreSuspicious = 25
)

// attackFindings are static findings that, at high severity, mean the file
// runs or fetches code by itself: each one alone makes a file malicious.
var attackFindings = map[string]bool{
	"dde":                     true,
	"template_injection":      true,
	"external_ole":            true,
	"external_frame":          true,
	"external_subdocument":    true,
	"equation_editor_exploit": true,
	"xlm_auto_open":           true,
	"external_web_query":      true,
}

// lureFindings are phishing lures (no code, but a click or scan away from
// a malicious page): suspicious on their own.
var lureFindings = map[string]bool{"qr_code_lure": true, "shape_hyperlink": true}

var severityPoints = map[string]int{"high": 40, "medium": 15, "low": 3}

// isExecutable reports file types that are machine code.
func isExecutable(fileType string) bool {
	low := strings.ToLower(fileType)
	return strings.HasPrefix(low, "pe") || strings.Contains(low, "shellcode") || strings.Contains(low, "executable") ||
		strings.Contains(low, "shortcut (lnk)") ||
		strings.Contains(low, "elf") || strings.Contains(low, "mach-o")
}

// computeVerdict derives the verdict, risk score and the reasons behind
// them from the evidence already in the report. The score is a sum of
// capped contributions; a partial analysis that found nothing is "unknown",
// never "clean".
func computeVerdict(r *report.Report) {
	score := 0
	var reasons []string
	add := func(points int, format string, a ...any) {
		score += points
		reasons = append(reasons, fmt.Sprintf("+%d ", points)+fmt.Sprintf(format, a...))
	}
	if n := len(r.Commands); n > 0 {
		add(min(60+10*(n-1), 80), "%d command(s) the document runs were recovered (first: %s)", n, cut(r.Commands[0].CommandLine, 80))
	}
	seenKind := map[string]bool{}
	for _, f := range r.StaticFindings {
		key := f.Kind + "/" + f.Severity
		if seenKind[key] {
			continue
		}
		seenKind[key] = true
		pts := severityPoints[f.Severity]
		if f.Severity == "high" && attackFindings[f.Kind] {
			pts = scoreMalicious
		}
		if lureFindings[f.Kind] && pts < scoreSuspicious {
			pts = scoreSuspicious
		}
		if pts > 0 {
			add(pts, "%s static finding: %s", f.Severity, f.Kind)
		}
	}
	execPayload, otherPayload := 0, 0
	for _, p := range r.DecodedPayloads {
		if isExecutable(p.FileType) {
			execPayload++
		} else {
			otherPayload++
		}
	}
	if execPayload > 0 {
		add(scoreMalicious, "%d decoded payload(s) are executable code", execPayload)
	}
	if otherPayload > 0 {
		add(25, "%d encoded payload(s) or script(s) decoded", otherPayload)
	}
	execArt, otherArt, scripts := 0, 0, 0
	for _, a := range r.Artifacts {
		switch {
		case isExecutable(a.FileType):
			execArt++
		case a.Discovery != "observed" && strings.Contains(strings.ToLower(a.FileType), "script"):
			scripts++
		case a.Discovery == "observed":
			// Files found inside the document (embedded objects, archive
			// members, attachments) are judged by their own analysis.
			otherArt++
		}
	}
	if scripts > 0 {
		add(40, "%d script(s) carried by the document", scripts)
	}
	if execArt > 0 {
		add(scoreMalicious, "%d dropped or embedded file(s) are executable code", execArt)
	}
	if otherArt > 0 {
		add(min(15*otherArt, 30), "%d file(s) written by the macro or embedded in the document", otherArt)
	}
	if r.Macros == "present" {
		pts := 10
		if len(r.EntryPoints) > 0 {
			pts = 25
		}
		add(pts, "macros present (%d auto-run entry point(s))", len(r.EntryPoints))
	}
	network := 0
	for _, i := range r.Indicators {
		switch i.Type {
		case "url", "ip", "ipv4", "domain", "unc_path":
			network++
		}
	}
	// Network indicators only weigh in next to active content: plain
	// documents are full of harmless hyperlinks.
	active := r.Macros == "present" || len(r.Commands) > 0 || len(r.DecodedPayloads) > 0
	if network > 0 && active {
		add(min(5*network, 20), "%d network indicator(s)", network)
	}
	if d := r.Decryption; d != nil && d.Decrypted && d.Password == "VelvetSweatshop" {
		add(10, "encrypted with Excel's default password (opens without a prompt, hides content from scanners)")
	}
	for _, c := range r.Children {
		if c.Report == nil {
			continue
		}
		if c.Report.Verdict == "malicious" || c.Report.Verdict == "suspicious" {
			add(c.Report.RiskScore, "%s %s: %s", strings.ReplaceAll(c.Source, "_", " "), c.Name, c.Report.Verdict)
		}
	}
	if score > 100 {
		score = 100
	}
	r.RiskScore = score
	r.VerdictReasons = reasons
	incomplete := r.Status != "complete" || len(r.LimitsHit) > 0 || r.Macros == "unknown" ||
		(r.Encrypted && (r.Decryption == nil || !r.Decryption.Decrypted))
	switch {
	case score >= scoreMalicious:
		r.Verdict = "malicious"
	case score >= scoreSuspicious:
		r.Verdict = "suspicious"
	case incomplete:
		r.Verdict = "unknown"
		r.VerdictReasons = append(r.VerdictReasons, "analysis incomplete (status "+r.Status+", macros "+r.Macros+"): absence of findings is not evidence of absence")
	default:
		r.Verdict = "clean"
	}
	for _, c := range r.Children {
		if c.Report != nil && worse(c.Report.Verdict, r.Verdict) {
			r.Verdict = c.Report.Verdict
		}
	}
}

var verdictRank = map[string]int{"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}

func worse(a, b string) bool { return verdictRank[a] > verdictRank[b] }

// VerdictAtLeast reports whether verdict v meets threshold t
// ("suspicious" or "malicious").
func VerdictAtLeast(v, t string) bool {
	return verdictRank[v] >= verdictRank[t] && (v == "suspicious" || v == "malicious")
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
