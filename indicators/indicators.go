// Package indicators extracts and normalises indicators of compromise
// (URLs, domains, IPs, paths, commands, registry keys, ProgIDs) from strings.
// Extraction is intentionally conservative: a match here is a *candidate*
// observation, never proof of execution or malice.
package indicators

import (
	"regexp"
	"strings"
)

// Finding is a single extracted indicator candidate.
type Finding struct {
	Type     string // url, domain, ipv4, path, command, registry, progid
	Value    string
	Evidence string // source text that produced the match
}

var (
	reURL  = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>),\]]+`)
	reIP   = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	reDom  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|info|biz|io|xyz|top|pw|tk|ml|ga|cf|gq|shop|club|online|site|cc|co|me|us|uk|de|fr|it|es|nl|eu|su|kz|ua|by|pl|cz|ro|vn|in|cn|jp|kr|tw|nz|au|br|ar|mx|tr|ir|il|ng|za|ke)\b`)
	reReg  = regexp.MustCompile(`(?i)\b(?:HKEY(?:_[A-Z0-9_]+)+|HK(?:CU|LM|CR|U|CC|DD|PD))\s*(?:\\|\\\\)?[\\/][^\s"'<>,\]]+`)
	rePath = regexp.MustCompile(`(?:[A-Za-z]:\\[^\s"'<>,\]]+|\\\\[^\s"'<>,\]]+|%[A-Za-z]+%\\[^\s"'<>,\]]+)`)
)

var commandMarkers = []string{
	"powershell", "cmd.exe", "cmd /c", "cmd /k", "command.com", "wmic",
	"regsvr32", "rundll32", "mshta", "msiexec", "certutil", "schtasks",
	"bitsadmin", "cscript", "wscript", "taskkill", "net.exe", "net user",
	"netstat", "ipconfig", "whoami", "vssadmin", "bcp.exe", "wevtutil",
	"sc.exe", "start /", "start-process", "invoke-expression", "invoke-command",
	"-enc ", "-encodedcommand", "downloadstring", "frombase64string", "iex ",
	"curl ", "wget ", "sh -", "/bin/sh", "/bin/bash", "gzip -",
}

// Scan extracts candidate indicators from text. It is safe to call on any
// string; malicious CI is never inferred.
func Scan(text string) []Finding {
	var out []Finding
	for _, m := range reURL.FindAllString(text, -1) {
		for _, u := range splitJoinedURLs(m) {
			out = append(out, Finding{Type: "url", Value: u, Evidence: m})
		}
	}
	for _, m := range reIP.FindAllString(text, -1) {
		if validIP(m) {
			out = append(out, Finding{Type: "ipv4", Value: m, Evidence: m})
		}
	}
	for _, m := range reDom.FindAllString(text, -1) {
		out = append(out, Finding{Type: "domain", Value: strings.ToLower(m), Evidence: m})
	}
	for _, m := range reReg.FindAllString(text, -1) {
		out = append(out, Finding{Type: "registry", Value: normalizeRegistry(m), Evidence: m})
	}
	for _, m := range rePath.FindAllString(text, -1) {
		out = append(out, Finding{Type: "path", Value: m, Evidence: m})
	}
	// A command candidate is the line that carries the marker, not the whole
	// input: scanning a module must not turn its entire source into one IOC.
	for _, line := range strings.Split(text, "\n") {
		low := strings.ToLower(line)
		for _, cmd := range commandMarkers {
			if strings.Contains(low, cmd) {
				v := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
				out = append(out, Finding{Type: "command", Value: v, Evidence: v})
				break
			}
		}
	}
	return out
}

var reEmbeddedScheme = regexp.MustCompile(`(?i)(?:https?|ftp)://`)

// splitJoinedURLs separates URL lists joined by a delimiter, as used by
// droppers that later split them ('http://a/x*http://b/y').split('*'). The
// match is cut wherever a new scheme starts, and the single delimiter left
// before it is dropped. Fragments without a host are discarded.
func splitJoinedURLs(m string) []string {
	locs := reEmbeddedScheme.FindAllStringIndex(m, -1)
	if len(locs) <= 1 {
		return []string{m}
	}
	var out []string
	for i, l := range locs {
		end := len(m)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		u := m[l[0]:end]
		if i+1 < len(locs) {
			u = strings.TrimRight(u, "*,;|!^~")
		}
		if len(u) > l[1]-l[0] {
			out = append(out, u)
		}
	}
	return out
}

// ScanString scans one value and limits the evidence snippet length.
func ScanValue(v string) []Finding {
	return Scan(v)
}

func validIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n := 0
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
			if n > 255 {
				return false
			}
		}
	}
	return true
}

func normalizeRegistry(s string) string {
	s = strings.ReplaceAll(s, "\\\\", "\\")
	s = strings.ReplaceAll(s, "\\", "/")
	return s
}

// NormalizeURL lower-cases the scheme/host but keeps the path intact.
func NormalizeURL(u string) string { return u }

// Dedupe merges findings by (type, value) while preserving distinct evidence.
func Dedupe(items []Finding) []Finding {
	seen := map[string]int{}
	var out []Finding
	for _, f := range items {
		key := f.Type + "\x00" + f.Value
		if i, ok := seen[key]; ok {
			if !strings.Contains(out[i].Evidence, f.Evidence) {
				out[i].Evidence += "\n" + f.Evidence
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	return out
}
