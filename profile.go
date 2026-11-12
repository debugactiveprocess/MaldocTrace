package maldoctrace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/payload"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

// minHexBlob is the smallest run of hex digits (in characters) assembled from
// string literals that is reported as an embedded binary payload.
const minHexBlob = 256

// recoverHexLiterals reassembles binary payloads that a macro stores as hex
// text split across string literals (h = "fce8..." : h = h & "..."), even
// when emulation could not build the buffer. The bytes are reported as a
// static recovery, not as something the macro was seen to produce.
func recoverHexLiterals(r *report.Report) {
	type piece struct {
		line int
		val  string
	}
	groups := map[string][]piece{}
	var order []string
	for _, d := range r.Decoded {
		if d.Method != "literal" || len(d.Value) < 16 || !isHexText(d.Value) {
			continue
		}
		key := d.Module + "\x00" + d.Proc
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], piece{d.Line, d.Value})
	}
	known := map[string]bool{}
	for _, p := range r.DecodedPayloads {
		known[p.SHA256] = true
	}
	for _, key := range order {
		ps := groups[key]
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].line < ps[j].line })
		// Consecutive literals (allowing a few lines between them) form a blob.
		start := 0
		for i := 1; i <= len(ps); i++ {
			if i < len(ps) && ps[i].line-ps[i-1].line <= 3 {
				continue
			}
			var sb strings.Builder
			for _, p := range ps[start:i] {
				sb.WriteString(p.val)
			}
			first := ps[start].line
			n := i - start
			start = i
			text := sb.String()
			if len(text) < minHexBlob || len(text)%2 != 0 {
				continue
			}
			raw, err := hex.DecodeString(text)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(raw)
			h := hex.EncodeToString(sum[:])
			if known[h] {
				continue
			}
			known[h] = true
			mod, proc, _ := strings.Cut(key, "\x00")
			p := report.DecodedPayload{
				ID: fmt.Sprintf("payload-%d", len(r.DecodedPayloads)+1), Kind: fmt.Sprintf("Hex string literals (%s.%s, %d literals from line %d)", mod, proc, n, first),
				Category: "binary", Encoding: []string{"hex"}, DerivedFrom: "static", Depth: 1, Status: "decoded",
				Size: len(raw), SHA256: h, Raw: raw,
				Details: []string{"assembled statically from string literals; the macro's own code was not needed to recover it"},
			}
			p.Content, _ = payload.DisplayBytes(raw)
			r.DecodedPayloads = append(r.DecodedPayloads, p)
		}
	}
}

func isHexText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// profileBinaries identifies every recovered binary payload: file formats
// (PE imports and sections) and, for raw code, the shellcode profile with
// any network configuration it carries. Network values become IOCs.
func profileBinaries(r *report.Report) {
	for i := range r.DecodedPayloads {
		p := &r.DecodedPayloads[i]
		if p.Category != "binary" || len(p.Raw) == 0 {
			continue
		}
		if p.FileType == "" {
			p.FileType, p.Facts = payload.DescribeBinary(p.Raw)
		}
		if p.FileType != "" {
			continue
		}
		prof := payload.ProfileShellcode(p.Raw)
		if prof.Empty() {
			continue
		}
		p.FileType = prof.Kind()
		p.Facts = append(p.Facts, prof.Facts()...)
		for _, v := range prof.Indicators() {
			scanEvidenceOpts(r, v, "shellcode_profile", p.ID, report.Source{}, true)
		}
		if ua := profUA(prof); ua != "" {
			r.IOCs = append(r.IOCs, report.IOC{Type: "user_agent", Value: ua, Discovery: "shellcode_profile",
				Occurrences: []report.Occurrence{{EvidenceID: p.ID, Discovery: "shellcode_profile"}}})
		}
	}
}

func profUA(p *payload.ShellcodeProfile) string {
	if p.Network == nil {
		return ""
	}
	return p.Network.UserAgent
}
