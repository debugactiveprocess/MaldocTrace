package payload

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// PDFInfo is the static description of a PDF document: its version and the
// name markers that make a PDF act on its own (scripts, actions run on open,
// launching programs, links, attachments). Nothing is rendered or run.
type PDFInfo struct {
	Version string
	// Markers counts active-content names (/JavaScript, /OpenAction...),
	// found in the file and in its decompressed streams. Names obfuscated
	// with #xx escapes (/J#61vaScript) are decoded first.
	Markers map[string]int
	URIs    []string
	Streams int
}

// pdfMarkers are the names reported, with why they matter.
var pdfMarkers = []string{"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/URI", "/EmbeddedFile", "/SubmitForm", "/XFA", "/RichMedia", "/ObjStm", "/Encrypt"}

// Active reports the markers that run something without the user asking
// for it beyond opening the file.
func (p *PDFInfo) Active() []string {
	var out []string
	for _, m := range []string{"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/XFA", "/RichMedia"} {
		if p.Markers[m] > 0 {
			out = append(out, m)
		}
	}
	return out
}

// Facts renders the description for reports.
func (p *PDFInfo) Facts() []string {
	var facts []string
	if p.Version != "" {
		facts = append(facts, "version "+p.Version)
	}
	var ms []string
	for _, m := range pdfMarkers {
		if n := p.Markers[m]; n > 0 {
			ms = append(ms, fmt.Sprintf("%s=%d", m, n))
		}
	}
	if len(ms) > 0 {
		facts = append(facts, "markers: "+strings.Join(ms, " "))
	} else {
		facts = append(facts, "no active-content markers")
	}
	for i, u := range p.URIs {
		if i == 8 {
			facts = append(facts, fmt.Sprintf("... %d more URIs", len(p.URIs)-i))
			break
		}
		facts = append(facts, "URI "+u)
	}
	return facts
}

var (
	pdfName   = regexp.MustCompile(`/[A-Za-z0-9#]+`)
	pdfURI    = regexp.MustCompile(`/URI\s*\(([^)]{1,1000})\)`)
	pdfStream = regexp.MustCompile(`stream\r?\n`)
)

// maxPDFInflate bounds the bytes decompressed from all streams of one PDF.
const maxPDFInflate = 32 << 20

// DescribePDF scans a PDF and its Flate streams for active-content markers.
func DescribePDF(b []byte) *PDFInfo {
	p := &PDFInfo{Markers: map[string]int{}}
	if bytes.HasPrefix(b, []byte("%PDF-")) && len(b) >= 8 {
		p.Version = strings.TrimSpace(string(b[5:8]))
	}
	scan := func(chunk []byte) {
		for _, m := range pdfName.FindAll(chunk, -1) {
			name := decodePDFName(string(m))
			for _, k := range pdfMarkers {
				if name == k {
					p.Markers[k]++
				}
			}
		}
		for _, m := range pdfURI.FindAllSubmatch(chunk, 64) {
			if len(p.URIs) < 64 {
				p.URIs = append(p.URIs, string(m[1]))
			}
		}
	}
	scan(b)
	budget := maxPDFInflate
	for _, loc := range pdfStream.FindAllIndex(b, 4096) {
		start := loc[1]
		end := bytes.Index(b[start:], []byte("endstream"))
		if end < 0 {
			continue
		}
		p.Streams++
		zr, err := zlib.NewReader(bytes.NewReader(b[start : start+end]))
		if err != nil {
			continue
		}
		out, _ := io.ReadAll(io.LimitReader(zr, int64(budget)))
		zr.Close()
		budget -= len(out)
		scan(out)
		if budget <= 0 {
			break
		}
	}
	sort.Strings(p.URIs)
	p.URIs = dedupe(p.URIs)
	return p
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// decodePDFName resolves #xx escapes in a PDF name.
func decodePDFName(s string) string {
	if !strings.Contains(s, "#") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			b.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}
