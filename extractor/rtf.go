package extractor

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

// rtfObject is one \objdata destination decoded to bytes.
type rtfObject struct {
	offset int
	data   []byte
}

// rtfObjData extracts every \objdata destination the way Word reads it:
// hex digit pairs, ignoring other characters, control words (with any
// numeric parameter, a common obfuscation), ignorable {\*...} groups and
// \binN raw runs. Exploit documents rely on these rules to hide the object
// from naive parsers.
func rtfObjData(b []byte, maxObjects int) []rtfObject {
	var out []rtfObject
	for start := 0; len(out) < maxObjects; {
		i := indexControlWord(b, start, "objdata")
		if i < 0 {
			break
		}
		p := skipControlWord(b, i)
		var hexd []byte
		depth := 0
	scan:
		for p < len(b) && len(hexd) < 2*MaxRTFObject {
			c := b[p]
			switch {
			case c == '{':
				if p+2 < len(b) && b[p+1] == '\\' && b[p+2] == '*' {
					p = skipGroup(b, p)
					continue
				}
				depth++
				p++
			case c == '}':
				depth--
				p++
				if depth < 0 {
					break scan
				}
			case c == '\\':
				if p+1 < len(b) && isLetter(b[p+1]) {
					word, param, next := readControlWord(b, p)
					if word == "bin" && param > 0 {
						next += param
					}
					p = next
				} else if p+1 < len(b) && b[p+1] == '\'' {
					p += 4
				} else {
					p += 2
				}
			case isHex(c):
				hexd = append(hexd, c)
				p++
			default:
				p++
			}
		}
		if len(hexd)%2 == 1 {
			hexd = hexd[:len(hexd)-1]
		}
		data := make([]byte, len(hexd)/2)
		for j := range data {
			data[j] = unhex(hexd[2*j])<<4 | unhex(hexd[2*j+1])
		}
		out = append(out, rtfObject{offset: i, data: data})
		start = p
	}
	return out
}

// MaxRTFObject bounds one decoded embedded object.
const MaxRTFObject = 32 << 20

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isHex(c byte) bool    { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// indexControlWord finds "\word" not followed by another letter.
func indexControlWord(b []byte, from int, word string) int {
	pat := []byte(`\` + word)
	for from < len(b) {
		i := bytes.Index(b[from:], pat)
		if i < 0 {
			return -1
		}
		i += from
		end := i + len(pat)
		if end >= len(b) || !isLetter(b[end]) {
			return i
		}
		from = end
	}
	return -1
}

// readControlWord parses \letters[-digits][space] at p.
func readControlWord(b []byte, p int) (string, int, int) {
	q := p + 1
	for q < len(b) && isLetter(b[q]) && q-p < 64 {
		q++
	}
	word := string(b[p+1 : q])
	neg := false
	if q < len(b) && b[q] == '-' {
		neg = true
		q++
	}
	ds := q
	for q < len(b) && b[q] >= '0' && b[q] <= '9' && q-ds < 10 {
		q++
	}
	// Overlong digit runs are consumed too (Word ignores the excess).
	for q < len(b) && b[q] >= '0' && b[q] <= '9' {
		q++
	}
	param := 0
	if q > ds {
		digits := string(b[ds:min(q, ds+9)])
		param, _ = strconv.Atoi(digits)
		if neg {
			param = -param
		}
	}
	if q < len(b) && b[q] == ' ' {
		q++
	}
	if param > len(b)-q {
		param = len(b) - q
	}
	return word, param, q
}

func skipControlWord(b []byte, p int) int {
	_, _, q := readControlWord(b, p)
	return q
}

// skipGroup returns the position after the group opening at p.
func skipGroup(b []byte, p int) int {
	depth := 0
	for ; p < len(b); p++ {
		switch b[p] {
		case '\\':
			p++
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return p + 1
			}
		}
	}
	return p
}

// ole1Info describes an OLE1 object ([MS-OLEDS] 2.2.4 ObjectHeader).
type ole1Info struct {
	class  string
	linked bool
	topic  string // linked object source (path or URL)
	native []byte
}

func lpString(b []byte, p int) (string, int, bool) {
	if p+4 > len(b) {
		return "", p, false
	}
	n := int(binary.LittleEndian.Uint32(b[p:]))
	p += 4
	if n < 0 || n > 4096 || p+n > len(b) {
		return "", p, false
	}
	return strings.TrimRight(string(b[p:p+n]), "\x00"), p + n, true
}

func parseOLE1(b []byte) (ole1Info, bool) {
	var info ole1Info
	if len(b) < 12 {
		return info, false
	}
	format := binary.LittleEndian.Uint32(b[4:])
	class, p, ok := lpString(b, 8)
	if !ok || class == "" || !printableASCII(class) {
		return info, false
	}
	info.class = class
	topic, p, ok := lpString(b, p)
	if !ok {
		return info, true
	}
	_, p, ok = lpString(b, p) // item name
	if !ok {
		return info, true
	}
	switch format {
	case 1:
		info.linked, info.topic = true, topic
	case 2:
		if p+4 <= len(b) {
			n := int(binary.LittleEndian.Uint32(b[p:]))
			if n >= 0 && p+4+n <= len(b) {
				info.native = b[p+4 : p+4+n]
			} else {
				info.native = b[p+4:]
			}
		}
	}
	return info, true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

type mtefFinding struct {
	detail  string
	payload []byte
}

// mtefExploit walks the first MTEF records of Equation Native data
// (optional 28-byte EQNOLEFILEHDR, 5-byte MTEF header, records) looking for
// the malformed records that overflow EQNEDT32.EXE buffers:
//   - FONT with a name longer than 40 bytes (CVE-2017-11882 / CVE-2018-0802);
//   - MATRIX with oversized row/column counts (CVE-2018-0798).
//
// Exploit builders often strip or corrupt the header, so both layouts are
// tried.
func mtefExploit(native []byte) mtefFinding {
	var starts []int
	if len(native) >= 2 && binary.LittleEndian.Uint16(native) == 28 {
		starts = append(starts, 28)
	}
	starts = append(starts, 0)
	for _, s := range starts {
		if s >= len(native) || native[s] != 3 { // MTEF version 3
			continue
		}
		p := s + 5
		for rec := 0; rec < 16 && p < len(native); rec++ {
			switch native[p] & 0x0F {
			case 0x00, 0x01: // END, LINE (no options modelled)
				p++
			case 0x08: // FONT: tface, style, NUL-terminated name
				if p+3 > len(native) {
					return mtefFinding{}
				}
				name := native[p+3:]
				if i := bytes.IndexByte(name, 0); i >= 0 {
					name = name[:i]
				}
				if len(name) > 40 {
					return mtefFinding{"MTEF FONT name of " + strconv.Itoa(len(name)) + " bytes overflows Equation Editor's 40-byte buffer (CVE-2017-11882 / CVE-2018-0802)", name}
				}
				p += 3 + len(name) + 1
			case 0x05: // MATRIX: valign, h_just, v_just, rows, cols, partitions
				if p+6 > len(native) {
					return mtefFinding{}
				}
				rows, cols := int(native[p+4]), int(native[p+5])
				if rows > 64 || cols > 64 {
					return mtefFinding{"MTEF MATRIX record declares " + strconv.Itoa(rows) + " rows x " + strconv.Itoa(cols) + " columns, overflowing Equation Editor's partition buffer (CVE-2018-0798)", native[p+6:]}
				}
				p += 6 + ((rows+1)*2+7)/8 + ((cols+1)*2+7)/8
			default:
				rec = 16
			}
		}
	}
	return mtefFinding{}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

// knownObjectClasses maps OLE class names to why they matter.
var knownObjectClasses = []struct{ prefix, severity, note string }{
	{"equation.3", "high", "Equation Editor object (EQNEDT32.EXE, a frequent exploit target)"},
	{"package", "high", "OLE Package: embeds a file the user can run"},
	{"ole2link", "high", "OLE2Link moniker: fetches a remote document (CVE-2017-0199 pattern)"},
	{"htmlfile", "high", "HTML file object (remote script execution pattern)"},
	{"word.document", "medium", "embedded Word document (may carry macros)"},
	{"excel.sheet", "medium", "embedded Excel workbook (may carry macros)"},
	{"forms.", "medium", "embedded ActiveX/Forms control"},
	{"shell.explorer", "high", "Shell.Explorer (embedded browser) object"},
}

// classifyRTFObject reports an embedded object and anything it reveals.
func classifyRTFObject(o rtfObject, res *Result) {
	loc := "rtf \\objdata at offset " + strconv.Itoa(o.offset)
	info, ok := parseOLE1(o.data)
	class := info.class
	if !ok {
		// Exploit builders often corrupt the OLE1 header; fall back to the
		// class names and markers found anywhere in the object.
		low := strings.ToLower(string(o.data))
		for _, k := range knownObjectClasses {
			if strings.Contains(low, k.prefix) {
				class = k.prefix
				break
			}
		}
	}
	e := ExternalRef{Kind: "embedded_ole", Severity: "medium", Location: loc, Target: class,
		Detail: "embedded OLE object (" + strconv.Itoa(len(o.data)) + " bytes)"}
	if class == "" {
		e.Target = ""
		e.Detail += " with an unreadable or deliberately corrupted OLE1 header"
	} else {
		e.Detail = "embedded OLE object of class " + class + " (" + strconv.Itoa(len(o.data)) + " bytes)"
	}
	lowClass := strings.ToLower(class)
	for _, k := range knownObjectClasses {
		if strings.HasPrefix(lowClass, k.prefix) {
			e.Severity = k.severity
			e.Detail += "; " + k.note
			break
		}
	}
	if info.linked {
		e.Kind, e.Severity = "external_ole", "high"
		e.Detail = "linked OLE object of class " + class + " loaded from " + info.topic
		e.Target = info.topic
	}
	native := info.native
	if native == nil {
		native = o.data
	}
	if strings.HasPrefix(lowClass, "equation.3") {
		if x := mtefExploit(native); x.detail != "" {
			e.Severity = "high"
			e.Detail += "; " + x.detail
			payload := x.payload
			if len(payload) > 1024 {
				payload = payload[:1024]
			}
			defer res.addExternal(ExternalRef{Kind: "equation_editor_exploit", Severity: "high", Location: loc,
				Target: hexString(payload), Detail: x.detail + "; target is the bytes after the malformed record (hex; usually the first-stage shellcode)"})
		}
	}
	if i := bytes.Index(native, cfbMagic); i >= 0 {
		e.Detail += "; contains an OLE compound file"
		if cfb, err := parseCFB(native[i:], &Limits{MaxContainerEntries: 4096, MaxStreams: 4096}); err == nil {
			for _, s := range cfb.listStreams() {
				if strings.EqualFold(leafName(s), "Equation Native") {
					e.Severity = "high"
					e.Detail += " with an \"Equation Native\" stream (Equation Editor exploit carrier)"
				}
			}
		}
	}
	res.addExternal(e)
	for _, u := range append(utf16URLs(o.data), urlText.FindAllString(string(o.data), 16)...) {
		res.addExternal(ExternalRef{Kind: "embedded_url", Severity: "medium", Location: loc, Target: u, Detail: "URL inside the embedded object"})
	}
}
