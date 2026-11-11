package extractor

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// ExternalRef is a reference to content outside the analysed file, found by
// static inspection only (nothing is fetched). Remote template injection,
// linked OLE objects and DDE fields run code without any VBA in the file.
type ExternalRef struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Location string `json:"location"`
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

func (r *Result) addExternal(e ExternalRef) {
	for _, x := range r.External {
		// The same reference repeated elsewhere (e.g. one hyperlink stored
		// in several drawing records) is reported once, at its first location.
		if x.Kind == e.Kind && x.Target == e.Target && (x.Detail == e.Detail || e.Target != "") {
			return
		}
	}
	if len(r.External) < 1024 {
		r.External = append(r.External, e)
	}
}

// zipPart reads one archive member with the size and ratio limits applied.
func zipPart(f *zip.File, lim *Limits) ([]byte, error) {
	if f.UncompressedSize64 > uint64(lim.MaxModuleSize) ||
		(f.CompressedSize64 > 0 && f.CompressedSize64*uint64(lim.MaxZipRatio) < f.UncompressedSize64) {
		return nil, fmt.Errorf("%s exceeds limits", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, lim.MaxModuleSize))
}

// scanOOXML inspects relationship parts, field codes, external links,
// worksheets/macro sheets and document properties of an OOXML package.
func scanOOXML(data []byte, lim *Limits, res *Result) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	parts := map[string]*zip.File{}
	for i, f := range zr.File {
		if i >= lim.MaxContainerEntries {
			break
		}
		parts[strings.ToLower(strings.TrimPrefix(f.Name, "/"))] = f
	}
	read := func(name string) []byte {
		f := parts[strings.ToLower(name)]
		if f == nil {
			return nil
		}
		b, err := zipPart(f, lim)
		if err != nil {
			res.addDiag("info", "ooxml", err.Error())
			return nil
		}
		return b
	}
	for name, f := range parts {
		switch {
		case strings.HasSuffix(name, ".rels"):
			if b, err := zipPart(f, lim); err == nil {
				scanRels(f.Name, b, res)
			}
		case strings.HasPrefix(name, "word/") && strings.HasSuffix(name, ".xml") &&
			(name == "word/document.xml" || strings.HasPrefix(name, "word/header") || strings.HasPrefix(name, "word/footer") ||
				name == "word/footnotes.xml" || name == "word/endnotes.xml"):
			if b, err := zipPart(f, lim); err == nil {
				scanWordFields(f.Name, b, res)
			}
		case strings.HasPrefix(name, "xl/externallinks/") && strings.HasSuffix(name, ".xml"):
			if b, err := zipPart(f, lim); err == nil {
				scanExternalLinkXML(f.Name, b, res)
			}
		}
	}
	if b := read("word/settings.xml"); b != nil {
		readDocVars(b, res)
	}
	images := 0
	for name := range parts {
		if strings.Contains(name, "/media/") {
			switch strings.ToLower(path.Ext(name)) {
			case ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".emf", ".wmf", ".tif", ".tiff":
				images++
			}
		}
	}
	checkQRLure(res.DocumentText, images, res)
	readOOXMLProperties(read, res)
	extractXLSX(read, res)
}

type xmlRels struct {
	Rels []struct {
		ID         string `xml:"Id,attr"`
		Type       string `xml:"Type,attr"`
		Target     string `xml:"Target,attr"`
		TargetMode string `xml:"TargetMode,attr"`
	} `xml:"Relationship"`
}

// scanRels reports external relationships. Only TargetMode="External"
// entries leave the package; hyperlinks are ignored (they need a click).
func scanRels(part string, b []byte, res *Result) {
	var rels xmlRels
	if xml.Unmarshal(b, &rels) != nil {
		return
	}
	for _, rel := range rels.Rels {
		if !strings.EqualFold(rel.TargetMode, "External") {
			continue
		}
		typ := rel.Type[strings.LastIndex(rel.Type, "/")+1:]
		e := ExternalRef{Location: part + "#" + rel.ID, Target: rel.Target, Detail: "relationship type " + typ}
		switch strings.ToLower(typ) {
		case "attachedtemplate":
			e.Kind, e.Severity = "template_injection", "high"
			e.Detail = "remote template loaded when the document opens (attachedTemplate)"
		case "oleobject":
			e.Kind, e.Severity = "external_ole", "high"
			e.Detail = "linked OLE object loaded from outside the file"
		case "frame":
			e.Kind, e.Severity = "external_frame", "high"
			e.Detail = "frameset loads a remote document"
		case "subdocument":
			e.Kind, e.Severity = "external_subdocument", "high"
			e.Detail = "master document loads a remote subdocument"
		case "externallinkpath", "xlexternallinkpath/xlpathmissing":
			e.Kind, e.Severity = "external_link", "medium"
			e.Detail = "workbook link to an external file"
		case "hyperlink":
			e.Kind, e.Severity = "hyperlink", "low"
			e.Detail = "hyperlink (opens when clicked)"
		case "image":
			e.Kind, e.Severity = "external_image", "medium"
			e.Detail = "image fetched from outside the file when rendered (can leak NTLM credentials over UNC/WebDAV)"
		default:
			e.Kind, e.Severity = "external_reference", "low"
		}
		low := strings.ToLower(rel.Target)
		if strings.HasPrefix(low, "mhtml:") || strings.Contains(low, "!x-usc:") {
			e.Severity = "high"
			e.Detail += "; MHTML moniker (MSHTML remote code execution pattern, e.g. CVE-2021-40444)"
		}
		if strings.HasPrefix(low, "ms-msdt:") || strings.Contains(low, "ms-msdt:") {
			e.Severity = "high"
			e.Detail += "; ms-msdt protocol handler (Follina, CVE-2022-30190)"
		}
		res.addExternal(e)
	}
}

// scanWordFields collects field instructions (w:instrText runs between
// fldChar begin/separate, and w:fldSimple) from a WordprocessingML part.
// Nested fields contribute their instruction text to the enclosing one.
func scanWordFields(part string, b []byte, res *Result) {
	type field struct {
		instr strings.Builder
		done  bool
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	var stack []*field
	finish := func(f *field) {
		if f.done {
			return
		}
		f.done = true
		instr := f.instr.String()
		checkField(part, instr, res)
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i] != f && !stack[i].done {
				stack[i].instr.WriteString(instr)
				break
			}
		}
	}
	inInstr := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "fldChar":
				switch attr(t, "fldCharType") {
				case "begin":
					if len(stack) < 64 {
						stack = append(stack, &field{})
					}
				case "separate":
					if n := len(stack); n > 0 {
						finish(stack[n-1])
					}
				case "end":
					if n := len(stack); n > 0 {
						finish(stack[n-1])
						stack = stack[:n-1]
					}
				}
			case "instrText":
				inInstr = true
			case "fldSimple":
				checkField(part, attr(t, "instr"), res)
			}
		case xml.EndElement:
			if t.Name.Local == "instrText" {
				inInstr = false
			}
		case xml.CharData:
			if inInstr && len(stack) > 0 && !stack[len(stack)-1].done {
				stack[len(stack)-1].instr.Write(t)
			}
		}
	}
}

func attr(t xml.StartElement, local string) string {
	for _, a := range t.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

// scanFieldCodes finds field instructions in Word binary text, where a field
// is 0x13 instruction [0x14 result] 0x15.
func scanFieldCodes(text, location string, res *Result) {
	var stack []int
	rs := []rune(text)
	for i, c := range rs {
		switch c {
		case 0x13:
			stack = append(stack, i+1)
		case 0x14, 0x15:
			if n := len(stack); n > 0 {
				start := stack[n-1]
				if c == 0x15 {
					stack = stack[:n-1]
				} else {
					stack[n-1] = len(rs) + 1 // instruction finished; ignore result text
				}
				if start <= i {
					checkField(location, strings.Map(func(r rune) rune {
						if r < 0x20 && r != '\t' {
							return -1
						}
						return r
					}, string(rs[start:i])), res)
				}
			}
		}
	}
}

var quoteField = regexp.MustCompile(`(?i)QUOTE((?:\s+\d{1,5})+)`)

// decodeQuoteFields replaces QUOTE fields made of character codes (an old
// DDE obfuscation: QUOTE 99 109 100 → "cmd") by their text.
func decodeQuoteFields(s string) string {
	return quoteField.ReplaceAllStringFunc(s, func(m string) string {
		var b strings.Builder
		for _, f := range strings.Fields(m)[1:] {
			if n, err := strconv.Atoi(f); err == nil && n > 0 && n < 0x110000 {
				b.WriteRune(rune(n))
			}
		}
		return b.String()
	})
}

// checkField classifies one field instruction.
func checkField(location, instr string, res *Result) {
	instr = strings.TrimSpace(instr)
	if instr == "" {
		return
	}
	decoded := decodeQuoteFields(instr)
	fields := strings.Fields(decoded)
	if len(fields) == 0 {
		return
	}
	switch strings.ToUpper(fields[0]) {
	case "DDE", "DDEAUTO":
		detail := "DDE field: launches an application when the field updates"
		if strings.EqualFold(fields[0], "DDEAUTO") {
			detail = "DDEAUTO field: launches an application automatically when the document opens"
		}
		if decoded != instr {
			detail += "; decoded from QUOTE character codes"
		}
		res.addExternal(ExternalRef{Kind: "dde", Severity: "high", Location: location, Target: decoded, Detail: detail})
	case "INCLUDEPICTURE", "INCLUDETEXT", "LINK", "IMPORT":
		target := ""
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, `\`) {
				target = strings.Trim(f, `"`)
				break
			}
		}
		low := strings.ToLower(target)
		if strings.Contains(low, "://") || strings.HasPrefix(low, `\\`) || strings.HasPrefix(low, "//") {
			sev := "medium"
			if strings.EqualFold(fields[0], "LINK") {
				sev = "high"
			}
			res.addExternal(ExternalRef{Kind: "external_field", Severity: sev, Location: location, Target: target,
				Detail: strings.ToUpper(fields[0]) + " field fetches remote content when updated"})
		}
	}
}

var qrLure = regexp.MustCompile(`(?i)\b(scan|escane(ie)?|escaneie|digitalize)\b[^.\r\n]{0,40}\bQR\b|\bQR[ -]?code\b`)

// checkQRLure flags documents whose text asks the reader to scan a QR code
// while embedding images: the destination URL lives in the image, so the
// file carries no macro, link or field ("quishing").
func checkQRLure(text string, images int, res *Result) {
	if images == 0 || text == "" {
		return
	}
	if m := qrLure.FindString(text); m != "" {
		res.addExternal(ExternalRef{Kind: "qr_code_lure", Severity: "medium", Location: "document text",
			Target: strings.TrimSpace(m),
			Detail: fmt.Sprintf("text asks the reader to scan a QR code and the file embeds %d image(s); the destination URL is inside the image and is not decoded", images)})
	}
}

// scanExternalLinkXML reports DDE links stored in xl/externalLinks.
func scanExternalLinkXML(part string, b []byte, res *Result) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		if t, ok := tok.(xml.StartElement); ok && t.Name.Local == "ddeLink" {
			svc, topic := attr(t, "ddeService"), attr(t, "ddeTopic")
			res.addExternal(ExternalRef{Kind: "dde", Severity: "high", Location: part, Target: svc + "|" + topic,
				Detail: "Excel DDE link: starts " + svc + " with topic " + strconv.Quote(topic)})
		}
	}
}

// ddeFormula matches Excel DDE formulas such as =cmd|' /c calc'!A0.
var ddeFormula = regexp.MustCompile(`(?i)(?:^|[=+\-@(,&])\s*([A-Za-z0-9_.]+)\s*\|\s*'([^']*)'\s*!\s*'?([^'\s,)]*)`)

// checkFormulaDDE reports cell formulas that invoke DDE.
func checkFormulaDDE(location, formula string, res *Result) {
	if m := ddeFormula.FindStringSubmatch(formula); m != nil {
		res.addExternal(ExternalRef{Kind: "dde", Severity: "high", Location: location, Target: m[1] + "|" + m[2] + "!" + m[3],
			Detail: "cell formula launches " + m[1] + " through DDE"})
	}
}

// RTF control words of interest.
var (
	rtfTemplate = regexp.MustCompile(`\{\\\*\\template\s+([^}]*)\}`)
	rtfObjClass = regexp.MustCompile(`\{\\\*\\objclass\s+([^}]*)\}`)
	rtfObjLink  = regexp.MustCompile(`\\objautlink|\\objlink`)
	rtfField    = regexp.MustCompile(`\{\\\*\\fldinst\s*((?:[^{}]|\{[^{}]*\})*)\}`)
)

// scanRTF inspects an RTF document for remote templates, embedded or linked
// OLE objects and field instructions.
func scanRTF(data []byte, res *Result) {
	s := string(data)
	for _, m := range rtfTemplate.FindAllStringSubmatch(s, 64) {
		res.addExternal(ExternalRef{Kind: "template_injection", Severity: "high", Location: "rtf", Target: rtfText(m[1]),
			Detail: `RTF \*\template: remote template loaded when the document opens`})
	}
	for _, m := range rtfObjClass.FindAllStringSubmatch(s, 64) {
		class := strings.TrimSpace(rtfText(m[1]))
		e := ExternalRef{Kind: "embedded_ole", Severity: "medium", Location: "rtf", Target: class, Detail: "embedded OLE object of class " + class}
		switch low := strings.ToLower(class); {
		case strings.HasPrefix(low, "equation.3"):
			e.Severity = "high"
			e.Detail += " (Equation Editor; exploited by CVE-2017-11882 / CVE-2018-0802)"
		case strings.HasPrefix(low, "package"):
			e.Severity = "high"
			e.Detail += " (OLE Package: embeds a file the user can run)"
		case strings.HasPrefix(low, "htmlfile"), strings.HasPrefix(low, "word.document"), strings.HasPrefix(low, "excel.sheet"):
			e.Severity = "high"
		}
		res.addExternal(e)
	}
	if loc := rtfObjLink.FindStringIndex(s); loc != nil {
		res.addExternal(ExternalRef{Kind: "ole_link", Severity: "medium", Location: "rtf offset " + strconv.Itoa(loc[0]),
			Detail: `object declared as a link (\objautlink/\objlink): Word refreshes it from its source`})
	}
	if i := indexControlWord(data, 0, "objupdate"); i >= 0 {
		res.addExternal(ExternalRef{Kind: "ole_autoupdate", Severity: "medium", Location: "rtf offset " + strconv.Itoa(i),
			Detail: `\objupdate makes Word load the object when the document opens, without user interaction`})
	}
	for _, m := range rtfField.FindAllStringSubmatch(s, 256) {
		checkField("rtf", rtfText(m[1]), res)
	}
	for _, o := range rtfObjData(data, 64) {
		classifyRTFObject(o, res)
	}
	if len(res.External) == 0 {
		res.addDiag("info", "rtf", "no embedded objects, remote templates or fields found")
	}
}

// rtfText strips RTF control words and groups from a short text value.
func rtfText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '{', '}', '\r', '\n':
			continue
		case '\\':
			if i+1 < len(s) && strings.ContainsRune(`\{}`, rune(s[i+1])) {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			if i+1 < len(s) && s[i+1] == '\'' && i+3 < len(s) {
				if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(n))
					i += 3
					continue
				}
			}
			j := i + 1
			for j < len(s) && (s[j] >= 'a' && s[j] <= 'z' || s[j] == '-' || s[j] >= '0' && s[j] <= '9' || s[j] == '*') {
				j++
			}
			if j < len(s) && s[j] == ' ' {
				j++
			}
			i = j - 1
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// relTarget resolves a relationship target against the part that owns it.
func relTarget(base, target string) string {
	if strings.HasPrefix(target, "/") {
		return strings.TrimPrefix(target, "/")
	}
	return path.Clean(path.Join(path.Dir(base), target))
}
