package extractor

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Evasive Word formats that Word opens like a .doc/.docm but that many
// scanners do not unpack:
//   - Word 2003 XML (w:wordDocument): the VBA project is the base64
//     w:binData named editdata.mso, an ActiveMime blob;
//   - Flat OPC (pkg:package): every OOXML part inline, binary parts such as
//     vbaProject.bin as base64 pkg:binaryData;
//   - MHT/MHTML: a MIME document whose ActiveMime part carries the VBA.
// ActiveMime is a small header followed by a zlib stream holding the CFB
// VBA project.

var activeMimeB64 = []byte("QWN0aXZlTWltZQ") // base64("ActiveMime")

// detectEvasive classifies the text-based Word formats.
func detectEvasive(data []byte) Format {
	head := data
	if len(head) > 64<<10 {
		head = head[:64<<10]
	}
	low := bytes.ToLower(head)
	switch {
	case isSYLK(data):
		return FormatSYLK
	case isIQY(data):
		return FormatIQY
	case bytes.Contains(low, []byte("<pkg:package")):
		return FormatFlatOPC
	case bytes.Contains(low, []byte("<w:worddocument")):
		return FormatWordXML
	case bytes.Contains(data, activeMimeB64):
		return FormatMHT
	case bytes.Contains(low, []byte("multipart/related")) && (bytes.Contains(low, []byte("urn:schemas-microsoft-com:office:word")) ||
		bytes.Contains(low, []byte("editdata.mso"))):
		// A Word document saved as a web page (an HTML email with inline
		// images is multipart/related too, without the Word namespace).
		return FormatMHT
	case isDDECSV(head):
		return FormatCSV
	}
	return FormatUnknown
}

// DecodeActiveMime returns the CFB inside an ActiveMime blob.
func DecodeActiveMime(b []byte) ([]byte, error) {
	if !bytes.HasPrefix(b, []byte("ActiveMime")) {
		return nil, fmt.Errorf("not an ActiveMime blob")
	}
	var offsets []int
	if len(b) >= 0x20 {
		offsets = append(offsets, int(binary.LittleEndian.Uint16(b[0x1E:]))+46)
	}
	offsets = append(offsets, 0x32, 0x22A)
	try := func(off int) []byte {
		if off <= 0 || off >= len(b) {
			return nil
		}
		zr, err := zlib.NewReader(bytes.NewReader(b[off:]))
		if err != nil {
			return nil
		}
		out, err := io.ReadAll(io.LimitReader(zr, 64<<20))
		if len(out) == 0 || (err != nil && !bytes.HasPrefix(out, cfbMagic)) {
			return nil
		}
		return out
	}
	for _, off := range offsets {
		if out := try(off); out != nil {
			return out, nil
		}
	}
	for off := 0; off < len(b) && off < 4096; off++ {
		if b[off] == 0x78 {
			if out := try(off); out != nil {
				return out, nil
			}
		}
	}
	return nil, fmt.Errorf("no zlib stream found in the ActiveMime blob")
}

// base64Runs decodes the base64 text that starts at each marker occurrence.
func base64Runs(data, marker []byte, max int) [][]byte {
	var out [][]byte
	for from := 0; len(out) < max; {
		i := bytes.Index(data[from:], marker)
		if i < 0 {
			break
		}
		start := from + i
		var clean []byte
	scan:
		for j := start; j < len(data); j++ {
			switch c := data[j]; {
			case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/':
				clean = append(clean, c)
			case c == '\r' || c == '\n' || c == ' ' || c == '\t':
			default:
				break scan
			}
		}
		from = start + len(marker)
		if len(clean)%4 == 1 {
			clean = clean[:len(clean)-1]
		}
		dec, _ := base64.RawStdEncoding.DecodeString(string(clean))
		if len(dec) > 0 {
			out = append(out, dec)
		}
	}
	return out
}

// extractActiveMimeProjects decodes every ActiveMime blob found as base64
// text (or raw) in data and extracts its VBA project.
func extractActiveMimeProjects(ctx context.Context, data []byte, where string, lim *Limits, res *Result) int {
	blobs := base64Runs(data, activeMimeB64, 16)
	if i := bytes.Index(data, []byte("ActiveMime")); i >= 0 {
		blobs = append(blobs, data[i:])
	}
	seen := map[[32]byte]bool{}
	n := 0
	for _, b := range blobs {
		cfb, err := DecodeActiveMime(b)
		if err != nil {
			res.addDiag("info", "activemime", err.Error())
			continue
		}
		sum := sha256.Sum256(cfb)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		n++
		if err := extractFromCFB(ctx, cfb, where+" (ActiveMime)", lim, res); err != nil {
			res.addDiag("warning", "activemime", err.Error())
		}
	}
	return n
}

var w2003Template = []byte("attachedTemplate")

// extractWordXML handles a Word 2003 XML document.
func extractWordXML(ctx context.Context, data []byte, lim *Limits, res *Result) error {
	if text, err := wordXMLText(bytes.NewReader(data)); err == nil {
		res.DocumentText = text
	}
	scanWordFields("w:wordDocument", data, res)
	readDocVars(data, res)
	// <w:attachedTemplate w:val="..."/>
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if t, ok := tok.(xml.StartElement); ok && t.Name.Local == string(w2003Template) {
			if v := attr(t, "val"); isRemotePath(v) {
				res.addExternal(ExternalRef{Kind: "template_injection", Severity: "high", Location: "w:attachedTemplate", Target: v,
					Detail: "remote template loaded when the Word 2003 XML document opens"})
			}
		}
	}
	n := extractActiveMimeProjects(ctx, data, "w:binData editdata.mso", lim, res)
	res.addCheck(fmt.Sprintf("Word 2003 XML: fields, attached template, document variables, ActiveMime VBA (%d)", n))
	return nil
}

// extractMHT handles an MHT/MHTML document.
func extractMHT(ctx context.Context, data []byte, lim *Limits, res *Result) error {
	n := 0
	if e, err := ParseEML(data); err == nil {
		for _, a := range e.Attachments {
			if bytes.HasPrefix(a.Data, []byte("ActiveMime")) {
				n += extractActiveMimeProjects(ctx, a.Data, "MHT part "+a.Name, lim, res)
			}
		}
		for _, b := range e.Bodies {
			if text := htmlText(b); text != "" && res.DocumentText == "" {
				res.DocumentText = text
			}
		}
	}
	if n == 0 {
		n = extractActiveMimeProjects(ctx, data, "MHT", lim, res)
	}
	res.addCheck(fmt.Sprintf("MHT parts and ActiveMime VBA (%d)", n))
	return nil
}

// htmlText strips tags from an HTML body (good enough for macros that read
// the document text).
func htmlText(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// flatOPCPart is one pkg:part of a Flat OPC document.
type flatOPCPart struct {
	Name string `xml:"name,attr"`
	XML  struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"xmlData"`
	Binary string `xml:"binaryData"`
}

// extractFlatOPC rebuilds the OOXML package of a Flat OPC document in
// memory and analyses it like a .docx/.docm.
func extractFlatOPC(ctx context.Context, data []byte, lim *Limits, res *Result) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := 0
	total := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		t, ok := tok.(xml.StartElement)
		if !ok || t.Name.Local != "part" {
			continue
		}
		var p flatOPCPart
		if err := dec.DecodeElement(&p, &t); err != nil {
			res.addDiag("warning", "flatopc", err.Error())
			break
		}
		name := strings.TrimPrefix(p.Name, "/")
		if name == "" {
			continue
		}
		var body []byte
		if p.Binary != "" {
			clean := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
					return -1
				}
				return r
			}, p.Binary)
			b, err := base64.StdEncoding.DecodeString(clean)
			if err != nil {
				res.addDiag("warning", "flatopc", name+": "+err.Error())
				continue
			}
			body = b
		} else {
			body = append([]byte(xml.Header), bytes.TrimSpace(p.XML.Inner)...)
		}
		total += len(body)
		if int64(total) > lim.MaxInputSize || parts >= lim.MaxContainerEntries {
			res.LimitsHit = append(res.LimitsHit, "MaxInputSize")
			res.addDiag("warning", "flatopc", "package too large; the rest was not read")
			break
		}
		w, err := zw.Create(name)
		if err != nil {
			continue
		}
		w.Write(body)
		parts++
	}
	if err := zw.Close(); err != nil {
		return err
	}
	res.addCheck(fmt.Sprintf("Flat OPC package rebuilt in memory (%d parts)", parts))
	if parts == 0 {
		return nil
	}
	return extractOOXML(ctx, buf.Bytes(), lim, res)
}
