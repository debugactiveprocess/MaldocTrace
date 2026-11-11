package extractor

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"strconv"
	"strings"
	"unicode/utf16"
)

// DocProperty is a document property or variable. Droppers hide payloads in
// Comments, custom properties or document variables and read them back with
// BuiltInDocumentProperties("Comments"), CustomDocumentProperties("x") or
// ActiveDocument.Variables("x").
type DocProperty struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Kind   string `json:"kind"` // builtin | custom | variable
	Source string `json:"source"`
}

func (r *Result) addProperty(p DocProperty) {
	if p.Value == "" || len(r.Properties) >= 4096 {
		return
	}
	r.Properties = append(r.Properties, p)
}

// Property IDs of the SummaryInformation and DocumentSummaryInformation sets,
// named as VBA's BuiltInDocumentProperties names them.
var summaryNames = map[uint32]string{
	2: "Title", 3: "Subject", 4: "Author", 5: "Keywords", 6: "Comments",
	7: "Template", 8: "Last Author", 9: "Revision Number", 18: "Application Name",
}
var docSummaryNames = map[uint32]string{2: "Category", 14: "Manager", 15: "Company", 26: "Content Type", 27: "Content Status"}

// readOLEProperties parses the \x05SummaryInformation and
// \x05DocumentSummaryInformation property set streams ([MS-OLEPS]).
func readOLEProperties(cfb *cfbReader, res *Result) {
	if b, err := cfb.readStream("\x05SummaryInformation"); err == nil {
		for i, set := range parsePropertySets(b) {
			if i == 0 {
				for id, v := range set.values {
					if n := summaryNames[id]; n != "" {
						res.addProperty(DocProperty{Name: n, Value: v, Kind: "builtin", Source: "SummaryInformation"})
					}
				}
			}
		}
	}
	if b, err := cfb.readStream("\x05DocumentSummaryInformation"); err == nil {
		for i, set := range parsePropertySets(b) {
			for id, v := range set.values {
				if i == 0 {
					if n := docSummaryNames[id]; n != "" {
						res.addProperty(DocProperty{Name: n, Value: v, Kind: "builtin", Source: "DocumentSummaryInformation"})
					}
				} else if n := set.names[id]; n != "" {
					res.addProperty(DocProperty{Name: n, Value: v, Kind: "custom", Source: "DocumentSummaryInformation"})
				}
			}
		}
	}
}

type propertySet struct {
	values map[uint32]string
	names  map[uint32]string // user-defined property names (dictionary)
}

// parsePropertySets decodes string, integer and boolean properties of every
// property set in a property set stream. Malformed input yields what was
// decoded so far.
func parsePropertySets(b []byte) []propertySet {
	if len(b) < 28 || binary.LittleEndian.Uint16(b) != 0xFFFE {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b[24:]))
	if n > 4 {
		n = 4
	}
	var out []propertySet
	for i := 0; i < n; i++ {
		hdr := 28 + i*20
		if hdr+20 > len(b) {
			break
		}
		off := int(binary.LittleEndian.Uint32(b[hdr+16:]))
		if off < 0 || off+8 > len(b) {
			break
		}
		out = append(out, parsePropertySet(b[off:]))
	}
	return out
}

func parsePropertySet(b []byte) propertySet {
	set := propertySet{values: map[uint32]string{}, names: map[uint32]string{}}
	size := int(binary.LittleEndian.Uint32(b))
	if size > len(b) || size < 8 {
		size = len(b)
	}
	b = b[:size]
	count := int(binary.LittleEndian.Uint32(b[4:]))
	if count > 1024 {
		count = 1024
	}
	codepage := uint16(1252)
	type entry struct{ id, off uint32 }
	var entries []entry
	for i := 0; i < count; i++ {
		p := 8 + i*8
		if p+8 > len(b) {
			break
		}
		e := entry{binary.LittleEndian.Uint32(b[p:]), binary.LittleEndian.Uint32(b[p+4:])}
		entries = append(entries, e)
		if e.id == 1 && int(e.off)+6 <= len(b) && binary.LittleEndian.Uint16(b[e.off:]) == 2 {
			codepage = binary.LittleEndian.Uint16(b[e.off+4:])
		}
	}
	for _, e := range entries {
		off := int(e.off)
		if off+4 > len(b) || off < 0 {
			continue
		}
		if e.id == 0 { // dictionary of user-defined names
			parseDictionary(b[off:], codepage, set.names)
			continue
		}
		if e.id == 1 {
			continue
		}
		if v, ok := propertyValue(b[off:], codepage); ok {
			set.values[e.id] = v
		}
	}
	return set
}

func propertyValue(b []byte, cp uint16) (string, bool) {
	typ := binary.LittleEndian.Uint16(b)
	d := b[4:]
	switch typ {
	case 0x1E: // VT_LPSTR
		if len(d) < 4 {
			return "", false
		}
		n := int(binary.LittleEndian.Uint32(d))
		if n < 0 || n > len(d)-4 {
			return "", false
		}
		s := d[4 : 4+n]
		if cp == 1200 {
			return utf16String(s), true
		}
		return strings.TrimRight(decodeCodepage(cp, s), "\x00"), true
	case 0x1F: // VT_LPWSTR
		if len(d) < 4 {
			return "", false
		}
		n := int(binary.LittleEndian.Uint32(d))
		if n < 0 || n*2 > len(d)-4 {
			return "", false
		}
		return utf16String(d[4 : 4+n*2]), true
	case 0x03: // VT_I4
		if len(d) >= 4 {
			return strconv.Itoa(int(int32(binary.LittleEndian.Uint32(d)))), true
		}
	case 0x02: // VT_I2
		if len(d) >= 2 {
			return strconv.Itoa(int(int16(binary.LittleEndian.Uint16(d)))), true
		}
	case 0x0B: // VT_BOOL
		if len(d) >= 2 {
			return strconv.FormatBool(binary.LittleEndian.Uint16(d) != 0), true
		}
	}
	return "", false
}

func parseDictionary(b []byte, cp uint16, names map[uint32]string) {
	if len(b) < 4 {
		return
	}
	n := int(binary.LittleEndian.Uint32(b))
	p := 4
	for i := 0; i < n && i < 1024; i++ {
		if p+8 > len(b) {
			return
		}
		id := binary.LittleEndian.Uint32(b[p:])
		l := int(binary.LittleEndian.Uint32(b[p+4:]))
		p += 8
		if cp == 1200 {
			if l < 0 || p+l*2 > len(b) {
				return
			}
			names[id] = utf16String(b[p : p+l*2])
			p += l * 2
			p += (4 - p%4) % 4
		} else {
			if l < 0 || p+l > len(b) {
				return
			}
			names[id] = strings.TrimRight(decodeCodepage(cp, b[p:p+l]), "\x00")
			p += l
		}
	}
}

func utf16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// readOOXMLProperties reads docProps/core.xml, app.xml and custom.xml.
func readOOXMLProperties(read func(string) []byte, res *Result) {
	coreNames := map[string]string{
		"title": "Title", "subject": "Subject", "creator": "Author", "keywords": "Keywords",
		"description": "Comments", "lastModifiedBy": "Last Author", "revision": "Revision Number",
		"category": "Category", "contentStatus": "Content Status",
	}
	appNames := map[string]string{"Company": "Company", "Manager": "Manager", "Template": "Template", "Application": "Application Name"}
	simple := func(part string, names map[string]string) {
		b := read(part)
		if b == nil {
			return
		}
		dec := xml.NewDecoder(bytes.NewReader(b))
		cur := ""
		for {
			tok, err := dec.Token()
			if err != nil {
				return
			}
			switch t := tok.(type) {
			case xml.StartElement:
				cur = names[t.Name.Local]
			case xml.EndElement:
				cur = ""
			case xml.CharData:
				if cur != "" {
					res.addProperty(DocProperty{Name: cur, Value: string(t), Kind: "builtin", Source: part})
				}
			}
		}
	}
	simple("docProps/core.xml", coreNames)
	simple("docProps/app.xml", appNames)
	if b := read("docProps/custom.xml"); b != nil {
		dec := xml.NewDecoder(bytes.NewReader(b))
		name, depth := "", 0
		var val strings.Builder
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "property" {
					name, depth = attr(t, "name"), 1
					val.Reset()
				} else if depth > 0 {
					depth++
				}
			case xml.EndElement:
				if t.Name.Local == "property" {
					res.addProperty(DocProperty{Name: name, Value: val.String(), Kind: "custom", Source: "docProps/custom.xml"})
					depth = 0
				} else if depth > 0 {
					depth--
				}
			case xml.CharData:
				if depth > 1 {
					val.Write(t)
				}
			}
		}
	}
}

// readDocVars reads document variables (w:docVars) from word/settings.xml.
func readDocVars(b []byte, res *Result) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		if t, ok := tok.(xml.StartElement); ok && t.Name.Local == "docVar" {
			res.addProperty(DocProperty{Name: attr(t, "name"), Value: attr(t, "val"), Kind: "variable", Source: "word/settings.xml"})
		}
	}
}
