package extractor

import (
	"bytes"
	"encoding/xml"
	"strconv"
	"strings"
)

// Sheet is an Excel worksheet or Excel 4.0 macro sheet. Cells keep the
// cached value and, for formula cells, the formula text in A1 notation
// (starting with "=").
type Sheet struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`       // worksheet | macrosheet | chart | vbmodule | dialog
	Visibility string `json:"visibility"` // visible | hidden | very_hidden
	Source     string `json:"source"`
	Cells      []Cell `json:"cells,omitempty"`
}

// Cell is one non-empty cell. Row and Col are 0-based.
type Cell struct {
	Row       int    `json:"row"`
	Col       int    `json:"col"`
	Value     string `json:"value,omitempty"`
	ValueKind string `json:"value_kind,omitempty"` // string | number | bool | error
	Formula   string `json:"formula,omitempty"`
	// Undecoded marks a binary formula that could not be fully decompiled.
	Undecoded bool `json:"undecoded,omitempty"`
}

// DefinedName is a workbook name. Excel runs a name starting with
// "Auto_Open" (any case, any suffix) when the workbook opens.
type DefinedName struct {
	Name    string `json:"name"`
	Builtin bool   `json:"builtin,omitempty"`
	Formula string `json:"formula"`
	Hidden  bool   `json:"hidden,omitempty"`
}

// maxCells bounds the cells kept per workbook.
const maxCells = 1 << 20

func (r *Result) cellBudget() int {
	n := 0
	for _, s := range r.Sheets {
		n += len(s.Cells)
	}
	return maxCells - n
}

// ColName converts a 0-based column index to letters (0 → A, 26 → AA).
func ColName(c int) string {
	s := ""
	for c >= 0 {
		s = string(rune('A'+c%26)) + s
		c = c/26 - 1
	}
	return s
}

// CellName formats a 0-based cell position in A1 notation.
func CellName(row, col int) string { return ColName(col) + strconv.Itoa(row+1) }

// ParseCellRef parses an A1 reference ("$B$12", "b12") into 0-based
// coordinates. It also accepts R1C1 ("R12C2").
func ParseCellRef(s string) (row, col int, ok bool) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "$", ""))
	if len(s) >= 4 && s[0] == 'R' {
		if i := strings.IndexByte(s, 'C'); i > 1 {
			r, err1 := strconv.Atoi(s[1:i])
			c, err2 := strconv.Atoi(s[i+1:])
			if err1 == nil && err2 == nil && r > 0 && c > 0 {
				return r - 1, c - 1, true
			}
		}
	}
	i := 0
	for i < len(s) && s[i] >= 'A' && s[i] <= 'Z' {
		col = col*26 + int(s[i]-'A'+1)
		i++
	}
	if i == 0 || i > 3 || i == len(s) {
		return 0, 0, false
	}
	r, err := strconv.Atoi(s[i:])
	if err != nil || r < 1 || r > 1048576 {
		return 0, 0, false
	}
	return r - 1, col - 1, true
}

// extractXLSX reads sheets, macro sheets and defined names of an OOXML
// workbook (xl/workbook.xml and its relationships).
func extractXLSX(read func(string) []byte, res *Result) {
	wb := read("xl/workbook.xml")
	if wb == nil {
		return
	}
	targets := map[string][2]string{} // rId -> (part, type)
	if b := read("xl/_rels/workbook.xml.rels"); b != nil {
		var rels xmlRels
		if xml.Unmarshal(b, &rels) == nil {
			for _, r := range rels.Rels {
				typ := strings.ToLower(r.Type[strings.LastIndex(r.Type, "/")+1:])
				targets[r.ID] = [2]string{relTarget("xl/workbook.xml", r.Target), typ}
			}
		}
	}
	var shared []string
	if b := read("xl/sharedStrings.xml"); b != nil {
		shared = readSharedStrings(b)
	}
	dec := xml.NewDecoder(bytes.NewReader(wb))
	var names []DefinedName
	var cur *DefinedName
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "sheet":
				state := attr(t, "state")
				vis := "visible"
				switch state {
				case "hidden":
					vis = "hidden"
				case "veryHidden":
					vis = "very_hidden"
				}
				tgt := targets[attr(t, "id")]
				kind := "worksheet"
				switch {
				case strings.Contains(tgt[1], "macrosheet"):
					kind = "macrosheet"
				case strings.Contains(tgt[1], "chartsheet"):
					kind = "chart"
				case strings.Contains(tgt[1], "dialogsheet"):
					kind = "dialog"
				}
				sh := &Sheet{Name: attr(t, "name"), Kind: kind, Visibility: vis, Source: tgt[0]}
				if tgt[0] != "" {
					if b := read(tgt[0]); b != nil {
						readSheetXML(b, shared, sh, res)
					}
				}
				res.Sheets = append(res.Sheets, sh)
			case "definedName":
				cur = &DefinedName{Name: strings.TrimPrefix(attr(t, "name"), "_xlnm."), Hidden: attr(t, "hidden") == "1"}
				cur.Builtin = strings.HasPrefix(attr(t, "name"), "_xlnm.")
			}
		case xml.CharData:
			if cur != nil {
				cur.Formula += string(t)
			}
		case xml.EndElement:
			if t.Name.Local == "definedName" && cur != nil {
				cur.Formula = "=" + strings.TrimPrefix(cur.Formula, "=")
				names = append(names, *cur)
				cur = nil
			}
		}
	}
	res.Names = append(res.Names, names...)
	if read("xl/workbook.bin") != nil {
		res.addDiag("warning", "xlsb", "binary workbook (.xlsb) sheets are not parsed")
	}
}

func readSharedStrings(b []byte) []string {
	dec := xml.NewDecoder(bytes.NewReader(b))
	var out []string
	var cur strings.Builder
	inSI, inT, inRPh := false, false, false
	for len(out) < maxCells {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "si":
				inSI = true
				cur.Reset()
			case "t":
				inT = true
			case "rPh":
				inRPh = true
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "si":
				out = append(out, cur.String())
				inSI = false
			case "t":
				inT = false
			case "rPh":
				inRPh = false
			}
		case xml.CharData:
			if inSI && inT && !inRPh {
				cur.Write(t)
			}
		}
	}
	return out
}

func readSheetXML(b []byte, shared []string, sh *Sheet, res *Result) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	budget := res.cellBudget()
	var c *Cell
	typ, field := "", ""
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "c":
				row, col, ok := ParseCellRef(attr(t, "r"))
				if !ok {
					c = nil
					continue
				}
				c = &Cell{Row: row, Col: col}
				typ = attr(t, "t")
			case "f", "v", "t":
				field = t.Name.Local
			}
		case xml.CharData:
			if c == nil {
				continue
			}
			switch field {
			case "f":
				c.Formula += string(t)
			case "v", "t":
				c.Value += string(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "f", "v", "t":
				field = ""
			case "c":
				if c == nil {
					continue
				}
				switch typ {
				case "s":
					if i, err := strconv.Atoi(c.Value); err == nil && i >= 0 && i < len(shared) {
						c.Value = shared[i]
					}
					c.ValueKind = "string"
				case "str", "inlineStr":
					c.ValueKind = "string"
				case "b":
					c.ValueKind = "bool"
				case "e":
					c.ValueKind = "error"
				default:
					if c.Value != "" {
						c.ValueKind = "number"
					}
				}
				if c.Formula != "" {
					c.Formula = "=" + c.Formula
					checkFormulaDDE(sh.Source+"!"+CellName(c.Row, c.Col), c.Formula, res)
				}
				if (c.Value != "" || c.Formula != "") && len(sh.Cells) < budget {
					sh.Cells = append(sh.Cells, *c)
				}
				c = nil
			}
		}
	}
}
