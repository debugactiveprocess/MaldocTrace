package extractor

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Text spreadsheet formats Excel opens without the protections of a
// workbook:
//   - SYLK (.slk, "ID;P"): C records carry cell values (K) and formulas (E,
//     R1C1 notation); "O;E" makes the file an Excel 4.0 macro sheet and an
//     NN record can name a cell Auto_Open. The cells are rebuilt and go
//     through the existing XLM checks and emulation.
//   - IQY web queries ("WEB", version, URL): Excel fetches the URL and
//     renders it as a sheet (often carrying a DDE payload).
//   - CSV whose cells are DDE formulas (=cmd|' /c ...'!A0).

// sylkSheetName is the name Excel gives the single sheet of a SYLK file
// opened as a macro sheet.
const sylkSheetName = "Macro1"

// textTrim is what precedes the first line of a text format: a byte order
// mark and blank characters.
var textTrim = string(rune(0xFEFF)) + " \t\r\n"

func isSYLK(data []byte) bool { return bytes.HasPrefix(data, []byte("ID;")) }

func isIQY(data []byte) bool {
	lines := strings.SplitN(strings.TrimLeft(string(data[:min(len(data), 4096)]), textTrim), "\n", 4)
	if len(lines) < 3 || !strings.EqualFold(strings.TrimSpace(lines[0]), "WEB") {
		return false
	}
	return strings.Contains(strings.ToLower(lines[2]), "://") || strings.Contains(strings.ToLower(lines[1]), "://")
}

func isDDECSV(data []byte) bool {
	low := bytes.ToLower(data)
	if bytes.Contains(low, []byte("sub ")) || bytes.Contains(low, []byte("function ")) || bytes.Contains(low, []byte("dim ")) {
		return false
	}
	return ddeFormula.Match(data) && (bytes.Count(data, []byte(",")) > 0 || bytes.Count(data, []byte(";")) > 0 || bytes.Count(data, []byte("\t")) > 0)
}

// sylkFields splits a SYLK record on ";", where ";;" is a literal ";".
func sylkFields(line string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] == ';' {
			if i+1 < len(line) && line[i+1] == ';' {
				cur.WriteByte(';')
				i++
				continue
			}
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(line[i])
	}
	return append(out, cur.String())
}

// extractSYLK rebuilds the cells and names of a SYLK file.
func extractSYLK(data []byte, lim *Limits, res *Result) error {
	sheet := &Sheet{Name: sylkSheetName, Kind: "worksheet", Visibility: "visible", Source: "SYLK"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	row, col := 0, 0
	macro, full := false, false
	for sc.Scan() {
		f := sylkFields(strings.TrimRight(sc.Text(), "\r"))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "O":
			for _, o := range f[1:] {
				if o == "E" {
					macro = true
				}
			}
		case "NN":
			var name, expr string
			for _, x := range f[1:] {
				if len(x) > 0 && x[0] == 'N' {
					name = x[1:]
				}
				if len(x) > 0 && x[0] == 'E' {
					expr = x[1:]
				}
			}
			if name != "" {
				if !strings.Contains(expr, "!") {
					expr = sylkSheetName + "!" + expr
				}
				res.Names = append(res.Names, DefinedName{Name: name, Formula: expr})
			}
		case "C", "F":
			cell := Cell{}
			has := false
			for _, x := range f[1:] {
				if x == "" {
					continue
				}
				switch x[0] {
				case 'X':
					if n, err := strconv.Atoi(x[1:]); err == nil && n > 0 && n <= 16384 {
						col = n - 1
					}
				case 'Y':
					if n, err := strconv.Atoi(x[1:]); err == nil && n > 0 && n <= 1048576 {
						row = n - 1
					}
				case 'K':
					if f[0] == "C" {
						cell.Value = strings.Trim(x[1:], `"`)
						has = true
					}
				case 'E':
					if f[0] == "C" {
						cell.Formula = "=" + strings.TrimPrefix(x[1:], "=")
						has = true
					}
				}
			}
			if has && f[0] == "C" && !full {
				if len(sheet.Cells) >= lim.MaxContainerEntries {
					full = true
					res.LimitsHit = append(res.LimitsHit, "MaxCells")
					res.addDiag("warning", "sylk", "too many cells; the rest were not read")
					continue
				}
				cell.Row, cell.Col = row, col
				sheet.Cells = append(sheet.Cells, cell)
				if cell.Formula != "" {
					checkFormulaDDE("SYLK "+CellName(row, col), cell.Formula, res)
					if xlmCommand(cell.Formula) {
						macro = true
					}
				}
			}
		}
	}
	if macro {
		sheet.Kind = "macrosheet"
	}
	res.Sheets = append(res.Sheets, sheet)
	res.addCheck(fmt.Sprintf("SYLK cells (%d) and names (%d): Excel 4.0 macros and DDE formulas", len(sheet.Cells), len(res.Names)))
	return nil
}

// xlmCommand reports formulas that only make sense on a macro sheet.
func xlmCommand(f string) bool {
	up := strings.ToUpper(f)
	for _, k := range []string{"EXEC(", "CALL(", "REGISTER(", "RUN(", "HALT(", "FORMULA(", "GOTO(", "FOPEN(", "URLDOWNLOADTOFILE"} {
		if strings.Contains(up, k) {
			return true
		}
	}
	return false
}

// extractIQY reports the URL of an Excel web query.
func extractIQY(data []byte, res *Result) error {
	lines := strings.Split(strings.ReplaceAll(strings.TrimLeft(string(data), textTrim), "\r", ""), "\n")
	for _, l := range lines[1:min(len(lines), 6)] {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "://") {
			res.addExternal(ExternalRef{Kind: "external_web_query", Severity: "high", Location: "IQY", Target: l,
				Detail: "Excel web query: Excel fetches this URL and renders it as a sheet when the file is opened (abused to deliver DDE and macro payloads)"})
			break
		}
	}
	res.addCheck("IQY web query URL")
	return nil
}

// extractDDECSV reports DDE formulas in CSV cells.
func extractDDECSV(data []byte, res *Result) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n := 0
	for line := 1; sc.Scan(); line++ {
		for _, cell := range strings.FieldsFunc(sc.Text(), func(r rune) bool { return r == ',' || r == ';' || r == '\t' }) {
			cell = strings.Trim(strings.TrimSpace(cell), `"`)
			if cell != "" && strings.ContainsAny(cell[:1], "=+-@") {
				checkFormulaDDE(fmt.Sprintf("CSV line %d", line), cell, res)
				n++
			}
		}
	}
	res.addCheck(fmt.Sprintf("CSV formulas (%d) for DDE", n))
	return nil
}
