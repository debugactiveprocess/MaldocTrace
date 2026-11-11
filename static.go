package maldoctrace

import (
	"fmt"
	"sort"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

// staticAnalysis records findings that need no emulation: external
// references (template injection, linked OLE, DDE), VBA stomping, Excel 4.0
// macro sheets and document properties.
func staticAnalysis(res *extractor.Result, r *report.Report) {
	for _, e := range res.External {
		f := addFinding(r, report.StaticFinding{Kind: e.Kind, Severity: e.Severity, Location: e.Location, Target: e.Target, Detail: e.Detail})
		if e.Target != "" {
			scanEvidence(r, e.Target, "static", f, report.Source{Module: e.Location})
		}
	}
	detectStomping(res, r)

	for _, s := range res.Sheets {
		if s.Kind != "macrosheet" {
			continue
		}
		ms := report.MacroSheet{Name: s.Name, Visibility: s.Visibility, Source: s.Source}
		cells := append([]extractor.Cell(nil), s.Cells...)
		sort.Slice(cells, func(i, j int) bool {
			if cells[i].Col != cells[j].Col {
				return cells[i].Col < cells[j].Col
			}
			return cells[i].Row < cells[j].Row
		})
		for _, c := range cells {
			if c.Formula == "" {
				continue
			}
			ms.Formulas = append(ms.Formulas, report.XLMFormula{Cell: extractor.CellName(c.Row, c.Col), Formula: c.Formula, Value: c.Value, Undecoded: c.Undecoded})
			scanEvidence(r, c.Formula, "literal", "xlm:"+s.Name+"!"+extractor.CellName(c.Row, c.Col), report.Source{Module: s.Name, Proc: extractor.CellName(c.Row, c.Col), Line: c.Row + 1})
		}
		r.MacroSheets = append(r.MacroSheets, ms)
		if s.Visibility != "visible" {
			addFinding(r, report.StaticFinding{Kind: "hidden_macrosheet", Severity: "medium", Location: s.Source, Target: s.Name,
				Detail: "Excel 4.0 macro sheet is " + strings.ReplaceAll(s.Visibility, "_", " ")})
		}
	}
	for _, n := range res.Names {
		if strings.HasPrefix(strings.ToLower(n.Name), "auto_open") && len(r.MacroSheets) > 0 {
			addFinding(r, report.StaticFinding{Kind: "xlm_auto_open", Severity: "high", Location: "defined name " + n.Name, Target: n.Formula,
				Detail: "Excel runs this Excel 4.0 macro when the workbook opens"})
		}
	}

	props := append([]extractor.DocProperty(nil), res.Properties...)
	sort.SliceStable(props, func(i, j int) bool {
		if props[i].Kind != props[j].Kind {
			return props[i].Kind < props[j].Kind
		}
		return props[i].Name < props[j].Name
	})
	for _, p := range props {
		r.Properties = append(r.Properties, report.Property{Name: p.Name, Value: p.Value, Kind: p.Kind, Source: p.Source})
		scanEvidence(r, p.Value, "literal", "property:"+p.Name, report.Source{Module: p.Source})
	}
}

func addFinding(r *report.Report, f report.StaticFinding) string {
	f.ID = fmt.Sprintf("finding-%d", len(r.StaticFindings)+1)
	r.StaticFindings = append(r.StaticFindings, f)
	return f.ID
}

// pcodeLiterals extracts string literals from a module's compiled p-code.
// LitStr operands are stored as a 16-bit length followed by the bytes, so
// length-prefixed printable runs are a precise approximation that needs no
// version-specific opcode tables.
func pcodeLiterals(b []byte) []string {
	var out []string
	for i := 0; i+2 < len(b) && len(out) < 4096; i++ {
		l := int(b[i]) | int(b[i+1])<<8
		if l < 4 || l > 8192 || i+2+l > len(b) {
			continue
		}
		ok := true
		for _, c := range b[i+2 : i+2+l] {
			if c < 0x20 || c > 0x7e {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, string(b[i+2:i+2+l]))
			i += 1 + l
		}
	}
	return out
}

// detectStomping compares string literals compiled into each module's
// p-code with its source. VBA stomping replaces or removes the source while
// keeping the p-code, which is what Office actually runs when the VBA
// version matches; literals present only in p-code reveal the real macro.
func detectStomping(res *extractor.Result, r *report.Report) {
	for _, m := range res.Modules {
		if len(m.PCode) == 0 {
			continue
		}
		src := strings.ToLower(m.Code)
		var missing []string
		seen := map[string]bool{}
		for _, lit := range pcodeLiterals(m.PCode) {
			low := strings.ToLower(lit)
			if seen[low] || strings.Contains(src, low) || strings.Contains(src, strings.ReplaceAll(low, `"`, `""`)) {
				continue
			}
			seen[low] = true
			missing = append(missing, lit)
		}
		emptySource := !hasProcedures(m.Code) && len(m.PCode) > 2048
		if len(missing) == 0 && !emptySource {
			continue
		}
		detail := fmt.Sprintf("%d string literal(s) compiled into the p-code are absent from the module source; Office runs the p-code, so the source shown may be a decoy", len(missing))
		sev := "high"
		if len(missing) == 0 {
			detail = fmt.Sprintf("module has %d bytes of compiled p-code but no procedures in its source", len(m.PCode))
			sev = "medium"
		}
		ev := missing
		if len(ev) > 50 {
			ev = ev[:50]
		}
		id := addFinding(r, report.StaticFinding{Kind: "vba_stomping", Severity: sev, Location: "module " + m.Name, Detail: detail, Evidence: ev})
		for _, lit := range missing {
			scanEvidence(r, lit, "pcode", id, report.Source{Module: m.Name})
			r.Decoded = append(r.Decoded, report.DecodedStr{Value: lit, Kind: "static", Method: "p-code literal (absent from source)", Module: m.Name})
		}
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "stomping", Module: m.Name,
			Message: "possible VBA stomping: the emulated source may not be the code Office executes", EvidenceIDs: []string{id}})
	}
}

func hasProcedures(code string) bool {
	for _, line := range strings.Split(strings.ToLower(code), "\n") {
		f := strings.Fields(line)
		for len(f) > 0 && (f[0] == "public" || f[0] == "private" || f[0] == "friend" || f[0] == "static") {
			f = f[1:]
		}
		if len(f) > 0 && (f[0] == "sub" || f[0] == "function" || f[0] == "property") {
			return true
		}
	}
	return false
}
