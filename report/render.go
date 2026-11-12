package report

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// TextOptions controls optional sections of the text rendering. The JSON
// output is never affected: it always carries the complete data.
type TextOptions struct {
	// ShowStrings adds the deduplicated "Reconstructed strings" section.
	ShowStrings bool
}

// Display limits for secondary sections, which reference primary entries by
// ID instead of repeating their full text.
const (
	secondaryPreview = 96
	valuePreview     = 200
	// maxBinaryDisplay bounds hex shown for large binaries (e.g. a PE);
	// shellcode-sized payloads are still shown in full.
	maxBinaryDisplay = 4096
	// maxFormulaLines bounds formula listings in text output.
	maxFormulaLines = 300
	// maxPropertyLines caps the document properties and variables shown in
	// text output (droppers can split a payload across hundreds of them).
	maxPropertyLines = 12
)

// RenderText renders a human-readable summary with default options.
func RenderText(r *Report) string { return RenderTextWith(r, TextOptions{}) }

// RenderTextWith renders a human-readable summary of the report.
func RenderTextWith(r *Report, opt TextOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MaldocTrace %s (schema %s)\n", r.ToolVersion, r.SchemaVersion)
	fmt.Fprintf(&b, "File: %s (%d bytes)\n", r.File.Name, r.File.Size)
	fmt.Fprintf(&b, "SHA-256: %s\n", r.File.SHA256)
	fmt.Fprintf(&b, "Format: %s\n", r.Format)
	fmt.Fprintf(&b, "Status: %s | Macros: %s\n", r.Status, r.Macros)
	fmt.Fprintf(&b, "Operational: %s | Semantic coverage: %s\n", r.OperationalStatus, r.SemanticCoverage)

	// Primary owners of event evidence: an event shown in full as a command,
	// payload or script call is referenced by that ID elsewhere.
	eventRefs := map[string][]string{}
	abbr := newAbbreviator(r)
	if len(r.StaticFindings) > 0 {
		fmt.Fprintln(&b, "\n-- Static findings --")
		for _, f := range r.StaticFindings {
			fmt.Fprintf(&b, "  [%s] %s (%s)\n", f.ID, f.Kind, f.Severity)
			if f.Target != "" {
				fmt.Fprintf(&b, "      Target: %s\n", printable(f.Target, 2*valuePreview, "static_findings"))
			}
			fmt.Fprintf(&b, "      Location: %s\n", f.Location)
			if f.Detail != "" {
				fmt.Fprintf(&b, "      Detail: %s\n", f.Detail)
			}
			for i, ev := range f.Evidence {
				if i == 10 {
					fmt.Fprintf(&b, "      ... %d more in JSON static_findings\n", len(f.Evidence)-i)
					break
				}
				fmt.Fprintf(&b, "      Evidence: %s\n", printable(abbr(ev), valuePreview, "static_findings"))
			}
		}
	}
	if len(r.Commands) > 0 {
		fmt.Fprintln(&b, "\n-- Recovered commands --")
		for _, c := range r.Commands {
			for _, ev := range c.EvidenceIDs {
				eventRefs[ev] = append(eventRefs[ev], c.ID)
			}
			fmt.Fprintf(&b, "  [%s] %s\n      Command: %s\n      Receiver: %s.%s\n      Source: %s\n      Discovery: %s\n      Execution: %s\n      Resolution: %s\n",
				c.ID, c.Kind, c.CommandLine, c.Receiver, c.Method, srcText(c.Source), c.Discovery, c.Execution, c.Resolution)
		}
	}
	if len(r.DecodedPayloads) > 0 {
		fmt.Fprintln(&b, "\n-- Decoded payloads and recovered scripts --")
		for _, p := range r.DecodedPayloads {
			if strings.HasPrefix(p.DerivedFrom, "event-") {
				eventRefs[p.DerivedFrom] = append(eventRefs[p.DerivedFrom], p.ID)
			}
			fmt.Fprintf(&b, "  [%s] %s\n", p.ID, p.Kind)
			fmt.Fprintf(&b, "      Category: %s", p.Category)
			if p.Language != "" {
				fmt.Fprintf(&b, " | Language: %s", p.Language)
			}
			fmt.Fprintf(&b, " | %d bytes", p.Size)
			if p.SHA256 != "" {
				fmt.Fprintf(&b, " | sha256=%s", p.SHA256)
			}
			fmt.Fprintln(&b)
			if len(p.Encoding) > 0 {
				fmt.Fprintf(&b, "      Encoding: %s\n", strings.Join(p.Encoding, " → "))
			}
			if p.FileType != "" {
				fmt.Fprintf(&b, "      File type: %s\n", p.FileType)
			}
			for _, f := range p.Facts {
				fmt.Fprintf(&b, "        %s\n", f)
			}
			for _, d := range p.Details {
				fmt.Fprintf(&b, "      Note: %s\n", d)
			}
			if len(p.Functions) > 0 {
				fmt.Fprintf(&b, "      Defines: %s\n", strings.Join(p.Functions, ", "))
			}
			if p.NormalizedContent != "" {
				fmt.Fprintf(&b, "      Content (normalized: %s; raw in JSON):\n%s\n", strings.Join(p.Normalization, ", "), indent(p.NormalizedContent, "        "))
			} else if limit := binaryLimit(p); p.Content != "" && p.Category == "binary" && isHex(p.Content) && len(p.Content) > 2*limit {
				fmt.Fprintf(&b, "      Content (hex, first %d of %d bytes; full content in JSON decoded_payloads):\n%s\n",
					limit, len(p.Content)/2, indent(wrap(p.Content[:2*limit], 64), "        "))
			} else if p.Content != "" && p.Category == "binary" && isHex(p.Content) {
				fmt.Fprintf(&b, "      Content (hex):\n%s\n", indent(wrap(p.Content, 64), "        "))
			} else if p.Content != "" {
				fmt.Fprintf(&b, "      Content:\n%s\n", indent(p.Content, "        "))
			}
			fmt.Fprintf(&b, "      Derived from: %s\n      Status: %s %s\n", p.DerivedFrom, p.Status, p.Error)
		}
	}
	if len(r.ScriptCalls) > 0 {
		fmt.Fprintln(&b, "\n-- Script engine calls (not OS commands) --")
		for _, c := range r.ScriptCalls {
			for _, ev := range c.EvidenceIDs {
				eventRefs[ev] = append(eventRefs[ev], c.ID)
			}
			target := c.Function + "()"
			if c.Function == "" {
				target = printable(c.Expression, valuePreview, "script_calls")
			}
			fmt.Fprintf(&b, "  [%s] %s %s.%s → %s\n", c.ID, c.Language, c.Engine, c.Method, target)
			if c.DefinedIn != "" {
				fmt.Fprintf(&b, "      Defined in: %s\n", c.DefinedIn)
			}
			fmt.Fprintf(&b, "      Source: %s\n      Execution: %s\n", srcText(c.Source), c.Execution)
		}
	}
	for _, ms := range r.MacroSheets {
		fmt.Fprintf(&b, "\n-- Excel 4.0 macro sheet %q (%s, %d formulas) --\n", ms.Name, strings.ReplaceAll(ms.Visibility, "_", " "), len(ms.Formulas))
		for i, f := range ms.Formulas {
			if i == maxFormulaLines {
				fmt.Fprintf(&b, "  ... %d more in JSON macro_sheets\n", len(ms.Formulas)-i)
				break
			}
			mark := ""
			if f.Undecoded {
				mark = "  (not fully decompiled)"
			}
			fmt.Fprintf(&b, "  %-7s %s%s\n", f.Cell, printable(f.Formula, 2*valuePreview, "macro_sheets"), mark)
		}
	}
	var written []DecodedStr
	for _, d := range r.Decoded {
		if strings.HasPrefix(d.Method, "XLM ") {
			written = append(written, d)
		}
	}
	if len(written) > 0 {
		fmt.Fprintln(&b, "\n-- XLM formulas written at run time (deobfuscated) --")
		for i, d := range written {
			if i == maxFormulaLines {
				fmt.Fprintf(&b, "  ... %d more in JSON decoded_strings\n", len(written)-i)
				break
			}
			fmt.Fprintf(&b, "  %s!%s  %s\n", d.Module, d.Proc, printable(abbr(d.Value), 2*valuePreview, "decoded_strings"))
		}
	}
	var props []Property
	for _, p := range r.Properties {
		if p.Kind != "builtin" || len(p.Value) >= 64 {
			props = append(props, p)
		}
	}
	if len(props) > 0 {
		fmt.Fprintln(&b, "\n-- Document properties and variables --")
		for i, p := range props {
			if i == maxPropertyLines {
				fmt.Fprintf(&b, "  ... %d more in JSON document_properties\n", len(props)-i)
				break
			}
			fmt.Fprintf(&b, "  [%s] %s = %s\n", p.Kind, p.Name, printable(abbr(p.Value), valuePreview, "document_properties"))
		}
	}
	if r.Encrypted {
		switch d := r.Decryption; {
		case d != nil && d.Decrypted:
			pw := fmt.Sprintf("%q", d.Password)
			if d.Password == "VelvetSweatshop" {
				pw += " (Excel's default password)"
			}
			fmt.Fprintf(&b, "\nEncrypted: yes, decrypted (%s, password %s)\n", d.Scheme, pw)
		case d != nil:
			fmt.Fprintf(&b, "\nEncrypted: yes, NOT decrypted (%s: %s); absence of macros is NOT evidence of absence\n", d.Scheme, d.Note)
		default:
			fmt.Fprintf(&b, "\nEncrypted: yes (no VBA extracted; absence is NOT evidence of absence)\n")
		}
	}
	if r.Macros == "present" {
		fmt.Fprintf(&b, "\n-- Entry points --\n")
		for _, ep := range r.EntryPoints {
			fmt.Fprintf(&b, "  %s.%s  (%s)\n", ep.Module, ep.Proc, ep.Trigger)
		}
		fmt.Fprintf(&b, "\n-- Modules --\n")
		for _, m := range r.Modules {
			unit := "chars"
			if strings.HasPrefix(m.Type, "xlm") {
				unit = "cells"
			}
			fmt.Fprintf(&b, "  %s  (%s, %d %s)\n", m.Name, m.Type, m.CodeLen, unit)
		}
	}
	if len(r.Events) > 0 {
		fmt.Fprintf(&b, "\n-- Simulated operations --\n")
		for _, e := range r.Events {
			loc := fmt.Sprintf("%s.%s:%d", e.Module, e.Proc, e.Line)
			if refs := eventRefs[fmt.Sprintf("event-%d", e.ID)]; len(refs) > 0 {
				fmt.Fprintf(&b, "  #%d %s [%s] → %s\n", e.ID, e.Type, loc, strings.Join(refs, ", "))
				continue
			}
			fmt.Fprintf(&b, "  #%d %s [%s] %s\n", e.ID, e.Type, loc, printable(abbr(strings.Join(e.Resolved, " ")), valuePreview, "events"))
		}
	}
	if len(r.Artifacts) > 0 {
		fmt.Fprintf(&b, "\n-- Reconstructed artifacts --\n")
		for _, a := range r.Artifacts {
			fmt.Fprintf(&b, "  %s sha256=%s (%d bytes)\n", a.Path, a.SHA256, a.Size)
			if a.FileType != "" {
				fmt.Fprintf(&b, "      File type: %s\n", a.FileType)
			}
			for _, f := range a.Facts {
				fmt.Fprintf(&b, "        %s\n", f)
			}
		}
	}
	if len(r.Decoded) > 0 {
		if opt.ShowStrings {
			renderStrings(&b, r.Decoded)
		} else {
			fmt.Fprintf(&b, "\nReconstructed strings: %d (hidden; use --show-strings, or see decoded_strings in JSON)\n", len(r.Decoded))
		}
	}
	return b.String()
}

// renderStrings prints reconstructed strings deduplicated by value, in order
// of first appearance, with every distinct occurrence and its method.
func renderStrings(b *strings.Builder, ds []DecodedStr) {
	type group struct {
		value string
		occ   []DecodedStr
		seen  map[string]bool
	}
	var groups []*group
	byValue := map[string]*group{}
	for _, d := range ds {
		g := byValue[d.Value]
		if g == nil {
			g = &group{value: d.Value, seen: map[string]bool{}}
			byValue[d.Value] = g
			groups = append(groups, g)
		}
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%s\x00%s", d.Module, d.Proc, d.Line, d.Col, d.Kind, d.Method)
		if g.seen[key] {
			continue
		}
		g.seen[key] = true
		g.occ = append(g.occ, d)
	}
	fmt.Fprintf(b, "\n-- Reconstructed strings (%d unique, %d total) --\n", len(groups), len(ds))
	for i, g := range groups {
		fmt.Fprintf(b, "  [string-%d] %s\n", i+1, printable(g.value, valuePreview, "decoded_strings"))
		for _, o := range g.occ {
			proc := o.Proc
			if proc == "" {
				proc = "(module level)"
			}
			method := o.Method
			if method == "" {
				method = "-"
			}
			fmt.Fprintf(b, "      %s.%s:%d col %d  %s/%s\n", o.Module, proc, o.Line, o.Col, o.Kind, method)
		}
	}
}

// newAbbreviator returns a function that replaces long text already shown in
// full in a primary section (command lines, encoded payloads) by a reference
// such as ⟨command-1⟩. It only affects text output.
func newAbbreviator(r *Report) func(string) string {
	const minLen = 32
	type ref struct{ text, id string }
	var refs []ref
	for _, c := range r.Commands {
		if len(c.CommandLine) >= minLen {
			refs = append(refs, ref{c.CommandLine, c.ID})
		}
	}
	for _, p := range r.DecodedPayloads {
		if len(p.Encoded) >= minLen {
			refs = append(refs, ref{p.Encoded, p.ID + ".encoded"})
		}
		if p.Category == "script" && len(p.Content) >= minLen {
			refs = append(refs, ref{p.Content, p.ID})
		}
	}
	// Longest first, so a command line wins over the Base64 it contains.
	for i := 1; i < len(refs); i++ {
		for j := i; j > 0 && len(refs[j].text) > len(refs[j-1].text); j-- {
			refs[j], refs[j-1] = refs[j-1], refs[j]
		}
	}
	return func(s string) string {
		for _, x := range refs {
			if strings.Contains(s, x.text) {
				s = strings.ReplaceAll(s, x.text, "⟨"+x.id+"⟩")
			}
		}
		return s
	}
}

func srcText(s Source) string {
	return fmt.Sprintf("%s.%s:%d (inherited=%t)", s.Module, s.Proc, s.Line, s.Inherited)
}

func indent(s, pad string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "\r", `\r`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// preview returns a short single-line excerpt for cross-references.
func preview(s string) string {
	s = escape(s)
	if len(s) > secondaryPreview {
		return cut(s, secondaryPreview) + "…"
	}
	return s
}

func printable(s string, max int, jsonField string) string {
	s = escape(s)
	if len(s) > max {
		return cut(s, max) + fmt.Sprintf("... [truncated display: %d bytes; full value in JSON %s]", len(s), jsonField)
	}
	return s
}

// cut truncates s to at most n bytes without splitting a UTF-8 sequence.
func cut(s string, n int) string {
	for n > 0 && n < len(s) && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return len(s)%2 == 0
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n])
		b.WriteByte('\n')
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}

// binaryLimit is how many bytes of a binary payload the text view shows. An
// identified file (PE, ZIP, ...) only needs its header; unidentified code
// such as shellcode is shown up to maxBinaryDisplay.
func binaryLimit(p DecodedPayload) int {
	if p.FileType != "" {
		return 256
	}
	return maxBinaryDisplay
}
