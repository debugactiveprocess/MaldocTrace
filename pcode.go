package maldoctrace

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/report"
	"github.com/debugactiveprocess/MaldocTrace/vba/pcode"
)

// procHead finds Sub/Function/Property definitions in VBA source.
var procHead = regexp.MustCompile(`(?im)^[ \t]*(?:(?:public|private|friend|static)[ \t]+)*(?:sub|function|property[ \t]+(?:get|let|set))[ \t]+([A-Za-z_][A-Za-z0-9_]*)`)

// lineContinuation joins VBA continued lines ("Sub _" + newline + "Name()").
var lineContinuation = regexp.MustCompile(`[ \t]_[ \t]*\r?\n`)

func procNames(code string) map[string]bool {
	out := map[string]bool{}
	code = lineContinuation.ReplaceAllString(code, " ")
	for _, m := range procHead.FindAllStringSubmatch(code, -1) {
		out[strings.ToLower(m[1])] = true
	}
	return out
}

// rebuildFromPCode decompiles the p-code of every module. A module whose
// source does not match its p-code (VBA stomping) is analysed from the code
// rebuilt from the p-code, which is what Office executes; with
// opts.PreferPCode every module that decompiles is.
func rebuildFromPCode(res *extractor.Result, r *report.Report, opts Options) {
	projects := map[*extractor.Project]*pcode.Project{}
	stomped := map[string]string{} // module name -> finding id
	for _, f := range r.StaticFindings {
		if f.Kind == "vba_stomping" {
			stomped[strings.TrimPrefix(f.Location, "module ")] = f.ID
		}
	}
	rebuilt := 0
	for i, m := range res.Modules {
		if len(m.PCode) == 0 || m.Project == nil || len(m.Project.VBAProject) == 0 {
			continue
		}
		proj, ok := projects[m.Project]
		if !ok {
			var err error
			proj, err = pcode.ParseProject(m.Project.VBAProject, m.Project.SysKind == 3, m.DecodeText)
			if err != nil && len(proj.Identifiers) == 0 {
				proj = nil
				r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "info", Stage: "pcode", Message: "cannot read the p-code identifier table: " + err.Error()})
			}
			projects[m.Project] = proj
		}
		if proj == nil || proj.VBA < 5 {
			continue
		}
		mod, err := pcode.Disassemble(m.PCode, proj)
		if err != nil {
			if _, bad := stomped[m.Name]; bad {
				r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "pcode", Module: m.Name, Message: "cannot disassemble the p-code: " + err.Error()})
			}
			continue
		}
		src := pcode.Decompile(mod, proj)
		if src.Procedures == 0 {
			continue
		}
		id, isStomped := stomped[m.Name]
		// Procedures that exist only in the p-code are stomping even when
		// no string literal differs.
		var hidden []string
		have := procNames(m.Code)
		for name := range procNames(src.Text) {
			if !have[name] {
				hidden = append(hidden, name)
			}
		}
		sort.Strings(hidden)
		if len(hidden) > 0 && !isStomped {
			id = addFinding(r, report.StaticFinding{Kind: "vba_stomping", Severity: "high", Location: "module " + m.Name,
				Detail:   fmt.Sprintf("%d procedure(s) compiled into the p-code are absent from the module source; Office runs the p-code, so the source shown is a decoy", len(hidden)),
				Evidence: hidden})
			isStomped = true
		}
		if !isStomped && !opts.PreferPCode {
			continue
		}
		detail := fmt.Sprintf("; the module was rebuilt from its p-code (%d lines, %d procedures", src.Lines, src.Procedures)
		if src.Unknown > 0 {
			detail += fmt.Sprintf(", %d line(s) not fully decompiled", src.Unknown)
		}
		detail += ") and that code was analysed instead of the source"
		for j := range r.StaticFindings {
			if r.StaticFindings[j].ID == id {
				r.StaticFindings[j].Detail += detail
			}
		}
		m.Code = src.Text
		m.CodeRaw = []byte(src.Text)
		for j := range r.Modules {
			if r.Modules[j].Name == m.Name && !r.Modules[j].FromPCode {
				r.Modules[j].FromPCode = true
				r.Modules[j].PCodeSource = src.Text
				r.Modules[j].CodeLen = len(src.Text)
				break
			}
		}
		res.Modules[i] = m
		rebuilt++
	}
	if rebuilt > 0 {
		r.Checks = append(r.Checks, fmt.Sprintf("VBA p-code decompiled (%d module(s) analysed from p-code)", rebuilt))
	}
}
