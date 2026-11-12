package maldoctrace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/debugactiveprocess/MaldocTrace/indicators"
	"github.com/debugactiveprocess/MaldocTrace/payload"
	"github.com/debugactiveprocess/MaldocTrace/report"
	"regexp"
	"strings"
)

func scanEvidence(r *report.Report, text, discovery, id string, src report.Source) {
	scanEvidenceOpts(r, text, discovery, id, src, false)
}

// scanEvidenceOpts scans text for IOCs. When isScript is set the text is
// script source, so the whole-text "command" heuristic is skipped: a script
// that merely mentions cmd.exe is a payload, not a command line.
func scanEvidenceOpts(r *report.Report, text, discovery, id string, src report.Source, isScript bool) {
	for _, f := range indicators.ScanValue(text) {
		if isScript && f.Type == "command" {
			continue
		}
		r.IOCs = append(r.IOCs, report.IOC{Type: f.Type, Value: f.Value, Discovery: discovery, Occurrences: []report.Occurrence{{Module: src.Module, Proc: src.Proc, Line: src.Line, Col: src.Col, Evidence: f.Evidence, EvidenceID: id, Discovery: discovery}}})
	}
}

// isScriptEvent reports whether an event carries script-engine source or a
// script-engine invocation (as opposed to an OS-level command).
func isScriptEvent(t string) bool {
	switch t {
	case "script_add_code", "script_run", "script_eval", "script_execute_statement":
		return true
	}
	return false
}

func recoverCommands(r *report.Report) {
	total := 0
	scriptFuncs := map[string]string{} // lower(function) -> payload ID
	for _, e := range r.Events {
		src := report.Source{Module: e.Module, Proc: e.Proc, Line: e.Line, Col: e.Col, Inherited: e.LocationInherited}
		eventID := fmt.Sprintf("event-%d", e.ID)
		script := isScriptEvent(e.Type)
		for _, a := range e.Arguments {
			if a.Kind != "unknown" {
				scanEvidenceOpts(r, a.Value, "emulated_call", eventID, src, script)
			}
		}
		if script {
			recoverScriptEvent(r, e, src, eventID, scriptFuncs)
			continue
		}
		if e.Type == "api_call" && e.Extra["buffer_hex"] != "" {
			recoverAPIBuffer(r, e, src, eventID, &total)
			continue
		}
		if content, err := hex.DecodeString(e.Extra["content_hex"]); err == nil && len(content) > 0 {
			scanEvidence(r, string(content), "virtual_file", eventID, src)
		}
		if hash := e.Extra["content_sha256"]; hash != "" {
			r.IOCs = append(r.IOCs, report.IOC{Type: "sha256", Value: hash, Discovery: "virtual_file", Occurrences: []report.Occurrence{{EvidenceID: eventID, Discovery: "virtual_file"}}})
		}
		switch e.Type {
		case "shell", "wscript_shell_run", "wscript_shell_exec", "shell_execute", "wmi_process_create", "unresolved_call":
		default:
			continue
		}
		cmd := ""
		if len(e.Resolved) > 0 {
			cmd = e.Resolved[0]
		}
		if len(e.Arguments) > 0 {
			cmd = e.Arguments[0].Value
		}
		if e.Type == "unresolved_call" && !strings.EqualFold(e.Method, "Create") && !strings.EqualFold(e.Method, "Run") && !strings.EqualFold(e.Method, "Exec") && !strings.EqualFold(e.Method, "ShellExecute") {
			continue
		}
		resolution := "resolved"
		for _, a := range e.Arguments {
			if a.Kind == "unknown" {
				resolution = "partial"
			}
		}
		execution := "simulated"
		if e.Type == "unresolved_call" {
			resolution = "unresolved_receiver"
			execution = "unresolved"
		}
		argv, parseErr := payload.SplitCommand(cmd)
		if e.Type == "shell_execute" && len(e.Arguments) > 1 {
			argv, parseErr = payload.SplitCommand(e.Arguments[1].Value)
			argv = append([]string{cmd}, argv...)
			if strings.ContainsAny(cmd, " \t") {
				cmd = `"` + cmd + `"`
			}
			cmd += " " + e.Arguments[1].Value
		}
		kind := "command"
		if len(argv) > 0 && payload.IsPowerShell(argv[0]) {
			kind = "PowerShell"
		}
		id := fmt.Sprintf("command-%d", len(r.Commands)+1)
		r.Commands = append(r.Commands, report.Command{ID: id, Kind: kind, CommandLine: cmd, Receiver: e.Receiver, Method: e.Method, Arguments: e.Arguments, Source: src, CallChain: e.CallChain, Discovery: "emulated_call", Execution: execution, Resolution: resolution, EvidenceIDs: []string{eventID}})
		if resolution != "resolved" {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "commands", Message: "incomplete command resolution", EvidenceIDs: []string{id}})
		}
		if kind != "PowerShell" {
			continue
		}
		encoded, found, err := payload.EncodedArgument(argv)
		if parseErr != nil {
			err = parseErr
		}
		if err != nil {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "payload", Message: err.Error(), EvidenceIDs: []string{id}})
			continue
		}
		if !found {
			continue
		}
		p := report.DecodedPayload{ID: fmt.Sprintf("payload-%d", len(r.DecodedPayloads)+1), Kind: "PowerShell EncodedCommand", Category: "encoded_command", Language: "PowerShell", Encoded: encoded, DerivedFrom: id, Encoding: []string{"Base64", "UTF-16LE"}, Depth: 1, Status: "decoded"}
		var bytes []byte
		if total >= 4*payload.MaxPayloadBytes {
			err = fmt.Errorf("aggregate decoded payload budget exhausted")
		} else {
			p.Content, bytes, err = payload.DecodeEncodedCommand(encoded)
		}
		p.Size = len(bytes)
		total += len(bytes)
		if len(bytes) > 0 {
			sum := sha256.Sum256(bytes)
			p.SHA256 = hex.EncodeToString(sum[:])
		}
		if err != nil {
			p.Status = "error"
			p.Error = err.Error()
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "payload", Message: err.Error(), EvidenceIDs: []string{p.ID}})
		} else {
			p.Raw = []byte(p.Content)
			scanText := p.Content
			if folded, n := payload.FoldPowerShellConcat(p.Content); n > 0 {
				p.NormalizedContent = folded
				p.Normalization = []string{"powershell_string_concatenation"}
				scanText = folded
			}
			// IOCs come from the normalized script only: scanning the raw
			// text as well would report fragments such as 'http://o'.
			scanEvidence(r, scanText, "decoded_payload", p.ID, src)
		}
		r.DecodedPayloads = append(r.DecodedPayloads, p)
	}
	followFileChains(r, &total)
	recoverHexLiterals(r)
	profileBinaries(r)
}

func recoverScriptEvent(r *report.Report, e report.Event, src report.Source, eventID string, scriptFuncs map[string]string) {
	lang := e.Extra["language"]
	arg := func(i int) string {
		if i < len(e.Arguments) && e.Arguments[i].Kind != "unknown" {
			return e.Arguments[i].Value
		}
		if i < len(e.Resolved) {
			return e.Resolved[i]
		}
		return ""
	}
	if e.Type == "script_add_code" {
		code := arg(0)
		sum := sha256.Sum256([]byte(code))
		p := report.DecodedPayload{
			ID: fmt.Sprintf("payload-%d", len(r.DecodedPayloads)+1), Kind: "Script (" + lang + ") via ScriptControl.AddCode",
			Category: "script", Language: lang, Content: code, Encoding: []string{}, DerivedFrom: eventID,
			SHA256: hex.EncodeToString(sum[:]), Size: len(code), Status: "recovered", Depth: 1,
		}
		if f := e.Extra["functions"]; f != "" {
			p.Functions = strings.Split(f, ",")
			for _, fn := range p.Functions {
				scriptFuncs[strings.ToLower(fn)] = p.ID
			}
		}
		p.Raw = []byte(code)
		scanEvidenceOpts(r, code, "script_payload", p.ID, src, true)
		r.DecodedPayloads = append(r.DecodedPayloads, p)
		return
	}
	c := report.ScriptCall{
		ID: fmt.Sprintf("script-call-%d", len(r.ScriptCalls)+1), Engine: "MSScriptControl.ScriptControl", Language: lang,
		Method: e.Method, Arguments: e.Arguments, Source: src, CallChain: e.CallChain,
		Execution: "not_executed", EvidenceIDs: []string{eventID},
	}
	switch e.Type {
	case "script_run":
		c.Function = arg(0)
		c.DefinedIn = scriptFuncs[strings.ToLower(c.Function)]
		if c.DefinedIn == "" {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "info", Stage: "scripts", Message: "script function " + c.Function + " not found in recovered script code", EvidenceIDs: []string{c.ID}})
		}
	default:
		c.Expression = arg(0)
		scanEvidenceOpts(r, c.Expression, "script_payload", c.ID, src, true)
	}
	r.ScriptCalls = append(r.ScriptCalls, c)
}

// recoverAPIBuffer turns a declared-API call that consumes a memory buffer
// (MultiByteToWideChar, RtlMoveMemory, WriteProcessMemory) into a recovered
// in-memory payload. The raw buffer is always reported in full; when it can
// be decoded statically (CP_UTF7) the decoded bytes become a payload.
func recoverAPIBuffer(r *report.Report, e report.Event, src report.Source, eventID string, total *int) {
	raw, err := hex.DecodeString(e.Extra["buffer_hex"])
	if err != nil {
		return
	}
	raw = bytes.TrimRight(raw, "\x00") // unused array space
	api := e.Extra["alias"]
	if api == "" {
		api = e.Extra["name"]
	}
	if len(raw) == 0 {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "info", Stage: "payload",
			Message: "buffer passed to " + api + " is empty or could not be built", EvidenceIDs: []string{eventID}})
		return
	}
	shown, _ := payload.DisplayBytes(raw)
	id := fmt.Sprintf("command-%d", len(r.Commands)+1)
	r.Commands = append(r.Commands, report.Command{
		ID: id, Kind: "In-memory payload via " + api, CommandLine: shown,
		Receiver: e.Extra["lib"], Method: api, Arguments: e.Arguments, Source: src, CallChain: e.CallChain,
		Discovery: "emulated_call", Execution: "simulated", Resolution: "resolved", EvidenceIDs: []string{eventID},
	})
	sum := sha256.Sum256(raw)
	p := report.DecodedPayload{
		ID: fmt.Sprintf("payload-%d", len(r.DecodedPayloads)+1), Category: "binary", Encoded: shown,
		DerivedFrom: id, Depth: 1, Encoding: []string{}, Size: len(raw), SHA256: hex.EncodeToString(sum[:]),
	}
	switch {
	case strings.EqualFold(api, "MultiByteToWideChar") && payload.IsUTF7CodePage(e.Extra["codepage"]):
		p.Kind = "UTF-7 buffer (" + e.Extra["buffer_source"] + ")"
		p.Encoding = []string{"UTF-7", "UTF-16LE"}
		if *total >= 4*payload.MaxPayloadBytes {
			err = fmt.Errorf("aggregate decoded payload budget exhausted")
		} else {
			var dec []byte
			dec, err = payload.DecodeUTF7(raw)
			if err == nil {
				*total += len(dec)
				dsum := sha256.Sum256(dec)
				p.Content, _ = payload.DisplayBytes(dec)
				p.Size, p.SHA256, p.Status, p.Raw = len(dec), hex.EncodeToString(dsum[:]), "decoded", dec
				scanEvidence(r, string(dec), "decoded_payload", p.ID, src)
			}
		}
		if err != nil {
			p.Status, p.Error, p.Content, p.Raw = "error", err.Error(), shown, raw
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "warning", Stage: "payload", Message: err.Error(), EvidenceIDs: []string{p.ID}})
		}
	default:
		// No static decoding applies: the buffer itself is the payload.
		p.Kind = "Raw buffer (" + e.Extra["buffer_source"] + ")"
		p.Content, p.Status, p.Raw = shown, "not_decoded", raw
		scanEvidence(r, string(raw), "decoded_payload", p.ID, src)
	}
	r.DecodedPayloads = append(r.DecodedPayloads, p)
}

// linkDuplicateIndicators marks IOCs whose full value is already shown as a
// command line or payload (SameAs), or that are fragments of recovered script
// source (PartOf), so text output can reference instead of repeat. Command
// candidates that are really script source are reclassified as "script".
func linkDuplicateIndicators(r *report.Report) {
	owners := map[string]string{}
	scripts := map[string]string{} // script content -> payload ID
	for _, p := range r.DecodedPayloads {
		owners[p.Content] = p.ID
		if p.Category == "script" {
			scripts[p.Content] = p.ID
		}
	}
	for _, c := range r.Commands {
		owners[c.CommandLine] = c.ID // commands take precedence
	}
	for i := range r.IOCs {
		v := r.IOCs[i].Value
		if id, ok := owners[v]; ok && len(v) > 0 {
			r.IOCs[i].SameAs = id
		}
		if r.IOCs[i].Type != "command" {
			continue
		}
		if id := scriptOwner(v, scripts); id != "" {
			r.IOCs[i].Type = "script"
			if r.IOCs[i].SameAs == "" {
				r.IOCs[i].PartOf = id
			}
		}
	}
}

// scriptOwner returns the payload ID whose script source equals v, contains
// it, or contains one of the VBA string literals of v (a source line that
// builds the script). Short values are ignored to avoid accidental matches.
func scriptOwner(v string, scripts map[string]string) string {
	if id, ok := scripts[v]; ok {
		return id
	}
	if len(v) < 16 {
		return ""
	}
	for s, id := range scripts {
		if strings.Contains(s, v) {
			return id
		}
	}
	for _, m := range reVBAString.FindAllStringSubmatch(v, -1) {
		lit := strings.ReplaceAll(m[1], `""`, `"`)
		if len(lit) < 16 {
			continue
		}
		for s, id := range scripts {
			if strings.Contains(s, lit) {
				return id
			}
		}
	}
	return ""
}

var reVBAString = regexp.MustCompile(`"((?:[^"]|"")*)"`)

func finalizeReport(r *report.Report) {
	recoverCommands(r)
	profileArtifacts(r)
	r.IOCs = dedupeIOCs(r.IOCs)
	for i := range r.IOCs {
		r.IOCs[i].ID = fmt.Sprintf("indicator-%d", i+1)
	}
	linkDuplicateIndicators(r)
	r.Indicators = r.IOCs
	for i := range r.Diagnostics {
		r.Diagnostics[i].ID = fmt.Sprintf("diagnostic-%d", i+1)
	}
	r.OperationalStatus = "completed"
	r.SemanticCoverage = "supported_subset"
	if hasWarnings(r.Diagnostics) || len(r.LimitsHit) > 0 {
		r.SemanticCoverage = "partial"
		if r.Status == "complete" {
			r.Status = "partial"
		}
	}
	if r.Status == "timeout" || r.Status == "failed" {
		r.OperationalStatus = r.Status
		r.SemanticCoverage = "partial"
	}
	r.Stats.IOCCount = len(r.IOCs)
	computeVerdict(r)
}
