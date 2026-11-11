package maldoctrace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"maldoctrace/indicators"
	"maldoctrace/payload"
	"maldoctrace/report"
)

// vfsFile is a file the macro wrote in the simulated environment.
type vfsFile struct {
	content []byte
	origin  string // evidence ID that produced it
}

func normPath(p string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(strings.Trim(p, `"`)), "/", `\`))
}

// buildVFS collects simulated file writes (Document.SaveAs, ADODB.Stream
// SaveToFile, ...) in order; later writes to the same path win.
func buildVFS(r *report.Report) map[string]vfsFile {
	vfs := map[string]vfsFile{}
	for _, e := range r.Events {
		h := e.Extra["content_hex"]
		if h == "" || len(e.Resolved) == 0 {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			continue
		}
		vfs[normPath(e.Resolved[0])] = vfsFile{content: b, origin: fmt.Sprintf("event-%d", e.ID)}
	}
	return vfs
}

// followFileChains statically reproduces what recovered commands do with
// files the macro wrote: "certutil -decode in out" is decoded from the
// simulated file system, and later commands that use the output (rundll32,
// regsvr32, ...) are linked to the decoded payload. Nothing is executed.
func followFileChains(r *report.Report, total *int) {
	vfs := buildVFS(r)
	produced := map[string]string{} // normalized output path -> payload ID
	for _, c := range r.Commands {
		argv, err := payload.SplitCommand(c.CommandLine)
		if err != nil || len(argv) == 0 {
			continue
		}
		if dec, ok := payload.ParseCertutil(argv); ok {
			in, found := vfs[normPath(dec.In)]
			if !found {
				r.Diagnostics = append(r.Diagnostics, report.Diagnostic{Severity: "info", Stage: "payload",
					Message: "certutil input " + dec.In + " was not written by the macro; content unknown", EvidenceIDs: []string{c.ID}})
				continue
			}
			p := report.DecodedPayload{
				ID: fmt.Sprintf("payload-%d", len(r.DecodedPayloads)+1), Kind: "certutil -decode output → " + dec.Out,
				Category: "binary", DerivedFrom: c.ID, Depth: 1, Encoding: []string{"Base64 (certutil -decode)"},
			}
			if dec.Hex {
				p.Kind, p.Encoding = "certutil -decodehex output → "+dec.Out, []string{"hex (certutil -decodehex)"}
			}
			p.Details = append(p.Details, "input "+dec.In+" written by "+in.origin)
			var out []byte
			if *total >= 4*payload.MaxPayloadBytes*16 {
				err = fmt.Errorf("aggregate decoded payload budget exhausted")
			} else {
				out, err = payload.DecodeCertutil(in.content, dec.Hex)
			}
			if err != nil {
				p.Status, p.Error = "error", err.Error()
				p.Content, _ = payload.DisplayBytes(in.content)
				r.DecodedPayloads = append(r.DecodedPayloads, p)
				continue
			}
			*total += len(out)
			sum := sha256.Sum256(out)
			p.Status, p.Size, p.SHA256, p.Raw = "decoded", len(out), hex.EncodeToString(sum[:]), out
			p.Content, _ = payload.DisplayBytes(out)
			p.FileType, p.Facts = payload.DescribeBinary(out)
			scanBinaryStrings(r, out, p.ID, c.Source)
			r.DecodedPayloads = append(r.DecodedPayloads, p)
			vfs[normPath(dec.Out)] = vfsFile{content: out, origin: p.ID}
			produced[normPath(dec.Out)] = p.ID
			continue
		}
		// Link later commands that load a decoded file.
		for _, a := range argv[1:] {
			target := a
			if i := strings.LastIndex(target, ","); i > 0 { // rundll32 file,Export
				target = target[:i]
			}
			if id, ok := produced[normPath(target)]; ok {
				for i := range r.DecodedPayloads {
					if r.DecodedPayloads[i].ID == id {
						r.DecodedPayloads[i].Details = append(r.DecodedPayloads[i].Details, "loaded by "+c.ID+": "+c.CommandLine)
					}
				}
			}
		}
	}
}

// scanBinaryStrings extracts network indicators from printable strings of a
// binary payload. Path and command heuristics are skipped: on arbitrary
// binaries they mostly produce noise.
func scanBinaryStrings(r *report.Report, b []byte, id string, src report.Source) {
	for _, s := range payload.PrintableStrings(b, 6, 20000) {
		for _, f := range indicators.ScanValue(s) {
			switch f.Type {
			case "url", "ipv4", "domain":
				r.IOCs = append(r.IOCs, report.IOC{Type: f.Type, Value: f.Value, Discovery: "decoded_payload",
					Occurrences: []report.Occurrence{{Module: src.Module, Proc: src.Proc, Line: src.Line, Evidence: f.Evidence, EvidenceID: id, Discovery: "decoded_payload"}}})
			}
		}
	}
}
