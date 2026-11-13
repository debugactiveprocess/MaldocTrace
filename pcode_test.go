package maldoctrace

import (
	"sort"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

// stomp wipes every module source after extraction, keeping the compiled
// p-code: the state of a VBA-stomped document (the source is removed or
// replaced, Office runs the p-code).
func stomp(decoy string) func(*extractor.Result) {
	return func(res *extractor.Result) {
		for _, m := range res.Modules {
			m.Code = decoy
			m.CodeRaw = []byte(decoy)
		}
	}
}

func commandSet(r *report.Report) []string {
	var out []string
	for _, c := range r.Commands {
		out = append(out, c.CommandLine)
	}
	sort.Strings(out)
	return out
}

func iocSet(r *report.Report) map[string]bool {
	out := map[string]bool{}
	for _, i := range r.Indicators {
		if i.Type != "command" {
			out[i.Type+"\x00"+i.Value] = true
		}
	}
	return out
}

// A stomped copy of each sample (source wiped or replaced by a decoy) must
// yield the same commands and indicators as the intact document, because the
// code is rebuilt from the p-code. The samples cover VBA6 and VBA7, 32- and
// 64-bit p-code, Declare with Lib/Alias, fixed arrays, With blocks, For
// loops and document-variable droppers.
func TestStompedSamplesRecoveredFromPCode(t *testing.T) {
	samples := []string{
		"0bd775f01fd87ec79164a6665f01a7f63b76359c09023326e7bc74cf48f23741.doc",
		"8f16fff004d1af4665bfb42bd08a93b204f19dca5adcde751d9dc7541e38aac9.doc",
		"394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc.doc",
		"7dbd8ecfada1d39a81a58c9468b91039.doc",
		"PO-465514-180820.doc.bin",
		"9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66.bin",
		"Commercial_Invoice.doc.bin",
	}
	decoys := map[string]string{
		"empty source": "",
		"decoy source": "Attribute VB_Name = \"Module1\"\r\nSub Hello()\r\n    MsgBox \"Quarterly report\"\r\nEnd Sub\r\n",
	}
	for _, name := range samples {
		data := readSample(t, name)
		want := AnalyzeFromBytes(nil, data, name, Options{})
		for label, decoy := range decoys {
			t.Run(name[:12]+"/"+label, func(t *testing.T) {
				got := AnalyzeFromBytes(nil, data, name, Options{afterExtract: stomp(decoy)})
				if !hasFinding(got, "vba_stomping") {
					t.Fatalf("stomping not reported: %+v", got.StaticFindings)
				}
				fromPCode := 0
				for _, m := range got.Modules {
					if m.FromPCode {
						fromPCode++
						if m.PCodeSource == "" {
							t.Errorf("module %s: rebuilt code not in the report", m.Name)
						}
					}
				}
				if fromPCode == 0 {
					t.Fatal("no module analysed from p-code")
				}
				if g, w := commandSet(got), commandSet(want); strings.Join(g, "\n") != strings.Join(w, "\n") {
					t.Fatalf("commands differ:\n got %q\nwant %q", g, w)
				}
				gi, wi := iocSet(got), iocSet(want)
				for k := range wi {
					if !gi[k] {
						t.Errorf("indicator lost: %q", strings.ReplaceAll(k, "\x00", " "))
					}
				}
				if got.Verdict != want.Verdict {
					t.Errorf("verdict %s, want %s", got.Verdict, want.Verdict)
				}
			})
		}
	}
}

// Intact documents are not flagged and keep their source.
func TestIntactSamplesNotStomped(t *testing.T) {
	for _, name := range []string{
		"0bd775f01fd87ec79164a6665f01a7f63b76359c09023326e7bc74cf48f23741.doc",
		"PO-465514-180820.doc.bin",
		"9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66.bin",
		"394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc.doc",
	} {
		r := AnalyzeFromBytes(nil, readSample(t, name), name, Options{})
		if hasFinding(r, "vba_stomping") {
			t.Errorf("%s: unexpected stomping finding %+v", name, r.StaticFindings)
		}
		for _, m := range r.Modules {
			if m.FromPCode {
				t.Errorf("%s: module %s analysed from p-code", name, m.Name)
			}
		}
	}
}
