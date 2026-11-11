package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"maldoctrace/report"
)

func testReport() *report.Report {
	return &report.Report{
		File: report.FileInfo{Path: "in.doc", SHA256: "abc123"},
		DecodedPayloads: []report.DecodedPayload{
			{ID: "payload-1", Kind: "certutil", Category: "binary", FileType: "PE32 DLL", Raw: []byte("MZ\x00\x01"), SHA256: sha("MZ\x00\x01")},
			{ID: "payload-2", Kind: "Script (JScript)", Category: "script", Raw: []byte("function f(){}")},
			{ID: "payload-3", Kind: "failed", Category: "binary"}, // no bytes: skipped
		},
		Artifacts: []report.Artifact{{Path: `C:\x.xls`, SHA256: sha("TVqQ"), Raw: []byte("TVqQ")}},
	}
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestDumpPayloads(t *testing.T) {
	dir := t.TempDir()
	written, err := dumpPayloads(testReport(), dir)
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "abc123")
	want := []string{"payload-1.bin", "payload-2.txt", "artifact-1.bin", "manifest.json"}
	if len(written) != len(want) {
		t.Fatalf("written=%v", written)
	}
	for _, w := range want {
		if _, err := os.Stat(filepath.Join(sub, w)); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(sub, "payload-1.bin")); string(b) != "MZ\x00\x01" {
		t.Fatalf("content %q", b)
	}
	var m dumpManifest
	b, _ := os.ReadFile(filepath.Join(sub, "manifest.json"))
	if err := json.Unmarshal(b, &m); err != nil || m.SHA256 != "abc123" || len(m.Generated) != 3 || m.Warning == "" {
		t.Fatalf("manifest=%+v err=%v", m, err)
	}
	for _, e := range m.Generated {
		if e.ReportSHA != "" && e.ReportSHA != e.FileSHA256 {
			t.Fatalf("hash mismatch for %s", e.File)
		}
		if strings.HasSuffix(e.File, ".exe") || strings.HasSuffix(e.File, ".dll") {
			t.Fatalf("executable extension: %s", e.File)
		}
	}
	if m.Generated[2].OriginPath != `C:\x.xls` {
		t.Fatalf("%+v", m.Generated[2])
	}
	// A second dump must refuse to overwrite and leave files untouched.
	if _, err := dumpPayloads(testReport(), dir); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err=%v", err)
	}
}

func TestDumpNothingToWrite(t *testing.T) {
	dir := t.TempDir()
	written, err := dumpPayloads(&report.Report{File: report.FileInfo{SHA256: "e"}}, dir)
	if err != nil || len(written) != 0 {
		t.Fatalf("%v %v", written, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("empty report must not create directories")
	}
}

func TestDumpFlagEndToEnd(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "m.bas")
	os.WriteFile(src, []byte("Sub AutoOpen()\nSet sc = CreateObject(\"MSScriptControl.ScriptControl\")\nsc.Language = \"JScript\"\nsc.AddCode \"function go(){}\"\nsc.Run \"go\"\nEnd Sub"), 0o644)
	out := filepath.Join(dir, "out")
	if err := runAnalyze([]string{src, "--input-format", "vba", "--format", "json", "--dump-payloads", out}); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(out, "*", "payload-1.txt"))
	if len(matches) != 1 {
		t.Fatalf("matches=%v", matches)
	}
	if b, _ := os.ReadFile(matches[0]); string(b) != "function go(){}" {
		t.Fatalf("%q", b)
	}
}

func TestDumpDirInsideScannedTreeRejected(t *testing.T) {
	dir := t.TempDir()
	if err := runAnalyze([]string{dir, "--recursive", "--format", "jsonl", "--dump-payloads", filepath.Join(dir, "dumps")}); !isUsage(err) {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestIsWithin(t *testing.T) {
	for _, tc := range []struct {
		path, root string
		want       bool
	}{
		{"a/b", "a", true}, {"a", "a", true}, {"ab", "a", false}, {"../x", ".", false}, {"..x", ".", true},
	} {
		if got, _ := isWithin(tc.path, tc.root); got != tc.want {
			t.Errorf("isWithin(%q,%q)=%v", tc.path, tc.root, got)
		}
	}
}
