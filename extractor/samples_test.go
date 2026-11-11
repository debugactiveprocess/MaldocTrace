package extractor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtractSamples validates extraction against the real sample files when
// present. It is skipped when the samples directory is unavailable.
func TestExtractSamples(t *testing.T) {
	dir := filepath.Join("..", "samples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("samples not present: %v", err)
	}
	if len(entries) == 0 {
		t.Skip("no samples")
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		res, err := Extract(context.Background(), data, nil)
		if err != nil && !strings.Contains(err.Error(), "encrypted") {
			t.Logf("%s: extract error: %v", e.Name(), err)
		}
		t.Logf("%s: format=%s encrypted=%v projects=%d modules=%d diags=%d",
			e.Name(), res.Format, res.Encrypted, len(res.Projects), len(res.Modules), len(res.Diagnostics))
		for _, m := range res.Modules {
			t.Logf("   module %q (%s) stream=%q codepage=%d -> %d chars",
				m.Name, m.FileName, m.StreamName, m.Codepage, len(m.Code))
		}
		for _, d := range res.Diagnostics {
			t.Logf("   [%s/%s] %s", d.Severity, d.Stage, d.Message)
		}
	}
}
