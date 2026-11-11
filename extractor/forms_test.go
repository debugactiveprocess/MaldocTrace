package extractor

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSampleFormsInventory(t *testing.T) {
	b, err := os.ReadFile("../samples/PO-465514-180820.doc.bin")
	if err != nil {
		t.Skip(err)
	}
	r, err := Extract(context.Background(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Forms {
		t.Logf("%s %s class=%d offset=%d size=%d props=%q", f.Module, f.Name, f.Class, f.Offset, f.ObjectSize, f.Properties)
	}
	lim := DefaultLimits()
	c, _ := parseCFB(b, &lim)
	for _, p := range c.listStreams() {
		if len(p) > 0 {
			t.Log(p)
			if strings.HasSuffix(p, "/f") {
				d, _ := c.readStream(p)
				t.Logf("header %x", d[:min(len(d), 96)])
			}
		}
	}
}
