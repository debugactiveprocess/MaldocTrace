package extractor

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

func xst(s string) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(s)))
	return append(b, utf16le(s)...)
}

// A Word 97-2003 file whose StwUser holds two document variables.
func TestWordDocumentVariables(t *testing.T) {
	names := []string{"enckey", "chunk0"}
	vals := []string{"zCQiEEKsdI", "KghSbVFFQ3tsSR8x"}
	stw := []byte{0xFF, 0xFF}
	stw = binary.LittleEndian.AppendUint16(stw, uint16(len(names)))
	stw = binary.LittleEndian.AppendUint16(stw, 4) // cbExtra
	for _, n := range names {
		stw = append(stw, xst(n)...)
		stw = append(stw, 0, 0, 0, 0)
	}
	for _, v := range vals {
		stw = append(stw, xst(v)...)
	}
	table := append(make([]byte, 64), stw...)
	wd := make([]byte, 0x400)
	binary.LittleEndian.PutUint16(wd, 0xA5EC)
	binary.LittleEndian.PutUint16(wd[0x0A:], 0x0200) // fWhichTblStm: 1Table
	binary.LittleEndian.PutUint32(wd[0x27A:], 64)
	binary.LittleEndian.PutUint32(wd[0x27E:], uint32(len(stw)))
	data := cfbtest.Build(cfbtest.Stream{Name: "WordDocument", Data: wd}, cfbtest.Stream{Name: "1Table", Data: table})
	res, err := Extract(context.Background(), data, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range res.Properties {
		if p.Kind == "variable" {
			got[p.Name] = p.Value
		}
	}
	for i, n := range names {
		if got[n] != vals[i] {
			t.Fatalf("variables = %v (diags %+v)", got, res.Diagnostics)
		}
	}
}
