package payload

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func TestDecodeUTF7(t *testing.T) {
	for in, want := range map[string]string{
		"Hi Mom -+Jjo--!": "Hi Mom -☺-!",
		"+AGEAYgBj-":      "abc",
		"1 +- 1":          "1 + 1",
		"+ZeVnLIqe-":      "日本語",
		"a\x00+AGI-":      "a\x00b",
	} {
		got, err := DecodeUTF7([]byte(in))
		if err != nil || !bytes.Equal(got, utf16le(want)) {
			t.Errorf("%q: got % x err=%v", in, got, err)
		}
	}
	if _, err := DecodeUTF7([]byte{'a', 0xff}); err == nil {
		t.Error("expected error for 8-bit input")
	}
}

func TestDisplayBytes(t *testing.T) {
	if s, k := DisplayBytes([]byte("+AGE-\x00x")); k != "text" || s != `+AGE-\x00x` {
		t.Fatalf("%q %s", s, k)
	}
	if s, k := DisplayBytes([]byte{0x90, 0x55, 0x48, 0x89, 0xe5}); k != "hex" || s != "90554889e5" {
		t.Fatalf("%q %s", s, k)
	}
}
