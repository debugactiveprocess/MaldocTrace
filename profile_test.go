package maldoctrace

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/payload"
)

// A macro that keeps a stager as hex text across string literals. The bytes
// imitate a reverse_https stager's layout (API hash pushes, port, strings);
// they are not functional code.
func TestHexLiteralShellcodeProfiled(t *testing.T) {
	push := func(v uint32) []byte { return binary.LittleEndian.AppendUint32([]byte{0x68}, v) }
	var sc []byte
	for _, part := range [][]byte{
		{0xFC, 0xE8, 0x82, 0, 0, 0},
		push(payload.ROR13Hash("kernel32.dll", "LoadLibraryA")), {0xFF, 0xD5},
		push(payload.ROR13Hash("wininet.dll", "InternetOpenA")), {0xFF, 0xD5},
		push(8080), {0xE8, 0x06, 0, 0, 0}, []byte("/stage\x00"),
		push(payload.ROR13Hash("wininet.dll", "InternetConnectA")), {0xFF, 0xD5},
		push(payload.ROR13Hash("wininet.dll", "HttpOpenRequestA")), {0xFF, 0xD5},
		[]byte("Mozilla/5.0 (test)\x00c2.test.invalid\x00"),
		make([]byte, 64),
	} {
		sc = append(sc, part...)
	}
	h := hex.EncodeToString(sc)
	var vba strings.Builder
	vba.WriteString("Sub AutoOpen()\n    Dim h As String\n")
	for i := 0; i < len(h); i += 96 {
		end := min(i+96, len(h))
		if i == 0 {
			vba.WriteString(`    h = "` + h[i:end] + "\"\n")
		} else {
			vba.WriteString(`    h = h & "` + h[i:end] + "\"\n")
		}
	}
	vba.WriteString("End Sub\n")
	r := AnalyzeFromBytes(context.Background(), []byte(vba.String()), "m.vba", Options{})
	if len(r.DecodedPayloads) != 1 {
		t.Fatalf("payloads = %+v", r.DecodedPayloads)
	}
	p := r.DecodedPayloads[0]
	if p.FileType != "shellcode, x86, reverse_http stager" || !strings.HasPrefix(p.Kind, "Hex string literals (Module1.AutoOpen") {
		t.Fatalf("payload = %s / %s / %v", p.Kind, p.FileType, p.Facts)
	}
	if _, ok := iocValues(r, "url")["http://c2.test.invalid:8080/stage"]; !ok {
		t.Errorf("stager URL not reported: %+v", r.IOCs)
	}
}
