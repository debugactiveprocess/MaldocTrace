package payload

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// The buffers below imitate the layout of common stagers (API hash pushes,
// strings, immediates) so the profiler can be tested. They are not
// functional code.

func push(v uint32) []byte { return binary.LittleEndian.AppendUint32([]byte{0x68}, v) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestROR13KnownValue(t *testing.T) {
	// Published block_api hash of kernel32.dll!LoadLibraryA.
	if h := ROR13Hash("kernel32.dll", "LoadLibraryA"); h != 0x0726774C {
		t.Fatalf("hash = 0x%08X", h)
	}
}

func callEBP() []byte { return []byte{0xFF, 0xD5} }

func TestProfileReverseHTTPSClassic(t *testing.T) {
	b := cat([]byte{0xFC, 0xE8, 0x82, 0, 0, 0},
		push(ROR13Hash("kernel32.dll", "LoadLibraryA")), callEBP(),
		push(ROR13Hash("wininet.dll", "InternetOpenA")), callEBP(),
		[]byte{0x53, 0x53, 0x6A, 0x03, 0x53, 0x53}, push(443), []byte{0xE8, 0x10, 0, 0, 0},
		[]byte("/a1b2c3\x00"),
		push(ROR13Hash("wininet.dll", "InternetConnectA")), callEBP(),
		push(0x84A83200), push(ROR13Hash("wininet.dll", "HttpOpenRequestA")), callEBP(),
		[]byte("Mozilla/5.0 (Windows NT 10.0)\x00"),
		push(ROR13Hash("wininet.dll", "HttpSendRequestA")), callEBP(),
		[]byte("c2.example.net\x00"))
	p := ProfileShellcode(b)
	if p.Empty() || p.Arch != "x86" || !strings.Contains(p.Hashing, "block_api") {
		t.Fatalf("profile = %+v", p)
	}
	if len(p.APIs) != 5 || p.APIs[2] != "wininet.dll!InternetConnectA" {
		t.Errorf("APIs = %v", p.APIs)
	}
	n := p.Network
	if n == nil || n.Kind != "reverse_https" || n.Host != "c2.example.net" || n.Port != 443 || n.URI != "/a1b2c3" || !strings.HasPrefix(n.UserAgent, "Mozilla/5.0") {
		t.Fatalf("network = %+v", n)
	}
	if n.URL() != "https://c2.example.net/a1b2c3" {
		t.Errorf("URL = %s", n.URL())
	}
	if p.Kind() != "shellcode, x86, reverse_https stager" {
		t.Errorf("kind = %s", p.Kind())
	}
}

// seeded computes the randomized block_api hash (seed, module without
// terminator, function with terminator), written independently of chainedTable.
func seeded(seed uint32, module, fn string) uint32 {
	h := seed
	for _, c := range []byte(strings.ToUpper(module)) {
		h = (h>>13 | h<<19) + uint32(c)
		h = (h>>13 | h<<19) + 0
	}
	for _, c := range append([]byte(fn), 0) {
		h = (h>>13 | h<<19) + uint32(c)
	}
	return h
}

func TestProfileSeededHashes(t *testing.T) {
	const seed = 0x30FE5C71
	b := cat([]byte{0xFC, 0xE8, 0x90, 0, 0, 0, 0x60}, binary.LittleEndian.AppendUint32([]byte{0xBF}, seed), []byte{0x31, 0xC0, 0xAC, 0x3C, 0x61},
		push(seeded(seed, "kernel32.dll", "LoadLibraryA")), callEBP(),
		push(seeded(seed, "wininet.dll", "InternetOpenA")), callEBP(),
		push(8443), []byte{0xE8, 0x05, 0, 0, 0}, []byte("/uri\x00"),
		push(seeded(seed, "wininet.dll", "InternetConnectA")), callEBP(),
		push(seeded(seed, "wininet.dll", "InternetSetOptionA")), callEBP(),
		[]byte("Host: front.example.com\r\n\x00"),
		[]byte("10.0.0.5\x00"))
	p := ProfileShellcode(b)
	if p.Empty() || !strings.Contains(p.Hashing, "0x30FE5C71") || len(p.APIs) != 4 {
		t.Fatalf("profile = %+v", p)
	}
	n := p.Network
	if n == nil || n.Kind != "reverse_https" || n.Host != "10.0.0.5" || n.Port != 8443 || n.HostHeader != "front.example.com" {
		t.Fatalf("network = %+v", n)
	}
	if got := strings.Join(p.Indicators(), " "); !strings.Contains(got, "https://10.0.0.5:8443/uri") || !strings.Contains(got, "front.example.com") {
		t.Errorf("indicators = %s", got)
	}
}

func TestProfileReverseTCP(t *testing.T) {
	b := cat([]byte{0xFC, 0xE8, 0x82, 0, 0, 0},
		push(ROR13Hash("ws2_32.dll", "WSAStartup")), callEBP(),
		[]byte{0x68, 192, 0, 2, 10, 0x68, 0x02, 0x00, 0x11, 0x5C}, // push 192.0.2.10; push port 4444, AF_INET
		push(ROR13Hash("ws2_32.dll", "connect")), callEBP())
	p := ProfileShellcode(b)
	if p.Network == nil || p.Network.Kind != "reverse_tcp" || p.Network.Host != "192.0.2.10" || p.Network.Port != 4444 {
		t.Fatalf("network = %+v", p.Network)
	}
}

func TestProfileXORLayers(t *testing.T) {
	url := "http://stage2.example.org/p.png"
	enc := make([]byte, len(url))
	for i := range url {
		enc[i] = url[i] ^ 0xE4
	}
	// xor byte ptr [rcx], 0x1b ; inc rcx ; ... followed by the encoded data
	b := cat([]byte{0x90, 0x55, 0x48, 0x89, 0xE5, 0x80, 0x31, 0x1B, 0x48, 0xFF, 0xC1, 0x90, 0x90, 0x90, 0x90, 0x90}, enc, make([]byte, 16))
	p := ProfileShellcode(b)
	if p.Empty() || len(p.XORStubs) != 1 || p.XORStubs[0].Key != 0x1B || p.XORStubs[0].Offset != 5 {
		t.Fatalf("stubs = %+v", p)
	}
	if len(p.XORKeys) != 1 || p.XORKeys[0].Key != 0xE4 || p.XORKeys[0].URLs[0] != url {
		t.Fatalf("xor keys = %+v", p.XORKeys)
	}
}

func TestProfileSkipsFilesAndNoise(t *testing.T) {
	if ProfileShellcode([]byte("MZ\x90\x00 this is a PE header and more bytes")) != nil {
		t.Error("PE treated as shellcode")
	}
	if p := ProfileShellcode(bytes.Repeat([]byte("plain text without code "), 20)); p != nil {
		t.Errorf("text treated as shellcode: %+v", p)
	}
}

func TestDescribePE(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil || len(b) < 2 || b[0] != 'M' || b[1] != 'Z' {
		t.Skip("test binary is not a PE on this platform")
	}
	kind, facts := DescribeBinary(b)
	all := strings.Join(facts, "\n")
	if !strings.Contains(kind, "executable") || !strings.Contains(all, "entry_point=0x") || !strings.Contains(all, "sections=.text(") || !strings.Contains(all, "subsystem=console") {
		t.Fatalf("kind=%s facts=%v", kind, facts)
	}
}

func FuzzProfileShellcode(f *testing.F) {
	f.Add([]byte{0xFC, 0xE8, 0x82, 0, 0, 0, 0x68, 0x4C, 0x77, 0x26, 0x07, 0xFF, 0xD5})
	f.Add([]byte{0x80, 0x31, 0x1B, 0x41, 0xBA, 0, 0, 0, 0, 0xBF, 1, 2, 3, 4, 0x31, 0xC0, 0xAC})
	f.Fuzz(func(t *testing.T, b []byte) {
		p := ProfileShellcode(b)
		p.Facts()
		p.Indicators()
		p.Kind()
	})
}
