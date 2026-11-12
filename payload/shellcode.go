package payload

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// ShellcodeProfile summarises what static inspection can tell about a raw
// code buffer: the API resolution technique, the APIs it resolves, simple
// XOR decoders and the network configuration of common stagers. Nothing is
// executed or emulated.
type ShellcodeProfile struct {
	Arch     string   // "x86", "x64" or ""
	Hashing  string   // e.g. "ROR13 (Metasploit block_api)"
	APIs     []string // resolved APIs, in order of first use
	XORStubs []XORStub
	XORKeys  []XORReveal
	Strings  []string // notable printable strings (ASCII and UTF-16)
	Network  *NetConfig
}

// XORStub is an instruction that XORs memory with a constant byte, the core
// of a self-decoding loop.
type XORStub struct {
	Offset int
	Key    byte
}

// XORReveal is a single-byte XOR key under which URLs appear.
type XORReveal struct {
	Key  byte
	URLs []string
}

// NetConfig is the connection a stager would make.
type NetConfig struct {
	Kind       string // reverse_tcp, reverse_http, reverse_https, download
	Host       string
	Port       int
	URI        string
	UserAgent  string
	HostHeader string
}

// URL returns the stager URL for HTTP(S) stagers.
func (n *NetConfig) URL() string {
	if n == nil || n.Host == "" || !strings.HasPrefix(n.Kind, "reverse_http") {
		return ""
	}
	scheme, def := "http", 80
	if n.Kind == "reverse_https" {
		scheme, def = "https", 443
	}
	host := n.Host
	if n.Port != 0 && n.Port != def {
		host = net.JoinHostPort(n.Host, fmt.Sprint(n.Port))
	}
	return scheme + "://" + host + n.URI
}

// Empty reports whether nothing was recognised.
func (p *ShellcodeProfile) Empty() bool {
	return p == nil || (len(p.APIs) == 0 && len(p.XORStubs) == 0 && len(p.XORKeys) == 0 && p.Network == nil)
}

// Facts renders the profile as report lines.
func (p *ShellcodeProfile) Facts() []string {
	if p.Empty() {
		return nil
	}
	var f []string
	if p.Hashing != "" {
		f = append(f, "API resolution: "+p.Hashing)
	}
	if len(p.APIs) > 0 {
		f = append(f, "resolves: "+strings.Join(p.APIs, ", "))
	}
	for _, s := range p.XORStubs {
		f = append(f, fmt.Sprintf("XOR decoder stub at offset 0x%x (key 0x%02X)", s.Offset, s.Key))
	}
	for _, x := range p.XORKeys {
		f = append(f, fmt.Sprintf("single-byte XOR key 0x%02X reveals: %s", x.Key, strings.Join(x.URLs, ", ")))
	}
	if n := p.Network; n != nil {
		line := "network: " + n.Kind
		switch {
		case n.URL() != "":
			line += " → " + n.URL()
		case n.Host != "" && n.Port != 0:
			line += " → " + net.JoinHostPort(n.Host, fmt.Sprint(n.Port))
		case n.Host != "":
			line += " → " + n.Host
		}
		f = append(f, line)
		if n.HostHeader != "" {
			f = append(f, "HTTP Host header: "+n.HostHeader+" (differs from the connection host: domain fronting)")
		}
		if n.UserAgent != "" {
			f = append(f, "User-Agent: "+n.UserAgent)
		}
	}
	return f
}

// Indicators returns network values worth reporting as IOCs.
func (p *ShellcodeProfile) Indicators() []string {
	if p == nil {
		return nil
	}
	var out []string
	if n := p.Network; n != nil {
		if u := n.URL(); u != "" {
			out = append(out, u)
		} else if n.Host != "" {
			out = append(out, n.Host)
		}
		if n.HostHeader != "" {
			out = append(out, n.HostHeader)
		}
	}
	for _, x := range p.XORKeys {
		out = append(out, x.URLs...)
	}
	return out
}

// Kind returns a short file-type label.
func (p *ShellcodeProfile) Kind() string {
	if p.Empty() {
		return ""
	}
	parts := []string{"shellcode"}
	if p.Arch != "" {
		parts = append(parts, p.Arch)
	}
	if p.Network != nil {
		parts = append(parts, p.Network.Kind+" stager")
	}
	return strings.Join(parts, ", ")
}

// --- API hashing ---------------------------------------------------------

func ror13(v uint32) uint32 { return v>>13 | v<<19 }

// ror13Module hashes a module name the way block_api walks BaseDllName:
// every byte of the upper-cased UTF-16LE string, terminator included.
func ror13Module(name string) uint32 {
	var h uint32
	for _, u := range utf16.Encode([]rune(strings.ToUpper(name) + "\x00")) {
		h = ror13(h) + uint32(u&0xff)
		h = ror13(h) + uint32(u>>8)
	}
	return h
}

func ror13Func(name string) uint32 {
	var h uint32
	for _, c := range []byte(name + "\x00") {
		h = ror13(h) + uint32(c)
	}
	return h
}

var shellcodeAPIs = map[string][]string{
	"kernel32.dll": {"LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc", "VirtualProtect", "VirtualFree",
		"ExitProcess", "ExitThread", "CreateProcessA", "CreateThread", "WaitForSingleObject", "GetVersion", "Sleep",
		"WinExec", "GetModuleHandleA", "CloseHandle", "CreateFileA", "WriteFile", "GetTempPathA", "SetUnhandledExceptionFilter"},
	"ntdll.dll": {"RtlExitUserThread", "NtAllocateVirtualMemory", "RtlCreateUserThread"},
	"wininet.dll": {"InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "HttpOpenRequestA", "HttpOpenRequestW",
		"HttpSendRequestA", "HttpSendRequestW", "InternetReadFile", "InternetSetOptionA", "InternetErrorDlg", "HttpQueryInfoA",
		"InternetCloseHandle", "InternetOpenUrlA", "HttpAddRequestHeadersA"},
	"winhttp.dll": {"WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse",
		"WinHttpReadData", "WinHttpSetOption", "WinHttpQueryHeaders"},
	"ws2_32.dll": {"WSAStartup", "WSASocketA", "connect", "bind", "listen", "accept", "recv", "send", "closesocket",
		"gethostbyname", "inet_addr", "WSACleanup"},
	"urlmon.dll":  {"URLDownloadToFileA", "URLDownloadToFileW"},
	"user32.dll":  {"MessageBoxA", "GetDesktopWindow"},
	"shell32.dll": {"ShellExecuteA"},
	"dnsapi.dll":  {"DnsQuery_A"},
}

var ror13Table = func() map[uint32]string {
	t := map[uint32]string{}
	for mod, fns := range shellcodeAPIs {
		mh := ror13Module(mod)
		for _, fn := range fns {
			t[mh+ror13Func(fn)] = mod + "!" + fn
		}
	}
	return t
}()

// chainedTable builds hashes for the randomized block_api variant: the hash
// starts from a seed, runs over the upper-cased UTF-16LE module name (no
// terminator) and continues over the function name (with terminator).
func chainedTable(seed uint32) map[uint32]string {
	t := map[uint32]string{}
	for mod, fns := range shellcodeAPIs {
		h := seed
		for _, u := range utf16.Encode([]rune(strings.ToUpper(mod))) {
			h = ror13(h) + uint32(u&0xff)
			h = ror13(h) + uint32(u>>8)
		}
		for _, fn := range fns {
			f := h
			for _, c := range append([]byte(fn), 0) {
				f = ror13(f) + uint32(c)
			}
			t[f] = mod + "!" + fn
		}
	}
	return t
}

// hashSeeds finds "mov edi, imm32" (x86) or "mov r9d, imm32" (x64) right
// before the hashing loop (xor eax,eax; lodsb), which seeds the hash.
func hashSeeds(b []byte) []uint32 {
	var out []uint32
	for i := 0; i+8 <= len(b) && len(out) < 4; i++ {
		switch {
		case b[i] == 0xBF && bytes.HasPrefix(b[i+5:], []byte{0x31, 0xC0, 0xAC}):
			out = append(out, binary.LittleEndian.Uint32(b[i+1:]))
		case b[i] == 0x41 && b[i+1] == 0xB9 && i+9 <= len(b) && bytes.HasPrefix(b[i+6:], []byte{0x48, 0x31, 0xC0}):
			out = append(out, binary.LittleEndian.Uint32(b[i+2:]))
		}
	}
	return out
}

// hashHits returns API hashes used as "push imm32" or "mov r10d, imm32".
func hashHits(b []byte, t map[uint32]string) (hits []apiHit, x64 int) {
	for i := 0; i+4 <= len(b); i++ {
		name, ok := t[binary.LittleEndian.Uint32(b[i:])]
		if !ok {
			continue
		}
		switch {
		case i >= 2 && b[i-2] == 0x41 && b[i-1] == 0xBA:
			x64++
		case i >= 1 && b[i-1] == 0x68:
		default:
			continue
		}
		hits = append(hits, apiHit{i, name})
	}
	return hits, x64
}

// bestHashTable tries the classic and the seeded block_api hashing and
// keeps the one that explains the most API hashes.
func bestHashTable(b []byte) ([]apiHit, int, string) {
	hits, x64 := hashHits(b, ror13Table)
	desc := "ROR13 module+function hashes (Metasploit block_api)"
	seeds := append(hashSeeds(b), 0)
	for _, s := range seeds {
		h, x := hashHits(b, chainedTable(s))
		if len(h) > len(hits) {
			hits, x64 = h, x
			desc = fmt.Sprintf("ROR13 chained hashes seeded with 0x%08X (Metasploit block_api, randomized)", s)
		}
	}
	return hits, x64, desc
}

// ROR13Hash returns the block_api hash of module!function (exported for tests).
func ROR13Hash(module, function string) uint32 { return ror13Module(module) + ror13Func(function) }

// --- profiling -----------------------------------------------------------

const maxProfileBytes = 4 << 20

var urlRe = regexp.MustCompile(`https?://[\x21-\x7e]{4,}`)

// ProfileShellcode inspects a raw code buffer. It returns nil when the
// buffer is a known file format (PE, ZIP, OLE, PDF) rather than code.
func ProfileShellcode(b []byte) *ShellcodeProfile {
	if len(b) < 16 {
		return nil
	}
	if ft, _ := DescribeBinary(b); ft != "" {
		return nil
	}
	if len(b) > maxProfileBytes {
		b = b[:maxProfileBytes]
	}
	p := &ShellcodeProfile{}
	hits, x64, hashing := bestHashTable(b)
	seen := map[string]bool{}
	for _, h := range hits {
		if !seen[h.name] {
			seen[h.name] = true
			p.APIs = append(p.APIs, h.name)
		}
	}
	if len(p.APIs) > 0 {
		p.Hashing = hashing
	}
	switch {
	case x64 > 0 || bytes.HasPrefix(b, []byte{0xFC, 0x48, 0x83, 0xE4, 0xF0}):
		p.Arch = "x64"
	case len(hits) > 0 || bytes.HasPrefix(b, []byte{0xFC, 0xE8}):
		p.Arch = "x86"
	}

	// XOR decoder stubs: xor byte ptr [reg], imm8 and xor byte ptr [reg+disp8], imm8.
	for i := 0; i+3 <= len(b) && len(p.XORStubs) < 4; i++ {
		if b[i] != 0x80 {
			continue
		}
		m := b[i+1]
		switch {
		case m >= 0x30 && m <= 0x37 && m != 0x34 && m != 0x35 && b[i+2] != 0:
			p.XORStubs = append(p.XORStubs, XORStub{i, b[i+2]})
		case m >= 0x70 && m <= 0x77 && m != 0x74 && i+4 <= len(b) && b[i+3] != 0:
			p.XORStubs = append(p.XORStubs, XORStub{i, b[i+3]})
		}
	}

	p.Strings = notableStrings(b)
	p.Network = netConfig(b, hits, p.Strings)

	// Single-byte XOR layers: keys under which URLs appear. Skipped when the
	// buffer already shows its URLs in the clear.
	if !urlRe.Match(b) {
		buf := make([]byte, len(b))
		for k := 1; k < 256 && len(p.XORKeys) < 3; k++ {
			for i := range b {
				buf[i] = b[i] ^ byte(k)
			}
			if urls := urlRe.FindAll(buf, 5); len(urls) > 0 {
				x := XORReveal{Key: byte(k)}
				for _, u := range urls {
					x.URLs = append(x.URLs, string(u))
				}
				p.XORKeys = append(p.XORKeys, x)
			}
		}
	}
	if p.Empty() {
		return nil
	}
	return p
}

type apiHit struct {
	off  int
	name string
}

var hostRe = regexp.MustCompile(`^(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})$`)

// notableStrings returns printable ASCII and UTF-16LE runs of 4+ chars.
func notableStrings(b []byte) []string {
	out := PrintableStrings(b, 4, 200)
	var cur []rune
	flush := func() {
		if len(cur) >= 4 {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 && b[i] >= 0x20 && b[i] < 0x7f {
			cur = append(cur, rune(b[i]))
			continue
		}
		flush()
	}
	flush()
	return out
}

// netConfig recovers the connection target of common stagers.
func netConfig(b []byte, hits []apiHit, strs []string) *NetConfig {
	has := func(names ...string) int {
		for _, h := range hits {
			for _, n := range names {
				if strings.HasSuffix(h.name, "!"+n) {
					return h.off
				}
			}
		}
		return -1
	}
	if off := has("InternetConnectA", "InternetConnectW", "WinHttpConnect"); off >= 0 {
		n := &NetConfig{Kind: "reverse_http"}
		if has("InternetSetOptionA", "WinHttpSetOption") >= 0 || secureFlags(b) {
			n.Kind = "reverse_https"
		}
		from := -1
		for _, h := range hits {
			if h.off < off && h.off > from {
				from = h.off // the previous API call (InternetOpen)
			}
		}
		if from < 0 {
			from = off - 48
		}
		n.Port = portBetween(b, from, off)
		for _, s := range strs {
			t := strings.TrimSpace(s)
			switch {
			case strings.HasPrefix(t, "Mozilla/") && n.UserAgent == "":
				n.UserAgent = t
			case strings.HasPrefix(strings.ToLower(t), "host:") && n.HostHeader == "":
				n.HostHeader = strings.TrimSpace(t[5:])
			case strings.HasPrefix(t, "/") && len(t) > 1 && n.URI == "":
				n.URI = t
			case hostRe.MatchString(t) && !strings.EqualFold(t, "wininet") && n.Host == "":
				n.Host = t
			}
		}
		return n
	}
	if has("connect") >= 0 {
		// x86: push <ip>; push 0x<port>0002   x64: mov r14, <ip><port>0002
		for i := 0; i+10 <= len(b); i++ {
			if b[i] == 0x68 && b[i+5] == 0x68 && b[i+6] == 0x02 && b[i+7] == 0x00 {
				return &NetConfig{Kind: "reverse_tcp", Host: net.IP(b[i+1 : i+5]).String(), Port: int(binary.BigEndian.Uint16(b[i+8:]))}
			}
			if i+10 <= len(b) && b[i] == 0x49 && b[i+1] == 0xBE && b[i+2] == 0x02 && b[i+3] == 0x00 {
				return &NetConfig{Kind: "reverse_tcp", Host: net.IP(b[i+6 : i+10]).String(), Port: int(binary.BigEndian.Uint16(b[i+4:]))}
			}
		}
		return &NetConfig{Kind: "reverse_tcp"}
	}
	if has("URLDownloadToFileA", "URLDownloadToFileW") >= 0 {
		for _, s := range strs {
			if u := urlRe.FindString(s); u != "" {
				return &NetConfig{Kind: "download", Host: u}
			}
		}
		return &NetConfig{Kind: "download"}
	}
	return nil
}

// portBetween finds the port pushed (x86 "push imm32") or moved into r8d
// (x64 "mov r8d, imm32") between the previous API call and the connect
// call's API hash; the host or URI string may sit in between.
func portBetween(b []byte, start, off int) int {
	if start < 0 {
		start = 0
	}
	for i := start; i < off; i++ {
		var v uint32
		switch {
		case b[i] == 0x68 && i+5 <= off:
			v = binary.LittleEndian.Uint32(b[i+1:])
		case b[i] == 0x41 && i+6 <= off && b[i+1] == 0xB8:
			v = binary.LittleEndian.Uint32(b[i+2:])
		default:
			continue
		}
		if v > 0 && v < 65536 && v != 3 { // 3 = INTERNET_SERVICE_HTTP
			return int(v) // the first one: the port is pushed before the flags
		}
	}
	return 0
}

// secureFlags reports a push of HttpOpenRequest flags that include
// INTERNET_FLAG_SECURE together with INTERNET_FLAG_RELOAD.
func secureFlags(b []byte) bool {
	for i := 0; i+5 <= len(b); i++ {
		if b[i] == 0x68 {
			v := binary.LittleEndian.Uint32(b[i+1:])
			if v&0x80000000 != 0 && v&0x00800000 != 0 && v&0x00000200 != 0 {
				return true
			}
		}
	}
	return false
}

// SortedAPIs is a helper for tests and stable output.
func (p *ShellcodeProfile) SortedAPIs() []string {
	out := append([]string{}, p.APIs...)
	sort.Strings(out)
	return out
}
