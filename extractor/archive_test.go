package extractor

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"testing"
)

func deflate(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// zipCryptoEncrypt applies the traditional PKWARE cipher (test only).
func zipCryptoEncrypt(plain []byte, password string, crc uint32) []byte {
	k := newZipCrypto(password)
	hdr := make([]byte, 12)
	for i := range hdr {
		hdr[i] = byte(i * 37)
	}
	hdr[11] = byte(crc >> 24)
	out := append(hdr, plain...)
	for i, c := range out {
		t := k[2] | 2
		out[i] = c ^ byte((t*(t^1))>>8)
		k.update(c)
	}
	return out
}

// winzipAESEncrypt builds an AE-2 payload: salt, verifier, data, MAC.
func winzipAESEncrypt(plain []byte, password string) []byte {
	salt := []byte("0123456789abcdef")
	dk := pbkdf2SHA1([]byte(password), salt, 1000, 66)
	block, _ := aes.NewCipher(dk[:32])
	enc := make([]byte, len(plain))
	var ctr, ks [16]byte
	for off := 0; off < len(plain); off += 16 {
		for i := 0; i < 16; i++ {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		block.Encrypt(ks[:], ctr[:])
		for i := 0; i < 16 && off+i < len(plain); i++ {
			enc[off+i] = plain[off+i] ^ ks[i]
		}
	}
	h := hmac.New(sha1.New, dk[32:64])
	h.Write(enc)
	out := append(append(append([]byte(nil), salt...), dk[64:66]...), enc...)
	return append(out, h.Sum(nil)[:10]...)
}

type rawMember struct {
	name   string
	plain  []byte
	method string // plain | zipcrypto | aes
	pw     string
}

func buildZip(t *testing.T, members ...rawMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		comp := deflate(m.plain)
		crc := crc32.ChecksumIEEE(m.plain)
		h := &zip.FileHeader{Name: m.name, Method: zip.Deflate, CRC32: crc, UncompressedSize64: uint64(len(m.plain))}
		var raw []byte
		switch m.method {
		case "zipcrypto":
			h.Flags |= 0x1
			raw = zipCryptoEncrypt(comp, m.pw, crc)
		case "aes":
			h.Flags |= 0x1
			h.Method = 99
			h.CRC32 = 0
			h.Extra = []byte{0x01, 0x99, 7, 0, 2, 0, 'A', 'E', 3, 8, 0}
			raw = winzipAESEncrypt(comp, m.pw)
		default:
			raw = comp
		}
		h.CompressedSize64 = uint64(len(raw))
		w, err := zw.CreateRaw(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(raw)
	}
	zw.Close()
	return buf.Bytes()
}

func TestZipArchivePasswords(t *testing.T) {
	doc := []byte("Sub AutoOpen()\r\nEnd Sub\r\n")
	data := buildZip(t,
		rawMember{name: "plain.txt", plain: []byte("hello"), method: "plain"},
		rawMember{name: "a/zc.bin", plain: doc, method: "zipcrypto", pw: "infected"},
		rawMember{name: "aes.bin", plain: bytes.Repeat(doc, 40), method: "aes", pw: "malware"},
		rawMember{name: "custom.bin", plain: doc, method: "zipcrypto", pw: "s3cret"},
		rawMember{name: "nope.bin", plain: doc, method: "aes", pw: "unknown-pw"},
	)
	if DetectContainer(data) != "zip" {
		t.Fatalf("detected %q", DetectContainer(data))
	}
	lim := DefaultLimits()
	lim.Passwords = []string{"s3cret"}
	a, err := OpenArchive(data, "zip", &lim)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"plain.txt": "", "a/zc.bin": "infected", "aes.bin": "malware", "custom.bin": "s3cret"}
	for _, m := range a.Members {
		pw, ok := want[m.Name]
		if !ok {
			if m.Name != "nope.bin" || m.Err == "" || m.Data != nil {
				t.Errorf("%s: %+v", m.Name, m)
			}
			continue
		}
		if m.Err != "" || m.Password != pw || len(m.Data) == 0 {
			t.Errorf("%s: err=%q pw=%q len=%d", m.Name, m.Err, m.Password, len(m.Data))
		}
	}
	if len(a.Members) != 5 {
		t.Fatalf("%d members", len(a.Members))
	}
}

func TestZipBombRejected(t *testing.T) {
	big := bytes.Repeat([]byte{0}, 4<<20)
	data := buildZip(t, rawMember{name: "bomb.bin", plain: big, method: "plain"})
	a, err := OpenArchive(data, "zip", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Members[0].Data != nil || len(a.LimitsHit) == 0 {
		t.Fatalf("bomb read: %+v", a.LimitsHit)
	}
}

// 7z archives made with 7-Zip from a synthetic one-line script, password
// "infected": one with encrypted names (-mhe=on), one with a plain header.
const (
	sevenZipEncHeader   = "377abcaf271c0004eedf5ef0c0000000000000002f000000000000007444d4f085863ecdb09d1a31c23a03f4717ced972cd5183314f07e24e3bf63d0aec6305f249646860c7b2c8887203ec6f18545f9691df57e1e0cbf4ccbdd34796d63b64e4a8af17455cfcd54b08b111b51d479dd2ce4d01076428b68e56676f93837f70e871cf1b327ae4a65679ba0e15d085a506d2cf0dd890ef48d80f77cf0be38cf7dac516ebb1d6f17342ced079d83b93e6f2fc745ff4c523f4b6c3eb495b38d3f268aec5f51b822a3e09c825744d636b3d680980a9d5a21c8d45056c587d249078a1706400109808000070b0100012406f1070112530fa16b49363cd37cf19a55e72aa1051d6e0c720a0153509f650000"
	sevenZipPlainHeader = "377abcaf271c0004ceda7bff40000000000000007200000000000000a15bb0cec8a947438678103a150ad692870e9934bbfadeadc222be1c14b7d252bc3700557f0164686fc01c8959f84f9c44a4cae5f6e16c80e211a6ab788c6ee1ad77cff60104060001094000070b0100022406f1070112530fcdf4ce53832950c9d6bae7f3ed76c55f2121010001000c3d3900080a0104621edc000005011901001117007500700064006100740065002e007600620073000000190400000000140a01007e498e53f572dd0115060100200000000000"
)

func TestSevenZipPasswords(t *testing.T) {
	for _, fx := range []string{sevenZipEncHeader, sevenZipPlainHeader} {
		data, _ := hex.DecodeString(fx)
		if DetectContainer(data) != "7z" {
			t.Fatal("7z not detected")
		}
		a, err := OpenArchive(data, "7z", nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Members) != 1 || a.Members[0].Name != "update.vbs" || a.Members[0].Password != "infected" ||
			!bytes.Contains(a.Members[0].Data, []byte("calc.exe")) {
			t.Fatalf("%+v", a.Members)
		}
	}
}

func FuzzArchives(f *testing.F) {
	enc, _ := hex.DecodeString(sevenZipPlainHeader)
	f.Add(enc)
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		OpenArchive(b, "zip", nil)
		OpenArchive(b, "7z", nil)
		winzipAES(b)
		_ = binary.LittleEndian
	})
}
