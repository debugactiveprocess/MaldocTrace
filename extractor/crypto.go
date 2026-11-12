package extractor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"unicode/utf16"
)

// DefaultPasswords are tried, in order, against encrypted documents.
// "VelvetSweatshop" is the password Excel uses when a workbook is "encrypted"
// without the user choosing one, so Excel opens it silently; malware relies
// on that to hide macros and cells from scanners. The rest are passwords
// commonly given in phishing e-mails or sample repositories.
var DefaultPasswords = []string{
	"VelvetSweatshop", "", "infected", "123", "1234", "12345", "123456", "1234567",
	"12345678", "123456789", "password", "Password", "P@ssw0rd", "pass", "qwerty",
	"abc123", "111111", "000000", "1", "2024", "2025", "2026", "invoice", "document",
	"secret", "test", "malware", "virus",
}

// maxSpinCount bounds the key-derivation work an attacker-controlled
// EncryptionInfo can ask for (Office uses 100000), and maxSpinWork bounds
// spinCount x passwords tried, so a huge spin count cannot stall analysis.
const (
	maxSpinCount = 1_000_000
	maxSpinWork  = 5_000_000
)

// Decryption records how an encrypted document was opened.
type Decryption struct {
	// Scheme names the encryption, e.g. "BIFF8 RC4", "ECMA-376 Agile (AES-256, SHA512)".
	Scheme string `json:"scheme"`
	// Decrypted reports whether a candidate password worked.
	Decrypted bool `json:"decrypted"`
	// Password is the password that worked (empty when not decrypted).
	Password string `json:"password,omitempty"`
	// Note explains why decryption was not possible (unsupported scheme,
	// unknown password).
	Note string `json:"note,omitempty"`
}

var errUnsupportedCrypto = errors.New("unsupported encryption")

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func candidatePasswords(lim *Limits) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{lim.Passwords, DefaultPasswords} {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// BIFF8 (.xls) FILEPASS: RC4 ([MS-OFFCRYPTO] 2.3.6) and RC4 CryptoAPI (2.3.5)

// rc4KeyFunc returns the RC4 key for a given block number.
type rc4KeyFunc func(block uint32) []byte

// biffRC4 is the parsed FILEPASS of an RC4-encrypted workbook.
type biffRC4 struct {
	cryptoAPI       bool
	salt            []byte
	encVerifier     []byte
	encVerifierHash []byte
	keyBits         int
}

func (h *biffRC4) scheme() string {
	if h.cryptoAPI {
		return fmt.Sprintf("BIFF8 RC4 CryptoAPI (%d-bit)", h.keyBits)
	}
	return "BIFF8 RC4"
}

// parseFilePass decodes a FILEPASS record body.
func parseFilePass(d []byte) (*biffRC4, string, error) {
	if len(d) < 2 {
		return nil, "BIFF8 (truncated FILEPASS)", errUnsupportedCrypto
	}
	if binary.LittleEndian.Uint16(d) == 0 {
		return nil, "BIFF8 XOR obfuscation", errUnsupportedCrypto
	}
	if len(d) < 6 {
		return nil, "BIFF8 (truncated FILEPASS)", errUnsupportedCrypto
	}
	major, minor := binary.LittleEndian.Uint16(d[2:]), binary.LittleEndian.Uint16(d[4:])
	switch {
	case major == 1 && minor == 1:
		if len(d) < 6+48 {
			return nil, "BIFF8 RC4 (truncated)", errUnsupportedCrypto
		}
		return &biffRC4{salt: d[6:22], encVerifier: d[22:38], encVerifierHash: d[38:54], keyBits: 128}, "BIFF8 RC4", nil
	case major >= 2 && major <= 4 && minor == 2:
		h, err := parseCryptoAPIHeader(d[6:])
		if err != nil {
			return nil, "BIFF8 RC4 CryptoAPI (malformed)", errUnsupportedCrypto
		}
		h.cryptoAPI = true
		return h, h.scheme(), nil
	}
	return nil, fmt.Sprintf("BIFF8 encryption version %d.%d", major, minor), errUnsupportedCrypto
}

// parseCryptoAPIHeader reads Flags, EncryptionHeader and EncryptionVerifier
// of an RC4 CryptoAPI header ([MS-OFFCRYPTO] 2.3.5.1).
func parseCryptoAPIHeader(d []byte) (*biffRC4, error) {
	if len(d) < 8 {
		return nil, errUnsupportedCrypto
	}
	hdrSize := int(binary.LittleEndian.Uint32(d[4:]))
	if hdrSize < 32 || 8+hdrSize > len(d) {
		return nil, errUnsupportedCrypto
	}
	hdr := d[8 : 8+hdrSize]
	algID := binary.LittleEndian.Uint32(hdr[8:])
	keyBits := int(binary.LittleEndian.Uint32(hdr[16:]))
	if algID != 0 && algID != 0x6801 { // CALG_RC4
		return nil, errUnsupportedCrypto
	}
	if keyBits == 0 {
		keyBits = 40
	}
	if keyBits < 40 || keyBits > 128 || keyBits%8 != 0 {
		return nil, errUnsupportedCrypto
	}
	v := d[8+hdrSize:]
	if len(v) < 4+16+16+4+20 || binary.LittleEndian.Uint32(v) != 16 {
		return nil, errUnsupportedCrypto
	}
	return &biffRC4{salt: v[4:20], encVerifier: v[20:36], encVerifierHash: v[40:60], keyBits: keyBits}, nil
}

// keyFunc derives the per-block key function for a password.
func (h *biffRC4) keyFunc(password string) rc4KeyFunc {
	pw := utf16le(password)
	if h.cryptoAPI {
		h0 := sha1.Sum(append(append([]byte{}, h.salt...), pw...))
		return func(block uint32) []byte {
			hf := sha1.Sum(append(h0[:], le32(block)...))
			if h.keyBits == 40 {
				return append(append([]byte{}, hf[:5]...), make([]byte, 11)...)
			}
			return append([]byte{}, hf[:h.keyBits/8]...)
		}
	}
	h0 := md5.Sum(pw)
	buf := make([]byte, 0, 16*21)
	for i := 0; i < 16; i++ {
		buf = append(buf, h0[:5]...)
		buf = append(buf, h.salt...)
	}
	h1 := md5.Sum(buf)
	trunc := append([]byte{}, h1[:5]...)
	return func(block uint32) []byte {
		hf := md5.Sum(append(append([]byte{}, trunc...), le32(block)...))
		return hf[:]
	}
}

// verify checks a password against the encrypted verifier.
func (h *biffRC4) verify(kf rc4KeyFunc) bool {
	c, err := rc4.NewCipher(kf(0))
	if err != nil {
		return false
	}
	v := make([]byte, len(h.encVerifier))
	c.XORKeyStream(v, h.encVerifier)
	vh := make([]byte, len(h.encVerifierHash))
	c.XORKeyStream(vh, h.encVerifierHash)
	if h.cryptoAPI {
		s := sha1.Sum(v)
		return bytes.Equal(s[:], vh[:20])
	}
	s := md5.Sum(v)
	return bytes.Equal(s[:], vh[:16])
}

// rc4Stream produces the keystream byte for any stream offset, re-keying
// every blockSize bytes as Office does.
type rc4Stream struct {
	kf        rc4KeyFunc
	blockSize int
	block     int
	pos       int // offset inside block already consumed
	c         *rc4.Cipher
}

func (s *rc4Stream) xorAt(dst []byte, offset int) {
	for i := range dst {
		o := offset + i
		b, in := o/s.blockSize, o%s.blockSize
		if s.c == nil || b != s.block || in < s.pos {
			s.c, _ = rc4.NewCipher(s.kf(uint32(b)))
			s.block, s.pos = b, 0
		}
		if in > s.pos {
			skip := make([]byte, in-s.pos)
			s.c.XORKeyStream(skip, skip)
			s.pos = in
		}
		one := []byte{dst[i]}
		s.c.XORKeyStream(one, one)
		dst[i] = one[0]
		s.pos++
	}
}

// BIFF records whose bodies are never encrypted ([MS-XLS] 2.2.10).
var biffPlainRecords = map[uint16]bool{
	0x0809: true, // BOF
	0x002F: true, // FILEPASS
	0x0194: true, // UsrExcl
	0x0195: true, // FileLock
	0x00E1: true, // InterfaceHdr
	0x0196: true, // RRDInfo
	0x0138: true, // RRDHead
}

// decryptBIFF returns a copy of a Workbook stream with every encrypted record
// body decrypted. Record headers stay as they are; the keystream position is
// the absolute stream offset.
func decryptBIFF(data []byte, kf rc4KeyFunc) []byte {
	out := append([]byte{}, data...)
	s := &rc4Stream{kf: kf, blockSize: 1024, block: -1}
	afterFilePass := false
	for p := 0; p+4 <= len(out); {
		typ := binary.LittleEndian.Uint16(out[p:])
		size := int(binary.LittleEndian.Uint16(out[p+2:]))
		body := p + 4
		end := body + size
		if end > len(out) {
			end = len(out)
		}
		if afterFilePass && !biffPlainRecords[typ] {
			start := body
			if typ == rtBoundSheet {
				start += 4 // lbPlyPos is stored in the clear
			}
			if start < end {
				s.xorAt(out[start:end], start)
			}
		}
		if typ == rtFilePass {
			afterFilePass = true
		}
		p = body + size
	}
	return out
}

// ---------------------------------------------------------------------------
// ECMA-376 encrypted packages (EncryptionInfo + EncryptedPackage streams)

type ooxmlKey struct {
	scheme  string
	decrypt func(pkg []byte) ([]byte, error)
}

// openEncryptedPackage tries the candidate passwords against an OOXML
// EncryptionInfo and returns the decrypted ZIP package.
func openEncryptedPackage(info, pkg []byte, passwords []string) ([]byte, *Decryption) {
	if len(info) < 8 {
		return nil, &Decryption{Scheme: "ECMA-376 (truncated EncryptionInfo)", Note: "unsupported encryption"}
	}
	major, minor := binary.LittleEndian.Uint16(info), binary.LittleEndian.Uint16(info[2:])
	var try func(pw string) *ooxmlKey
	var scheme string
	switch {
	case major == 4 && minor == 4:
		a, err := parseAgile(info[8:])
		if err != nil {
			return nil, &Decryption{Scheme: "ECMA-376 Agile", Note: "unsupported encryption: " + err.Error()}
		}
		scheme = a.scheme()
		try = a.tryPassword
		if a.pw.SpinCount > 0 {
			if n := maxSpinWork / a.pw.SpinCount; n < len(passwords) {
				passwords = passwords[:max(n, 1)]
			}
		}
	case (major == 3 || major == 4) && minor == 2:
		s, err := parseStandard(info[8:])
		if err != nil {
			return nil, &Decryption{Scheme: "ECMA-376 Standard", Note: "unsupported encryption: " + err.Error()}
		}
		scheme = s.scheme()
		try = s.tryPassword
	case (major == 3 || major == 4) && minor == 3:
		return nil, &Decryption{Scheme: "ECMA-376 Extensible", Note: "unsupported encryption"}
	default:
		return nil, &Decryption{Scheme: fmt.Sprintf("EncryptionInfo version %d.%d", major, minor), Note: "unsupported encryption"}
	}
	for _, pw := range passwords {
		if k := try(pw); k != nil {
			out, err := k.decrypt(pkg)
			if err != nil {
				return nil, &Decryption{Scheme: scheme, Note: "password accepted but package decryption failed: " + err.Error()}
			}
			return out, &Decryption{Scheme: scheme, Decrypted: true, Password: pw}
		}
	}
	return nil, &Decryption{Scheme: scheme, Note: "password not in the candidate list (use --password)"}
}

func packageSize(pkg []byte) (int, []byte, error) {
	if len(pkg) < 8 {
		return 0, nil, errors.New("EncryptedPackage too short")
	}
	// StreamSize is declared as 8 bytes, but only the low 32 bits are
	// reliable: writers leave the high half uninitialised, and Office and
	// other readers ignore it.
	size := uint64(binary.LittleEndian.Uint32(pkg))
	if size > uint64(len(pkg)) {
		return 0, nil, errors.New("EncryptedPackage declares a size larger than the stream")
	}
	return int(size), pkg[8:], nil
}

// --- Standard encryption ([MS-OFFCRYPTO] 2.3.4.5) ---

type standardInfo struct {
	keyBits         int
	salt            []byte
	encVerifier     []byte
	encVerifierHash []byte
}

func (s *standardInfo) scheme() string {
	return fmt.Sprintf("ECMA-376 Standard (AES-%d)", s.keyBits)
}

func parseStandard(d []byte) (*standardInfo, error) {
	if len(d) < 4 {
		return nil, errors.New("truncated header")
	}
	hdrSize := int(binary.LittleEndian.Uint32(d))
	if hdrSize < 32 || 4+hdrSize > len(d) {
		return nil, errors.New("bad header size")
	}
	hdr := d[4 : 4+hdrSize]
	algID := binary.LittleEndian.Uint32(hdr[8:])
	keyBits := int(binary.LittleEndian.Uint32(hdr[16:]))
	switch algID {
	case 0x660E, 0x660F, 0x6610: // AES-128/192/256
	default:
		return nil, fmt.Errorf("algorithm 0x%04X", algID)
	}
	if keyBits != 128 && keyBits != 192 && keyBits != 256 {
		return nil, fmt.Errorf("key size %d", keyBits)
	}
	v := d[4+hdrSize:]
	if len(v) < 4+16+16+4+32 || binary.LittleEndian.Uint32(v) != 16 {
		return nil, errors.New("bad verifier")
	}
	return &standardInfo{keyBits: keyBits, salt: v[4:20], encVerifier: v[20:36], encVerifierHash: v[40:72]}, nil
}

func (s *standardInfo) key(password string) []byte {
	h := sha1.Sum(append(append([]byte{}, s.salt...), utf16le(password)...))
	for i := uint32(0); i < 50000; i++ {
		h = sha1.Sum(append(le32(i), h[:]...))
	}
	hf := sha1.Sum(append(h[:], le32(0)...))
	derive := func(fill byte) [20]byte {
		buf := bytes.Repeat([]byte{fill}, 64)
		for i := range hf {
			buf[i] ^= hf[i]
		}
		return sha1.Sum(buf)
	}
	x1, x2 := derive(0x36), derive(0x5c)
	return append(x1[:], x2[:]...)[:s.keyBits/8]
}

func ecbDecrypt(key, data []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a whole number of AES blocks")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		b.Decrypt(out[i:], data[i:])
	}
	return out, nil
}

func (s *standardInfo) tryPassword(pw string) *ooxmlKey {
	key := s.key(pw)
	v, err := ecbDecrypt(key, s.encVerifier)
	if err != nil {
		return nil
	}
	vh, err := ecbDecrypt(key, s.encVerifierHash)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(v)
	if !bytes.Equal(sum[:], vh[:20]) {
		return nil
	}
	return &ooxmlKey{scheme: s.scheme(), decrypt: func(pkg []byte) ([]byte, error) {
		size, body, err := packageSize(pkg)
		if err != nil {
			return nil, err
		}
		body = body[:len(body)-len(body)%aes.BlockSize]
		out, err := ecbDecrypt(key, body)
		if err != nil {
			return nil, err
		}
		if size > len(out) {
			return nil, errors.New("decrypted package shorter than declared")
		}
		return out[:size], nil
	}}
}

// --- Agile encryption ([MS-OFFCRYPTO] 2.3.4.10) ---

type agileKeyData struct {
	SaltValue     string `xml:"saltValue,attr"`
	HashAlgorithm string `xml:"hashAlgorithm,attr"`
	KeyBits       int    `xml:"keyBits,attr"`
	BlockSize     int    `xml:"blockSize,attr"`
	CipherAlg     string `xml:"cipherAlgorithm,attr"`
	Chaining      string `xml:"cipherChaining,attr"`
}

type agileEncryptedKey struct {
	agileKeyData
	SpinCount                  int    `xml:"spinCount,attr"`
	EncryptedVerifierHashInput string `xml:"encryptedVerifierHashInput,attr"`
	EncryptedVerifierHashValue string `xml:"encryptedVerifierHashValue,attr"`
	EncryptedKeyValue          string `xml:"encryptedKeyValue,attr"`
}

type agileInfo struct {
	keyData agileKeyData
	pw      agileEncryptedKey
	keySalt []byte
	pwSalt  []byte
	evhi    []byte
	evhv    []byte
	ekv     []byte
}

func (a *agileInfo) scheme() string {
	return fmt.Sprintf("ECMA-376 Agile (AES-%d, %s)", a.pw.KeyBits, a.pw.HashAlgorithm)
}

func agileHash(name string) (func() hash.Hash, error) {
	switch name {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA384":
		return sha512.New384, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("hash algorithm %q", name)
}

func parseAgile(d []byte) (*agileInfo, error) {
	var doc struct {
		KeyData       agileKeyData `xml:"keyData"`
		KeyEncryptors struct {
			List []struct {
				URI string            `xml:"uri,attr"`
				Key agileEncryptedKey `xml:"encryptedKey"`
			} `xml:"keyEncryptor"`
		} `xml:"keyEncryptors"`
	}
	if err := xml.Unmarshal(d, &doc); err != nil {
		return nil, fmt.Errorf("EncryptionInfo XML: %v", err)
	}
	a := &agileInfo{keyData: doc.KeyData}
	found := false
	for _, ke := range doc.KeyEncryptors.List {
		if ke.Key.EncryptedKeyValue != "" {
			a.pw, found = ke.Key, true
			break
		}
	}
	if !found {
		return nil, errors.New("no password key encryptor")
	}
	for _, k := range []agileKeyData{a.keyData, a.pw.agileKeyData} {
		if k.CipherAlg != "AES" || k.Chaining != "ChainingModeCBC" {
			return nil, fmt.Errorf("cipher %s/%s", k.CipherAlg, k.Chaining)
		}
		if _, err := agileHash(k.HashAlgorithm); err != nil {
			return nil, err
		}
	}
	if a.pw.KeyBits != 128 && a.pw.KeyBits != 192 && a.pw.KeyBits != 256 {
		return nil, fmt.Errorf("key size %d", a.pw.KeyBits)
	}
	if a.pw.SpinCount < 0 || a.pw.SpinCount > maxSpinCount {
		return nil, fmt.Errorf("spin count %d", a.pw.SpinCount)
	}
	var err error
	dec := func(s string) []byte {
		if err != nil {
			return nil
		}
		var b []byte
		b, err = base64.StdEncoding.DecodeString(s)
		return b
	}
	a.keySalt, a.pwSalt = dec(a.keyData.SaltValue), dec(a.pw.SaltValue)
	a.evhi, a.evhv, a.ekv = dec(a.pw.EncryptedVerifierHashInput), dec(a.pw.EncryptedVerifierHashValue), dec(a.pw.EncryptedKeyValue)
	if err != nil {
		return nil, fmt.Errorf("base64: %v", err)
	}
	if len(a.keySalt) == 0 || len(a.pwSalt) < aes.BlockSize {
		return nil, errors.New("missing salt")
	}
	return a, nil
}

var (
	agileBlkVerifierInput = []byte{0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79}
	agileBlkVerifierValue = []byte{0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e}
	agileBlkKeyValue      = []byte{0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6}
)

func hashOf(newHash func() hash.Hash, parts ...[]byte) []byte {
	h := newHash()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// fitKey truncates a hash to n bytes or pads it with 0x36.
func fitKey(b []byte, n int) []byte {
	if len(b) >= n {
		return append([]byte{}, b[:n]...)
	}
	return append(append([]byte{}, b...), bytes.Repeat([]byte{0x36}, n-len(b))...)
}

func cbcDecrypt(key, iv, data []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 || len(data) == 0 {
		return nil, errors.New("ciphertext is not a whole number of AES blocks")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(b, iv[:aes.BlockSize]).CryptBlocks(out, data)
	return out, nil
}

func (a *agileInfo) tryPassword(pw string) *ooxmlKey {
	newHash, _ := agileHash(a.pw.HashAlgorithm)
	h := hashOf(newHash, a.pwSalt, utf16le(pw))
	for i := 0; i < a.pw.SpinCount; i++ {
		h = hashOf(newHash, le32(uint32(i)), h)
	}
	n := a.pw.KeyBits / 8
	k1 := fitKey(hashOf(newHash, h, agileBlkVerifierInput), n)
	k2 := fitKey(hashOf(newHash, h, agileBlkVerifierValue), n)
	in, err := cbcDecrypt(k1, a.pwSalt, a.evhi)
	if err != nil {
		return nil
	}
	val, err := cbcDecrypt(k2, a.pwSalt, a.evhv)
	if err != nil {
		return nil
	}
	if len(in) < a.pw.SaltValueSize() {
		return nil
	}
	got := hashOf(newHash, in[:a.pw.SaltValueSize()])
	if len(val) < len(got) || !bytes.Equal(got, val[:len(got)]) {
		return nil
	}
	k3 := fitKey(hashOf(newHash, h, agileBlkKeyValue), n)
	secret, err := cbcDecrypt(k3, a.pwSalt, a.ekv)
	if err != nil {
		return nil
	}
	dataKeyLen := a.keyData.KeyBits / 8
	if dataKeyLen == 0 || dataKeyLen > len(secret) {
		dataKeyLen = n
	}
	secret = secret[:dataKeyLen]
	ivHash, _ := agileHash(a.keyData.HashAlgorithm)
	return &ooxmlKey{scheme: a.scheme(), decrypt: func(pkg []byte) ([]byte, error) {
		size, body, err := packageSize(pkg)
		if err != nil {
			return nil, err
		}
		const seg = 4096
		out := make([]byte, 0, len(body))
		for i := 0; i*seg < len(body); i++ {
			chunk := body[i*seg:]
			if len(chunk) > seg {
				chunk = chunk[:seg]
			}
			chunk = chunk[:len(chunk)-len(chunk)%aes.BlockSize]
			if len(chunk) == 0 {
				break
			}
			iv := fitKey(hashOf(ivHash, a.keySalt, le32(uint32(i))), aes.BlockSize)
			dec, err := cbcDecrypt(secret, iv, chunk)
			if err != nil {
				return nil, err
			}
			out = append(out, dec...)
		}
		if size > len(out) {
			return nil, errors.New("decrypted package shorter than declared")
		}
		return out[:size], nil
	}}
}

// SaltValueSize is the verifier input length: the salt size declared for the
// password key (16 for every Office version).
func (k agileEncryptedKey) SaltValueSize() int {
	if b, err := base64.StdEncoding.DecodeString(k.SaltValue); err == nil && len(b) > 0 {
		return len(b)
	}
	return 16
}
