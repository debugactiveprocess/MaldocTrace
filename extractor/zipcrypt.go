package extractor

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

// Encrypted ZIP members: the traditional PKWARE cipher (ZipCrypto) and
// WinZip AES (AE-1/AE-2, compression method 99). archive/zip reads the
// directory and hands out the raw member bytes; decryption and inflation are
// done here, in memory.

var errBadPassword = errors.New("wrong password")

// zipCryptoKeys is the PKWARE traditional encryption state.
type zipCryptoKeys [3]uint32

func newZipCrypto(password string) *zipCryptoKeys {
	k := &zipCryptoKeys{0x12345678, 0x23456789, 0x34567890}
	for i := 0; i < len(password); i++ {
		k.update(password[i])
	}
	return k
}

func crc32Byte(crc uint32, b byte) uint32 {
	return crc32.IEEETable[byte(crc)^b] ^ crc>>8
}

func (k *zipCryptoKeys) update(c byte) {
	k[0] = crc32Byte(k[0], c)
	k[1] = (k[1]+k[0]&0xff)*134775813 + 1
	k[2] = crc32Byte(k[2], byte(k[1]>>24))
}

func (k *zipCryptoKeys) decrypt(b []byte) {
	for i, c := range b {
		t := k[2] | 2
		p := c ^ byte((t*(t^1))>>8)
		k.update(p)
		b[i] = p
	}
}

// decryptZipCrypto removes the traditional encryption of raw member data.
func decryptZipCrypto(f *zip.File, raw []byte, password string) ([]byte, error) {
	if len(raw) < 12 {
		return nil, ErrTruncated
	}
	buf := append([]byte(nil), raw...)
	k := newZipCrypto(password)
	k.decrypt(buf[:12])
	check := byte(f.CRC32 >> 24)
	if f.Flags&0x8 != 0 {
		check = byte(f.ModifiedTime >> 8)
	}
	if buf[11] != check {
		return nil, errBadPassword
	}
	k.decrypt(buf[12:])
	return buf[12:], nil
}

// pbkdf2SHA1 derives a key with PBKDF2-HMAC-SHA1 (RFC 8018).
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	var out []byte
	for block := uint32(1); len(out) < keyLen; block++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write(binary.BigEndian.AppendUint32(nil, block))
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// winzipAES reads the AES extra field (0x9901): strength and real method.
func winzipAES(extra []byte) (strength int, method uint16, ok bool) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+n > len(extra) {
			return 0, 0, false
		}
		if id == 0x9901 && n >= 7 {
			d := extra[4 : 4+n]
			return int(d[4]), binary.LittleEndian.Uint16(d[5:]), true
		}
		extra = extra[4+n:]
	}
	return 0, 0, false
}

// decryptWinZipAES decrypts and authenticates an AE-1/AE-2 member.
func decryptWinZipAES(raw []byte, strength int, password string) ([]byte, error) {
	keyLen := map[int]int{1: 16, 2: 24, 3: 32}[strength]
	if keyLen == 0 {
		return nil, fmt.Errorf("unknown AES strength %d", strength)
	}
	saltLen := keyLen / 2
	if len(raw) < saltLen+2+10 {
		return nil, ErrTruncated
	}
	salt, pwv := raw[:saltLen], raw[saltLen:saltLen+2]
	data, mac := raw[saltLen+2:len(raw)-10], raw[len(raw)-10:]
	dk := pbkdf2SHA1([]byte(password), salt, 1000, 2*keyLen+2)
	if !bytes.Equal(dk[2*keyLen:], pwv) {
		return nil, errBadPassword
	}
	var h hash.Hash = hmac.New(sha1.New, dk[keyLen:2*keyLen])
	h.Write(data)
	if !hmac.Equal(h.Sum(nil)[:10], mac) {
		return nil, fmt.Errorf("AES authentication code mismatch")
	}
	block, err := aes.NewCipher(dk[:keyLen])
	if err != nil {
		return nil, err
	}
	// CTR mode with a little-endian counter starting at 1.
	out := make([]byte, len(data))
	var ctr, ks [16]byte
	for off := 0; off < len(data); off += 16 {
		for i := 0; i < 16; i++ {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		block.Encrypt(ks[:], ctr[:])
		for i := 0; i < 16 && off+i < len(data); i++ {
			out[off+i] = data[off+i] ^ ks[i]
		}
	}
	return out, nil
}

// decompressZip inflates member data stored with the given method.
func decompressZip(method uint16, data []byte, limit int64) ([]byte, error) {
	var r io.Reader
	switch method {
	case zip.Store:
		r = bytes.NewReader(data)
	case zip.Deflate:
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		r = fr
	case 12:
		r = bzip2.NewReader(bytes.NewReader(data))
	default:
		return nil, fmt.Errorf("unsupported compression method %d", method)
	}
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, ErrLimitExceeded
	}
	return out, nil
}

// openZipMember returns the plain content of a member, trying the
// candidate passwords when it is encrypted. It reports the password that
// worked ("" for an unencrypted member).
func openZipMember(f *zip.File, passwords []string, limit int64) ([]byte, string, error) {
	encrypted := f.Flags&0x1 != 0
	strength, aesMethod, isAES := winzipAES(f.Extra)
	if f.Method == 99 && !isAES {
		return nil, "", fmt.Errorf("AES member without its extra field")
	}
	if !encrypted && f.Method != 99 {
		rc, err := f.Open()
		if err != nil {
			raw, rerr := f.OpenRaw()
			if rerr != nil {
				return nil, "", err
			}
			b, _ := io.ReadAll(io.LimitReader(raw, limit+1))
			out, derr := decompressZip(f.Method, b, limit)
			return out, "", derr
		}
		defer rc.Close()
		out, err := io.ReadAll(io.LimitReader(rc, limit+1))
		if err == nil && int64(len(out)) > limit {
			err = ErrLimitExceeded
		}
		return out, "", err
	}
	rr, err := f.OpenRaw()
	if err != nil {
		return nil, "", err
	}
	raw, err := io.ReadAll(io.LimitReader(rr, int64(f.CompressedSize64)+1))
	if err != nil {
		return nil, "", err
	}
	lastErr := errBadPassword
	for _, pw := range passwords {
		var plain []byte
		method := f.Method
		if isAES {
			plain, err = decryptWinZipAES(raw, strength, pw)
			method = aesMethod
		} else {
			plain, err = decryptZipCrypto(f, raw, pw)
		}
		if err != nil {
			lastErr = err
			continue
		}
		out, err := decompressZip(method, plain, limit)
		if err != nil {
			lastErr = err
			if err == ErrLimitExceeded {
				return nil, pw, err
			}
			continue
		}
		// AE-2 stores no CRC; ZipCrypto's one-byte check passes for 1 in
		// 256 wrong passwords, so the CRC decides.
		if f.CRC32 != 0 && crc32.ChecksumIEEE(out) != f.CRC32 {
			lastErr = errBadPassword
			continue
		}
		return out, pw, nil
	}
	return nil, "", lastErr
}
