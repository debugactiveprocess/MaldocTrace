package payload

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const cpUTF7 = 65000

var b64Index = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		t[c] = int8(i)
	}
	return t
}()

// DecodeUTF7 converts UTF-7 bytes (RFC 2152, as MultiByteToWideChar with
// CP_UTF7 does) into the UTF-16LE bytes that would be written to the wide
// buffer. Shellcode loaders use this to hide arbitrary bytes in ASCII text.
func DecodeUTF7(in []byte) ([]byte, error) {
	if len(in) > MaxPayloadBytes {
		return nil, fmt.Errorf("UTF-7 input exceeds size limit")
	}
	var out []byte
	put := func(u uint16) { out = binary.LittleEndian.AppendUint16(out, u) }
	for i := 0; i < len(in); {
		c := in[i]
		if c != '+' {
			if c >= 0x80 {
				return out, fmt.Errorf("invalid UTF-7 byte 0x%02x at offset %d", c, i)
			}
			put(uint16(c))
			i++
			continue
		}
		i++
		if i < len(in) && in[i] == '-' { // "+-" encodes '+'
			put('+')
			i++
			continue
		}
		var acc uint32
		bits := 0
		for i < len(in) && b64Index[in[i]] >= 0 {
			acc = acc<<6 | uint32(b64Index[in[i]])
			bits += 6
			if bits >= 16 {
				bits -= 16
				put(uint16(acc >> uint(bits)))
				acc &= (1 << uint(bits)) - 1
			}
			i++
		}
		if i < len(in) && in[i] == '-' {
			i++ // the terminating '-' is absorbed
		}
	}
	return out, nil
}

// IsUTF7CodePage reports whether a Windows code page number is CP_UTF7.
func IsUTF7CodePage(cp string) bool { return strings.TrimSpace(cp) == fmt.Sprint(cpUTF7) }

// DisplayBytes renders a buffer for humans: mostly-printable data as escaped
// text (\xNN for other bytes), anything else as hex.
func DisplayBytes(b []byte) (string, string) {
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == 0 || c == '\r' || c == '\n' || c == '\t' {
			printable++
		}
	}
	if len(b) > 0 && printable*10 >= len(b)*9 {
		var s strings.Builder
		for _, c := range b {
			if c >= 0x20 && c < 0x7f && c != '\\' {
				s.WriteByte(c)
			} else {
				fmt.Fprintf(&s, `\x%02x`, c)
			}
		}
		return s.String(), "text"
	}
	return fmt.Sprintf("%x", b), "hex"
}
