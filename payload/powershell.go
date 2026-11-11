// Package payload performs bounded, static decoding. It never executes input.
package payload

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

const MaxPayloadBytes = 1 << 20

// SplitCommand implements double-quoted Windows argv grouping and backslash
// escaping before quotes. It deliberately does not interpret shell operators.
func SplitCommand(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i == len(s) {
			break
		}
		var b strings.Builder
		quoted := false
		for i < len(s) {
			if !quoted && (s[i] == ' ' || s[i] == '\t') {
				break
			}
			if s[i] == '\\' {
				start := i
				for i < len(s) && s[i] == '\\' {
					i++
				}
				n := i - start
				if i < len(s) && s[i] == '"' {
					b.WriteString(strings.Repeat("\\", n/2))
					if n%2 == 1 {
						b.WriteByte('"')
						i++
						continue
					}
					quoted = !quoted
					i++
					continue
				}
				b.WriteString(strings.Repeat("\\", n))
				continue
			}
			if s[i] == '"' {
				quoted = !quoted
				i++
				continue
			}
			b.WriteByte(s[i])
			i++
		}
		if quoted {
			return out, fmt.Errorf("unterminated command-line quote")
		}
		out = append(out, b.String())
	}
	return out, nil
}

func IsPowerShell(executable string) bool {
	s := strings.ToLower(executable)
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	return s == "powershell" || s == "powershell.exe" || s == "pwsh" || s == "pwsh.exe"
}

// EncodedArgument follows the host parameter aliases, not arbitrary substring
// matches. -EncodedArguments/-ea are data, not EncodedCommand.
func EncodedArgument(argv []string) (string, bool, error) {
	if len(argv) == 0 || !IsPowerShell(argv[0]) {
		return "", false, nil
	}
	for i := 1; i < len(argv); i++ {
		s := strings.ToLower(argv[i])
		if !strings.HasPrefix(s, "-") {
			return "", false, nil
		}
		s = strings.TrimPrefix(s, "-")
		if s != "" && (strings.HasPrefix("command", s) || strings.HasPrefix("file", s)) {
			return "", false, nil
		}
		if s == "ec" || (s != "" && strings.HasPrefix("encodedcommand", s)) {
			if i+1 == len(argv) {
				return "", true, fmt.Errorf("EncodedCommand argument is missing")
			}
			return argv[i+1], true, nil
		}
		switch {
		case s == "ea", strings.HasPrefix(s, "encodeda"), s == "ep", strings.HasPrefix(s, "ex"), s == "w", strings.HasPrefix(s, "window"), s == "o", s == "of", strings.HasPrefix(s, "output"), s == "if", strings.HasPrefix(s, "inp"):
			i++
		case s == "nop", s == "noprofile", s == "noni", s == "noninteractive", s == "nologo", s == "noexit", s == "sta", s == "mta":
		default:
			return "", false, fmt.Errorf("unsupported or ambiguous PowerShell option %q", argv[i])
		}
	}
	return "", false, nil
}

func DecodeEncodedCommand(encoded string) (string, []byte, error) {
	if len(encoded) > MaxPayloadBytes*2 {
		return "", nil, fmt.Errorf("encoded payload exceeds size limit")
	}
	encoded = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, encoded)
	b, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("invalid Base64: %w", err)
	}
	if len(b) > MaxPayloadBytes {
		return "", nil, fmt.Errorf("decoded payload exceeds size limit")
	}
	if len(b)%2 != 0 {
		return "", b, fmt.Errorf("invalid UTF-16LE: odd byte length")
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", b, fmt.Errorf("invalid UTF-16LE surrogate")
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", b, fmt.Errorf("invalid UTF-16LE surrogate")
		}
	}
	return strings.TrimPrefix(string(utf16.Decode(units)), "\ufeff"), b, nil
}
