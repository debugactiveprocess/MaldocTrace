package payload

import (
	"bytes"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"
)

// CertutilDecode describes a "certutil -decode|-decodehex <in> <out>" call.
type CertutilDecode struct {
	Hex     bool
	In, Out string
}

// ParseCertutil recognises certutil decode invocations in an argv.
func ParseCertutil(argv []string) (CertutilDecode, bool) {
	if len(argv) < 4 {
		return CertutilDecode{}, false
	}
	exe := strings.ToLower(path.Base(strings.ReplaceAll(argv[0], `\`, "/")))
	if exe != "certutil" && exe != "certutil.exe" {
		return CertutilDecode{}, false
	}
	var files []string
	var c CertutilDecode
	verb := false
	for _, a := range argv[1:] {
		low := strings.ToLower(a)
		if strings.HasPrefix(low, "-") || strings.HasPrefix(low, "/") && len(low) > 1 && !strings.Contains(low[1:], "/") {
			switch strings.TrimLeft(low, "-/") {
			case "decode":
				verb = true
			case "decodehex":
				verb, c.Hex = true, true
			}
			continue
		}
		files = append(files, a)
	}
	if !verb || len(files) < 2 {
		return CertutilDecode{}, false
	}
	c.In, c.Out = files[0], files[1]
	return c, true
}

// DecodeCertutil reproduces certutil's Base64 (-decode) or hex (-decodehex)
// decoding of a file's content: PEM-style "-----BEGIN/END" lines are
// ignored, whitespace is skipped.
func DecodeCertutil(content []byte, isHex bool) ([]byte, error) {
	var body strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "-----") {
			continue
		}
		body.WriteString(t)
	}
	s := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, body.String())
	if isHex {
		return hex.DecodeString(s)
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("invalid Base64: %w", err)
	}
	return b, nil
}

// DescribeBinary identifies common binary formats and returns a short type
// and human-readable facts. It parses headers only; nothing is executed.
func DescribeBinary(b []byte) (string, []string) {
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		f, err := pe.NewFile(bytes.NewReader(b))
		if err != nil {
			return "PE (MZ header, unparsable: " + err.Error() + ")", nil
		}
		defer f.Close()
		kind := "PE32 executable"
		if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
			kind = "PE32+ executable"
		}
		if f.Characteristics&pe.IMAGE_FILE_DLL != 0 {
			kind = strings.Replace(kind, "executable", "DLL", 1)
		}
		var facts []string
		facts = append(facts, fmt.Sprintf("machine=0x%04x", f.Machine))
		if f.TimeDateStamp != 0 {
			facts = append(facts, "compiled="+time.Unix(int64(f.TimeDateStamp), 0).UTC().Format(time.RFC3339))
		}
		var secs []string
		for _, s := range f.Sections {
			secs = append(secs, s.Name)
		}
		facts = append(facts, "sections="+strings.Join(secs, ","))
		if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
			facts = append(facts, "imports="+strings.Join(libs, ","))
		}
		return kind, facts
	}
	switch {
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "ZIP archive", nil
	case bytes.HasPrefix(b, []byte{0xD0, 0xCF, 0x11, 0xE0}):
		return "OLE/CFB compound file", nil
	case bytes.HasPrefix(b, []byte("%PDF")):
		return "PDF document", nil
	}
	return "", nil
}

// PrintableStrings returns ASCII runs of at least min bytes (like strings(1)).
func PrintableStrings(b []byte, min, limit int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b) && len(out) < limit; i++ {
		if i < len(b) && b[i] >= 0x20 && b[i] < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			out = append(out, string(b[start:i]))
		}
		start = -1
	}
	return out
}
