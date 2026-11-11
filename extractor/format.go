package extractor

import "bytes"

// Format identifies the container or source language detected for an input.
type Format int

const (
	// FormatUnknown means the input did not match any recognised format.
	FormatUnknown Format = iota
	// FormatCFB is an OLE Compound File Binary container (MS-CFB).
	FormatCFB
	// FormatOOXML is a ZIP based Office Open XML container.
	FormatOOXML
	// FormatVBA is a plain-text VBA source file.
	FormatVBA
	// FormatRTF is a Rich Text Format document.
	FormatRTF
)

func (f Format) String() string {
	switch f {
	case FormatCFB:
		return "cfb"
	case FormatOOXML:
		return "ooxml"
	case FormatVBA:
		return "vba"
	case FormatRTF:
		return "rtf"
	default:
		return "unknown"
	}
}

// cfbMagic is the 8-byte CFB header magic (little-endian D0CF11E0A1B11AE1).
var cfbMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// zipMagics cover common ZIP local-file-header signatures.
var zipMagics = [][]byte{
	{0x50, 0x4B, 0x03, 0x04},
	{0x50, 0x4B, 0x05, 0x06},
	{0x50, 0x4B, 0x07, 0x08},
}

// Detect inspects the first bytes of data to classify the format. It only
// looks at magic bytes and does not validate the container. A file that
// cannot be classified and contains NUL bytes (a strong binary signal) is
// FormatUnknown; a text file falling through is treated as FormatVBA.
func Detect(data []byte) Format {
	if len(data) >= 8 && bytes.Equal(data[:8], cfbMagic) {
		return FormatCFB
	}
	for _, m := range zipMagics {
		if len(data) >= len(m) && bytes.Equal(data[:len(m)], m) {
			return FormatOOXML
		}
	}
	// Word opens any file starting with `{\rt` as RTF (`{\rtf1` is not required).
	if len(data) >= 4 && bytes.Equal(data[:4], []byte(`{\rt`)) {
		return FormatRTF
	}
	if containsNUL := bytes.IndexByte(data, 0) >= 0; containsNUL {
		return FormatUnknown
	}
	return FormatVBA
}
