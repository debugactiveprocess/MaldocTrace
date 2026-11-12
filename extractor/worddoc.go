package extractor

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// Word 97-2003 binary documents ([MS-DOC]) carry the same code-free attack
// surface as their OOXML counterparts: field codes (DDE, INCLUDEPICTURE...),
// an attached template that Word loads on open, and embedded or linked OLE
// objects in the ObjectPool storage.

// wordFIB returns the WordDocument stream and the table stream named by the
// FIB, or nil when the document is not a readable Word binary file.
func wordFIB(cfb *cfbReader) (wd, tbl []byte, table string) {
	wd, err := cfb.readStream("WordDocument")
	if err != nil || len(wd) < 0x1AA || binary.LittleEndian.Uint16(wd) != 0xA5EC {
		return nil, nil, ""
	}
	flags := binary.LittleEndian.Uint16(wd[0x0A:])
	if flags&0x0100 != 0 { // fEncrypted
		return nil, nil, ""
	}
	table = "0Table"
	if flags&0x0200 != 0 {
		table = "1Table"
	}
	tbl, err = cfb.readStream(table)
	if err != nil {
		return nil, nil, ""
	}
	return wd, tbl, table
}

// readSttb decodes a string table ([MS-DOC] 2.2.4 STTB): extended form
// (0xFFFF marker, UTF-16 strings) or the older ANSI form.
func readSttb(b []byte, max int) []string {
	if len(b) < 4 {
		return nil
	}
	ext := binary.LittleEndian.Uint16(b) == 0xFFFF
	p := 0
	if ext {
		p = 2
	}
	if p+4 > len(b) {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(b[p:]))
	cbExtra := int(binary.LittleEndian.Uint16(b[p+2:]))
	p += 4
	var out []string
	for i := 0; i < n && i < max; i++ {
		var s string
		if ext {
			if p+2 > len(b) {
				break
			}
			cch := int(binary.LittleEndian.Uint16(b[p:]))
			p += 2
			if p+2*cch > len(b) {
				break
			}
			s = utf16String(b[p : p+2*cch])
			p += 2 * cch
		} else {
			if p+1 > len(b) {
				break
			}
			cch := int(b[p])
			p++
			if p+cch > len(b) {
				break
			}
			s = string(b[p : p+cch])
			p += cch
		}
		p += cbExtra
		out = append(out, s)
	}
	return out
}

// isRemotePath reports URLs and UNC paths (WebDAV and SMB both leak NTLM
// credentials or fetch remote content).
func isRemotePath(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(low, "://") || strings.HasPrefix(low, `\\`) || strings.HasPrefix(low, "//")
}

// readAttachedTemplate reports the attached template of a Word binary
// document (SttbfAssoc entry ibstAssocDot, FIB fcSttbfAssoc/lcbSttbfAssoc)
// when it points outside the machine: remote template injection.
func readAttachedTemplate(wd, tbl []byte, table string, res *Result) {
	fc := int64(binary.LittleEndian.Uint32(wd[0x19A:]))
	lcb := int64(binary.LittleEndian.Uint32(wd[0x19E:]))
	if lcb < 4 || fc < 0 || fc+lcb > int64(len(tbl)) {
		return
	}
	assoc := readSttb(tbl[fc:fc+lcb], 18)
	const ibstAssocDot = 1
	if len(assoc) <= ibstAssocDot {
		return
	}
	dot := strings.TrimSpace(assoc[ibstAssocDot])
	if dot == "" || !isRemotePath(dot) {
		return
	}
	res.addExternal(ExternalRef{Kind: "template_injection", Severity: "high", Location: table + " (SttbfAssoc)", Target: dot,
		Detail: "remote template loaded when the document opens (attached template of a Word 97-2003 document)"})
}

// scanWordBinary runs the Word 97-2003 checks that need no VBA: fields in
// every story, the attached template and the ObjectPool objects.
func scanWordBinary(cfb *cfbReader, res *Result) {
	wd, tbl, table := wordFIB(cfb)
	if wd == nil {
		return
	}
	if text, err := wordStoryText(cfb, true); err == nil || text != "" {
		scanFieldCodes(text, "WordDocument", res)
		res.addCheck("Word field codes (all stories)")
	}
	readAttachedTemplate(wd, tbl, table, res)
	res.addCheck("Word attached template (SttbfAssoc)")
	if cfb.find("ObjectPool") != nil {
		n := len(scanObjectPool(cfb, res))
		res.addCheck("Word ObjectPool (" + strconv.Itoa(n) + " object(s))")
	} else {
		res.addCheck("Word ObjectPool (absent)")
	}
}
