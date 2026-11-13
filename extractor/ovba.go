package extractor

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
)

// Dir stream record identifiers (MS-OVBA 2.3.1.1). Only the subset needed to
// locate and decode module source streams is defined here.
const (
	recProjectSysKind       = 0x0001
	recProjectLCID          = 0x0002
	recProjectCodePage      = 0x0003
	recProjectName          = 0x0004
	recProjectDocString     = 0x0005
	recProjectHelpFilePath  = 0x0006
	recProjectHelpContext   = 0x0007
	recProjectLibFlags      = 0x0008
	recProjectVersion       = 0x0009
	recProjectConstants     = 0x000C
	recReferenceRegistered  = 0x000D
	recReferenceProject     = 0x000E
	recProjectModules       = 0x000F
	recTerminator           = 0x0010
	recProjectCookie        = 0x0013
	recProjectLCIDInvoke    = 0x0014
	recReferenceName        = 0x0016
	recModuleName           = 0x0019
	recModuleStreamName     = 0x001A
	recModuleDocString      = 0x001C
	recModuleHelpContext    = 0x001E
	recModuleTypeProc       = 0x0021
	recModuleTypeClass      = 0x0022
	recModuleReadOnly       = 0x0025
	recModulePrivate        = 0x0028
	recModuleTerminator     = 0x002B
	recModuleCookie         = 0x002C
	recReferenceControl     = 0x002F
	recModuleOffset         = 0x0031
	recModuleStreamNameUni  = 0x0032
	recReferenceOriginal    = 0x0033
	recModuleNameUni        = 0x0047
	recProjectCompatVersion = 0x004A
)

// decompressOVBA implements the MS-OVBA 2.4.1 CompressedContainer decoding,
// including the 2.4.1.3 compressed-chunk (RLE copy/literal token) algorithm.
// limit caps the number of bytes that may be produced; if surpassed an
// ErrLimitExceeded is returned.
func decompressOVBA(data []byte, limit int64) ([]byte, error) {
	if len(data) == 0 {
		return nil, Wrap("ovba.decompress", ErrTruncated)
	}
	if data[0] != 0x01 {
		return nil, Wrap("ovba.decompress", fmt.Errorf("invalid CompressedContainer signature byte 0x%02X", data[0]))
	}
	out := make([]byte, 0, len(data)*3/2)
	pos := 1
	for pos < len(data) {
		if pos+2 > len(data) {
			break
		}
		chStart := pos
		header := binary.LittleEndian.Uint16(data[pos : pos+2])
		chunkSize := int(header&0x0FFF) + 3
		signature := (header >> 12) & 0x07
		if signature != 0b011 {
			return nil, Wrap("ovba.decompress", fmt.Errorf("invalid chunk signature %d", signature))
		}
		flag := (header >> 15) & 0x01
		pos += 2
		end := chStart + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if flag == 0 {
			n := 4096
			if end-pos < n {
				n = end - pos
			}
			if n > 0 {
				if int64(len(out))+int64(n) > limit {
					return nil, Wrap("ovba.decompress", ErrLimitExceeded)
				}
				out = append(out, data[pos:pos+n]...)
			}
			pos = end
		} else {
			chunkStart := len(out)
			for pos < end {
				flagByte := data[pos]
				pos++
				for bit := 0; bit < 8; bit++ {
					if pos >= end {
						break
					}
					flagBit := (flagByte >> bit) & 1
					if flagBit == 0 {
						if int64(len(out))+1 > limit {
							return nil, Wrap("ovba.decompress", ErrLimitExceeded)
						}
						out = append(out, data[pos])
						pos++
					} else {
						if pos+2 > end {
							pos = end
							break
						}
						token := binary.LittleEndian.Uint16(data[pos : pos+2])
						pos += 2
						diff := len(out) - chunkStart
						bitCount := uint16(4)
						if diff >= 16 {
							bitCount = uint16(math.Ceil(math.Log2(float64(diff))))
						}
						lengthMask := uint16(0xFFFF) >> bitCount
						offsetMask := ^lengthMask
						length := int(token&lengthMask) + 3
						offset := int((token&offsetMask)>>(16-bitCount)) + 1
						copySource := len(out) - offset
						if copySource < 0 {
							return nil, Wrap("ovba.decompress", fmt.Errorf("copy token offset %d out of range", offset))
						}
						if int64(len(out))+int64(length) > limit {
							return nil, Wrap("ovba.decompress", ErrLimitExceeded)
						}
						for i := 0; i < length; i++ {
							out = append(out, out[copySource+i])
						}
					}
				}
			}
		}
	}
	return out, nil
}

// codepageEncoding maps a Windows codepage identifier to a Go text encoding.
// Unknown codepages fall back to Windows-1252, matching the reference
// behaviour for CP-1252-centric office documents.
func codepageEncoding(cp uint16) encoding.Encoding {
	switch cp {
	case 65001:
		return unicode.UTF8
	case 1200:
		return unicode.UTF16(unicode.LittleEndian, unicode.UseBOM)
	case 1201:
		return unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
	case 1250:
		return charmap.Windows1250
	case 1251:
		return charmap.Windows1251
	case 1252:
		return charmap.Windows1252
	case 1253:
		return charmap.Windows1253
	case 1254:
		return charmap.Windows1254
	case 1255:
		return charmap.Windows1255
	case 1256:
		return charmap.Windows1256
	case 1257:
		return charmap.Windows1257
	case 1258:
		return charmap.Windows1258
	case 874:
		return charmap.Windows874
	case 10000, 10006, 10007, 10029, 10079, 10081:
		return charmap.Macintosh
	case 20127:
		return charmap.Windows1252 // US-ASCII subset, cp1252 is ASCII-compatible
	case 20866:
		return charmap.KOI8R
	case 21866:
		return charmap.KOI8U
	case 28591:
		return charmap.ISO8859_1
	case 28592:
		return charmap.ISO8859_2
	case 28593:
		return charmap.ISO8859_3
	case 28594:
		return charmap.ISO8859_4
	case 28595:
		return charmap.ISO8859_5
	case 28596:
		return charmap.ISO8859_6
	case 28597:
		return charmap.ISO8859_7
	case 28598:
		return charmap.ISO8859_8
	case 28599:
		return charmap.ISO8859_9
	case 28603:
		return charmap.ISO8859_13
	case 28605:
		return charmap.ISO8859_15
	case 932:
		return japanese.ShiftJIS
	case 949:
		return korean.EUCKR
	case 936:
		return simplifiedchinese.GBK
	case 950:
		return traditionalchinese.Big5
	default:
		return charmap.Windows1252
	}
}

func decodeUTF16(data []byte, order binary.ByteOrder) string {
	u := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u = append(u, order.Uint16(data[i:i+2]))
	}
	return string(utf16.Decode(u))
}

// DecodeText decodes bytes of the module (p-code identifiers and literals)
// with the project code page.
func (m *Module) DecodeText(b []byte) string { return decodeCodepage(m.Codepage, b) }

// decodeCodepage decodes bytes using the given Windows codepage identifier,
// falling back to Windows-1252 when unavailable. A leading UTF-16 BOM switches
// to UTF-16 decoding.
func decodeCodepage(cp uint16, data []byte) string {
	if len(data) >= 2 {
		if data[0] == 0xFF && data[1] == 0xFE {
			return decodeUTF16(data[2:], binary.LittleEndian)
		}
		if data[0] == 0xFE && data[1] == 0xFF {
			return decodeUTF16(data[2:], binary.BigEndian)
		}
	}
	decoded, err := codepageEncoding(cp).NewDecoder().Bytes(data)
	if err != nil {
		return string(data)
	}
	return string(decoded)
}

// ModuleType classifies a VBA module by the MODULETYPE record.
type ModuleType int

const (
	ModuleTypeProcedural ModuleType = iota
	ModuleTypeDocumentClassDesigner
)

// rawModule is a module declared in the dir stream before its source is read.
type rawModule struct {
	name          string
	nameUni       string
	streamName    string
	streamNameUni string
	textOffset    uint32
	typ           ModuleType
	readOnly      bool
	private       bool
}

// vbaProject is the parsed content of a VBA "dir" stream.
type vbaProject struct {
	codepage uint16
	name     string
	sysKind  uint32
	lcid     uint32
	modules  []rawModule
}

// dirReader is a bounded reader over the decompressed dir stream.
type dirReader struct {
	data []byte
	pos  int
}

func (r *dirReader) read(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, ErrTruncated
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *dirReader) u16() (uint16, error) {
	b, err := r.read(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *dirReader) u32() (uint32, error) {
	b, err := r.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// readStringWithUnicode reads a PROJECT string record of the form
// [size(4)][bytes][reserved(2)][sizeUnicode(4)][utf16 bytes], returning the
// MBCS and UTF-16 decodings. The reserved marker value is ignored.
func (r *dirReader) readStringWithUnicode(cp uint16) (string, string, error) {
	n, err := r.u32()
	if err != nil {
		return "", "", err
	}
	if n > 1<<20 {
		return "", "", ErrLimitExceeded
	}
	b, err := r.read(int(n))
	if err != nil {
		return "", "", err
	}
	if _, err := r.u16(); err != nil { // reserved marker
		return "", "", err
	}
	un, err := r.u32()
	if err != nil {
		return "", "", err
	}
	if un > 1<<20 {
		return "", "", ErrLimitExceeded
	}
	ub, err := r.read(int(un))
	if err != nil {
		return "", "", err
	}
	return decodeCodepage(cp, b), decodeUTF16(ub, binary.LittleEndian), nil
}

// parseDir parses a decompressed VBA dir stream. It is tolerant of
// non-conforming header values (common in the wild) but fails on truncation.
func parseDir(data []byte) (*vbaProject, error) {
	r := &dirReader{data: data}
	p := &vbaProject{}

	id, err := r.u16()
	if err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if id != recProjectSysKind {
		return nil, Wrap("ovba.dir", fmt.Errorf("unexpected first record 0x%04X", id))
	}
	if _, err := r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if p.sysKind, err = r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}

	// PROJECTCOMPATVERSION (optional) followed by PROJECTLCID.
	if id, err = r.u16(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if id == recProjectCompatVersion {
		if _, err = r.u32(); err != nil {
			return nil, Wrap("ovba.dir", err)
		}
		if _, err = r.u32(); err != nil {
			return nil, Wrap("ovba.dir", err)
		}
		if id, err = r.u16(); err != nil {
			return nil, Wrap("ovba.dir", err)
		}
	}
	if _, err = r.u32(); err != nil { // PROJECTLCID size
		return nil, Wrap("ovba.dir", err)
	}
	if p.lcid, err = r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}

	// PROJECTLCIDINVOKE.
	if _, err = r.u16(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if _, err = r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if _, err = r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}

	// PROJECTCODEPAGE.
	if _, err = r.u16(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if _, err = r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if p.codepage, err = r.u16(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}

	// PROJECTNAME.
	if id, err = r.u16(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	var n uint32
	if n, err = r.u32(); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	if n > 1<<16 {
		return nil, Wrap("ovba.dir", ErrLimitExceeded)
	}
	var nb []byte
	if nb, err = r.read(int(n)); err != nil {
		return nil, Wrap("ovba.dir", err)
	}
	p.name = decodeCodepage(p.codepage, nb)

	// Remaining project records until PROJECTMODULES or TERMINATOR.
	if err = parseProjectTail(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// parseProjectTail handles PROJECT* records and the REFERENCE array that
// precede the PROJECTMODULES / TERMINATOR record.
func parseProjectTail(r *dirReader, p *vbaProject) error {
	id, err := r.u16()
	if err != nil {
		return Wrap("ovba.dir", err)
	}
	for {
		switch id {
		case recProjectDocString, recProjectHelpFilePath, recProjectConstants:
			if _, _, err = r.readStringWithUnicode(p.codepage); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recProjectHelpContext, recProjectLibFlags:
			if _, err = r.u32(); err != nil {
				return Wrap("ovba.dir", err)
			}
			if _, err = r.u32(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recProjectVersion:
			// Reserved(4), VersionMajor(4), VersionMinor(2).
			if _, err = r.u32(); err != nil {
				return Wrap("ovba.dir", err)
			}
			if _, err = r.u32(); err != nil {
				return Wrap("ovba.dir", err)
			}
			if _, err = r.u16(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recReferenceName: // 0x0016
			if err = r.skipReferenceName(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recReferenceOriginal: // 0x0033
			if err = r.skipReferenceOriginal(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recReferenceControl: // 0x002F
			if err = r.skipReferenceControl(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recReferenceRegistered: // 0x000D
			if err = r.skipReferenceRegistered(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recReferenceProject: // 0x000E
			if err = r.skipReferenceProject(); err != nil {
				return Wrap("ovba.dir", err)
			}
		case recProjectModules: // 0x000F
			return p.parseModules(r)
		case recTerminator:
			return nil
		default:
			// Unknown or version-specific project record: skip generically as
			// [size(4)][data(size)]. Known compound records are handled above.
			n, err := r.u32()
			if err != nil {
				return Wrap("ovba.dir", err)
			}
			if n > 1<<20 {
				return Wrap("ovba.dir", ErrLimitExceeded)
			}
			if _, err := r.read(int(n)); err != nil {
				return Wrap("ovba.dir", err)
			}
		}
		if id, err = r.u16(); err != nil {
			return Wrap("ovba.dir", err)
		}
	}
}

// rewind backs up the reader by n bytes, used for a small amount of lookahead
// when a record's optional tail is actually the next record id.
func (r *dirReader) rewind(n int) {
	if r.pos >= n {
		r.pos -= n
	}
}

// skipReferenceName consumes a REFERENCENAME (0x0016) record:
// [size(4)][name][reserved(2) == 0x003E][sizeUnicode(4)][utf16]. When the
// reserved marker is absent the value is the next record id and is pushed back.
func (r *dirReader) skipReferenceName() error {
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n > 1<<20 {
		return ErrLimitExceeded
	}
	if _, err := r.read(int(n)); err != nil {
		return err
	}
	reserved, err := r.u16()
	if err != nil {
		return err
	}
	if reserved == 0x003E {
		un, err := r.u32()
		if err != nil {
			return err
		}
		if un > 1<<20 {
			return ErrLimitExceeded
		}
		if _, err := r.read(int(un)); err != nil {
			return err
		}
		return nil
	}
	r.rewind(2)
	return nil
}

func (r *dirReader) skipReferenceOriginal() error {
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n > 1<<20 {
		return ErrLimitExceeded
	}
	_, err = r.read(int(n))
	return err
}

func (r *dirReader) skipReferenceRegistered() error {
	if _, err := r.u32(); err != nil { // total size
		return err
	}
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n > 1<<20 {
		return ErrLimitExceeded
	}
	if _, err := r.read(int(n)); err != nil {
		return err
	}
	if _, err := r.u32(); err != nil {
		return err
	}
	_, err = r.u16()
	return err
}

func (r *dirReader) skipReferenceProject() error {
	if _, err := r.u32(); err != nil {
		return err
	}
	na, err := r.u32()
	if err != nil {
		return err
	}
	if na > 1<<20 {
		return ErrLimitExceeded
	}
	if _, err := r.read(int(na)); err != nil {
		return err
	}
	nr, err := r.u32()
	if err != nil {
		return err
	}
	if nr > 1<<20 {
		return ErrLimitExceeded
	}
	if _, err := r.read(int(nr)); err != nil {
		return err
	}
	if _, err := r.u32(); err != nil {
		return err
	}
	_, err = r.u16()
	return err
}

// skipReferenceControl handles the REFERENCECONTROL (0x002F) record including
// its optional extended name record and trailing extended type-library data.
func (r *dirReader) skipReferenceControl() error {
	if _, err := r.u32(); err != nil { // size of twiddled libid
		return err
	}
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n > 1<<20 {
		return ErrLimitExceeded
	}
	if _, err := r.read(int(n)); err != nil {
		return err
	}
	if _, err := r.u32(); err != nil { // reserved1
		return err
	}
	if _, err := r.u16(); err != nil { // reserved2
		return err
	}
	check2, err := r.u16()
	if err != nil {
		return err
	}
	if check2 == 0x0016 { // optional extended name record
		nn, err := r.u32()
		if err != nil {
			return err
		}
		if nn > 1<<20 {
			return ErrLimitExceeded
		}
		if _, err := r.read(int(nn)); err != nil {
			return err
		}
		reserved, err := r.u16()
		if err != nil {
			return err
		}
		if reserved == 0x003E {
			un, err := r.u32()
			if err != nil {
				return err
			}
			if un > 1<<20 {
				return ErrLimitExceeded
			}
			if _, err := r.read(int(un)); err != nil {
				return err
			}
			if _, err := r.u16(); err != nil { // reserved3 == 0x0030
				return err
			}
		}
	}
	if _, err := r.u32(); err != nil { // sizeextended
		return err
	}
	ne, err := r.u32()
	if err != nil {
		return err
	}
	if ne > 1<<20 {
		return ErrLimitExceeded
	}
	if _, err := r.read(int(ne)); err != nil {
		return err
	}
	if _, err := r.u32(); err != nil { // reserved4
		return err
	}
	if _, err := r.u16(); err != nil { // reserved5
		return err
	}
	if _, err := r.read(16); err != nil { // original type lib
		return err
	}
	_, err = r.u32() // cookie
	return err
}

// parseModules consumes the PROJECTMODULES payload: count, optional
// PROJECTCOOKIE, then each module terminated by MODULETERMINATOR.
func (p *vbaProject) parseModules(r *dirReader) error {
	if _, err := r.u32(); err != nil { // PROJECTMODULES size
		return Wrap("ovba.dir", err)
	}
	count, err := r.u16()
	if err != nil {
		return Wrap("ovba.dir", err)
	}
	if count > 1<<14 {
		return Wrap("ovba.dir", ErrLimitExceeded)
	}
	// Optional PROJECTCOOKIE (0x0013) record.
	id, err := r.u16()
	if err != nil {
		return Wrap("ovba.dir", err)
	}
	if id == recProjectCookie {
		if _, err := r.u32(); err != nil {
			return Wrap("ovba.dir", err)
		}
		if _, err := r.u16(); err != nil {
			return Wrap("ovba.dir", err)
		}
	} else {
		r.rewind(2)
	}
	for i := 0; i < int(count); i++ {
		m, err := parseModule(r, p)
		if err != nil {
			return Wrap("ovba.dir.module", err)
		}
		p.modules = append(p.modules, m)
	}
	return nil
}

// parseModule parses one MODULE record sequence terminated by MODULETERMINATOR,
// following MS-OVBA 2.3.4.2.3.2 and tolerating missing optional sections.
func parseModule(r *dirReader, p *vbaProject) (rawModule, error) {
	var m rawModule
	id, err := r.u16()
	if err != nil {
		return m, err
	}
	if id != recModuleName {
		return m, fmt.Errorf("expected MODULENAME 0x%04X, got 0x%04X", recModuleName, id)
	}
	n, err := r.u32()
	if err != nil {
		return m, err
	}
	if n > 1<<16 {
		return m, ErrLimitExceeded
	}
	nb, err := r.read(int(n))
	if err != nil {
		return m, err
	}
	m.name = decodeCodepage(p.codepage, nb)

	id, err = r.u16()
	if err != nil {
		return m, err
	}
	if id == recModuleNameUni {
		if m.nameUni, err = r.readUniField(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleStreamName {
		n, err := r.u32()
		if err != nil {
			return m, err
		}
		if n > 1<<16 {
			return m, ErrLimitExceeded
		}
		sb, err := r.read(int(n))
		if err != nil {
			return m, err
		}
		m.streamName = decodeCodepage(p.codepage, sb)
		if _, err := r.u16(); err != nil { // reserved 0x0032
			return m, err
		}
		if m.streamNameUni, err = r.readUniField(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleDocString {
		if err := r.discardBounded(); err != nil {
			return m, err
		}
		if _, err := r.u16(); err != nil { // reserved 0x0048
			return m, err
		}
		if err := r.discardBoundedUni(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleOffset {
		if _, err := r.u32(); err != nil { // size == 4
			return m, err
		}
		if m.textOffset, err = r.u32(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleHelpContext {
		if _, err := r.u32(); err != nil {
			return m, err
		}
		if _, err := r.u32(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleCookie {
		if _, err := r.u32(); err != nil {
			return m, err
		}
		if _, err := r.u16(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleTypeProc || id == recModuleTypeClass {
		if id == recModuleTypeClass {
			m.typ = ModuleTypeDocumentClassDesigner
		}
		if _, err := r.u32(); err != nil { // reserved
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleReadOnly {
		m.readOnly = true
		if _, err := r.u32(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModulePrivate {
		m.private = true
		if _, err := r.u32(); err != nil {
			return m, err
		}
		if id, err = r.u16(); err != nil {
			return m, err
		}
	}
	if id == recModuleTerminator {
		if _, err := r.u32(); err != nil { // reserved == 0
			return m, err
		}
		return m, nil
	}
	return m, fmt.Errorf("module %q missing MODULETERMINATOR, got 0x%04X", m.name, id)
}

func (r *dirReader) readUniField() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	if n > 1<<16 {
		return "", ErrLimitExceeded
	}
	b, err := r.read(int(n))
	if err != nil {
		return "", err
	}
	return decodeUTF16(b, binary.LittleEndian), nil
}

func (r *dirReader) discardBounded() error {
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n > 1<<16 {
		return ErrLimitExceeded
	}
	_, err = r.read(int(n))
	return err
}

func (r *dirReader) discardBoundedUni() error {
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n > 1<<16 {
		return ErrLimitExceeded
	}
	_, err = r.read(int(n))
	return err
}
