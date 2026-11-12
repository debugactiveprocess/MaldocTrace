package extractor

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// OLE object storages ([MS-OLEDS]) appear in Word's ObjectPool, Excel's MBD
// storages and the oleObject*.bin parts of OOXML packages. Each storage may
// hold:
//
//	\x01Ole          OLEStream: flags (linked object) and the source monikers
//	\x01CompObj      user type and ProgID of the object
//	\x03ObjInfo      Word ODT: link and update flags
//	\x01Ole10Native  OLE1 Package: label, original path, temp path, file data
//	Equation Native  Equation Editor MTEF data
//	Package/CONTENTS the embedded file itself (OOXML package, PDF...)

// OLEObject is what was learned from one OLE object storage.
type OLEObject struct {
	Location string
	// UserType and ProgID come from \x01CompObj.
	UserType string
	ProgID   string
	// Linked is set when the \x01Ole stream flags the object as a link;
	// Monikers lists the decoded link sources (URL or file path).
	Linked   bool
	Monikers []string
	// AutoUpdate is set when ObjInfo says a link refreshes without asking.
	AutoUpdate bool
	// Package fields come from \x01Ole10Native.
	Package *OLEPackage
	// Equation is the exploit description of a malformed MTEF stream.
	Equation mtefFinding
	// Contents is the embedded file (Package, CONTENTS, CONTENTS stream...)
	// and ContentsStream names the stream it came from.
	Contents       []byte
	ContentsStream string
}

// OLEPackage is a decoded Ole10Native (OLE1 Package object) payload.
type OLEPackage struct {
	Label    string
	Path     string
	TempPath string
	Data     []byte
}

// Class returns the best class name known for the object.
func (o *OLEObject) Class() string {
	if o.ProgID != "" {
		return o.ProgID
	}
	if o.UserType != "" {
		return o.UserType
	}
	if o.Package != nil {
		return "Package"
	}
	return ""
}

var (
	clsidURLMoniker  = []byte{0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9, 0x0B}
	clsidFileMoniker = []byte{0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
)

const (
	nameOle       = "\x01Ole"
	nameCompObj   = "\x01CompObj"
	nameObjInfo   = "\x03ObjInfo"
	nameOle10Nat  = "\x01Ole10Native"
	nameEquation  = "Equation Native"
	maxOLEObjects = 256
)

// parseOLEStream reads the flags and moniker targets of an \x01Ole stream.
// The monikers are found by their CLSIDs rather than by walking the
// OLEStream fields, so composite monikers and corrupted size fields still
// yield their URL or path.
func parseOLEStream(b []byte) (linked bool, targets []string) {
	if len(b) >= 8 {
		linked = binary.LittleEndian.Uint32(b[4:])&1 != 0
	}
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] && len(targets) < 16 {
			seen[s] = true
			targets = append(targets, s)
		}
	}
	for from := 0; from < len(b); {
		i := bytes.Index(b[from:], clsidURLMoniker)
		if i < 0 {
			break
		}
		p := from + i + 16
		from = p
		if p+4 > len(b) {
			break
		}
		n := int(binary.LittleEndian.Uint32(b[p:]))
		p += 4
		if n <= 0 || n > len(b)-p {
			n = len(b) - p
		}
		add(utf16Z(b[p : p+n]))
	}
	for from := 0; from < len(b); {
		i := bytes.Index(b[from:], clsidFileMoniker)
		if i < 0 {
			break
		}
		p := from + i + 16
		from = p
		// cAnti (2), ansiLength (4), ansiPath
		if p+6 > len(b) {
			break
		}
		n := int(binary.LittleEndian.Uint32(b[p+2:]))
		p += 6
		if n <= 0 || n > 4096 || p+n > len(b) {
			continue
		}
		ansi := strings.TrimRight(string(b[p:p+n]), "\x00")
		p += n
		// endServer (2), version (2), reserved (16), cbUnicodePathSize (4),
		// cbUnicodePathBytes (4), usKeyValue (2), unicode path.
		if p+28 <= len(b) {
			cb := int(binary.LittleEndian.Uint32(b[p+20:]))
			q := p + 30
			if cb > 6 && q+cb-6 <= len(b) {
				if u := utf16Z(b[q : q+cb-6]); u != "" {
					ansi = u
				}
			}
		}
		if printableASCII(ansi) || strings.ContainsAny(ansi, `\/:`) {
			add(ansi)
		}
	}
	return linked, targets
}

// utf16Z decodes UTF-16LE text up to the first NUL.
func utf16Z(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// parseCompObj returns the user type and ProgID of a \x01CompObj stream
// ([MS-OLEDS] 2.3.8): 28-byte header, AnsiUserType, AnsiClipboardFormat,
// then the ProgID as a length-prefixed ANSI string.
func parseCompObj(b []byte) (userType, progID string) {
	userType, p, ok := lpString(b, 28)
	if !ok {
		return "", ""
	}
	if p+4 > len(b) {
		return userType, ""
	}
	switch m := binary.LittleEndian.Uint32(b[p:]); {
	case m == 0:
		p += 4
	case m == 0xFFFFFFFF || m == 0xFFFFFFFE:
		p += 8
	default:
		if _, q, ok := lpString(b, p); ok {
			p = q
		} else {
			return userType, ""
		}
	}
	prog, _, ok := lpString(b, p)
	if !ok || !printableASCII(prog) || len(prog) > 128 {
		prog = ""
	}
	if !printableASCII(userType) {
		userType = strings.Map(func(r rune) rune {
			if r < 0x20 {
				return -1
			}
			return r
		}, userType)
	}
	return userType, prog
}

// parseOle10Native decodes an OLE1 Package ([MS-OLEDS] 2.3.6 and the
// Packager format): total size, then type, label, original path, reserved,
// temp path and the file data. Malformed streams yield what could be read.
func parseOle10Native(b []byte) *OLEPackage {
	if len(b) < 6 {
		return nil
	}
	total := int(binary.LittleEndian.Uint32(b))
	body := b[4:]
	if total > 0 && total <= len(body) {
		body = body[:total]
	}
	pkg := &OLEPackage{}
	p := 2 // type (2 = embedded file)
	sz := func() (string, bool) {
		if p >= len(body) {
			return "", false
		}
		i := bytes.IndexByte(body[p:], 0)
		if i < 0 || i > 1024 {
			return "", false
		}
		s := string(body[p : p+i])
		p += i + 1
		return s, true
	}
	var ok bool
	if pkg.Label, ok = sz(); !ok {
		pkg.Data = body
		return pkg
	}
	if pkg.Path, ok = sz(); !ok {
		return pkg
	}
	// Reserved (2 bytes, 0x0000) and type (2 bytes, 0x0003), then the
	// temp path as a length-prefixed string.
	p += 4
	if p+4 > len(body) {
		return pkg
	}
	n := int(binary.LittleEndian.Uint32(body[p:]))
	p += 4
	if n < 0 || n > 4096 || p+n > len(body) {
		return pkg
	}
	pkg.TempPath = strings.TrimRight(string(body[p:p+n]), "\x00")
	p += n
	if p+4 > len(body) {
		return pkg
	}
	n = int(binary.LittleEndian.Uint32(body[p:]))
	p += 4
	if n < 0 || n > len(body)-p {
		n = len(body) - p
	}
	pkg.Data = body[p : p+n]
	return pkg
}

// odtFlags reads the ODT flags of a Word \x03ObjInfo stream: bit 0 is fLink
// and bit 3 fManual (a link without fManual refreshes automatically).
func odtFlags(b []byte) (link, manual bool) {
	if len(b) < 2 {
		return false, false
	}
	f := binary.LittleEndian.Uint16(b)
	return f&0x0001 != 0, f&0x0008 != 0
}

// oleStoragePrefixes returns the storages (with a trailing slash) whose
// path starts with root and that directly contain one of the OLE object
// streams. root "" means the container root itself counts too.
func oleStoragePrefixes(cfb *cfbReader, root string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range cfb.listStreams() {
		switch leafName(s) {
		case nameOle, nameCompObj, nameOle10Nat, nameEquation, nameObjInfo:
		default:
			continue
		}
		dir := parentPath(s)
		if !strings.HasPrefix(dir, root) || seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, dir)
		if len(out) >= maxOLEObjects {
			break
		}
	}
	return out
}

// readOLEObject inspects the OLE object stored under prefix ("" for the
// container root, or "ObjectPool/_1234/").
func readOLEObject(cfb *cfbReader, prefix, location string) *OLEObject {
	o := &OLEObject{Location: location}
	if b, err := cfb.readStream(prefix + nameCompObj); err == nil {
		o.UserType, o.ProgID = parseCompObj(b)
	}
	if b, err := cfb.readStream(prefix + nameOle); err == nil {
		o.Linked, o.Monikers = parseOLEStream(b)
	}
	if b, err := cfb.readStream(prefix + nameObjInfo); err == nil {
		link, manual := odtFlags(b)
		if link {
			o.Linked = true
			o.AutoUpdate = !manual
		}
	}
	if b, err := cfb.readStream(prefix + nameOle10Nat); err == nil {
		o.Package = parseOle10Native(b)
	}
	if b, err := cfb.readStream(prefix + nameEquation); err == nil {
		o.Equation = mtefExploit(b)
		if o.ProgID == "" && o.UserType == "" {
			o.ProgID = "Equation.3"
		}
	}
	for _, name := range []string{"Package", "CONTENTS", "Contents"} {
		if b, err := cfb.readStream(prefix + name); err == nil && len(b) > 0 {
			o.Contents, o.ContentsStream = b, name
			break
		}
	}
	if o.Contents == nil && o.Package != nil && len(o.Package.Data) > 0 {
		o.Contents, o.ContentsStream = o.Package.Data, nameOle10Nat
	}
	return o
}

// reportOLEObject turns an inspected object into external references.
func reportOLEObject(o *OLEObject, res *Result) {
	class := o.Class()
	lowClass := strings.ToLower(class)
	e := ExternalRef{Kind: "embedded_ole", Severity: "medium", Location: o.Location, Target: class,
		Detail: "embedded OLE object"}
	if class != "" {
		e.Detail = "embedded OLE object of class " + class
		if o.UserType != "" && o.UserType != class {
			e.Detail += " (" + o.UserType + ")"
		}
	}
	for _, k := range knownObjectClasses {
		if strings.HasPrefix(lowClass, k.prefix) {
			e.Severity = k.severity
			e.Detail += "; " + k.note
			break
		}
	}
	if p := o.Package; p != nil {
		e.Severity = "high"
		e.Detail += "; OLE Package"
		if p.Label != "" {
			e.Detail += " labelled " + strconv.Quote(p.Label)
		}
		if p.Path != "" {
			e.Detail += ", original path " + strconv.Quote(p.Path)
		}
		if p.TempPath != "" && p.TempPath != p.Path {
			e.Detail += ", temp path " + strconv.Quote(p.TempPath)
		}
		e.Detail += " (" + strconv.Itoa(len(p.Data)) + " bytes)"
		if p.Label != "" && class == "" {
			e.Target = p.Label
		}
	}
	if o.Equation.detail != "" {
		e.Severity = "high"
		e.Detail += "; " + o.Equation.detail
		payload := o.Equation.payload
		if len(payload) > 1024 {
			payload = payload[:1024]
		}
		defer res.addExternal(ExternalRef{Kind: "equation_editor_exploit", Severity: "high", Location: o.Location,
			Target: hexString(payload), Detail: o.Equation.detail + "; target is the bytes after the malformed record (hex; usually the first-stage shellcode)"})
	}
	if o.Linked || len(o.Monikers) > 0 {
		for _, m := range o.Monikers {
			low := strings.ToLower(m)
			detail := "linked OLE object"
			if class != "" {
				detail += " of class " + class
			}
			detail += " loaded from " + m
			if strings.Contains(low, "://") {
				detail += "; Office fetches the URL moniker when the object is loaded (CVE-2017-0199 pattern)"
			}
			if o.AutoUpdate {
				detail += "; the link updates automatically"
			}
			res.addExternal(ExternalRef{Kind: "external_ole", Severity: "high", Location: o.Location, Target: m, Detail: detail})
		}
		if len(o.Monikers) == 0 {
			e.Detail += "; flagged as a linked object but no link source could be decoded"
		}
	}
	if len(o.Monikers) == 0 || class != "" || o.Package != nil {
		res.addExternal(e)
	}
	var urls []string
	if p := o.Package; p != nil {
		urls = append(urls, urlText.FindAllString(p.Path+" "+p.TempPath, 4)...)
	}
	for _, u := range urls {
		res.addExternal(ExternalRef{Kind: "embedded_url", Severity: "medium", Location: o.Location, Target: u, Detail: "URL inside the embedded object"})
	}
}

// scanObjectPool reports the embedded and linked objects of a Word 97-2003
// document (ObjectPool/_<id> storages).
func scanObjectPool(cfb *cfbReader, res *Result) []*OLEObject {
	var out []*OLEObject
	for _, prefix := range oleStoragePrefixes(cfb, "ObjectPool/") {
		o := readOLEObject(cfb, prefix, strings.TrimSuffix(prefix, "/"))
		reportOLEObject(o, res)
		out = append(out, o)
	}
	return out
}
