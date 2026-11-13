package extractor

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	// CLSID is the class of the object's storage ("{XXXXXXXX-...}", empty
	// when unset) and CLSIDClass its name when it is a known class. Office
	// instantiates the object by this CLSID, whatever CompObj claims.
	CLSID      string
	CLSIDClass string
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
	if o.CLSIDClass != "" {
		return o.CLSIDClass
	}
	if o.Package != nil {
		return "Package"
	}
	return ""
}

// oleClassCLSIDs names the OLE classes recognised by the CLSID of their
// storage, so an object without (or with a forged) \x01CompObj stream is
// still classified.
var oleClassCLSIDs = map[string]string{
	"{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}": "Shell.Explorer.1",
	"{8856F961-340A-11D0-A96B-00C04FD705A2}": "Shell.Explorer.2",
	"{25336920-03F9-11CF-8FD0-00AA00686F13}": "htmlfile",
	"{0002CE02-0000-0000-C000-000000000046}": "Equation.3",
	"{0003000C-0000-0000-C000-000000000046}": "Package",
	"{00000300-0000-0000-C000-000000000046}": "OLE2Link",
}

// formatCLSID renders a CLSID stored in its on-disk (mixed-endian) layout
// as "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", or "" when it is all zero.
func formatCLSID(c [16]byte) string {
	if c == ([16]byte{}) {
		return ""
	}
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		binary.LittleEndian.Uint32(c[0:]), binary.LittleEndian.Uint16(c[4:]), binary.LittleEndian.Uint16(c[6:]),
		c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15])
}

// setCLSID records the storage class of the object.
func (o *OLEObject) setCLSID(c [16]byte) {
	o.CLSID = formatCLSID(c)
	o.CLSIDClass = oleClassCLSIDs[o.CLSID]
}

// classNote returns the severity and note of the first known class that
// name starts with.
func classNote(name string) (severity, note string, ok bool) {
	low := strings.ToLower(name)
	if low == "" {
		return "", "", false
	}
	for _, k := range knownObjectClasses {
		if strings.HasPrefix(low, k.prefix) {
			return k.severity, k.note, true
		}
	}
	return "", "", false
}

// isBrowserClass reports the OLE classes that host the Internet Explorer
// engine (Shell.Explorer, the WebBrowser control) and navigate to a URL
// stored in their persisted data when the document is opened.
func isBrowserClass(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "shell.explorer")
}

// objectURLs returns the URLs and UNC paths found in an object's data, as
// UTF-16 (how Shell.Explorer persists its location) or as ANSI text.
func objectURLs(b []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range append(utf16URLs(b), urlText.FindAllString(string(b), 16)...) {
		if !seen[u] && len(out) < 16 {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// shortcutExts are file types that run when the browser object opens them;
// URLs ending in them are the payload of the Shell.Explorer.1 chain.
var shortcutExts = []string{".lnk", ".url", ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".cmd", ".bat", ".exe", ".scr", ".cpl", ".msi", ".library-ms", ".search-ms"}

// reportBrowserURLs reports the URLs an embedded browser object navigates
// to. It returns them so callers can skip duplicate generic findings.
func reportBrowserURLs(class string, data []byte, location string, res *Result) map[string]bool {
	done := map[string]bool{}
	for _, u := range objectURLs(data) {
		detail := "embedded " + class + " object (Internet Explorer browser control) navigates to this URL when the document opens"
		if strings.EqualFold(class, "Shell.Explorer.1") {
			detail += "; Shell.Explorer.1 was left without a kill bit and is exploited as CVE-2026-21509"
		}
		p := strings.ToLower(u)
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			p = p[:i]
		}
		for _, ext := range shortcutExts {
			if strings.HasSuffix(p, ext) {
				detail += "; the target is a " + ext + " file, which the browser object opens and runs without a prompt"
				break
			}
		}
		if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "file:") {
			detail += "; UNC/WebDAV path: Windows also sends the user's NTLM credentials to that host"
		}
		res.addExternal(ExternalRef{Kind: "browser_object_url", Severity: "high", Location: location, Target: u, Detail: detail})
		done[u] = true
	}
	return done
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
	o.setCLSID(cfb.storageCLSID(strings.TrimSuffix(prefix, "/")))
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
	e := ExternalRef{Kind: "embedded_ole", Severity: "medium", Location: o.Location, Target: class,
		Detail: "embedded OLE object"}
	if class != "" {
		e.Detail = "embedded OLE object of class " + class
		if o.UserType != "" && o.UserType != class {
			e.Detail += " (" + o.UserType + ")"
		}
	}
	if o.CLSIDClass != "" {
		if class == o.CLSIDClass {
			e.Detail += " (identified by its storage CLSID " + o.CLSID + ")"
		} else {
			e.Detail += "; its storage CLSID " + o.CLSID + " is " + o.CLSIDClass + ", the class Office actually instantiates"
		}
	}
	// The storage CLSID decides what runs, so a known dangerous CLSID wins
	// over a harmless-looking ProgID.
	for _, name := range []string{o.CLSIDClass, class} {
		if sev, note, ok := classNote(name); ok {
			e.Severity = sev
			e.Detail += "; " + note
			break
		}
	}
	var browserURLs map[string]bool
	for _, name := range []string{o.CLSIDClass, class} {
		if isBrowserClass(name) {
			browserURLs = reportBrowserURLs(name, o.Contents, o.Location, res)
			if len(browserURLs) == 0 {
				e.Detail += "; no navigation URL could be decoded from its data"
			}
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
		if browserURLs[u] {
			continue
		}
		res.addExternal(ExternalRef{Kind: "embedded_url", Severity: "medium", Location: o.Location, Target: u, Detail: "URL inside the embedded object"})
	}
}
