package emulation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf16"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

type folderObject struct {
	h    *Host
	path string
}

func (o *folderObject) TypeName() string { return "File" }
func (o *folderObject) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "size":
		if t := o.h.textFile(o.path); t != "" {
			return runtime.VInt(int64(len(t)))
		}
		// A downloaded file's size is not known: droppers test it before
		// launching the payload, and an unknown value lets speculative
		// emulation follow that branch.
		return runtime.NewUnknown("size of " + o.path + " is not simulated")
	case "path":
		return runtime.VString(o.path)
	case "name":
		return runtime.VString(fsoPathPart("getfilename", o.path))
	}
	return runtime.VEmpty
}
func (o *folderObject) Set(name string, v runtime.Value) {}
func (o *folderObject) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "delete":
		o.h.recStr("file_delete", o.path, nil)
		return runtime.VEmpty
	case "copy":
		o.h.rec("file_copy", args, nil)
		return runtime.VEmpty
	case "openastextstream":
		return runtime.VObject(&textStream{h: o.h, path: o.path})
	}
	return runtime.VUnknown
}

type textStream struct {
	h      *Host
	path   string
	closed bool
}

const maxTextFile = 4 << 20

// appendTextFile records text written to a simulated file.
func (h *Host) appendTextFile(path, text string) {
	if h.textFiles == nil {
		h.textFiles = map[string]*strings.Builder{}
	}
	key := strings.ToLower(path)
	b := h.textFiles[key]
	if b == nil {
		b = &strings.Builder{}
		h.textFiles[key] = b
	}
	if b.Len()+len(text) <= maxTextFile {
		b.WriteString(text)
	}
}

// textFile returns what the script wrote to a simulated file.
func (h *Host) textFile(path string) string {
	if b := h.textFiles[strings.ToLower(path)]; b != nil {
		return b.String()
	}
	return ""
}

func (o *textStream) TypeName() string { return "TextStream" }
func (o *textStream) Get(name string) runtime.Value {
	return runtime.VEmpty
}
func (o *textStream) Set(name string, v runtime.Value) {}
func (o *textStream) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "write", "writeline", "writeblanklines":
		o.h.rec("file_write", args, map[string]string{"path": o.path})
		text := ""
		if len(args) > 0 {
			text = args[0].CoerceString()
		}
		switch strings.ToLower(name) {
		case "writeline":
			text += "\r\n"
		case "writeblanklines":
			text = "\r\n"
		}
		o.h.appendTextFile(o.path, text)
		return runtime.VEmpty
	case "readall", "readline":
		o.h.recStr("file_read", o.path, nil)
		return runtime.VString(o.h.textFile(o.path))
	case "close":
		// The whole text written through the stream is reported once, so
		// a script dropped line by line is recovered as one artifact.
		if content := o.h.textFile(o.path); content != "" && !o.closed {
			o.closed = true
			sum := sha256.Sum256([]byte(content))
			o.h.recStr("file_close", o.path, map[string]string{
				"content_sha256": hex.EncodeToString(sum[:]), "content_hex": hex.EncodeToString([]byte(content)),
			})
		}
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

// adodbStream simulates ADODB.Stream: a byte buffer with a position, a
// text/binary mode and a charset. Written data is captured so SaveToFile
// reports a reconstructed artifact. When no Charset is set, text is stored
// as UTF-8 without a BOM (the legacy behaviour scans rely on); an explicit
// Charset gets the real encoding, including the BOM ADODB writes at the
// start of a utf-8 or unicode stream.
type adodbStream struct {
	h          *Host
	buf        *buffer
	pos        int
	binary     bool
	charset    string
	charsetSet bool
}

func (o *adodbStream) TypeName() string { return "ADODB.Stream" }
func (o *adodbStream) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "position":
		return runtime.VInt(int64(o.pos))
	case "size":
		return runtime.VInt(int64(o.buf.len()))
	case "eos":
		return runtime.VBool(o.pos >= o.buf.len())
	case "type":
		if o.binary {
			return runtime.VInt(1)
		}
		return runtime.VInt(2)
	case "charset":
		return runtime.VString(o.cs())
	case "read", "readtext":
		// Methods called without parentheses (x = .Read) arrive as
		// property reads.
		return o.Call(name, nil)
	}
	return runtime.VEmpty
}

func (o *adodbStream) cs() string {
	if o.charset == "" {
		return "Unicode"
	}
	return o.charset
}

func (o *adodbStream) Set(name string, v runtime.Value) {
	switch strings.ToLower(name) {
	case "type":
		n, _ := v.CoerceInt()
		o.binary = n == 1
	case "charset":
		o.charset, o.charsetSet = v.CoerceString(), true
	case "position":
		n, _ := v.CoerceInt()
		if n >= 0 && int(n) <= o.buf.len() {
			o.pos = int(n)
		}
	}
}

// encodeText converts text to the stream's charset.
func (o *adodbStream) encodeText(s string) []byte {
	if !o.charsetSet {
		return []byte(s)
	}
	var out []byte
	switch strings.ToLower(o.charset) {
	case "utf-8", "utf8":
		if o.pos == 0 {
			out = append(out, 0xEF, 0xBB, 0xBF)
		}
		return append(out, s...)
	case "unicode", "utf-16", "utf-16le":
		if o.pos == 0 {
			out = append(out, 0xFF, 0xFE)
		}
		for _, u := range utf16.Encode([]rune(s)) {
			out = append(out, byte(u), byte(u>>8))
		}
		return out
	default: // us-ascii, windows-1252, iso-8859-1 ...
		for _, r := range s {
			if r > 0xFF {
				r = '?'
			}
			out = append(out, byte(r))
		}
		return out
	}
}

// decodeText converts stream bytes to text, skipping a leading BOM.
func (o *adodbStream) decodeText(b []byte) string {
	if !o.charsetSet {
		return string(b)
	}
	switch strings.ToLower(o.charset) {
	case "utf-8", "utf8":
		return string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))
	case "unicode", "utf-16", "utf-16le":
		b = bytes.TrimPrefix(b, []byte{0xFF, 0xFE})
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		return string(utf16.Decode(u))
	case "us-ascii", "ascii":
		r := make([]rune, len(b))
		for i, c := range b {
			if c > 0x7F {
				c = '?'
			}
			r[i] = rune(c)
		}
		return string(r)
	default:
		r := make([]rune, len(b))
		for i, c := range b {
			r[i] = rune(c)
		}
		return string(r)
	}
}

func (o *adodbStream) write(p []byte) {
	o.pos = o.buf.writeAt(o.pos, p)
}

// readCount returns the bytes from the position: n < 0 means all.
func (o *adodbStream) readCount(args []runtime.Value) []byte {
	n := -1
	if len(args) > 0 {
		if v, ok := args[0].CoerceInt(); ok && v >= 0 {
			n = int(v)
		}
	}
	rest := o.buf.b[min(o.pos, o.buf.len()):]
	if n >= 0 && n < len(rest) {
		rest = rest[:n]
	}
	o.pos += len(rest)
	return rest
}

func (o *adodbStream) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "open", "close", "flush":
		return runtime.VEmpty
	case "writetext":
		s := argString(args, 0)
		if n, ok := argInt(args, 1); ok && n == 1 { // adWriteLine
			s += string([]byte{'\r', '\n'})
		}
		o.write(o.encodeText(s))
		return runtime.VEmpty
	case "write":
		o.write(argBytes(args, 0))
		return runtime.VEmpty
	case "read":
		return ByteArray(o.readCount(args))
	case "readtext":
		return runtime.VString(o.decodeText(o.readCount(args)))
	case "seteos":
		o.buf.b = o.buf.b[:min(o.pos, o.buf.len())]
		return runtime.VEmpty
	case "savetofile":
		p := argString(args, 0)
		o.h.recStr("file_write", p, map[string]string{
			"content_sha256": o.buf.sha256(), "content_hex": o.buf.hex(),
		})
		return runtime.VEmpty
	case "loadfromfile":
		o.h.recStr("file_read", argString(args, 0), nil)
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

// ByteArray returns a VBA Byte array value.
func ByteArray(b []byte) runtime.Value {
	arr := make([]runtime.Value, len(b))
	for i, c := range b {
		arr[i] = runtime.VInt(int64(c))
	}
	return runtime.VArray(arr)
}

func argString(args []runtime.Value, i int) string {
	if i < len(args) {
		return args[i].CoerceString()
	}
	return ""
}

func argBytes(args []runtime.Value, i int) []byte {
	if i < len(args) && args[i].Kind == runtime.KindString {
		return []byte(args[i].Str)
	}
	if i < len(args) && args[i].Kind == runtime.KindArray {
		var b []byte
		for _, e := range args[i].Arr {
			if n, ok := e.CoerceInt(); ok {
				b = append(b, byte(n))
			}
		}
		return b
	}
	return nil
}

type buffer struct{ b []byte }

func newBuf() *buffer                  { return &buffer{} }
func (b *buffer) writeString(s string) { b.b = append(b.b, []byte(s)...) }
func (b *buffer) writeBytes(p []byte)  { b.b = append(b.b, p...) }

// writeAt overwrites from pos, growing the buffer, and returns the new pos.
func (b *buffer) writeAt(pos int, p []byte) int {
	if pos > len(b.b) {
		pos = len(b.b)
	}
	end := pos + len(p)
	if end > len(b.b) {
		b.b = append(b.b, make([]byte, end-len(b.b))...)
	}
	copy(b.b[pos:], p)
	return end
}
func (b *buffer) len() int { return len(b.b) }
func (b *buffer) sha256() string {
	h := sha256.Sum256(b.b)
	return hex.EncodeToString(h[:])
}
func (b *buffer) hex() string { return hex.EncodeToString(b.b) }
