package emulation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"maldoctrace/vba/runtime"
)

type folderObject struct {
	h    *Host
	path string
}

func (o *folderObject) TypeName() string { return "File" }
func (o *folderObject) Get(name string) runtime.Value {
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
	h    *Host
	path string
}

func (o *textStream) TypeName() string { return "TextStream" }
func (o *textStream) Get(name string) runtime.Value {
	return runtime.VEmpty
}
func (o *textStream) Set(name string, v runtime.Value) {}
func (o *textStream) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "write", "writeline":
		o.h.rec("file_write", args, map[string]string{"path": o.path})
		return runtime.VEmpty
	case "readall", "readline":
		o.h.recStr("file_read", o.path, nil)
		return runtime.VString("")
	case "close":
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

// adodbStream simulates ADODB.Stream and captures written data so SaveToFile
// reports a reconstructed artifact hash.
type adodbStream struct {
	h   *Host
	buf *buffer
}

func (o *adodbStream) TypeName() string { return "ADODB.Stream" }
func (o *adodbStream) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "position", "size":
		return runtime.VInt(int64(o.buf.len()))
	}
	return runtime.VEmpty
}
func (o *adodbStream) Set(name string, v runtime.Value) {}
func (o *adodbStream) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "open", "close":
		return runtime.VEmpty
	case "writetext":
		o.buf.writeString(argString(args, 0))
		return runtime.VEmpty
	case "write":
		o.buf.writeBytes(argBytes(args, 0))
		return runtime.VEmpty
	case "savetofile":
		p := argString(args, 0)
		o.h.recStr("file_write", p, map[string]string{
			"content_sha256": o.buf.sha256(), "content_hex": o.buf.hex(),
		})
		return runtime.VEmpty
	case "readtext":
		o.h.recStr("file_read", "", nil)
		return runtime.VString("")
	}
	return runtime.VUnknown
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
func (b *buffer) len() int             { return len(b.b) }
func (b *buffer) sha256() string {
	h := sha256.Sum256(b.b)
	return hex.EncodeToString(h[:])
}
func (b *buffer) hex() string { return hex.EncodeToString(b.b) }
