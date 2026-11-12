package emulation

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// xmlDOM models MSXML2.DOMDocument / Microsoft.XMLDOM far enough for the
// classic Base64 decoding trick: CreateElement, DataType = "bin.base64",
// Text = data, then NodeTypedValue returns the decoded bytes (and the
// reverse, NodeTypedValue = bytes, then Text returns Base64).
type xmlDOM struct{ h *Host }

func (o *xmlDOM) TypeName() string { return "DOMDocument" }
func (o *xmlDOM) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "documentelement":
		return runtime.VObject(&xmlElement{h: o.h, name: "root"})
	}
	return runtime.VEmpty
}
func (o *xmlDOM) Set(name string, v runtime.Value) {}
func (o *xmlDOM) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "createelement", "createnode":
		n := argString(args, len(args)-1)
		if strings.EqualFold(name, "createnode") && len(args) >= 2 {
			n = argString(args, 1)
		}
		return runtime.VObject(&xmlElement{h: o.h, name: n})
	case "loadxml", "load", "appendchild", "setproperty":
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

// xmlElement is a DOM element with a typed value.
type xmlElement struct {
	h        *Host
	name     string
	dataType string
	text     string
}

func (o *xmlElement) TypeName() string { return "IXMLDOMElement" }

// typed decodes the element text according to its data type.
func (o *xmlElement) typed() runtime.Value {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, o.text)
	switch strings.ToLower(o.dataType) {
	case "bin.base64":
		b, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "="))
		}
		if err != nil {
			return runtime.NewUnknown("invalid Base64 in bin.base64 element")
		}
		return ByteArray(b)
	case "bin.hex":
		b, err := hex.DecodeString(clean)
		if err != nil {
			return runtime.NewUnknown("invalid hex in bin.hex element")
		}
		return ByteArray(b)
	}
	return runtime.VString(o.text)
}

func (o *xmlElement) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "text", "nodevalue":
		return runtime.VString(o.text)
	case "datatype":
		return runtime.VString(o.dataType)
	case "nodename", "tagname":
		return runtime.VString(o.name)
	case "nodetypedvalue":
		return o.typed()
	}
	return runtime.VEmpty
}

func (o *xmlElement) Set(name string, v runtime.Value) {
	switch strings.ToLower(name) {
	case "text", "nodevalue":
		o.text = v.CoerceString()
	case "datatype":
		o.dataType = v.CoerceString()
	case "nodetypedvalue":
		b := argBytes([]runtime.Value{v}, 0)
		switch strings.ToLower(o.dataType) {
		case "bin.base64":
			o.text = base64.StdEncoding.EncodeToString(b)
		case "bin.hex":
			o.text = hex.EncodeToString(b)
		default:
			o.text = v.CoerceString()
		}
	}
}

func (o *xmlElement) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "setattribute", "appendchild":
		return runtime.VEmpty
	}
	return runtime.VUnknown
}
