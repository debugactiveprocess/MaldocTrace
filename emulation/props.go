package emulation

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// Document properties and variables are a common payload hiding place:
// BuiltInDocumentProperties("Comments"), CustomDocumentProperties("x"),
// ActiveDocument.Variables("x").Value.

type docProp struct {
	name, kind string
	value      runtime.Value
}

// SetProperties provides the document properties and variables.
func (h *Host) SetProperties(props []extractor.DocProperty) {
	for _, p := range props {
		h.props = append(h.props, &docProp{name: p.Name, kind: p.Kind, value: runtime.VString(p.Value)})
	}
}

// propCollection is BuiltInDocumentProperties, CustomDocumentProperties or
// Variables.
type propCollection struct {
	h    *Host
	kind string // builtin | custom | variable
}

func (o *propCollection) TypeName() string { return "DocumentProperties" }
func (o *propCollection) Get(name string) runtime.Value {
	if strings.EqualFold(name, "Count") {
		n := int64(0)
		for _, p := range o.h.props {
			if p.kind == o.kind {
				n++
			}
		}
		return runtime.VInt(n)
	}
	return runtime.NewUnknown("unsupported property " + name)
}
func (o *propCollection) Set(string, runtime.Value) {}
func (o *propCollection) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "", "item":
		if len(args) == 0 {
			return runtime.NewUnknown("property name missing")
		}
		if n, ok := args[0].CoerceInt(); ok && args[0].Kind != runtime.KindString {
			i := int64(0)
			for _, p := range o.h.props {
				if p.kind == o.kind {
					i++
					if i == n {
						return runtime.VObject(&propItem{p: p})
					}
				}
			}
			return runtime.NewUnknown("property index out of range")
		}
		key := args[0].CoerceString()
		for _, p := range o.h.props {
			if p.kind == o.kind && strings.EqualFold(p.name, key) {
				return runtime.VObject(&propItem{p: p})
			}
		}
		if o.kind == "builtin" {
			// Word returns an empty value for an unset built-in property.
			return runtime.VObject(&propItem{p: &docProp{name: key, kind: o.kind, value: runtime.VString("")}})
		}
		return runtime.NewUnknown(o.kind + " property " + key + " not present in the document")
	case "add":
		p := &docProp{name: argString(args, 0), kind: o.kind}
		if len(args) > 1 {
			p.value = args[len(args)-1]
		}
		o.h.props = append(o.h.props, p)
		return runtime.VObject(&propItem{p: p})
	}
	return runtime.NewUnknown("unsupported DocumentProperties method " + name)
}

type propItem struct{ p *docProp }

func (o *propItem) TypeName() string            { return "DocumentProperty" }
func (o *propItem) DefaultValue() runtime.Value { return o.p.value }
func (o *propItem) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "value":
		return o.p.value
	case "name":
		return runtime.VString(o.p.name)
	}
	return runtime.NewUnknown("unsupported DocumentProperty property " + name)
}
func (o *propItem) Set(name string, v runtime.Value) {
	if strings.EqualFold(name, "Value") {
		o.p.value = v
	}
}
func (o *propItem) SetDefaultValue(v runtime.Value) { o.p.value = v }
func (o *propItem) Call(name string, _ []runtime.Value) runtime.Value {
	if strings.EqualFold(name, "Delete") {
		o.p.value = runtime.VEmpty
		return runtime.VEmpty
	}
	return runtime.NewUnknown("unsupported DocumentProperty method " + name)
}
