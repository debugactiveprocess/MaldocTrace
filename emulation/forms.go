package emulation

import (
	"maldoctrace/vba/runtime"
	"strings"
)

func (h *Host) RegisterForm(module, name string, props map[string]string, stream string, offset int) {
	key := strings.ToLower(module)
	if h.formControls[key] == nil {
		h.formControls[key] = map[string]*formObject{}
	}
	h.formControls[key][strings.ToLower(name)] = &formObject{h: h, name: module + "." + name, props: props, stream: stream}
}

type formObject struct {
	h      *Host
	name   string
	props  map[string]string
	stream string
}

func (o *formObject) TypeName() string { return "Forms.Control:" + o.name }
func (o *formObject) Get(n string) runtime.Value {
	if v, ok := o.props[strings.ToLower(n)]; ok {
		return runtime.VString(v)
	}
	return runtime.NewUnknown("missing form property " + o.name + "." + n)
}
func (o *formObject) Set(n string, v runtime.Value)                  { o.props[strings.ToLower(n)] = v.CoerceString() }
func (o *formObject) Call(n string, a []runtime.Value) runtime.Value { return runtime.VUnknown }
func (o *formObject) DefaultValue() runtime.Value                    { return o.Get("value") }
