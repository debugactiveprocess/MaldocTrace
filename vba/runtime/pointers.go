package runtime

import (
	"encoding/hex"
	"strconv"
	"strings"

	"maldoctrace/vba/ast"
)

// Simulated pointers. VarPtr/StrPtr return a deterministic fake address that
// identifies the referenced array element or variable, so that a later
// declared-API call (MultiByteToWideChar, RtlMoveMemory, ...) can be linked to
// the buffer it reads. No memory is ever allocated or accessed.

const ptrBase = int64(0x10000000)
const ptrStride = int64(0x01000000)

type pointerRef struct {
	array  string // lower-case array name ("" for a scalar variable)
	name   string // name as written in the source
	offset int64  // element offset from the array lower bound
	scalar string // variable name for StrPtr/VarPtr on a scalar
}

// evalPointer handles VarPtr/StrPtr/ObjPtr without evaluating the operand.
func (rt *Interp) evalPointer(arg ast.Expr) Value {
	var name string
	var idx ast.Expr
	switch x := arg.(type) {
	case *ast.Paren:
		return rt.evalPointer(x.X)
	case *ast.Ident:
		name = x.Name
	case *ast.Call:
		if id, ok := x.Fn.(*ast.Ident); ok && len(x.Args) == 1 {
			name, idx = id.Name, x.Args[0]
		}
	case *ast.Index:
		if id, ok := x.Base.(*ast.Ident); ok {
			name, idx = id.Name, x.Idx
		}
	}
	if name == "" {
		return NewUnknown("pointer to unsupported expression")
	}
	low := strings.ToLower(name)
	ref := pointerRef{name: name}
	if arr, ok := rt.arrays[low]; ok {
		ref.array = low
		if idx != nil {
			n, ok := rt.eval(idx).CoerceInt()
			if !ok {
				return NewUnknown("pointer with unknown index")
			}
			ref.offset = n - arr.lower
		}
	} else {
		ref.scalar = low
	}
	if rt.pointers == nil {
		rt.pointers = map[int64]pointerRef{}
	}
	base := ptrBase + int64(len(rt.pointers))*ptrStride
	for addr, r := range rt.pointers {
		if r.array == ref.array && r.scalar == ref.scalar {
			base = addr - r.offset
			break
		}
	}
	addr := base + ref.offset
	rt.pointers[addr] = ref
	return VInt(addr)
}

// pointerBytes returns the bytes a simulated pointer refers to, at most n
// bytes when n > 0, and a human-readable description of the source.
func (rt *Interp) pointerBytes(addr int64, n int64) ([]byte, string, bool) {
	ref, ok := rt.pointers[addr]
	if !ok {
		return nil, "", false
	}
	if ref.scalar != "" {
		v, ok := rt.getVar(ref.scalar)
		if !ok || v.IsUnknown() {
			return nil, "", false
		}
		b := []byte(v.CoerceString())
		if n > 0 && int64(len(b)) > n {
			b = b[:n]
		}
		return b, ref.name, true
	}
	arr := rt.arrays[ref.array]
	if arr == nil || ref.offset < 0 || ref.offset >= int64(len(arr.elems)) {
		return nil, "", false
	}
	elems := arr.elems[ref.offset:]
	if n > 0 && int64(len(elems)) > n {
		elems = elems[:n]
	}
	out := make([]byte, len(elems))
	for i, e := range elems {
		if v, ok := e.CoerceInt(); ok {
			out[i] = byte(v)
		}
	}
	return out, ref.name + "(" + strconv.FormatInt(ref.offset+arr.lower, 10) + ")", true
}

// apiBufferArgs maps well-known APIs (by alias or name, lower case) to the
// argument indexes of the source buffer, its byte count and, when relevant,
// the code page.
var apiBufferArgs = map[string]struct{ src, count, codepage int }{
	"multibytetowidechar": {2, 3, 0},
	"rtlmovememory":       {1, 2, -1},
	"copymemory":          {1, 2, -1},
	"writeprocessmemory":  {2, 3, -1},
}

// annotateAPIBuffer records the buffer a declared-API call reads from, when an
// argument is a simulated pointer. The bytes are stored hex-encoded in Extra.
func (rt *Interp) annotateAPIBuffer(d *ast.Declare, args []Value, extra map[string]string) {
	api := strings.ToLower(d.Alias)
	if api == "" {
		api = strings.ToLower(d.Name)
	}
	spec, known := apiBufferArgs[api]
	candidates := []int{}
	if known {
		candidates = append(candidates, spec.src)
	} else {
		for i := range args {
			candidates = append(candidates, i)
		}
	}
	for _, i := range candidates {
		if i >= len(args) {
			continue
		}
		addr, ok := args[i].CoerceInt()
		if !ok {
			continue
		}
		var n int64
		if known && spec.count < len(args) {
			n, _ = args[spec.count].CoerceInt()
		}
		b, src, ok := rt.pointerBytes(addr, n)
		if !ok {
			continue
		}
		extra["api"] = api
		extra["buffer_arg"] = strconv.Itoa(i)
		extra["buffer_source"] = src
		extra["buffer_hex"] = hex.EncodeToString(b)
		if known && spec.codepage >= 0 && spec.codepage < len(args) {
			if cp, ok := args[spec.codepage].CoerceInt(); ok {
				extra["codepage"] = strconv.FormatInt(cp, 10)
			}
		}
		return
	}
}
