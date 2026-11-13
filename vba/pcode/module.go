package pcode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Instr is one decoded p-code instruction.
type Instr struct {
	Op string
	// Type is the 6-bit operand type stored above the opcode number
	// (variable type suffix, Dim scope, call form, special literal...).
	Type int
	// Names are resolved identifier operands, Words immediate operands.
	Names []string
	Words []int
	// Bytes is the payload of a variable-length instruction (literal
	// string, comment text).
	Bytes []byte
	// Func and Var describe the procedure or variable of FuncDefn,
	// VarDefn and Dim-like instructions.
	Func *FuncDecl
	Var  *VarDecl
	// Import is the class name of New/TypeOf operands, when known.
	Import string
}

// Line is the p-code of one source line.
type Line []Instr

// FuncDecl is a Sub/Function/Property declaration from the indirect table.
type FuncDecl struct {
	Name    string
	Kind    string // "Sub", "Function", "Property Get", "Property Let", "Property Set"
	Scope   string // "Public", "Private", "Friend" or ""
	Static  bool
	Declare bool
	PtrSafe bool
	Lib     string
	Alias   string
	Params  []Param
	Returns string
	HasAs   bool
}

// Param is one procedure parameter.
type Param struct {
	Name     string
	ByVal    bool
	ByRef    bool
	Optional bool
	Type     string
}

// VarDecl is a variable declaration from the indirect table.
type VarDecl struct {
	Name string
	New  bool
	Type string
	// Array is set for array variables; the bounds of a fixed-size array
	// are pushed by the p-code of the declaring line.
	Array bool
}

// Module is the disassembled p-code of one module.
type Module struct {
	Lines []Line
}

var typeNames = []string{"", "Null", "Integer", "Long", "Single", "Double", "Currency", "Date", "String", "Object", "Error", "Boolean", "Variant", "", "Decimal", "", "", "Byte", "", "", "LongLong"}

func typeName(id int) string {
	t := id &^ 0xE0
	if t == 20 && id&0x80 != 0 {
		return "LongPtr"
	}
	if t >= 0 && t < len(typeNames) {
		return typeNames[t]
	}
	return ""
}

// arrayDescMagic starts the indirect-table descriptor of an array type;
// its element type is the byte at offset 6.
const arrayDescMagic = 0x1B

var declTableSig = []byte{0xB6, 0x00, 0xFF, 0xFF, 0x01, 0x01}

// ErrNoPCode is returned for a module stream without a p-code line table.
var ErrNoPCode = errors.New("pcode: module has no compiled p-code")

// limits that keep hostile streams from producing unbounded output.
const (
	maxLines      = 200000
	maxLineLength = 0x10000
	maxParams     = 64
)

// Disassemble decodes the p-code of a module stream (the bytes before the
// compressed source, or the whole stream).
func Disassemble(stream []byte, p *Project) (mod *Module, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pcode: malformed module: %v", r)
		}
	}()
	if p == nil || p.VBA < 6 {
		return nil, errors.New("pcode: only VBA6/VBA7 p-code is supported")
	}
	if len(stream) < 0x50 {
		return nil, ErrNoPCode
	}
	be := binary.LittleEndian.Uint16(stream[2:]) > 0xFF
	rd := &reader{b: stream, be: be}
	at32 := func(off int) int {
		r := &reader{b: stream, p: off, be: be}
		v := r.u32()
		if r.err != nil || v > uint32(len(stream)) {
			return -1
		}
		return int(v)
	}
	slice := func(lenAt int) []byte {
		n := at32(lenAt)
		if n < 0 || lenAt+4+n > len(stream) {
			return nil
		}
		return stream[lenAt+4 : lenAt+4+n]
	}
	m := &modTables{proj: p, be: be}
	// The declaration table (Declare statements: library and alias) is
	// length-prefixed right after the bytes B6 00 FF FF 01 01; where that
	// lands depends on the Office build (0x43 for 64-bit Office 2010,
	// 0x3F otherwise), so it is located by that signature.
	declLen := 0x3F
	if p.Is64 && p.Version < 0xA0 {
		declLen = 0x43
	}
	if i := bytes.Index(stream[0x30:min(len(stream), 0x60)], declTableSig); i >= 0 {
		declLen = 0x30 + i + len(declTableSig)
	}
	m.decls = slice(declLen)
	if v := at32(0x11); v >= 0 {
		start := v + 10
		if p.Is64 {
			start = v + 12
		}
		m.indirect = slice(start)
	}
	if v := at32(0x05); v >= 0 {
		m.objects = slice(v + 0x8A)
	}
	base := at32(0x19)
	if base < 0 {
		return nil, ErrNoPCode
	}
	rd.p = base + 0x3C
	if rd.u16() != 0xCAFE {
		return nil, ErrNoPCode
	}
	rd.skip(2)
	n := rd.u16()
	if rd.err != nil || n > maxLines {
		return nil, ErrNoPCode
	}
	codeStart := rd.p + n*12 + 10
	mod = &Module{Lines: make([]Line, 0, n)}
	for i := 0; i < n; i++ {
		rd.skip(4)
		length := rd.u16()
		rd.skip(2)
		off := int(rd.u32())
		if rd.err != nil {
			return mod, rd.err
		}
		var line Line
		if length > 0 && length < maxLineLength && off >= 0 && codeStart+off+length <= len(stream) {
			line = m.decodeLine(stream[codeStart+off : codeStart+off+length])
		}
		mod.Lines = append(mod.Lines, line)
	}
	return mod, nil
}

type modTables struct {
	proj                     *Project
	be                       bool
	decls, indirect, objects []byte
}

func (m *modTables) word(b []byte, off int) int {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	if m.be {
		return int(binary.BigEndian.Uint16(b[off:]))
	}
	return int(binary.LittleEndian.Uint16(b[off:]))
}

func (m *modTables) dword(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	if m.be {
		return binary.BigEndian.Uint32(b[off:])
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func (m *modTables) decodeLine(code []byte) Line {
	r := &reader{b: code, be: m.be}
	var line Line
	for r.p+2 <= len(code) && r.err == nil {
		w := r.u16()
		typ := w >> 10
		op := normalizeOpcode(w&0x3FF, m.proj.VBA, m.proj.Is64)
		if op < 0 || op >= len(opTable) {
			line = append(line, Instr{Op: "Unknown", Type: typ, Words: []int{w & 0x3FF}})
			break
		}
		info := opTable[op]
		in := Instr{Op: info.name, Type: typ}
		for _, kind := range info.operands {
			switch kind {
			case opName:
				in.Names = append(in.Names, m.proj.Name(r.u16()))
			case opWord:
				in.Words = append(in.Words, r.u16())
			case opImport:
				v := r.u16()
				in.Words = append(in.Words, v)
				if info.name != "Open" && v+8 <= len(m.objects) {
					in.Import = m.proj.Name(m.word(m.objects, v+6))
				}
			case opFunc, opVar, opRecord, opType, opContext:
				d := int(r.u32())
				in.Words = append(in.Words, d)
				switch kind {
				case opFunc:
					if d >= 0 && d+61 <= len(m.indirect) {
						in.Func = m.funcDecl(d, typ)
					}
				case opVar:
					if d >= 0 && d+16 <= len(m.indirect) {
						in.Var = m.varDecl(d)
					}
					if typ&0x10 != 0 {
						in.Words = append(in.Words, r.u16())
					}
				case opType:
					if d >= 0 && d+7 <= len(m.indirect) {
						in.Import = typeName(int(m.indirect[d+6]))
					}
				case opRecord:
					if d >= 0 && d+20 <= len(m.indirect) {
						in.Names = append(in.Names, m.proj.Name(m.word(m.indirect, d+2)))
					}
				case opContext:
					if m.proj.Is64 {
						r.u32()
					}
				}
			}
		}
		if info.variable {
			n := r.u16()
			if !r.need(n) {
				break
			}
			in.Bytes = code[r.p : r.p+n]
			r.p += n + n&1
		}
		line = append(line, in)
	}
	return line
}

func (m *modTables) funcDecl(d, opType int) *FuncDecl {
	t := m.indirect
	p := m.proj
	f := &FuncDecl{}
	flags := m.word(t, d)
	f.Name = p.Name(m.word(t, d+2))
	o := 0
	if p.VBA > 5 {
		o = 4
	}
	if p.Is64 {
		o += 16
	}
	argOff := m.dword(t, d+o+36)
	ret := m.dword(t, d+o+40)
	declOff := m.word(t, d+o+44)
	var cOptions, newFlags byte
	if d+o+57 < len(t) {
		cOptions, newFlags = t[d+o+54], t[d+o+57]
	}
	if !p.Is64 && newFlags&0x02 == 0 {
		f.Scope = "Private"
	}
	if newFlags&0x04 != 0 {
		f.Scope = "Friend"
	}
	if opType&0x04 != 0 {
		f.Scope = "Public"
	}
	f.Static = flags&0x0080 != 0
	if cOptions&0x90 == 0 && declOff != 0xFFFF {
		f.Declare = true
		f.Lib = p.Name(m.word(m.decls, declOff+2))
		// The word at +4 is the offset of the Alias name, a NUL-terminated
		// ANSI string elsewhere in the declaration table.
		if a := m.word(m.decls, declOff+4); a > declOff+4 && a < len(m.decls) {
			if end := bytes.IndexByte(m.decls[a:], 0); end > 0 && end < 256 {
				if alias := m.decls[a : a+end]; printableName(alias) {
					f.Alias = string(alias)
				}
			}
		}
	}
	f.PtrSafe = newFlags&0x20 != 0
	f.HasAs = flags&0x0020 != 0
	switch {
	case flags&0x1000 != 0:
		f.Kind = "Sub"
		if opType == 2 || opType == 6 {
			f.Kind = "Function"
		}
	case flags&0x2000 != 0:
		f.Kind = "Property Get"
	case flags&0x4000 != 0:
		f.Kind = "Property Let"
	case flags&0x8000 != 0:
		f.Kind = "Property Set"
	default:
		f.Kind = "Sub"
	}
	ao := 0
	if p.Is64 {
		ao = 4
	}
	seen := map[uint32]bool{}
	for argOff != 0 && argOff != 0xFFFFFFFF && int(argOff)+26 < len(t) && !seen[argOff] && len(f.Params) < maxParams {
		seen[argOff] = true
		a := int(argOff)
		pf := m.word(t, a)
		par := Param{Name: p.Name(m.word(t, a+2))}
		at := m.dword(t, a+ao+12)
		opts := m.word(t, a+ao+24)
		par.ByVal = opts&0x0004 != 0
		par.ByRef = opts&0x0002 != 0
		par.Optional = opts&0x0200 != 0
		if pf&0x0020 != 0 && at&0xFFFF0000 != 0 {
			par.Type = typeName(int(at & 0xFF))
		}
		f.Params = append(f.Params, par)
		// The link to the next parameter follows the 64-bit pointers too.
		argOff = m.dword(t, a+ao+20)
	}
	if f.HasAs {
		if ret&0xFFFF0000 == 0xFFFF0000 {
			f.Returns = typeName(int(ret & 0xFF))
		} else {
			f.Returns = p.Name(m.word(t, int(ret)+6))
		}
	}
	return f
}

func (m *modTables) varDecl(d int) *VarDecl {
	t := m.indirect
	v := &VarDecl{Name: m.proj.Name(m.word(t, d+2))}
	hasAs := t[d]&0x20 != 0
	v.New = t[d+1]&0x20 != 0
	// Scalar variables carry bit 0x40 in their first flag byte; arrays do
	// not, and their type field points to an array descriptor.
	v.Array = t[d]&0x40 == 0
	o := 12
	if m.proj.Is64 {
		o = 16
	}
	if v.Array {
		desc := int(m.dword(t, d+o))
		if desc >= 0 && desc+7 <= len(t) && t[desc] == arrayDescMagic {
			if hasAs {
				v.Type = typeName(int(t[desc+6]))
			}
			return v
		}
	}
	if hasAs {
		if m.word(t, d+o+2) == 0xFFFF {
			if d+o < len(t) {
				v.Type = typeName(int(t[d+o]))
			}
		} else if !m.proj.Is64 {
			v.Type = m.objectType(d + o)
		}
	}
	return v
}

// objectType resolves the class name of a variable declared As SomeClass.
func (m *modTables) objectType(off int) string {
	desc := int(m.dword(m.indirect, off))
	if desc < 0 || desc+4 > len(m.indirect) {
		return ""
	}
	if m.word(m.indirect, desc)&0x02 != 0 {
		if desc+7 <= len(m.indirect) {
			return typeName(int(m.indirect[desc+6]))
		}
		return ""
	}
	w := m.word(m.indirect, desc+2)
	if w == 0 {
		return ""
	}
	o := (w >> 2) * 10
	if o+8 > len(m.objects) {
		return ""
	}
	return m.proj.Name(m.word(m.objects, o+6))
}

// printableName accepts identifier-like ASCII (API names, ordinals "#12").
func printableName(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7E {
			return false
		}
	}
	return len(b) > 0
}

// literal helpers used by the decompiler.
func wordsInt(ws []int) int64 {
	var v uint64
	for i := len(ws) - 1; i >= 0; i-- {
		v = v<<16 | uint64(ws[i]&0xFFFF)
	}
	switch len(ws) {
	case 1:
		return int64(int16(v))
	case 2:
		return int64(int32(v))
	}
	return int64(v)
}

func wordsFloat(ws []int) float64 {
	var v uint64
	for i := len(ws) - 1; i >= 0; i-- {
		v = v<<16 | uint64(ws[i]&0xFFFF)
	}
	if len(ws) == 2 {
		return float64(math.Float32frombits(uint32(v)))
	}
	return math.Float64frombits(v)
}
