package pcode

import (
	"encoding/binary"
	"errors"
)

// Project holds what the p-code of every module needs from the project:
// the identifier names (in _VBA_PROJECT) and how the modules were compiled.
type Project struct {
	// Version is the _VBA_PROJECT version word (Office 2010 0x97, 2013
	// 0xA3, 2016+ 32-bit 0xB2, 64-bit 0xD7, Mac 0xD9).
	Version uint16
	// VBA is the VBA generation (5, 6 or 7) the p-code was compiled by.
	VBA int
	// Is64 is set for p-code compiled by 64-bit Office (dir PROJECTSYSKIND 3).
	Is64        bool
	Identifiers []string
	// Decode turns identifier and string bytes into text (the project
	// code page); nil means Latin-1.
	Decode func([]byte) string
}

// ErrNotVBAProject is returned for a stream without the _VBA_PROJECT magic.
var ErrNotVBAProject = errors.New("pcode: not a _VBA_PROJECT stream")

// reader is a bounds-checked cursor; reads past the end set err and return
// zero so parsing code can check once at the end.
type reader struct {
	b   []byte
	p   int
	be  bool
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.p < 0 || r.p+n > len(r.b) {
		r.err = errors.New("pcode: truncated structure")
		return false
	}
	return true
}

func (r *reader) u16() int {
	if !r.need(2) {
		return 0
	}
	var v uint16
	if r.be {
		v = binary.BigEndian.Uint16(r.b[r.p:])
	} else {
		v = binary.LittleEndian.Uint16(r.b[r.p:])
	}
	r.p += 2
	return int(v)
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	var v uint32
	if r.be {
		v = binary.BigEndian.Uint32(r.b[r.p:])
	} else {
		v = binary.LittleEndian.Uint32(r.b[r.p:])
	}
	r.p += 4
	return v
}

func (r *reader) skip(n int) {
	if r.need(n) {
		r.p += n
	}
}

// skipCounted skips a 16-bit (or 32-bit) element count followed by that
// many elements of size elem; with allowNone a count of all ones means no
// elements.
func (r *reader) skipCounted(wide bool, elem int, allowNone bool) {
	var n int
	if wide {
		v := r.u32()
		if allowNone && v == 0xFFFFFFFF {
			return
		}
		n = int(v)
	} else {
		v := r.u16()
		if allowNone && v == 0xFFFF {
			return
		}
		n = v
	}
	if n < 0 || n > len(r.b) {
		r.err = errors.New("pcode: bad element count")
		return
	}
	r.skip(n * elem)
}

// ParseProject reads the identifier table of a _VBA_PROJECT stream. is64
// comes from the dir stream (PROJECTSYSKIND == 3). A stream that cannot be
// fully parsed still yields the identifiers read so far, with the error.
func ParseProject(stream []byte, is64 bool, decode func([]byte) string) (*Project, error) {
	p := &Project{Is64: is64, Decode: decode}
	if p.Decode == nil {
		p.Decode = latin1
	}
	if len(stream) < 8 || binary.LittleEndian.Uint16(stream) != 0x61CC {
		return p, ErrNotVBAProject
	}
	p.Version = binary.LittleEndian.Uint16(stream[2:])
	switch {
	case p.Version >= 0x97:
		p.VBA = 7
	case p.Version >= 0x6B:
		p.VBA = 6
	default:
		p.VBA = 5
	}
	v := int(p.Version)
	notIn := v != 0x60 && v != 0x62 && v != 0x63
	unicodeRef := (v >= 0x5B && notIn) || v == 0x4E
	unicodeName := (v >= 0x59 && notIn) || v == 0x4E
	ansiName := v <= 0x59 && v != 0x4E
	r := &reader{b: stream, p: 0x1E, be: binary.LittleEndian.Uint16(stream[5:]) == 0x000E}

	// References.
	refs := r.u16()
	r.skip(2)
	for i := 0; i < refs && r.err == nil; i++ {
		n := r.u16()
		switch {
		case n == 0:
			r.skip(6)
		case (unicodeRef && n < 5) || (!unicodeRef && n < 3):
			r.skip(n)
		default:
			kindAt := r.p + 2
			if unicodeRef {
				kindAt = r.p + 4
			}
			var kind byte
			if kindAt < len(stream) {
				kind = stream[kindAt]
			}
			r.skip(n)
			if kind == 'C' || kind == 'D' {
				r.skipCounted(false, 1, false)
			}
		}
		r.skip(10)
		if r.u16() != 0 {
			r.skipCounted(false, 1, false)
			n := r.u16()
			if n != 0 {
				r.skip(2)
			}
			r.skip(n + 30)
		}
	}
	r.skipCounted(false, 2, false) // class/user form table
	r.skipCounted(false, 4, false) // compile-time constants
	r.skip(2)
	r.skipCounted(false, 1, true) // typeinfo id
	r.skipCounted(false, 1, true) // description
	r.skipCounted(false, 1, true) // help file
	r.skip(0x64)

	// Module descriptors.
	mods := r.u16()
	for i := 0; i < mods && r.err == nil; i++ {
		n := r.u16()
		if unicodeName {
			r.skip(n)
		}
		if ansiName {
			if n != 0 {
				n = r.u16()
			}
			r.skip(n)
		}
		r.skipCounted(false, 1, false)
		r.skipCounted(false, 1, true)
		r.u16()
		if v >= 0x6B {
			r.skipCounted(false, 1, true)
		}
		r.skipCounted(false, 1, true)
		r.skip(2)
		if v != 0x51 {
			r.skip(4)
		}
		r.skipCounted(false, 8, false)
		r.skip(11)
	}
	r.skip(6)
	r.skipCounted(true, 1, false)
	r.skip(6)
	w0 := r.u16()
	ids := r.u16()
	w1 := r.u16()
	r.skip(4)
	junk := ids + w1 - w0
	ids = w0 - w1
	if r.err != nil {
		return p, r.err
	}
	if junk < 0 || ids < 0 || ids > 0x10000 || junk > 0x10000 {
		return p, errors.New("pcode: implausible identifier counts")
	}
	typeLen := func() (typ, n int) {
		if !r.need(2) {
			return 0, 0
		}
		a, b := int(r.b[r.p]), int(r.b[r.p+1])
		r.p += 2
		if r.be {
			return a, b
		}
		return b, a
	}
	for i := 0; i < junk && r.err == nil; i++ {
		r.skip(4)
		typ, n := typeLen()
		if typ > 0x7F {
			r.skip(6)
		}
		r.skip(n)
	}
	for i := 0; i < ids && r.err == nil; i++ {
		keyword := false
		typ, n := typeLen()
		if typ == 0 && n == 0 {
			r.skip(2)
			typ, n = typeLen()
			keyword = true
		}
		if typ&0x80 != 0 {
			r.skip(6)
		}
		if n > 0 {
			if !r.need(n) {
				break
			}
			p.Identifiers = append(p.Identifiers, p.Decode(r.b[r.p:r.p+n]))
			r.p += n
		}
		if !keyword {
			r.skip(4)
		}
	}
	return p, r.err
}

func latin1(b []byte) string {
	u := make([]rune, len(b))
	for i, c := range b {
		u[i] = rune(c)
	}
	return string(u)
}

// builtinNames are the VBA keywords and operators that identifier codes
// below 0x100 refer to.
var builtinNames = []string{
	"<crash>", "0", "Abs", "Access", "AddressOf", "Alias", "And", "Any",
	"Append", "Array", "As", "Assert", "B", "Base", "BF", "Binary",
	"Boolean", "ByRef", "Byte", "ByVal", "Call", "Case", "CBool", "CByte",
	"CCur", "CDate", "CDec", "CDbl", "CDecl", "ChDir", "CInt", "Circle",
	"CLng", "Close", "Compare", "Const", "CSng", "CStr", "CurDir", "CurDir$",
	"CVar", "CVDate", "CVErr", "Currency", "Database", "Date", "Date$", "Debug",
	"Decimal", "Declare", "DefBool", "DefByte", "DefCur", "DefDate", "DefDec", "DefDbl",
	"DefInt", "DefLng", "DefObj", "DefSng", "DefStr", "DefVar", "Dim", "Dir",
	"Dir$", "Do", "DoEvents", "Double", "Each", "Else", "ElseIf", "Empty",
	"End", "EndIf", "Enum", "Eqv", "Erase", "Error", "Error$", "Event",
	"WithEvents", "Explicit", "F", "False", "Fix", "For", "Format",
	"Format$", "FreeFile", "Friend", "Function", "Get", "Global", "Go", "GoSub",
	"Goto", "If", "Imp", "Implements", "In", "Input", "Input$", "InputB",
	"InputB", "InStr", "InputB$", "Int", "InStrB", "Is", "Integer", "Left",
	"LBound", "LenB", "Len", "Lib", "Let", "Line", "Like", "Load",
	"Local", "Lock", "Long", "Loop", "LSet", "Me", "Mid", "Mid$",
	"MidB", "MidB$", "Mod", "Module", "Name", "New", "Next", "Not",
	"Nothing", "Null", "Object", "On", "Open", "Option", "Optional", "Or",
	"Output", "ParamArray", "Preserve", "Print", "Private", "Property", "PSet", "Public",
	"Put", "RaiseEvent", "Random", "Randomize", "Read", "ReDim", "Rem", "Resume",
	"Return", "RGB", "RSet", "Scale", "Seek", "Select", "Set", "Sgn",
	"Shared", "Single", "Spc", "Static", "Step", "Stop", "StrComp", "String",
	"String$", "Sub", "Tab", "Text", "Then", "To", "True", "Type",
	"TypeOf", "UBound", "Unload", "Unlock", "Unknown", "Until", "Variant", "WEnd",
	"While", "Width", "With", "Write", "Xor", "#Const", "#Else", "#ElseIf",
	"#End", "#If", "Attribute", "VB_Base", "VB_Control", "VB_Creatable", "VB_Customizable", "VB_Description",
	"VB_Exposed", "VB_Ext_Key", "VB_HelpID", "VB_Invoke_Func", "VB_Invoke_Property", "VB_Invoke_PropertyPut", "VB_Invoke_PropertyPutRef", "VB_MemberFlags",
	"VB_Name", "VB_PredeclaredId", "VB_ProcData", "VB_TemplateDerived", "VB_VarDescription", "VB_VarHelpID", "VB_VarMemberFlags", "VB_VarProcData",
	"VB_UserMemId", "VB_VarUserMemId", "VB_GlobalNameSpace",
}

// Name resolves an identifier code from the p-code.
func (p *Project) Name(code int) string {
	id := code >> 1
	if id >= 0x100 {
		id -= 0x100
		// No one-entry gap after index 0xBE: with it, only 87 of the 283
		// procedure names of a project with 610 identifiers matched its
		// source; without it all 283 did.
		if p.VBA >= 7 {
			id -= 4
			if p.Is64 {
				id -= 3
			}
		}
		if id >= 0 && id < len(p.Identifiers) {
			return p.Identifiers[id]
		}
		return ""
	}
	if p.VBA >= 7 && id >= 0xC3 {
		id--
	}
	if id >= 0 && id < len(builtinNames) {
		return builtinNames[id]
	}
	return ""
}
