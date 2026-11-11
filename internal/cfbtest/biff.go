package cfbtest

import (
	"encoding/binary"
	"math"
)

// Parsed-formula token builders (BIFF8 Rgce, value class).

// PtgStr is a string constant.
func PtgStr(s string) []byte { return append([]byte{0x17, byte(len(s)), 0}, s...) }

// PtgInt is an integer constant.
func PtgInt(n uint16) []byte { return []byte{0x1E, byte(n), byte(n >> 8)} }

// PtgNum is a floating-point constant.
func PtgNum(f float64) []byte {
	b := []byte{0x1F, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint64(b[1:], math.Float64bits(f))
	return b
}

// PtgRef is an absolute reference to a cell of the same sheet.
func PtgRef(row, col uint16) []byte {
	return []byte{0x44, byte(row), byte(row >> 8), byte(col), byte(col >> 8)}
}

// PtgRef3d is an absolute reference through EXTERNSHEET entry ixti.
func PtgRef3d(ixti, row, col uint16) []byte {
	return []byte{0x3A, byte(ixti), byte(ixti >> 8), byte(row), byte(row >> 8), byte(col), byte(col >> 8)}
}

// PtgFunc calls a fixed-arity built-in function.
func PtgFunc(idx uint16) []byte { return []byte{0x41, byte(idx), byte(idx >> 8)} }

// PtgFuncVar calls a function with n arguments; set 0x8000 in idx for a
// command-equivalent function.
func PtgFuncVar(n byte, idx uint16) []byte { return []byte{0x42, n, byte(idx), byte(idx >> 8)} }

// PtgConcat is the & operator.
var PtgConcat = []byte{0x08}

// Cat concatenates token sequences.
func Cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Formula is a formula cell of a macro sheet.
type Formula struct {
	Row, Col uint16
	Rgce     []byte
}

func bof(dt uint16) []byte {
	d := make([]byte, 16)
	binary.LittleEndian.PutUint16(d, 0x0600)
	binary.LittleEndian.PutUint16(d[2:], dt)
	return Record(0x0809, d)
}

var eof = Record(0x000A, nil)

func shortString(s string) []byte { return append([]byte{byte(len(s)), 0}, s...) }

// MacroWorkbook returns an .xls (CFB with a BIFF8 Workbook stream) holding
// a visible worksheet "Sheet1" with label A1 = label, and an Excel 4.0 macro
// sheet named macroName (hidden when hidden is set) with the formulas.
// Auto_Open points to the macro sheet cell (autoRow, autoCol).
func MacroWorkbook(macroName string, hidden bool, autoRow, autoCol uint16, label string, formulas []Formula) []byte {
	sheet := Cat(bof(0x0010), Record(0x0204, Cat([]byte{0, 0, 0, 0, 0, 0}, []byte{byte(len(label)), 0, 0}, []byte(label))), eof)
	var macro []byte
	macro = append(macro, bof(0x0040)...)
	for _, f := range formulas {
		d := make([]byte, 22)
		binary.LittleEndian.PutUint16(d, f.Row)
		binary.LittleEndian.PutUint16(d[2:], f.Col)
		binary.LittleEndian.PutUint16(d[20:], uint16(len(f.Rgce)))
		macro = append(macro, Record(0x0006, append(d, f.Rgce...))...)
	}
	macro = append(macro, eof...)

	boundsheet := func(pos uint32, state, dt byte, name string) []byte {
		d := make([]byte, 6)
		binary.LittleEndian.PutUint32(d, pos)
		d[4], d[5] = state, dt
		return Record(0x0085, append(d, shortString(name)...))
	}
	name := make([]byte, 14)
	binary.LittleEndian.PutUint16(name, 0x0020) // fBuiltin
	name[3] = 1                                 // cch
	nameRgce := PtgRef3d(0, autoRow, autoCol)
	binary.LittleEndian.PutUint16(name[4:], uint16(len(nameRgce)))
	name = append(name, 0, 0x01) // flags, built-in name Auto_Open
	name = append(name, nameRgce...)
	supbook := []byte{2, 0, 0x01, 0x04}
	externsheet := []byte{1, 0, 0, 0, 1, 0, 1, 0}
	state := byte(0)
	if hidden {
		state = 1
	}
	build := func(p1, p2 uint32) []byte {
		return Cat(bof(0x0005),
			boundsheet(p1, 0, 0, "Sheet1"),
			boundsheet(p2, state, 1, macroName),
			Record(0x01AE, supbook), Record(0x0017, externsheet), Record(0x0018, name),
			eof)
	}
	globals := build(0, 0)
	p1 := uint32(len(globals))
	p2 := p1 + uint32(len(sheet))
	wb := Cat(build(p1, p2), sheet, macro)
	return Build(Stream{Name: "Workbook", Data: wb})
}
