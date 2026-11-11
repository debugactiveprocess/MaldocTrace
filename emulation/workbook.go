package emulation

import (
	"strconv"
	"strings"

	"maldoctrace/extractor"
	"maldoctrace/vba/runtime"
)

// The workbook model is shared by VBA (Sheets/Range/Cells) and the Excel 4.0
// macro engine, so a value written by one is read by the other. Payloads are
// often stored in (hidden) cells and assembled at run time.

type xlCell struct {
	v       runtime.Value
	formula string // "=..." for formula cells
}

type xlSheet struct {
	name, kind, vis string
	cells           map[[2]int]*xlCell
}

type workbook struct {
	sheets []*xlSheet
	names  []extractor.DefinedName
}

// maxWrites bounds cells created at run time.
const maxWrites = 1 << 16

// SetWorkbook provides the sheets and defined names of the analysed workbook.
func (h *Host) SetWorkbook(sheets []*extractor.Sheet, names []extractor.DefinedName) {
	wb := &workbook{names: names}
	for _, s := range sheets {
		xs := &xlSheet{name: s.Name, kind: s.Kind, vis: s.Visibility, cells: map[[2]int]*xlCell{}}
		for _, c := range s.Cells {
			xs.cells[[2]int{c.Row, c.Col}] = &xlCell{v: cellValue(c), formula: c.Formula}
		}
		wb.sheets = append(wb.sheets, xs)
	}
	h.wb = wb
}

func cellValue(c extractor.Cell) runtime.Value {
	switch c.ValueKind {
	case "number":
		if f, err := strconv.ParseFloat(c.Value, 64); err == nil {
			return runtime.VFloat(f)
		}
	case "bool":
		return runtime.VBool(strings.EqualFold(c.Value, "TRUE"))
	case "error":
		return xlError(c.Value)
	case "string":
		return runtime.VString(c.Value)
	}
	if c.Value == "" {
		return runtime.VEmpty
	}
	return runtime.VString(c.Value)
}

// xlError is an Excel error value (#VALUE!, #NAME?, ...).
func xlError(name string) runtime.Value {
	return runtime.Value{Kind: runtime.KindError, ErrNum: 2015, Str: name}
}

func (h *Host) workbook() *workbook {
	if h.wb == nil {
		h.wb = &workbook{}
	}
	return h.wb
}

func (wb *workbook) sheet(name string) *xlSheet {
	name = strings.Trim(name, "'")
	for _, s := range wb.sheets {
		if strings.EqualFold(s.name, name) {
			return s
		}
	}
	return nil
}

// sheetAt returns the 1-based n-th sheet; onlyWorksheets restricts the
// numbering to worksheets as the Worksheets collection does.
func (wb *workbook) sheetAt(n int64, onlyWorksheets bool) *xlSheet {
	i := int64(0)
	for _, s := range wb.sheets {
		if onlyWorksheets && s.kind != "worksheet" {
			continue
		}
		i++
		if i == n {
			return s
		}
	}
	return nil
}

func (wb *workbook) active() *xlSheet {
	for _, s := range wb.sheets {
		if s.kind == "worksheet" && s.vis == "visible" {
			return s
		}
	}
	if len(wb.sheets) > 0 {
		return wb.sheets[0]
	}
	s := &xlSheet{name: "Sheet1", kind: "worksheet", vis: "visible", cells: map[[2]int]*xlCell{}}
	wb.sheets = append(wb.sheets, s)
	return s
}

func (s *xlSheet) get(r, c int) *xlCell { return s.cells[[2]int{r, c}] }

func (s *xlSheet) value(r, c int) runtime.Value {
	if x := s.get(r, c); x != nil {
		return x.v
	}
	return runtime.VEmpty
}

func (s *xlSheet) set(r, c int, v runtime.Value, formula string) bool {
	if r < 0 || c < 0 || r > 1048575 || c > 16383 {
		return false
	}
	x := s.get(r, c)
	if x == nil {
		if len(s.cells) >= maxWrites {
			return false
		}
		x = &xlCell{}
		s.cells[[2]int{r, c}] = x
	}
	x.v, x.formula = v, formula
	return true
}

// lookupSheet resolves a Sheets(...) argument (name or 1-based index).
func (h *Host) lookupSheet(arg runtime.Value, onlyWorksheets bool) runtime.Value {
	wb := h.workbook()
	var s *xlSheet
	if arg.Kind == runtime.KindString {
		s = wb.sheet(arg.Str)
	} else if n, ok := arg.CoerceInt(); ok {
		s = wb.sheetAt(n, onlyWorksheets)
	}
	if s == nil {
		return runtime.NewUnknown("sheet " + arg.CoerceString() + " not present")
	}
	return runtime.VObject(&sheetObject{h: h, s: s})
}

// sheetsCollection is Workbook.Sheets / Worksheets.
type sheetsCollection struct {
	h              *Host
	onlyWorksheets bool
}

func (o *sheetsCollection) TypeName() string { return "Sheets" }
func (o *sheetsCollection) Get(name string) runtime.Value {
	if strings.EqualFold(name, "Count") {
		n := int64(0)
		for _, s := range o.h.workbook().sheets {
			if !o.onlyWorksheets || s.kind == "worksheet" {
				n++
			}
		}
		return runtime.VInt(n)
	}
	return runtime.NewUnknown("unsupported Sheets property " + name)
}
func (o *sheetsCollection) Set(string, runtime.Value) {}
func (o *sheetsCollection) Call(name string, args []runtime.Value) runtime.Value {
	if (name == "" || strings.EqualFold(name, "Item")) && len(args) > 0 {
		return o.h.lookupSheet(args[0], o.onlyWorksheets)
	}
	return runtime.NewUnknown("unsupported Sheets method " + name)
}

// sheetObject is a Worksheet (or macro sheet).
type sheetObject struct {
	h *Host
	s *xlSheet
}

func (o *sheetObject) TypeName() string { return "Worksheet" }
func (o *sheetObject) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "name", "codename":
		return runtime.VString(o.s.name)
	case "visible":
		switch o.s.vis {
		case "hidden":
			return runtime.VInt(0)
		case "very_hidden":
			return runtime.VInt(2)
		}
		return runtime.VInt(-1)
	case "cells":
		return runtime.VObject(&cellsObject{h: o.h, s: o.s})
	case "usedrange", "range":
		return runtime.VObject(&rangeObject{h: o.h, s: o.s})
	}
	return runtime.NewUnknown("unsupported Worksheet property " + name)
}
func (o *sheetObject) Set(name string, v runtime.Value) {
	if strings.EqualFold(name, "Visible") {
		o.h.recStr("sheet_visibility", o.s.name+" = "+v.CoerceString(), nil)
	}
}
func (o *sheetObject) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "range":
		return o.h.rangeFromArgs(o.s, args)
	case "cells":
		return (&cellsObject{h: o.h, s: o.s}).Call("", args)
	case "activate", "select", "unprotect", "protect", "calculate":
		return runtime.VEmpty
	}
	return runtime.NewUnknown("unsupported Worksheet method " + name)
}

// cellsObject is Worksheet.Cells.
type cellsObject struct {
	h *Host
	s *xlSheet
}

func (o *cellsObject) TypeName() string                 { return "Range" }
func (o *cellsObject) Get(name string) runtime.Value    { return runtime.NewUnknown("Cells." + name) }
func (o *cellsObject) Set(name string, v runtime.Value) {}
func (o *cellsObject) Call(name string, args []runtime.Value) runtime.Value {
	if name != "" && !strings.EqualFold(name, "Item") {
		return runtime.NewUnknown("unsupported Cells method " + name)
	}
	if len(args) < 2 {
		return runtime.NewUnknown("Cells needs row and column")
	}
	r, ok1 := args[0].CoerceInt()
	c, ok2 := args[1].CoerceInt()
	if !ok2 && args[1].Kind == runtime.KindString {
		if _, col, ok := extractor.ParseCellRef(args[1].Str + "1"); ok {
			c, ok2 = int64(col+1), true
		}
	}
	if !ok1 || !ok2 || r < 1 || c < 1 {
		return runtime.NewUnknown("cell position unknown")
	}
	return runtime.VObject(&rangeObject{h: o.h, s: o.s, r: int(r - 1), c: int(c - 1)})
}

// rangeFromArgs resolves Range("A1"), Range("Sheet1!B2") or a defined name.
func (h *Host) rangeFromArgs(s *xlSheet, args []runtime.Value) runtime.Value {
	if len(args) == 0 {
		return runtime.NewUnknown("Range without address")
	}
	if args[0].Kind == runtime.KindObject {
		return args[0]
	}
	ref := args[0].CoerceString()
	if i := strings.LastIndex(ref, "!"); i > 0 {
		if sh := h.workbook().sheet(ref[:i]); sh != nil {
			s, ref = sh, ref[i+1:]
		}
	}
	if i := strings.IndexByte(ref, ':'); i > 0 {
		ref = ref[:i] // multi-cell ranges are read through their first cell
	}
	r, c, ok := extractor.ParseCellRef(ref)
	if !ok {
		for _, n := range h.workbook().names {
			if strings.EqualFold(n.Name, ref) {
				return h.rangeFromArgs(s, []runtime.Value{runtime.VString(strings.TrimPrefix(n.Formula, "="))})
			}
		}
		return runtime.NewUnknown("range " + ref + " not resolved")
	}
	return runtime.VObject(&rangeObject{h: h, s: s, r: r, c: c})
}

// rangeObject is a single-cell Range.
type rangeObject struct {
	h    *Host
	s    *xlSheet
	r, c int
}

func (o *rangeObject) TypeName() string { return "Range" }
func (o *rangeObject) DefaultValue() runtime.Value {
	return o.Get("Value")
}
func (o *rangeObject) Get(name string) runtime.Value {
	switch strings.ToLower(name) {
	case "value", "value2", "text":
		return o.s.value(o.r, o.c)
	case "formula", "formulalocal", "formular1c1":
		if x := o.s.get(o.r, o.c); x != nil && x.formula != "" {
			return runtime.VString(x.formula)
		}
		return o.s.value(o.r, o.c)
	case "row":
		return runtime.VInt(int64(o.r + 1))
	case "column":
		return runtime.VInt(int64(o.c + 1))
	case "address":
		return runtime.VString("$" + extractor.ColName(o.c) + "$" + strconv.Itoa(o.r+1))
	case "worksheet", "parent":
		return runtime.VObject(&sheetObject{h: o.h, s: o.s})
	case "cells":
		return runtime.VObject(&cellsObject{h: o.h, s: o.s})
	}
	return runtime.NewUnknown("unsupported Range property " + name)
}
func (o *rangeObject) Set(name string, v runtime.Value) {
	switch strings.ToLower(name) {
	case "value", "value2", "formula", "formulalocal":
		o.SetDefaultValue(v)
	}
}

// SetDefaultValue implements assignment to the default member
// (Range("A1") = x).
func (o *rangeObject) SetDefaultValue(v runtime.Value) {
	s := v.CoerceString()
	if strings.HasPrefix(s, "=") && v.Kind == runtime.KindString {
		o.s.set(o.r, o.c, runtime.VEmpty, s)
		o.h.recordXLMWrite(o.s, o.r, o.c, s, "VBA Range assignment")
		return
	}
	o.s.set(o.r, o.c, v, "")
}
func (o *rangeObject) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "offset":
		dr, _ := argInt(args, 0)
		dc, _ := argInt(args, 1)
		return runtime.VObject(&rangeObject{h: o.h, s: o.s, r: o.r + int(dr), c: o.c + int(dc)})
	case "cells":
		return (&cellsObject{h: o.h, s: o.s}).Call("", args)
	case "select", "activate", "clear", "clearcontents", "copy", "delete":
		return runtime.VEmpty
	}
	return runtime.NewUnknown("unsupported Range method " + name)
}

func argInt(args []runtime.Value, i int) (int64, bool) {
	if i < len(args) {
		return args[i].CoerceInt()
	}
	return 0, false
}

// globalExcel is an application-level global (Range, Cells, Sheets,
// Worksheets, ExecuteExcel4Macro) used without a receiver.
type globalExcel struct {
	h    *Host
	name string
}

func (o *globalExcel) TypeName() string { return o.name }
func (o *globalExcel) Get(name string) runtime.Value {
	switch o.name {
	case "sheets", "worksheets":
		return (&sheetsCollection{h: o.h, onlyWorksheets: o.name == "worksheets"}).Get(name)
	}
	return runtime.NewUnknown(o.name + "." + name)
}
func (o *globalExcel) Set(string, runtime.Value) {}
func (o *globalExcel) Call(name string, args []runtime.Value) runtime.Value {
	if name != "" && !strings.EqualFold(name, "Item") {
		return runtime.NewUnknown("unsupported " + o.name + " method " + name)
	}
	switch o.name {
	case "range":
		return o.h.rangeFromArgs(o.h.workbook().active(), args)
	case "cells":
		return (&cellsObject{h: o.h, s: o.h.workbook().active()}).Call("", args)
	case "sheets", "worksheets":
		if len(args) == 0 {
			return runtime.VObject(&sheetsCollection{h: o.h, onlyWorksheets: o.name == "worksheets"})
		}
		return o.h.lookupSheet(args[0], o.name == "worksheets")
	case "executeexcel4macro":
		return o.h.ExecuteExcel4Macro(argString(args, 0))
	}
	return runtime.VUnknown
}
