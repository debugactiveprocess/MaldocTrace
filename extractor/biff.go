package extractor

import (
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// BIFF8 record types ([MS-XLS] 2.3).
const (
	rtFormula     = 0x0006
	rtEOF         = 0x000A
	rtExternName  = 0x0023
	rtExternSheet = 0x0017
	rtName        = 0x0018
	rtFilePass    = 0x002F
	rtContinue    = 0x003C
	rtBoundSheet  = 0x0085
	rtMulRK       = 0x00BD
	rtSST         = 0x00FC
	rtLabelSST    = 0x00FD
	rtSupBook     = 0x01AE
	rtNumber      = 0x0203
	rtLabel       = 0x0204
	rtBoolErr     = 0x0205
	rtString      = 0x0207
	rtRK          = 0x027E
	rtBOF         = 0x0809
	rtMsoDrawing  = 0x00EC
	rtHLink       = 0x01B8
)

type biffRecord struct {
	typ  uint16
	pos  int
	data []byte
}

type biffSupBook struct {
	self  bool
	names []string
}

type biffName struct {
	name    string
	builtin bool
	hidden  bool
	rgce    []byte
}

type biffFormula struct {
	sheet    *Sheet
	idx      int // index in sheet.Cells
	rgce     []byte
	shared   bool
	row, col int
}

// biffBook holds what is needed to decompile formulas.
type biffBook struct {
	sheetNames []string
	xti        [][3]int // supbook, itabFirst, itabLast
	supbooks   []*biffSupBook
	names      []biffName
}

// extractBIFF parses the Workbook stream of an .xls file: sheet directory,
// shared strings, cell values, formulas (decompiled from parsed tokens to
// A1 text) and defined names. Macro sheets (Excel 4.0) are flagged as such.
func extractBIFF(cfb *cfbReader, stream string, lim *Limits, res *Result) {
	data, err := cfb.readStream(stream)
	if err != nil {
		res.addDiag("warning", "biff", err.Error())
		return
	}
	recs := biffRecords(data)
	decrypted := false
	for _, rec := range recs {
		if rec.typ != rtFilePass {
			continue
		}
		res.Encrypted = true
		h, scheme, err := parseFilePass(rec.data)
		if err != nil {
			res.Decryption = &Decryption{Scheme: scheme, Note: "unsupported encryption"}
			res.addDiag("warning", "biff", "workbook is encrypted ("+scheme+", not supported); cells and macro sheets cannot be read")
			return
		}
		for _, pw := range candidatePasswords(lim) {
			if kf := h.keyFunc(pw); h.verify(kf) {
				data = decryptBIFF(data, kf)
				recs = biffRecords(data)
				decrypted = true
				res.Decryption = &Decryption{Scheme: scheme, Decrypted: true, Password: pw}
				res.addDiag("info", "decrypt", fmt.Sprintf("decrypted %s workbook with %s", scheme, describePassword(pw)))
				break
			}
		}
		if !decrypted {
			res.Decryption = &Decryption{Scheme: scheme, Note: "password not in the candidate list (use --password)"}
			res.addDiag("warning", "biff", "workbook is encrypted ("+scheme+"); password unknown, cells and macro sheets cannot be read")
			return
		}
		break
	}
	if len(recs) == 0 || recs[0].typ != rtBOF {
		res.addDiag("info", "biff", stream+": not a BIFF8 workbook")
		return
	}
	if len(recs[0].data) >= 2 && binary.LittleEndian.Uint16(recs[0].data) != 0x0600 {
		res.addDiag("warning", "biff", fmt.Sprintf("%s: BIFF version 0x%04X not supported (BIFF8 expected)", stream, binary.LittleEndian.Uint16(recs[0].data)))
		return
	}
	book := &biffBook{}
	sheetAt := map[int]*Sheet{}
	var sst []string
	var current *Sheet
	var formulas []biffFormula
	var pending *biffFormula // formula awaiting its STRING result
	budget := res.cellBudget()
	cells := 0
	addCell := func(sh *Sheet, c Cell) int {
		if sh == nil || cells >= budget {
			return -1
		}
		cells++
		sh.Cells = append(sh.Cells, c)
		return len(sh.Cells) - 1
	}
	for i := 0; i < len(recs); i++ {
		rec := recs[i]
		d := rec.data
		switch rec.typ {
		case rtBOF:
			if sh := sheetAt[rec.pos]; sh != nil {
				current = sh
			} else if rec.pos != 0 {
				current = nil
			}
		case rtEOF:
			current = nil
		case rtFilePass:
			if !decrypted {
				return
			}
		case rtBoundSheet:
			if len(d) < 8 {
				continue
			}
			pos := int(binary.LittleEndian.Uint32(d))
			vis := [...]string{"visible", "hidden", "very_hidden", "visible"}[d[4]&3]
			kind := "worksheet"
			switch d[5] {
			case 1:
				kind = "macrosheet"
			case 2:
				kind = "chart"
			case 6:
				kind = "vbmodule"
			}
			name, _ := shortXLString(d[6:])
			sh := &Sheet{Name: name, Kind: kind, Visibility: vis, Source: stream}
			res.Sheets = append(res.Sheets, sh)
			book.sheetNames = append(book.sheetNames, name)
			sheetAt[pos] = sh
		case rtSST:
			segs := [][]byte{d}
			for i+1 < len(recs) && recs[i+1].typ == rtContinue {
				i++
				segs = append(segs, recs[i].data)
			}
			sst = parseSST(segs)
		case rtSupBook:
			sb := &biffSupBook{}
			if len(d) >= 4 && binary.LittleEndian.Uint16(d[2:]) == 0x0401 {
				sb.self = true
			}
			book.supbooks = append(book.supbooks, sb)
		case rtExternName:
			if n := len(book.supbooks); n > 0 && len(d) > 6 {
				name, _ := shortXLString(d[6:])
				book.supbooks[n-1].names = append(book.supbooks[n-1].names, name)
			}
		case rtExternSheet:
			if len(d) >= 2 {
				n := int(binary.LittleEndian.Uint16(d))
				for j := 0; j < n && 2+j*6+6 <= len(d); j++ {
					p := 2 + j*6
					book.xti = append(book.xti, [3]int{int(binary.LittleEndian.Uint16(d[p:])), int(int16(binary.LittleEndian.Uint16(d[p+2:]))), int(int16(binary.LittleEndian.Uint16(d[p+4:])))})
				}
			}
		case rtName:
			book.names = append(book.names, parseNameRecord(d))
		case rtLabelSST:
			if len(d) >= 10 {
				idx := int(binary.LittleEndian.Uint32(d[6:]))
				v := ""
				if idx < len(sst) {
					v = sst[idx]
				}
				addCell(current, Cell{Row: int(binary.LittleEndian.Uint16(d)), Col: int(binary.LittleEndian.Uint16(d[2:])), Value: v, ValueKind: "string"})
			}
		case rtLabel:
			if len(d) >= 8 {
				v, _ := xlUnicodeString(d[6:])
				addCell(current, Cell{Row: int(binary.LittleEndian.Uint16(d)), Col: int(binary.LittleEndian.Uint16(d[2:])), Value: v, ValueKind: "string"})
			}
		case rtNumber:
			if len(d) >= 14 {
				f := math.Float64frombits(binary.LittleEndian.Uint64(d[6:]))
				addCell(current, Cell{Row: int(binary.LittleEndian.Uint16(d)), Col: int(binary.LittleEndian.Uint16(d[2:])), Value: fmtNum(f), ValueKind: "number"})
			}
		case rtRK:
			if len(d) >= 10 {
				addCell(current, Cell{Row: int(binary.LittleEndian.Uint16(d)), Col: int(binary.LittleEndian.Uint16(d[2:])), Value: fmtNum(rkValue(binary.LittleEndian.Uint32(d[6:]))), ValueKind: "number"})
			}
		case rtMulRK:
			if len(d) >= 6 {
				row := int(binary.LittleEndian.Uint16(d))
				col := int(binary.LittleEndian.Uint16(d[2:]))
				for p := 4; p+6 <= len(d)-2; p += 6 {
					addCell(current, Cell{Row: row, Col: col, Value: fmtNum(rkValue(binary.LittleEndian.Uint32(d[p+2:]))), ValueKind: "number"})
					col++
				}
			}
		case rtBoolErr:
			if len(d) >= 8 {
				c := Cell{Row: int(binary.LittleEndian.Uint16(d)), Col: int(binary.LittleEndian.Uint16(d[2:]))}
				if d[7] != 0 {
					c.Value, c.ValueKind = errName(d[6]), "error"
				} else {
					c.Value, c.ValueKind = strings.ToUpper(strconv.FormatBool(d[6] != 0)), "bool"
				}
				addCell(current, c)
			}
		case rtFormula:
			if len(d) < 22 || current == nil {
				continue
			}
			c := Cell{Row: int(binary.LittleEndian.Uint16(d)), Col: int(binary.LittleEndian.Uint16(d[2:]))}
			val := d[6:14]
			stringResult := false
			if val[6] == 0xFF && val[7] == 0xFF {
				switch val[0] {
				case 0:
					stringResult = true
					c.ValueKind = "string"
				case 1:
					c.Value, c.ValueKind = strings.ToUpper(strconv.FormatBool(val[2] != 0)), "bool"
				case 2:
					c.Value, c.ValueKind = errName(val[2]), "error"
				case 3:
					c.ValueKind = "string"
				}
			} else {
				c.Value, c.ValueKind = fmtNum(math.Float64frombits(binary.LittleEndian.Uint64(val))), "number"
			}
			grbit := binary.LittleEndian.Uint16(d[14:])
			cce := int(binary.LittleEndian.Uint16(d[20:]))
			rgce := d[22:]
			if cce <= len(rgce) {
				rgce = rgce[:cce]
			}
			idx := addCell(current, c)
			if idx < 0 {
				continue
			}
			f := biffFormula{sheet: current, idx: idx, rgce: rgce, shared: grbit&0x0008 != 0, row: c.Row, col: c.Col}
			formulas = append(formulas, f)
			pending = nil
			if stringResult {
				pending = &formulas[len(formulas)-1]
			}
		case rtMsoDrawing, rtHLink:
			kind, sev, detail := "shape_hyperlink", "medium", "hyperlink attached to a picture or shape (a click on the lure opens it)"
			if rec.typ == rtHLink {
				kind, sev, detail = "hyperlink", "low", "cell hyperlink"
			}
			for _, u := range utf16URLs(d) {
				res.addExternal(ExternalRef{Kind: kind, Severity: sev, Location: fmt.Sprintf("%s record 0x%04X at %d", stream, rec.typ, rec.pos), Target: u, Detail: detail})
			}
		case rtString:
			if pending != nil {
				v, _ := xlUnicodeString(d)
				pending.sheet.Cells[pending.idx].Value = v
				pending = nil
			}
		}
	}
	for _, f := range formulas {
		text, ok := book.decompile(f.rgce, f.sheet.Name)
		c := &f.sheet.Cells[f.idx]
		c.Formula = "=" + text
		c.Undecoded = !ok
		checkFormulaDDE(stream+":"+f.sheet.Name+"!"+CellName(f.row, f.col), c.Formula, res)
	}
	for _, n := range book.names {
		text, _ := book.decompile(n.rgce, "")
		res.Names = append(res.Names, DefinedName{Name: n.name, Builtin: n.builtin, Hidden: n.hidden, Formula: "=" + text})
	}
	if cells >= budget {
		res.LimitsHit = append(res.LimitsHit, "MaxCells")
	}
}

func biffRecords(data []byte) []biffRecord {
	var out []biffRecord
	for p := 0; p+4 <= len(data); {
		typ := binary.LittleEndian.Uint16(data[p:])
		n := int(binary.LittleEndian.Uint16(data[p+2:]))
		if p+4+n > len(data) {
			break
		}
		if typ == 0 && n == 0 {
			break // padding after the last substream
		}
		out = append(out, biffRecord{typ: typ, pos: p, data: data[p+4 : p+4+n]})
		p += 4 + n
	}
	return out
}

// builtinNames are the one-character names of built-in defined names.
var builtinNames = map[byte]string{
	0x00: "Consolidate_Area", 0x01: "Auto_Open", 0x02: "Auto_Close", 0x03: "Extract", 0x04: "Database",
	0x05: "Criteria", 0x06: "Print_Area", 0x07: "Print_Titles", 0x08: "Recorder", 0x09: "Data_Form",
	0x0A: "Auto_Activate", 0x0B: "Auto_Deactivate", 0x0C: "Sheet_Title", 0x0D: "_FilterDatabase",
}

func parseNameRecord(d []byte) biffName {
	if len(d) < 15 {
		return biffName{name: "?"}
	}
	grbit := binary.LittleEndian.Uint16(d)
	cch := int(d[3])
	cce := int(binary.LittleEndian.Uint16(d[4:]))
	n := biffName{hidden: grbit&0x0001 != 0, builtin: grbit&0x0020 != 0}
	p := 14
	name, used := xlStringNoCch(d[p:], cch)
	p += used
	if n.builtin && len(name) == 1 {
		if bn, ok := builtinNames[name[0]]; ok {
			name = bn
		}
	}
	n.name = name
	if p <= len(d) {
		r := d[p:]
		if cce <= len(r) {
			r = r[:cce]
		}
		n.rgce = r
	}
	return n
}

// shortXLString reads a ShortXLUnicodeString (cch u8, flags u8, chars).
func shortXLString(b []byte) (string, int) {
	if len(b) < 2 {
		return "", len(b)
	}
	s, n := xlStringNoCch(b[1:], int(b[0]))
	return s, 1 + n
}

// xlUnicodeString reads an XLUnicodeString (cch u16, flags u8, chars).
func xlUnicodeString(b []byte) (string, int) {
	if len(b) < 3 {
		return "", len(b)
	}
	s, n := xlStringNoCch(b[2:], int(binary.LittleEndian.Uint16(b)))
	return s, 2 + n
}

// xlStringNoCch reads flags u8 followed by cch characters, either Latin-1
// ("compressed") or UTF-16LE when fHighByte is set.
func xlStringNoCch(b []byte, cch int) (string, int) {
	if len(b) < 1 {
		return "", 0
	}
	if b[0]&1 != 0 {
		n := cch * 2
		if n > len(b)-1 {
			n = (len(b) - 1) &^ 1
		}
		return utf16String(b[1 : 1+n]), 1 + n
	}
	n := cch
	if n > len(b)-1 {
		n = len(b) - 1
	}
	return latin1(b[1 : 1+n]), 1 + n
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// parseSST decodes the shared string table, whose strings may continue
// across CONTINUE records (a continued character run restarts with a new
// flags byte).
func parseSST(segs [][]byte) []string {
	if len(segs) == 0 || len(segs[0]) < 8 {
		return nil
	}
	unique := int(binary.LittleEndian.Uint32(segs[0][4:]))
	r := &segReader{segs: segs, p: 8}
	var out []string
	for i := 0; i < unique && i < maxCells && !r.eof(); i++ {
		cch := int(r.u16())
		flags := r.byte()
		runs, ext := 0, 0
		if flags&0x08 != 0 {
			runs = int(r.u16())
		}
		if flags&0x04 != 0 {
			ext = int(int32(r.u32()))
		}
		var sb strings.Builder
		high := flags&1 != 0
		for left := cch; left > 0 && !r.eof(); {
			if r.atSegEnd() {
				r.next()
				high = r.byte()&1 != 0
				continue
			}
			if high {
				lo, hi := r.byte(), r.byte()
				sb.WriteRune(rune(uint16(lo) | uint16(hi)<<8))
			} else {
				sb.WriteRune(rune(r.byte()))
			}
			left--
		}
		r.skip(runs*4 + ext)
		out = append(out, sb.String())
	}
	return out
}

type segReader struct {
	segs [][]byte
	s, p int
}

func (r *segReader) eof() bool { return r.s >= len(r.segs) }
func (r *segReader) atSegEnd() bool {
	return r.s < len(r.segs) && r.p >= len(r.segs[r.s]) && r.s+1 < len(r.segs)
}
func (r *segReader) next() { r.s++; r.p = 0 }
func (r *segReader) byte() byte {
	for r.s < len(r.segs) && r.p >= len(r.segs[r.s]) {
		r.next()
	}
	if r.s >= len(r.segs) {
		return 0
	}
	b := r.segs[r.s][r.p]
	r.p++
	return b
}
func (r *segReader) u16() uint16 { return uint16(r.byte()) | uint16(r.byte())<<8 }
func (r *segReader) u32() uint32 { return uint32(r.u16()) | uint32(r.u16())<<16 }
func (r *segReader) skip(n int) {
	for ; n > 0 && !r.eof(); n-- {
		r.byte()
	}
}

func rkValue(rk uint32) float64 {
	var v float64
	if rk&2 != 0 {
		v = float64(int32(rk) >> 2)
	} else {
		v = math.Float64frombits(uint64(rk&0xFFFFFFFC) << 32)
	}
	if rk&1 != 0 {
		v /= 100
	}
	return v
}

func fmtNum(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func errName(b byte) string {
	switch b {
	case 0x00:
		return "#NULL!"
	case 0x07:
		return "#DIV/0!"
	case 0x0F:
		return "#VALUE!"
	case 0x17:
		return "#REF!"
	case 0x1D:
		return "#NAME?"
	case 0x24:
		return "#NUM!"
	case 0x2A:
		return "#N/A"
	}
	return "#ERR" + strconv.Itoa(int(b)) + "!"
}

// quoteSheet quotes a sheet name for use in a reference when needed.
func quoteSheet(s string) string {
	for _, c := range s {
		if !(c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c > 127) {
			return "'" + strings.ReplaceAll(s, "'", "''") + "'"
		}
	}
	return s
}

func refText(rw, col uint16) string {
	c := int(col & 0x3FFF)
	s := ""
	if col&0x4000 == 0 {
		s += "$"
	}
	s += ColName(c)
	if col&0x8000 == 0 {
		s += "$"
	}
	return s + strconv.Itoa(int(rw)+1)
}

func (b *biffBook) sheetForXTI(ixti int) string {
	if ixti < 0 || ixti >= len(b.xti) {
		return "#REF"
	}
	t := b.xti[ixti][1]
	if t >= 0 && t < len(b.sheetNames) {
		return quoteSheet(b.sheetNames[t])
	}
	return "#REF"
}

func (b *biffBook) nameX(ixti, idx int) string {
	if ixti >= 0 && ixti < len(b.xti) {
		sb := b.xti[ixti][0]
		if sb >= 0 && sb < len(b.supbooks) {
			if b.supbooks[sb].self {
				if idx >= 1 && idx <= len(b.names) {
					return b.names[idx-1].name
				}
			} else if idx >= 1 && idx <= len(b.supbooks[sb].names) {
				return b.supbooks[sb].names[idx-1]
			}
		}
	}
	return "NAMEX_" + strconv.Itoa(idx)
}

// decompile converts BIFF8 parsed formula tokens (Rgce) to A1 formula text.
// ok is false when a token could not be decoded; the text then holds what
// was rebuilt with a marker for the unknown part.
func (b *biffBook) decompile(rgce []byte, _ string) (string, bool) {
	var st []string
	pop := func() string {
		if len(st) == 0 {
			return "?"
		}
		v := st[len(st)-1]
		st = st[:len(st)-1]
		return v
	}
	popN := func(n int) []string {
		if n > len(st) {
			n = len(st)
		}
		args := append([]string(nil), st[len(st)-n:]...)
		st = st[:len(st)-n]
		return args
	}
	binops := map[byte]string{0x03: "+", 0x04: "-", 0x05: "*", 0x06: "/", 0x07: "^", 0x08: "&", 0x09: "<", 0x0A: "<=", 0x0B: "=", 0x0C: ">=", 0x0D: ">", 0x0E: "<>", 0x0F: " ", 0x10: ",", 0x11: ":"}
	need := func(p, n int) bool { return p+n <= len(rgce) }
	u16 := func(p int) int { return int(binary.LittleEndian.Uint16(rgce[p:])) }
	fail := func(p int, why string) (string, bool) {
		st = append(st, fmt.Sprintf("<%s at %d>", why, p))
		return strings.Join(st, " "), false
	}
	for p := 0; p < len(rgce); {
		t := rgce[p]
		p++
		if op, ok := binops[t]; ok {
			r, l := pop(), pop()
			st = append(st, l+op+r)
			continue
		}
		base := t
		if t >= 0x20 {
			base = t&0x1F | 0x20 // normalise the value class bits
		}
		switch base {
		case 0x01, 0x02: // PtgExp, PtgTbl
			return fail(p, "shared formula")
		case 0x12:
			st = append(st, "+"+pop())
		case 0x13:
			st = append(st, "-"+pop())
		case 0x14:
			st = append(st, pop()+"%")
		case 0x15:
			st = append(st, "("+pop()+")")
		case 0x16:
			st = append(st, "")
		case 0x17: // PtgStr
			if !need(p, 2) {
				return fail(p, "truncated")
			}
			s, n := xlStringNoCch(rgce[p+1:], int(rgce[p]))
			p += 1 + n
			st = append(st, `"`+strings.ReplaceAll(s, `"`, `""`)+`"`)
		case 0x19: // PtgAttr
			if !need(p, 3) {
				return fail(p, "truncated")
			}
			grbit := rgce[p]
			data := u16(p + 1)
			p += 3
			if grbit&0x04 != 0 { // tAttrChoose: jump table
				p += (data + 1) * 2
			}
			if grbit&0x10 != 0 { // tAttrSum: SUM of one argument
				st = append(st, "SUM("+pop()+")")
			}
		case 0x1C:
			if !need(p, 1) {
				return fail(p, "truncated")
			}
			st = append(st, errName(rgce[p]))
			p++
		case 0x1D:
			if !need(p, 1) {
				return fail(p, "truncated")
			}
			st = append(st, strings.ToUpper(strconv.FormatBool(rgce[p] != 0)))
			p++
		case 0x1E:
			if !need(p, 2) {
				return fail(p, "truncated")
			}
			st = append(st, strconv.Itoa(u16(p)))
			p += 2
		case 0x1F:
			if !need(p, 8) {
				return fail(p, "truncated")
			}
			st = append(st, fmtNum(math.Float64frombits(binary.LittleEndian.Uint64(rgce[p:]))))
			p += 8
		case 0x20: // PtgArray: values follow the formula; not rebuilt
			p += 7
			st = append(st, "{array}")
		case 0x21: // PtgFunc
			if !need(p, 2) {
				return fail(p, "truncated")
			}
			idx := u16(p)
			p += 2
			n, ok := ftabArity[idx]
			if !ok {
				return fail(p, "fixed-arity function "+funcName(idx))
			}
			st = append(st, funcName(idx)+"("+strings.Join(popN(n), ",")+")")
		case 0x22: // PtgFuncVar
			if !need(p, 3) {
				return fail(p, "truncated")
			}
			n := int(rgce[p] & 0x7F)
			idx := u16(p + 1)
			p += 3
			args := popN(n)
			name := funcName(idx)
			if idx&0x7FFF == 255 && idx&0x8000 == 0 && len(args) > 0 { // user-defined: first arg is the name
				name, args = args[0], args[1:]
			}
			st = append(st, name+"("+strings.Join(args, ",")+")")
		case 0x23: // PtgName
			if !need(p, 4) {
				return fail(p, "truncated")
			}
			idx := int(binary.LittleEndian.Uint32(rgce[p:]))
			p += 4
			if idx >= 1 && idx <= len(b.names) {
				st = append(st, b.names[idx-1].name)
			} else {
				st = append(st, "NAME_"+strconv.Itoa(idx))
			}
		case 0x24: // PtgRef
			if !need(p, 4) {
				return fail(p, "truncated")
			}
			st = append(st, refText(uint16(u16(p)), uint16(u16(p+2))))
			p += 4
		case 0x25: // PtgArea
			if !need(p, 8) {
				return fail(p, "truncated")
			}
			st = append(st, refText(uint16(u16(p)), uint16(u16(p+4)))+":"+refText(uint16(u16(p+2)), uint16(u16(p+6))))
			p += 8
		case 0x26, 0x27, 0x28: // PtgMemArea, PtgMemErr, PtgMemNoMem
			p += 6
		case 0x29: // PtgMemFunc
			p += 2
		case 0x2A:
			p += 4
			st = append(st, "#REF!")
		case 0x2B:
			p += 8
			st = append(st, "#REF!")
		case 0x2C: // PtgRefN (relative)
			if !need(p, 4) {
				return fail(p, "truncated")
			}
			st = append(st, fmt.Sprintf("R[%d]C[%d]", int16(u16(p)), int8(u16(p+2)&0xFF)))
			p += 4
		case 0x2D:
			p += 8
			st = append(st, "{relative area}")
		case 0x39: // PtgNameX
			if !need(p, 6) {
				return fail(p, "truncated")
			}
			st = append(st, b.nameX(u16(p), int(binary.LittleEndian.Uint32(rgce[p+2:]))))
			p += 6
		case 0x3A: // PtgRef3d
			if !need(p, 6) {
				return fail(p, "truncated")
			}
			st = append(st, b.sheetForXTI(u16(p))+"!"+refText(uint16(u16(p+2)), uint16(u16(p+4))))
			p += 6
		case 0x3B: // PtgArea3d
			if !need(p, 10) {
				return fail(p, "truncated")
			}
			st = append(st, b.sheetForXTI(u16(p))+"!"+refText(uint16(u16(p+2)), uint16(u16(p+6)))+":"+refText(uint16(u16(p+4)), uint16(u16(p+8))))
			p += 10
		case 0x3C:
			p += 6
			st = append(st, "#REF!")
		case 0x3D:
			p += 10
			st = append(st, "#REF!")
		default:
			return fail(p-1, fmt.Sprintf("token 0x%02X", t))
		}
	}
	if len(st) != 1 {
		return strings.Join(st, " "), len(st) == 0
	}
	return st[0], true
}

var urlText = regexp.MustCompile(`(?i)(?:https?|ftp|file)://[^\s"'<>\x00]{3,1000}|\\\\[A-Za-z0-9._-]+\\[^\s"'<>\x00]{1,1000}`)

// utf16URLs finds URLs stored as UTF-16LE text (OfficeArt and HLINK keep
// hyperlinks this way), at either byte alignment.
func utf16URLs(b []byte) []string {
	var out []string
	seen := map[string]bool{}
	for align := 0; align < 2; align++ {
		if len(b) < align+2 {
			break
		}
		s := utf16String(b[align : align+(len(b)-align)&^1])
		for _, u := range urlText.FindAllString(s, 16) {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}
