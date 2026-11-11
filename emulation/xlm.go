package emulation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"maldoctrace/extractor"
	"maldoctrace/vba/runtime"
)

// The Excel 4.0 macro engine executes macro-sheet formulas cell by cell
// (down a column, following GOTO/RUN/WHILE/FOR) over the shared workbook
// model. Like the VBA interpreter, every external effect (EXEC, CALL,
// REGISTER, FOPEN/FWRITE) is recorded and simulated, never performed.

// XLMWrite is a formula or value written into a cell at run time
// (FORMULA, FORMULA.FILL, SET.VALUE, Range assignment). Deobfuscating macros
// build their real code this way, so these are the recovered formulas.
type XLMWrite struct {
	Sheet, Cell, Text, Via string
}

// XLMWrites returns the formulas written at run time.
func (h *Host) XLMWrites() []XLMWrite { return h.xlmWrites }

func (h *Host) recordXLMWrite(s *xlSheet, r, c int, text, via string) {
	if len(h.xlmWrites) < 4096 {
		h.xlmWrites = append(h.xlmWrites, XLMWrite{Sheet: s.name, Cell: extractor.CellName(r, c), Text: text, Via: via})
	}
}

// xv is an evaluated XLM value; ref is set when the value is a reference.
type xv struct {
	v   runtime.Value
	ref *xlRef
}

type xlRef struct {
	s              *xlSheet
	r1, c1, r2, c2 int
}

type xlmPos struct {
	s    *xlSheet
	r, c int
}

type xlmLoop struct {
	pos       xlmPos // the WHILE/FOR cell
	isFor     bool
	counter   string
	end, step float64
}

type xlmReg struct {
	dll, fn string
}

type xlmEngine struct {
	h       *Host
	ctx     context.Context
	steps   int
	max     int
	cur     xlmPos
	jump    *xlmPos
	halt    bool
	ret     bool
	frames  []xlmPos
	loops   []xlmLoop
	names   map[string]xv
	regs    map[string]xlmReg
	regIDs  map[int64]xlmReg
	files   map[int64]*xlmFile
	nextFH  int64
	pending []xlmPos // ON.TIME / deferred runs
	inline  bool     // evaluating ExecuteExcel4Macro text, not a cell
	cache   map[string]xNode
}

type xlmFile struct {
	path string
	buf  strings.Builder
}

// MaxXLMSteps bounds formula evaluations per run.
const MaxXLMSteps = 200000

func (h *Host) engine(ctx context.Context) *xlmEngine {
	if h.xlm == nil {
		h.xlm = &xlmEngine{h: h, ctx: ctx, max: MaxXLMSteps, names: map[string]xv{}, regs: map[string]xlmReg{},
			regIDs: map[int64]xlmReg{}, files: map[int64]*xlmFile{}, cache: map[string]xNode{}}
	}
	if ctx != nil {
		h.xlm.ctx = ctx
	}
	return h.xlm
}

// XLMEntry is a macro-sheet cell run when the workbook opens.
type XLMEntry struct {
	Name, Sheet, Cell string
}

// XLMEntries lists Auto_Open names that point into a macro sheet. Excel runs
// any defined name whose name starts with "Auto_Open" (case-insensitive).
func (h *Host) XLMEntries() []XLMEntry {
	var out []XLMEntry
	for _, n := range h.workbook().names {
		if !strings.HasPrefix(strings.ToLower(n.Name), "auto_open") {
			continue
		}
		if p, ok := h.resolveRefText(strings.TrimPrefix(n.Formula, "=")); ok {
			out = append(out, XLMEntry{Name: n.Name, Sheet: p.s.name, Cell: extractor.CellName(p.r, p.c)})
		}
	}
	return out
}

func (h *Host) resolveRefText(text string) (xlmPos, bool) {
	n, err := parseXLM(text)
	if err != nil {
		return xlmPos{}, false
	}
	r, ok := n.(xRef)
	if !ok || r.sheet == "" {
		return xlmPos{}, false
	}
	s := h.workbook().sheet(r.sheet)
	if s == nil {
		return xlmPos{}, false
	}
	return xlmPos{s: s, r: r.r1, c: r.c1}, true
}

// RunXLM executes the macro starting at sheet!cell.
func (h *Host) RunXLM(ctx context.Context, sheet, cell string) {
	s := h.workbook().sheet(sheet)
	r, c, ok := extractor.ParseCellRef(cell)
	if s == nil || !ok {
		return
	}
	e := h.engine(ctx)
	e.run(xlmPos{s: s, r: r, c: c})
	for len(e.pending) > 0 && !e.exhausted() {
		p := e.pending[0]
		e.pending = e.pending[1:]
		e.run(p)
	}
}

// runXLMMacro implements Application.Run "Sheet!Cell" for macro sheets.
func (h *Host) runXLMMacro(ref string) (runtime.Value, bool) {
	p, ok := h.resolveRefText(ref)
	if !ok || p.s.kind != "macrosheet" {
		return runtime.Value{}, false
	}
	h.engine(nil).run(p)
	return runtime.VEmpty, true
}

// ExecuteExcel4Macro evaluates one XLM formula (Application.ExecuteExcel4Macro).
func (h *Host) ExecuteExcel4Macro(text string) runtime.Value {
	h.recStr("execute_excel4_macro", text, nil)
	e := h.engine(nil)
	n, err := parseXLM(text)
	if err != nil {
		h.Note("ExecuteExcel4Macro: cannot parse " + strconv.Quote(text) + ": " + err.Error())
		return runtime.NewUnknown("unparsed XLM")
	}
	saved, savedInline := e.cur, e.inline
	if e.cur.s == nil {
		e.cur = xlmPos{s: h.workbook().active()}
	}
	e.inline = true // events take the location of the VBA call
	defer func() { e.cur, e.inline = saved, savedInline }()
	return e.value(e.eval(n))
}

func (e *xlmEngine) exhausted() bool {
	if e.ctx != nil && e.ctx.Err() != nil {
		return true
	}
	return e.steps >= e.max
}

// run executes formulas from p downward until HALT, RETURN with an empty
// call stack, a blank cell or the step budget.
func (e *xlmEngine) run(p xlmPos) {
	e.halt, e.ret, e.jump = false, false, nil
	e.frames, e.loops = nil, nil
	for !e.halt {
		if e.exhausted() {
			e.h.Note("XLM: execution budget exhausted at " + p.s.name + "!" + extractor.CellName(p.r, p.c))
			return
		}
		cell := p.s.get(p.r, p.c)
		if cell == nil || (cell.formula == "" && cell.v.Kind == runtime.KindEmpty) {
			// A blank cell ends the macro, or returns from a subroutine.
			if len(e.frames) == 0 {
				return
			}
			p = e.frames[len(e.frames)-1]
			e.frames = e.frames[:len(e.frames)-1]
			continue
		}
		if cell.formula == "" {
			p.r++ // constants in a macro column are skipped
			continue
		}
		e.steps++
		e.cur = p
		res := e.evalFormula(cell.formula)
		if res.ref == nil {
			cell.v = res.v
		} else {
			cell.v = e.value(res)
		}
		switch {
		case e.halt:
			return
		case e.jump != nil:
			p, e.jump = *e.jump, nil
		case e.ret:
			e.ret = false
			if len(e.frames) == 0 {
				return
			}
			p = e.frames[len(e.frames)-1]
			e.frames = e.frames[:len(e.frames)-1]
		default:
			p.r++
		}
	}
}

func (e *xlmEngine) evalFormula(text string) xv {
	n, ok := e.cache[text]
	if !ok {
		var err error
		n, err = parseXLM(text)
		if err != nil {
			e.h.Note("XLM: cannot parse " + e.where() + " " + strconv.Quote(text) + ": " + err.Error())
			n = nil
		}
		if len(e.cache) < 65536 {
			e.cache[text] = n
		}
	}
	if n == nil {
		return xv{v: runtime.NewUnknown("unparsed formula")}
	}
	return e.eval(n)
}

func (e *xlmEngine) where() string {
	if e.cur.s == nil {
		return ""
	}
	return e.cur.s.name + "!" + extractor.CellName(e.cur.r, e.cur.c)
}

func (e *xlmEngine) sheetOf(name string) *xlSheet {
	if name == "" {
		if e.cur.s != nil {
			return e.cur.s
		}
		return e.h.workbook().active()
	}
	return e.h.workbook().sheet(name)
}

// value dereferences a reference to the value of its first cell.
func (e *xlmEngine) value(x xv) runtime.Value {
	if x.ref != nil {
		return x.ref.s.value(x.ref.r1, x.ref.c1)
	}
	return x.v
}

func (e *xlmEngine) eval(n xNode) xv {
	if e.steps++; e.exhausted() {
		return xv{v: runtime.NewUnknown("XLM budget exhausted")}
	}
	switch x := n.(type) {
	case xNum:
		return xv{v: runtime.VFloat(float64(x))}
	case xStr:
		return xv{v: runtime.VString(string(x))}
	case xBool:
		return xv{v: runtime.VBool(bool(x))}
	case xErr:
		return xv{v: xlError(string(x))}
	case xMiss:
		return xv{v: runtime.VEmpty}
	case xRef:
		s := e.sheetOf(x.sheet)
		if s == nil {
			return xv{v: xlError("#REF!")}
		}
		return xv{ref: &xlRef{s: s, r1: x.r1, c1: x.c1, r2: x.r2, c2: x.c2}}
	case xName:
		return e.name(string(x))
	case xUnary:
		v := e.value(e.eval(x.x))
		if v.IsUnknown() {
			return xv{v: v}
		}
		f, ok := num(v)
		if !ok {
			return xv{v: xlError("#VALUE!")}
		}
		if x.op == "-" {
			return xv{v: runtime.VFloat(-f)}
		}
		return xv{v: runtime.VFloat(f / 100)}
	case xBinary:
		return xv{v: e.binary(x)}
	case xCall:
		return e.call(x)
	}
	return xv{v: runtime.NewUnknown("unsupported XLM node")}
}

func (e *xlmEngine) name(n string) xv {
	if v, ok := e.names[strings.ToLower(n)]; ok {
		return v
	}
	for _, d := range e.h.workbook().names {
		if strings.EqualFold(d.Name, n) {
			return e.evalFormula(d.Formula)
		}
	}
	return xv{v: xlError("#NAME?")}
}

func num(v runtime.Value) (float64, bool) {
	switch v.Kind {
	case runtime.KindEmpty:
		return 0, true
	case runtime.KindBool:
		if v.B {
			return 1, true
		}
		return 0, true
	case runtime.KindString:
		f, err := strconv.ParseFloat(strings.TrimSpace(v.Str), 64)
		return f, err == nil
	case runtime.KindError:
		return 0, false
	}
	return v.CoerceFloat()
}

// text renders a value as Excel would when concatenating.
func text(v runtime.Value) string {
	switch v.Kind {
	case runtime.KindBool:
		if v.B {
			return "TRUE"
		}
		return "FALSE"
	case runtime.KindFloat:
		return strconv.FormatFloat(v.Float, 'f', -1, 64)
	case runtime.KindError:
		return v.Str
	}
	return v.CoerceString()
}

func isErr(v runtime.Value) bool { return v.Kind == runtime.KindError }

func (e *xlmEngine) binary(x xBinary) runtime.Value {
	l := e.value(e.eval(x.l))
	r := e.value(e.eval(x.r))
	if l.IsUnknown() {
		return l
	}
	if r.IsUnknown() {
		return r
	}
	if isErr(l) {
		return l
	}
	if isErr(r) {
		return r
	}
	switch x.op {
	case "&":
		return runtime.VString(text(l) + text(r))
	case "=", "<>", "<", ">", "<=", ">=":
		var c int
		lf, lok := num(l)
		rf, rok := num(r)
		if l.Kind != runtime.KindString && r.Kind != runtime.KindString && lok && rok {
			switch {
			case lf < rf:
				c = -1
			case lf > rf:
				c = 1
			}
		} else {
			c = strings.Compare(strings.ToLower(text(l)), strings.ToLower(text(r)))
		}
		switch x.op {
		case "=":
			return runtime.VBool(c == 0)
		case "<>":
			return runtime.VBool(c != 0)
		case "<":
			return runtime.VBool(c < 0)
		case ">":
			return runtime.VBool(c > 0)
		case "<=":
			return runtime.VBool(c <= 0)
		}
		return runtime.VBool(c >= 0)
	}
	lf, lok := num(l)
	rf, rok := num(r)
	if !lok || !rok {
		return xlError("#VALUE!")
	}
	switch x.op {
	case "+":
		return runtime.VFloat(lf + rf)
	case "-":
		return runtime.VFloat(lf - rf)
	case "*":
		return runtime.VFloat(lf * rf)
	case "/":
		if rf == 0 {
			return xlError("#DIV/0!")
		}
		return runtime.VFloat(lf / rf)
	case "^":
		return runtime.VFloat(math.Pow(lf, rf))
	}
	return runtime.NewUnknown("operator " + x.op)
}

// arg evaluates argument i to a value (missing → Empty).
func (e *xlmEngine) arg(c xCall, i int) runtime.Value {
	if i >= len(c.args) {
		return runtime.VEmpty
	}
	return e.value(e.eval(c.args[i]))
}

func (e *xlmEngine) argRef(c xCall, i int) *xlRef {
	if i >= len(c.args) {
		return nil
	}
	x := e.eval(c.args[i])
	if x.ref != nil {
		return x.ref
	}
	// A text reference ("R1C1" or "Sheet!A1") is accepted too.
	if x.v.Kind == runtime.KindString {
		if n, err := parseXLM(x.v.Str); err == nil {
			if r, ok := n.(xRef); ok {
				if s := e.sheetOf(r.sheet); s != nil {
					return &xlRef{s: s, r1: r.r1, c1: r.c1, r2: r.r2, c2: r.c2}
				}
			}
		}
	}
	return nil
}

func numArg(v runtime.Value) (int, bool) {
	f, ok := num(v)
	if !ok || math.IsNaN(f) || math.Abs(f) > 1e9 {
		return 0, false
	}
	return int(f), true
}

func (e *xlmEngine) record(t, method string, c xCall, args []runtime.Value, extra map[string]string) {
	ev := &runtime.Event{Type: t, Receiver: "XLM", Method: method, Simulated: true, Extra: extra}
	if e.cur.s != nil && !e.inline {
		ev.Module = e.cur.s.name
		ev.Proc = extractor.CellName(e.cur.r, e.cur.c)
		ev.Line = e.cur.r + 1
		ev.Col = e.cur.c + 1
		if x := e.cur.s.get(e.cur.r, e.cur.c); x != nil {
			ev.Raw = []string{x.formula}
		}
	}
	for _, a := range args {
		arg := runtime.Argument{Value: text(a), Kind: "string"}
		if a.IsUnknown() {
			arg.Kind, arg.UnknownReason, arg.Value = "unknown", a.Unknown, ""
		}
		ev.Arguments = append(ev.Arguments, arg)
		ev.Resolved = append(ev.Resolved, arg.Value)
	}
	e.h.Record(ev)
}

func (e *xlmEngine) write(ref *xlRef, v runtime.Value, via string) {
	if ref == nil {
		e.h.Note("XLM: " + via + " target unresolved at " + e.where())
		return
	}
	cells := 0
	for r := ref.r1; r <= ref.r2; r++ {
		for c := ref.c1; c <= ref.c2; c++ {
			if cells++; cells > 4096 {
				return
			}
			s := text(v)
			if v.Kind == runtime.KindString && strings.HasPrefix(s, "=") && via != "SET.VALUE" {
				ref.s.set(r, c, runtime.VEmpty, s)
				e.h.recordXLMWrite(ref.s, r, c, s, via)
			} else {
				ref.s.set(r, c, v, "")
			}
		}
	}
}

func (e *xlmEngine) goTo(ref *xlRef) {
	if ref != nil {
		e.jump = &xlmPos{s: ref.s, r: ref.r1, c: ref.c1}
	}
}

// skipToNext moves execution past the NEXT() matching the loop at p.
func (e *xlmEngine) skipToNext(p xlmPos) {
	depth := 0
	for r := p.r + 1; r < p.r+65536; r++ {
		x := p.s.get(r, p.c)
		if x == nil || x.formula == "" {
			if x == nil {
				if _, more := p.s.cells[[2]int{r + 1, p.c}]; !more && r > p.r+1024 {
					break
				}
			}
			continue
		}
		f := strings.ToUpper(strings.TrimPrefix(x.formula, "="))
		switch {
		case strings.HasPrefix(f, "WHILE("), strings.HasPrefix(f, "FOR("), strings.HasPrefix(f, "FOR.CELL("):
			depth++
		case strings.HasPrefix(f, "NEXT("):
			if depth == 0 {
				e.jump = &xlmPos{s: p.s, r: r + 1, c: p.c}
				return
			}
			depth--
		}
	}
	e.h.Note("XLM: no NEXT() for loop at " + p.s.name + "!" + extractor.CellName(p.r, p.c))
	e.halt = true
}

// simulated answers for environment probes used as anti-sandbox checks.
func workspaceInfo(n int) runtime.Value {
	switch n {
	case 1:
		return runtime.VString("Windows (64-bit) NT 10.00")
	case 2:
		return runtime.VString("16.0")
	case 13:
		return runtime.VFloat(1920)
	case 14:
		return runtime.VFloat(1080)
	case 19, 42:
		return runtime.VBool(true)
	case 31:
		return runtime.VBool(false)
	}
	return runtime.VEmpty
}

func (e *xlmEngine) call(c xCall) xv {
	val := func(v runtime.Value) xv { return xv{v: v} }
	str := func(i int) string { return text(e.arg(c, i)) }
	switch c.name {
	// --- control flow ---
	case "GOTO":
		e.goTo(e.argRef(c, 0))
		return val(runtime.VBool(true))
	case "HALT", "CLOSE", "QUIT", "FILE.CLOSE":
		e.halt = true
		return val(runtime.VBool(true))
	case "RETURN":
		e.ret = true
		return val(e.arg(c, 0))
	case "RUN":
		ref := e.argRef(c, 0)
		if ref == nil {
			if n := str(0); n != "" {
				if p, ok := e.h.resolveRefText(n); ok {
					ref = &xlRef{s: p.s, r1: p.r, c1: p.c}
				}
			}
		}
		if ref != nil && len(e.frames) < 256 {
			e.frames = append(e.frames, xlmPos{s: e.cur.s, r: e.cur.r + 1, c: e.cur.c})
			e.goTo(ref)
		}
		return val(runtime.VBool(true))
	case "ON.TIME":
		if ref := e.argRef(c, 1); ref != nil {
			e.pending = append(e.pending, xlmPos{s: ref.s, r: ref.r1, c: ref.c1})
		} else if p, ok := e.h.resolveRefText(str(1)); ok {
			e.pending = append(e.pending, p)
		}
		return val(runtime.VBool(true))
	case "IF":
		cond := e.arg(c, 0)
		if cond.IsUnknown() {
			e.h.Note("XLM: IF condition unknown at " + e.where() + "; taking the TRUE branch")
		}
		b, ok := num(cond)
		if cond.IsUnknown() || (ok && b != 0) || (cond.Kind == runtime.KindBool && cond.B) {
			if len(c.args) > 1 {
				return e.eval(c.args[1])
			}
			return val(runtime.VBool(true))
		}
		if len(c.args) > 2 {
			return e.eval(c.args[2])
		}
		return val(runtime.VBool(false))
	case "WHILE":
		cond := e.arg(c, 0)
		b, _ := num(cond)
		if cond.IsUnknown() || b == 0 || len(e.loops) >= 64 {
			e.skipToNext(e.cur)
		} else {
			e.loops = append(e.loops, xlmLoop{pos: e.cur})
		}
		return val(runtime.VBool(true))
	case "FOR":
		name := strings.ToLower(str(0))
		start, _ := num(e.arg(c, 1))
		end, _ := num(e.arg(c, 2))
		step := 1.0
		if len(c.args) > 3 {
			if s, ok := num(e.arg(c, 3)); ok && s != 0 {
				step = s
			}
		}
		e.names[name] = xv{v: runtime.VFloat(start)}
		if (step > 0 && start > end) || (step < 0 && start < end) || len(e.loops) >= 64 {
			e.skipToNext(e.cur)
		} else {
			e.loops = append(e.loops, xlmLoop{pos: e.cur, isFor: true, counter: name, end: end, step: step})
		}
		return val(runtime.VBool(true))
	case "NEXT":
		if len(e.loops) == 0 {
			return val(runtime.VBool(true))
		}
		l := e.loops[len(e.loops)-1]
		if !l.isFor {
			e.loops = e.loops[:len(e.loops)-1]
			e.jump = &l.pos // re-evaluate the WHILE condition
			return val(runtime.VBool(true))
		}
		cur, _ := num(e.names[l.counter].v)
		cur += l.step
		e.names[l.counter] = xv{v: runtime.VFloat(cur)}
		if (l.step > 0 && cur <= l.end) || (l.step < 0 && cur >= l.end) {
			e.jump = &xlmPos{s: l.pos.s, r: l.pos.r + 1, c: l.pos.c}
		} else {
			e.loops = e.loops[:len(e.loops)-1]
		}
		return val(runtime.VBool(true))
	case "BREAK":
		if len(e.loops) > 0 {
			l := e.loops[len(e.loops)-1]
			e.loops = e.loops[:len(e.loops)-1]
			e.skipToNext(l.pos)
		}
		return val(runtime.VBool(true))

	// --- cell and name writes ---
	case "FORMULA", "FORMULA.FILL", "FORMULA.ARRAY":
		v := e.arg(c, 0)
		ref := e.argRef(c, 1)
		if len(c.args) < 2 {
			ref = &xlRef{s: e.cur.s, r1: e.cur.r + 1, c1: e.cur.c, r2: e.cur.r + 1, c2: e.cur.c}
			e.h.Note("XLM: " + c.name + " without a target at " + e.where() + "; assuming the next cell")
		}
		if v.IsUnknown() {
			e.h.Note("XLM: " + c.name + " value unknown at " + e.where())
			return val(v)
		}
		e.write(ref, v, c.name)
		return val(runtime.VBool(true))
	case "SET.VALUE":
		e.write(e.argRef(c, 0), e.arg(c, 1), "SET.VALUE")
		return val(runtime.VBool(true))
	case "SET.NAME", "DEFINE.NAME":
		name := strings.ToLower(str(0))
		if len(c.args) > 1 {
			x := e.eval(c.args[1])
			if x.ref == nil {
				x.v = e.value(x)
			}
			e.names[name] = x
		}
		return val(runtime.VBool(true))

	// --- external effects (simulated) ---
	case "EXEC":
		cmd := e.arg(c, 0)
		e.record("shell", "EXEC", c, []runtime.Value{cmd}, nil)
		return val(runtime.VFloat(1))
	case "REGISTER", "REGISTER.ID":
		dll, fn := str(0), str(1)
		reg := xlmReg{dll: dll, fn: fn}
		id := int64(len(e.regIDs) + 1)
		e.regIDs[id] = reg
		if len(c.args) > 3 {
			if alias := str(3); alias != "" {
				e.regs[strings.ToLower(alias)] = reg
			}
		}
		e.record("api_register", c.name, c, []runtime.Value{e.arg(c, 0), e.arg(c, 1), e.arg(c, 3)},
			map[string]string{"lib": dll, "name": fn})
		return val(runtime.VFloat(float64(id)))
	case "CALL":
		first := e.arg(c, 0)
		if id, ok := num(first); ok && first.Kind != runtime.KindString {
			if reg, ok := e.regIDs[int64(id)]; ok {
				return val(e.api(c, reg, e.evalArgs(c, 1)))
			}
		}
		return val(e.api(c, xlmReg{dll: text(first), fn: str(1)}, e.evalArgs(c, 3)))
	case "FOPEN":
		e.nextFH++
		e.files[e.nextFH] = &xlmFile{path: str(0)}
		e.record("file_open", "FOPEN", c, []runtime.Value{e.arg(c, 0)}, nil)
		return val(runtime.VFloat(float64(e.nextFH)))
	case "FWRITE", "FWRITELN":
		if h, ok := numArg(e.arg(c, 0)); ok {
			if f := e.files[int64(h)]; f != nil && f.buf.Len() < 64<<20 {
				f.buf.WriteString(str(1))
				if c.name == "FWRITELN" {
					f.buf.WriteString("\r\n")
				}
			}
		}
		return val(runtime.VFloat(float64(len(str(1)))))
	case "FCLOSE":
		if h, ok := numArg(e.arg(c, 0)); ok {
			if f := e.files[int64(h)]; f != nil {
				content := f.buf.String()
				sum := sha256.Sum256([]byte(content))
				e.record("file_write", "FCLOSE", c, []runtime.Value{runtime.VString(f.path)}, map[string]string{
					"path": f.path, "content_hex": hex.EncodeToString([]byte(content)), "content_sha256": hex.EncodeToString(sum[:]),
				})
				delete(e.files, int64(h))
			}
		}
		return val(runtime.VBool(true))
	case "FILE.DELETE":
		e.record("file_delete", c.name, c, []runtime.Value{e.arg(c, 0)}, nil)
		return val(runtime.VBool(true))
	case "ALERT", "MESSAGE":
		e.record("message_box", c.name, c, []runtime.Value{e.arg(c, 0)}, nil)
		return val(runtime.VBool(true))
	case "EVALUATE":
		n, err := parseXLM(str(0))
		if err != nil {
			return val(xlError("#VALUE!"))
		}
		return e.eval(n)
	case "INDIRECT":
		if r := e.argRef(c, 0); r != nil {
			return xv{ref: r}
		}
		return val(xlError("#REF!"))

	// --- environment probes ---
	case "GET.WORKSPACE":
		n, _ := numArg(e.arg(c, 0))
		e.h.Note(fmt.Sprintf("XLM: GET.WORKSPACE(%d) answered with a simulated value", n))
		return val(workspaceInfo(n))
	case "GET.WINDOW", "GET.DOCUMENT", "GET.CELL", "INFO", "GET.WORKBOOK", "GET.NOTE":
		n, _ := numArg(e.arg(c, 0))
		e.h.Note(fmt.Sprintf("XLM: %s(%d) answered with a simulated value", c.name, n))
		switch {
		case c.name == "GET.CELL" && (n == 17 || n == 19):
			return val(runtime.VFloat(11))
		case c.name == "GET.WINDOW" && (n == 7 || n == 23):
			return val(runtime.VBool(false))
		case c.name == "GET.DOCUMENT" && n == 76:
			return val(runtime.VString("[Book1]" + e.cur.s.name))
		case c.name == "GET.DOCUMENT" && n == 88:
			return val(runtime.VString("Book1"))
		}
		return val(runtime.VBool(true))
	case "NOW":
		return val(runtime.VFloat(45000.5))
	case "TODAY":
		return val(runtime.VFloat(45000))
	case "RAND":
		return val(runtime.VFloat(0.5))
	case "RANDBETWEEN":
		return val(e.arg(c, 0))
	case "ROW", "COLUMN":
		r := e.argRef(c, 0)
		row, col := e.cur.r, e.cur.c
		if r != nil {
			row, col = r.r1, r.c1
		}
		if c.name == "ROW" {
			return val(runtime.VFloat(float64(row + 1)))
		}
		return val(runtime.VFloat(float64(col + 1)))
	case "ACTIVE.CELL", "SELECTION", "CALLER":
		return xv{ref: &xlRef{s: e.cur.s, r1: e.cur.r, c1: e.cur.c, r2: e.cur.r, c2: e.cur.c}}
	case "OFFSET":
		r := e.argRef(c, 0)
		dr, _ := numArg(e.arg(c, 1))
		dc, _ := numArg(e.arg(c, 2))
		if r == nil {
			return val(xlError("#REF!"))
		}
		return xv{ref: &xlRef{s: r.s, r1: r.r1 + dr, c1: r.c1 + dc, r2: r.r1 + dr, c2: r.c1 + dc}}
	case "GET.FORMULA":
		if r := e.argRef(c, 0); r != nil {
			if x := r.s.get(r.r1, r.c1); x != nil && x.formula != "" {
				return val(runtime.VString(x.formula))
			}
			return val(r.s.value(r.r1, r.c1))
		}
		return val(xlError("#REF!"))
	case "DAY", "MONTH", "YEAR", "HOUR", "MINUTE", "SECOND", "WEEKDAY":
		return val(runtime.VFloat(1))
	case "ECHO", "ERROR", "WAIT", "BEEP", "WORKBOOK.HIDE", "WORKBOOK.UNHIDE", "HIDE", "UNHIDE", "SELECT",
		"APP.MAXIMIZE", "APP.MINIMIZE", "APP.RESTORE", "WINDOW.MINIMIZE", "WINDOW.MAXIMIZE", "ACTIVATE",
		"WORKBOOK.ACTIVATE", "WORKBOOK.SELECT", "CALCULATE.NOW", "CANCEL.KEY", "DISABLE.INPUT", "VOLATILE",
		"SAVE", "SAVE.AS", "OPEN", "PAUSE", "RESUME", "ARGUMENT", "RESULT", "SEND.KEYS", "END.IF", "ELSE":
		return val(runtime.VBool(true))
	}
	if v, ok := e.textFunc(c); ok {
		return val(v)
	}
	if reg, ok := e.regs[strings.ToLower(c.name)]; ok {
		return val(e.api(c, reg, e.evalArgs(c, 0)))
	}
	// A defined name pointing to a macro cell called as a function.
	if p, ok := e.namedMacro(c.name); ok && len(e.frames) < 256 {
		e.frames = append(e.frames, xlmPos{s: e.cur.s, r: e.cur.r + 1, c: e.cur.c})
		e.jump = &p
		return val(runtime.VBool(true))
	}
	e.h.Note("XLM: unsupported function " + c.name + " at " + e.where())
	return val(runtime.NewUnknown("unsupported XLM function " + c.name))
}

func (e *xlmEngine) namedMacro(name string) (xlmPos, bool) {
	for _, d := range e.h.workbook().names {
		if strings.EqualFold(d.Name, name) {
			return e.h.resolveRefText(strings.TrimPrefix(d.Formula, "="))
		}
	}
	if x, ok := e.names[strings.ToLower(name)]; ok && x.ref != nil {
		return xlmPos{s: x.ref.s, r: x.ref.r1, c: x.ref.c1}, true
	}
	return xlmPos{}, false
}

func (e *xlmEngine) evalArgs(c xCall, from int) []runtime.Value {
	var out []runtime.Value
	for i := from; i < len(c.args); i++ {
		out = append(out, e.arg(c, i))
	}
	return out
}

// api records a Win32 API call made through CALL or a REGISTER alias.
// Process-creating and download APIs map to the same event types as their
// VBA equivalents so commands and IOCs are recovered the same way.
func (e *xlmEngine) api(c xCall, reg xlmReg, args []runtime.Value) runtime.Value {
	extra := map[string]string{"lib": reg.dll, "name": reg.fn}
	fn := strings.ToLower(reg.fn)
	at := func(i int) runtime.Value {
		if i < len(args) {
			return args[i]
		}
		return runtime.VEmpty
	}
	switch {
	case strings.HasPrefix(fn, "shellexecute"):
		e.record("shell_execute", reg.fn, c, []runtime.Value{at(2), at(3)}, extra)
		return runtime.VFloat(42)
	case fn == "winexec":
		e.record("shell", reg.fn, c, []runtime.Value{at(0)}, extra)
		return runtime.VFloat(33)
	case strings.HasPrefix(fn, "createprocess"):
		cmd := at(1)
		if text(cmd) == "" {
			cmd = at(0)
		}
		e.record("shell", reg.fn, c, []runtime.Value{cmd}, extra)
		return runtime.VFloat(1)
	case strings.HasPrefix(fn, "urldownloadtofile"):
		extra["url"], extra["path"] = text(at(1)), text(at(2))
		e.record("http_download", reg.fn, c, []runtime.Value{at(1), at(2)}, extra)
		return runtime.VFloat(0)
	}
	e.record("api_call", reg.fn, c, args, extra)
	return runtime.VFloat(1)
}

// textFunc implements the pure text/number functions used to deobfuscate.
func (e *xlmEngine) textFunc(c xCall) (runtime.Value, bool) {
	if !textFuncs[c.name] {
		return runtime.Value{}, false
	}
	args := e.evalArgs(c, 0)
	for _, a := range args {
		if a.IsUnknown() {
			return a, true
		}
	}
	s := func(i int) string {
		if i < len(args) {
			return text(args[i])
		}
		return ""
	}
	n := func(i int) (float64, bool) {
		if i < len(args) {
			return num(args[i])
		}
		return 0, false
	}
	bad := xlError("#VALUE!")
	switch c.name {
	case "CHAR":
		f, ok := n(0)
		if !ok || f < 1 || f > 255 {
			return bad, true
		}
		return runtime.VString(string(rune(int(f)))), true
	case "CODE":
		r := []rune(s(0))
		if len(r) == 0 {
			return bad, true
		}
		return runtime.VFloat(float64(r[0])), true
	case "LEN":
		return runtime.VFloat(float64(len([]rune(s(0))))), true
	case "MID":
		r := []rune(s(0))
		st, ok1 := n(1)
		ln, ok2 := n(2)
		if !ok1 || !ok2 || st < 1 || ln < 0 {
			return bad, true
		}
		a := int(st) - 1
		if a > len(r) {
			return runtime.VString(""), true
		}
		b := a + int(ln)
		if b > len(r) {
			b = len(r)
		}
		return runtime.VString(string(r[a:b])), true
	case "LEFT", "RIGHT":
		r := []rune(s(0))
		k := 1
		if len(args) > 1 {
			f, ok := n(1)
			if !ok || f < 0 {
				return bad, true
			}
			k = int(f)
		}
		if k > len(r) {
			k = len(r)
		}
		if c.name == "LEFT" {
			return runtime.VString(string(r[:k])), true
		}
		return runtime.VString(string(r[len(r)-k:])), true
	case "CONCATENATE":
		var b strings.Builder
		for i := range args {
			b.WriteString(s(i))
		}
		return runtime.VString(b.String()), true
	case "UPPER":
		return runtime.VString(strings.ToUpper(s(0))), true
	case "LOWER":
		return runtime.VString(strings.ToLower(s(0))), true
	case "TRIM":
		return runtime.VString(strings.Join(strings.Fields(s(0)), " ")), true
	case "CLEAN":
		return runtime.VString(strings.Map(func(r rune) rune {
			if r < 32 {
				return -1
			}
			return r
		}, s(0))), true
	case "REPT":
		k, ok := n(1)
		if !ok || k < 0 || k*float64(len(s(0))) > 1<<20 {
			return bad, true
		}
		return runtime.VString(strings.Repeat(s(0), int(k))), true
	case "SUBSTITUTE":
		return runtime.VString(strings.ReplaceAll(s(0), s(1), s(2))), true
	case "REPLACE":
		r := []rune(s(0))
		st, ok1 := n(1)
		ln, ok2 := n(2)
		if !ok1 || !ok2 || st < 1 {
			return bad, true
		}
		a := int(st) - 1
		if a > len(r) {
			a = len(r)
		}
		b := a + int(ln)
		if b > len(r) {
			b = len(r)
		}
		return runtime.VString(string(r[:a]) + s(3) + string(r[b:])), true
	case "FIND", "SEARCH":
		hay, needle := s(1), s(0)
		if c.name == "SEARCH" {
			hay, needle = strings.ToLower(hay), strings.ToLower(needle)
		}
		i := strings.Index(hay, needle)
		if i < 0 {
			return bad, true
		}
		return runtime.VFloat(float64(len([]rune(hay[:i])) + 1)), true
	case "VALUE":
		f, ok := n(0)
		if !ok {
			return bad, true
		}
		return runtime.VFloat(f), true
	case "T":
		if len(args) > 0 && args[0].Kind == runtime.KindString {
			return args[0], true
		}
		return runtime.VString(""), true
	case "N":
		f, _ := n(0)
		return runtime.VFloat(f), true
	case "TEXT":
		return runtime.VString(s(0)), true
	case "INT", "TRUNC", "ABS", "ROUND", "ROUNDUP", "ROUNDDOWN", "SQRT", "SIGN", "EXP", "LN", "LOG10":
		f, ok := n(0)
		if !ok {
			return bad, true
		}
		switch c.name {
		case "INT":
			f = math.Floor(f)
		case "TRUNC", "ROUNDDOWN":
			f = math.Trunc(f)
		case "ABS":
			f = math.Abs(f)
		case "ROUND":
			d, _ := n(1)
			p := math.Pow(10, d)
			f = math.Round(f*p) / p
		case "ROUNDUP":
			if f >= 0 {
				f = math.Ceil(f)
			} else {
				f = math.Floor(f)
			}
		case "SQRT":
			f = math.Sqrt(f)
		case "SIGN":
			switch {
			case f > 0:
				f = 1
			case f < 0:
				f = -1
			}
		case "EXP":
			f = math.Exp(f)
		case "LN":
			f = math.Log(f)
		case "LOG10":
			f = math.Log10(f)
		}
		return runtime.VFloat(f), true
	case "MOD":
		a, ok1 := n(0)
		b, ok2 := n(1)
		if !ok1 || !ok2 || b == 0 {
			return xlError("#DIV/0!"), true
		}
		return runtime.VFloat(a - b*math.Floor(a/b)), true
	case "POWER":
		a, _ := n(0)
		b, _ := n(1)
		return runtime.VFloat(math.Pow(a, b)), true
	case "SUM", "PRODUCT", "MIN", "MAX", "AVERAGE", "COUNT", "COUNTA":
		var vals []float64
		for i := range args {
			if f, ok := n(i); ok {
				vals = append(vals, f)
			}
		}
		acc := 0.0
		switch c.name {
		case "PRODUCT":
			acc = 1
			for _, f := range vals {
				acc *= f
			}
		case "MIN", "MAX":
			for i, f := range vals {
				if i == 0 || (c.name == "MIN" && f < acc) || (c.name == "MAX" && f > acc) {
					acc = f
				}
			}
		case "COUNT", "COUNTA":
			acc = float64(len(vals))
		default:
			for _, f := range vals {
				acc += f
			}
			if c.name == "AVERAGE" && len(vals) > 0 {
				acc /= float64(len(vals))
			}
		}
		return runtime.VFloat(acc), true
	case "AND", "OR":
		res := c.name == "AND"
		for i := range args {
			f, _ := n(i)
			if c.name == "AND" {
				res = res && f != 0
			} else {
				res = res || f != 0
			}
		}
		return runtime.VBool(res), true
	case "NOT":
		f, _ := n(0)
		return runtime.VBool(f == 0), true
	case "TRUE":
		return runtime.VBool(true), true
	case "FALSE":
		return runtime.VBool(false), true
	case "ISERROR", "ISERR":
		return runtime.VBool(len(args) > 0 && isErr(args[0])), true
	case "ISNA":
		return runtime.VBool(len(args) > 0 && isErr(args[0]) && args[0].Str == "#N/A"), true
	case "ISNUMBER":
		return runtime.VBool(len(args) > 0 && (args[0].Kind == runtime.KindFloat || args[0].Kind == runtime.KindInt)), true
	case "ISTEXT":
		return runtime.VBool(len(args) > 0 && args[0].Kind == runtime.KindString), true
	case "ISBLANK":
		return runtime.VBool(len(args) > 0 && args[0].Kind == runtime.KindEmpty), true
	case "ISLOGICAL":
		return runtime.VBool(len(args) > 0 && args[0].Kind == runtime.KindBool), true
	case "EXACT":
		return runtime.VBool(s(0) == s(1)), true
	case "CHOOSE":
		k, ok := n(0)
		if !ok || int(k) < 1 || int(k) >= len(args) {
			return bad, true
		}
		return args[int(k)], true
	}
	return runtime.Value{}, false
}

var textFuncs = map[string]bool{}

func init() {
	for _, f := range strings.Fields(`CHAR CODE LEN MID LEFT RIGHT CONCATENATE UPPER LOWER TRIM CLEAN REPT SUBSTITUTE
		REPLACE FIND SEARCH VALUE T N TEXT INT TRUNC ABS ROUND ROUNDUP ROUNDDOWN SQRT SIGN EXP LN LOG10 MOD POWER
		SUM PRODUCT MIN MAX AVERAGE COUNT COUNTA AND OR NOT TRUE FALSE ISERROR ISERR ISNA ISNUMBER ISTEXT ISBLANK
		ISLOGICAL EXACT CHOOSE`) {
		textFuncs[f] = true
	}
}
