package pcode

import (
	"fmt"
	"strconv"
	"strings"
)

// Source is the result of decompiling a module.
type Source struct {
	// Text is VBA source rebuilt from the p-code, one line per p-code line.
	Text string
	// Lines is the number of lines rebuilt and Unknown the number that
	// held an instruction the decompiler could not render (they are
	// emitted as comments).
	Lines, Unknown int
	// Procedures counts the Sub/Function/Property definitions found.
	Procedures int
}

var binOps = map[string]string{
	"Imp": "Imp", "Eqv": "Eqv", "Xor": "Xor", "Or": "Or", "And": "And",
	"Eq": "=", "Ne": "<>", "Le": "<=", "Ge": ">=", "Lt": "<", "Gt": ">",
	"Add": "+", "Sub": "-", "Mod": "Mod", "IDiv": "\\", "Mul": "*", "Div": "/",
	"Concat": "&", "Like": "Like", "Pwr": "^", "Is": "Is",
}

// oneArgFns are intrinsic functions that take one stack operand.
var oneArgFns = map[string]string{
	"FnAbs": "Abs", "FnFix": "Fix", "FnInt": "Int", "FnSgn": "Sgn", "FnLen": "Len", "FnLenB": "LenB",
}

// fixedFns are intrinsic functions with a fixed operand count.
var fixedFns = map[string]struct {
	name string
	n    int
}{
	"FnInStr": {"InStr", 2}, "FnInStr3": {"InStr", 3}, "FnInStr4": {"InStr", 4},
	"FnInStrB": {"InStrB", 2}, "FnInStrB3": {"InStrB", 3}, "FnInStrB4": {"InStrB", 4},
	"FnMid": {"Mid", 3}, "FnMidB": {"MidB", 3},
	"FnStrComp": {"StrComp", 2}, "FnStrComp3": {"StrComp", 3},
	"FnStringVar": {"String", 2}, "FnStringStr": {"String$", 2},
	"FnFormat": {"Format", 2}, "FnDir": {"Dir", 0}, "FnCurDir": {"CurDir", 0},
	"FnFreeFile": {"FreeFile", 0}, "FnError": {"Error", 0},
}

// coerceFns name the conversion function of Coerce's type field.
var coerceFns = map[int]string{
	0: "CVar", 2: "CInt", 3: "CLng", 4: "CSng", 5: "CDbl", 6: "CCur", 7: "CDate", 8: "CStr",
	10: "CVErr", 11: "CBool", 12: "CVar", 14: "CDec", 17: "CByte", 20: "CLngLng", 21: "CLngPtr",
}

var caseOps = map[string]string{"CaseGt": ">", "CaseLt": "<", "CaseGe": ">=", "CaseLe": "<=", "CaseNe": "<>", "CaseEq": "="}

var optionNames = []string{"Base 0", "Base 1", "Compare Text", "Compare Binary", "Explicit", "Private Module"}

// stack markers that are not expressions.
const (
	markOmitted    = "\x00omitted"
	markOptionBase = "\x00optionbase"
	markDebug      = "\x00debug"
)

type lineState struct {
	p     *Project
	stack []string
	stmts []string
	// prefix holds an open single-line If ("If c Then ").
	prefix  string
	forVar  string
	inFor   bool
	cases   []string
	print   []string
	printOn bool
	bad     bool
}

func (s *lineState) push(v string) { s.stack = append(s.stack, v) }

func (s *lineState) pop() string {
	if len(s.stack) == 0 {
		s.bad = true
		return ""
	}
	v := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	return v
}

// expr renders a stack value for use inside an expression.
func expr(v string) string {
	switch v {
	case markOmitted, markOptionBase, markDebug:
		return ""
	}
	return v
}

// popN pops n operands and returns them in source order.
func (s *lineState) popN(n int) []string {
	if n < 0 || n > 4096 {
		s.bad = true
		return nil
	}
	out := make([]string, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = expr(s.pop())
	}
	return out
}

// argList joins call arguments, dropping trailing omitted ones.
func argList(args []string) string {
	for len(args) > 0 && args[len(args)-1] == "" {
		args = args[:len(args)-1]
	}
	return strings.Join(args, ", ")
}

func call(name string, args []string) string { return name + "(" + argList(args) + ")" }

func (s *lineState) stmt(v string) { s.stmts = append(s.stmts, v) }

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Decompile rebuilds VBA source from a disassembled module.
func Decompile(m *Module, p *Project) *Source {
	src := &Source{}
	var b strings.Builder
	// openProc tracks a FuncDefn without its End yet: a definition that
	// is followed by another one is a Declare statement.
	openProc := -1
	lines := make([]string, len(m.Lines))
	for i, l := range m.Lines {
		text, unknown, def, end := decompileLine(l, p)
		if def != nil && def.Declare {
			text = strings.TrimPrefix(text, "\x00def")
			def = nil
		}
		if def != nil {
			if openProc >= 0 && strings.HasPrefix(lines[openProc], "\x00def") {
				lines[openProc] = declareText(m.Lines[openProc])
			}
			openProc = i
			src.Procedures++
		}
		if end {
			if openProc >= 0 {
				lines[openProc] = strings.TrimPrefix(lines[openProc], "\x00def")
			}
			openProc = -1
		}
		if unknown {
			src.Unknown++
		}
		lines[i] = text
	}
	if openProc >= 0 && strings.HasPrefix(lines[openProc], "\x00def") {
		lines[openProc] = declareText(m.Lines[openProc])
	}
	for _, l := range lines {
		b.WriteString(strings.TrimPrefix(l, "\x00def"))
		b.WriteString("\r\n")
	}
	src.Lines = len(lines)
	src.Text = b.String()
	return src
}

// declareText renders a procedure definition that has no body.
func declareText(l Line) string {
	for _, in := range l {
		if in.Func != nil {
			f := *in.Func
			f.Declare = true
			return funcText(&f)
		}
	}
	return ""
}

func funcText(f *FuncDecl) string {
	var parts []string
	if f.Scope != "" {
		parts = append(parts, f.Scope)
	}
	if f.Static {
		parts = append(parts, "Static")
	}
	if f.Declare {
		parts = append(parts, "Declare")
		if f.PtrSafe {
			parts = append(parts, "PtrSafe")
		}
	}
	parts = append(parts, f.Kind, f.Name)
	head := strings.Join(parts, " ")
	if f.Declare {
		lib := f.Lib
		if lib == "" {
			lib = "unknown"
		}
		head += " Lib " + quote(lib)
		if f.Alias != "" {
			head += " Alias " + quote(f.Alias)
		}
		head += " "
	}
	var ps []string
	for _, p := range f.Params {
		if p.Name == "" {
			continue
		}
		s := p.Name
		switch {
		case p.ByVal:
			s = "ByVal " + s
		case p.ByRef:
			s = "ByRef " + s
		}
		if p.Optional {
			s = "Optional " + s
		}
		if p.Type != "" {
			s += " As " + p.Type
		}
		ps = append(ps, s)
	}
	head += "(" + strings.Join(ps, ", ") + ")"
	if f.HasAs && f.Returns != "" && isTypeName(f.Returns) {
		head += " As " + f.Returns
	}
	return head
}

func isTypeName(s string) bool {
	for _, t := range typeNames {
		if t != "" && t == s {
			return true
		}
	}
	return false
}

// decompileLine renders one line. def is the procedure it defines, if any,
// and end reports an End Sub/Function/Property.
func decompileLine(l Line, p *Project) (text string, unknown bool, def *FuncDecl, end bool) {
	s := &lineState{p: p}
	for _, in := range l {
		if !s.exec(in) {
			unknown = true
			s.stmts = append(s.stmts, "' p-code not decompiled: "+in.Op)
			break
		}
		if in.Op == "FuncDefn" || in.Op == "FuncDefnSave" {
			def = in.Func
		}
		switch in.Op {
		case "EndSub", "EndFunc", "EndProp":
			end = true
		}
	}
	if s.printOn {
		s.flushPrint()
	}
	text = s.prefix + strings.Join(s.stmts, ": ")
	if def != nil {
		text = "\x00def" + text
	}
	return text, unknown, def, end
}

func (s *lineState) flushPrint() {
	s.stmt(strings.TrimSpace(strings.Join(s.print, "")))
	s.print, s.printOn = nil, false
}

func (s *lineState) name(in Instr) string {
	if len(in.Names) > 0 && in.Names[0] != "" {
		return in.Names[0]
	}
	return "unknown"
}

func (s *lineState) count(in Instr) int {
	if len(in.Words) > 0 {
		return in.Words[0]
	}
	return 0
}

// exec runs one instruction; it returns false for an instruction it
// cannot render.
func (s *lineState) exec(in Instr) bool {
	if op, ok := binOps[in.Op]; ok {
		b := expr(s.pop())
		a := expr(s.pop())
		s.push(a + " " + op + " " + b)
		return true
	}
	if fn, ok := oneArgFns[in.Op]; ok {
		s.push(fn + "(" + expr(s.pop()) + ")")
		return true
	}
	if fn, ok := fixedFns[in.Op]; ok {
		if fn.n == 0 {
			s.push(fn.name)
			return true
		}
		s.push(call(fn.name, s.popN(fn.n)))
		return true
	}
	if op, ok := caseOps[in.Op]; ok {
		s.cases = append(s.cases, "Is "+op+" "+expr(s.pop()))
		return true
	}
	switch in.Op {
	// Operators and grouping.
	case "Not":
		s.push("Not " + expr(s.pop()))
	case "UMi":
		s.push("-" + expr(s.pop()))
	case "Paren":
		s.push("(" + expr(s.pop()) + ")")
	case "Sharp":
		s.push("#" + expr(s.pop()))
	case "FnLBound", "FnUBound":
		n := 1
		if s.count(in) > 0 {
			n = 2
		}
		s.push(call(strings.TrimPrefix(in.Op, "Fn"), s.popN(n)))
	case "Coerce", "CoerceVar":
		fn, ok := coerceFns[in.Type]
		if !ok {
			fn = "CVar"
		}
		s.push(fn + "(" + expr(s.pop()) + ")")

	// Literals.
	case "LitStr":
		s.push(quote(s.p.Decode(in.Bytes)))
	case "LitDI2", "LitDI4", "LitDI8":
		s.push(strconv.FormatInt(wordsInt(in.Words), 10))
	case "LitHI2", "LitHI4", "LitHI8":
		v := uint64(wordsInt(in.Words))
		switch len(in.Words) {
		case 1:
			v &= 0xFFFF
		case 2:
			v &= 0xFFFFFFFF
		}
		suffix := ""
		if len(in.Words) == 2 {
			suffix = "&"
		}
		s.push("&H" + strings.ToUpper(strconv.FormatUint(v, 16)) + suffix)
	case "LitOI2", "LitOI4", "LitOI8":
		s.push("&O" + strconv.FormatUint(uint64(wordsInt(in.Words))&0xFFFFFFFF, 8))
	case "LitR4", "LitR8":
		s.push(strconv.FormatFloat(wordsFloat(in.Words), 'g', -1, 64))
	case "LitSmallI2":
		s.push(strconv.Itoa(in.Type))
	case "LitCy":
		s.push(strconv.FormatFloat(float64(wordsInt(in.Words))/10000, 'f', -1, 64))
	case "LitDate":
		s.push("#" + strconv.FormatFloat(wordsFloat(in.Words), 'g', -1, 64) + "#")
	case "LitVarSpecial":
		s.push([]string{"False", "True", "Null", "Empty"}[in.Type&3])
	case "LitNothing":
		s.push("Nothing")
	case "LitDefault", "ParamOmitted":
		s.push(markOmitted)
	case "OptionBase":
		s.push(markOptionBase)
	case "Me", "MeImplicit":
		s.push("Me")
	case "New":
		s.push("New " + in.Import)
	case "TypeOf":
		s.push("TypeOf " + expr(s.pop()) + " Is " + in.Import)
	case "ParamByVal":
		s.push("ByVal " + expr(s.pop()))
	case "ParamNamed":
		s.push(s.name(in) + ":=" + expr(s.pop()))
	case "LdAddressOf":
		s.push("AddressOf " + s.name(in))
	case "MemAddressOf":
		s.push("AddressOf " + expr(s.pop()) + "." + s.name(in))

	// Loads.
	case "Ld", "LdLHS":
		s.push(s.name(in))
	case "MemLd":
		s.push(expr(s.pop()) + "." + s.name(in))
	case "DictLd":
		s.push(expr(s.pop()) + "!" + s.name(in))
	case "MemLdWith":
		s.push("." + s.name(in))
	case "DictLdWith":
		s.push("!" + s.name(in))
	case "IndexLd":
		args := s.popN(s.count(in))
		s.push(call(expr(s.pop()), args))
	case "ArgsLd", "ArgsArray":
		s.push(call(s.name(in), s.popN(s.count(in))))
	case "ArgsMemLd":
		obj := expr(s.pop())
		s.push(call(obj+"."+s.name(in), s.popN(s.count(in))))
	case "ArgsDictLd":
		obj := expr(s.pop())
		s.push(call(obj+"!"+s.name(in), s.popN(s.count(in))))
	case "ArgsMemLdWith":
		s.push(call("."+s.name(in), s.popN(s.count(in))))
	case "ArgsDictLdWith":
		s.push(call("!"+s.name(in), s.popN(s.count(in))))

	// Stores.
	case "St", "SetOrSt":
		s.stmt(s.name(in) + " = " + expr(s.pop()))
	case "Set":
		s.stmt("Set " + s.name(in) + " = " + expr(s.pop()))
	case "MemSt", "MemSet", "DictSt", "DictSet":
		obj := expr(s.pop())
		sep, set := ".", ""
		if strings.HasPrefix(in.Op, "Dict") {
			sep = "!"
		}
		if strings.HasSuffix(in.Op, "Set") {
			set = "Set "
		}
		s.stmt(set + obj + sep + s.name(in) + " = " + expr(s.pop()))
	case "MemStWith", "MemSetWith", "DictStWith", "DictSetWith":
		sep, set := ".", ""
		if strings.HasPrefix(in.Op, "Dict") {
			sep = "!"
		}
		if strings.HasSuffix(in.Op, "SetWith") {
			set = "Set "
		}
		s.stmt(set + sep + s.name(in) + " = " + expr(s.pop()))
	case "IndexSt", "IndexSet":
		args := s.popN(s.count(in))
		target := call(expr(s.pop()), args)
		set := ""
		if in.Op == "IndexSet" {
			set = "Set "
		}
		s.stmt(set + target + " = " + expr(s.pop()))
	case "ArgsSt", "ArgsSet":
		args := s.popN(s.count(in))
		set := ""
		if in.Op == "ArgsSet" {
			set = "Set "
		}
		s.stmt(set + call(s.name(in), args) + " = " + expr(s.pop()))
	case "ArgsMemSt", "ArgsMemSet", "ArgsDictSt", "ArgsDictSet":
		obj := expr(s.pop())
		args := s.popN(s.count(in))
		sep, set := ".", ""
		if strings.HasPrefix(in.Op, "ArgsDict") {
			sep = "!"
		}
		if strings.HasSuffix(in.Op, "Set") {
			set = "Set "
		}
		s.stmt(set + call(obj+sep+s.name(in), args) + " = " + expr(s.pop()))
	case "ArgsMemStWith", "ArgsMemSetWith", "ArgsDictStWith", "ArgsDictSetWith":
		args := s.popN(s.count(in))
		sep, set := ".", ""
		if strings.HasPrefix(in.Op, "ArgsDict") {
			sep = "!"
		}
		if strings.HasSuffix(in.Op, "SetWith") {
			set = "Set "
		}
		s.stmt(set + call(sep+s.name(in), args) + " = " + expr(s.pop()))

	// Calls.
	case "ArgsCall":
		s.callStmt(in, s.name(in), s.popN(s.count(in)))
	case "ArgsMemCall":
		obj := expr(s.pop())
		s.callStmt(in, obj+"."+s.name(in), s.popN(s.count(in)))
	case "ArgsMemCallWith":
		s.callStmt(in, "."+s.name(in), s.popN(s.count(in)))

	// Statement structure.
	case "BoS", "BoSImplicit", "BoL", "LbMark", "LineCont", "SetStmt", "Let", "StartWithExpr", "EndContext", "Context", "Stack", "Assert":
	case "StartForVariable":
		s.inFor = true
	case "EndForVariable":
		s.forVar = expr(s.pop())
		s.inFor = false
	case "QuoteRem":
		s.stmt("'" + s.p.Decode(in.Bytes))
	case "Rem":
		s.stmt("Rem " + s.p.Decode(in.Bytes))
	case "Reparse":
		s.stmt(s.p.Decode(in.Bytes))
	case "Label":
		s.stmt(s.name(in) + ":")
	case "LineNum":
		s.stmt(s.name(in))

	// Declarations.
	case "FuncDefn", "FuncDefnSave":
		if in.Func == nil {
			return false
		}
		s.stmt(funcText(in.Func))
	case "EndSub":
		s.stmt("End Sub")
	case "EndFunc":
		s.stmt("End Function")
	case "EndProp":
		s.stmt("End Property")
	case "Dim", "DimImplicit":
		s.stmt(dimKeyword(in.Type))
	case "VarDefn":
		if in.Var == nil {
			return false
		}
		v := in.Var.Name
		if in.Var.Array {
			// Fixed-size arrays push (lower, upper) bound pairs before
			// their VarDefn; dynamic arrays push nothing.
			var bounds []string
			for len(s.stack) >= 2 {
				hi := expr(s.pop())
				lo := s.pop()
				if lo == markOptionBase || lo == "" {
					bounds = append([]string{hi}, bounds...)
				} else {
					bounds = append([]string{expr(lo) + " To " + hi}, bounds...)
				}
			}
			if len(s.stack) == 1 {
				bounds = append([]string{expr(s.pop())}, bounds...)
			}
			v += "(" + strings.Join(bounds, ", ") + ")"
		}
		if in.Var.Type != "" || in.Var.New {
			v += " As "
			if in.Var.New {
				v += "New "
			}
			v += in.Var.Type
		}
		s.appendDecl(v)
	case "Type":
		s.stmt("Type " + s.name(in))
	case "EndType":
		s.stmt("End Type")
	case "EndEnum":
		s.stmt("End Enum")
	case "Option":
		if in.Type < len(optionNames) {
			s.stmt("Option " + optionNames[in.Type])
		}
	case "DefType":
		// DefInt and friends only change implicit types: not needed to run.

	// Conditional compilation.
	case "LbIf":
		s.stmt("#If " + expr(s.pop()) + " Then")
	case "LbElseIf":
		s.stmt("#ElseIf " + expr(s.pop()) + " Then")
	case "LbElse":
		s.stmt("#Else")
	case "LbEndIf":
		s.stmt("#End If")
	case "LbConst":
		s.stmt("#Const " + s.name(in) + " = " + expr(s.pop()))

	// Control flow.
	case "IfBlock":
		s.stmt("If " + expr(s.pop()) + " Then")
	case "ElseIfBlock":
		s.stmt("ElseIf " + expr(s.pop()) + " Then")
	case "IfTypeBlock":
		s.stmt("If TypeOf " + expr(s.pop()) + " Is " + in.Import + " Then")
	case "ElseIfTypeBlock":
		s.stmt("ElseIf TypeOf " + expr(s.pop()) + " Is " + in.Import + " Then")
	case "ElseBlock":
		s.stmt("Else")
	case "EndIfBlock":
		s.stmt("End If")
	case "If":
		s.prefix += "If " + expr(s.pop()) + " Then "
	case "Else":
		s.prefix += strings.Join(s.stmts, ": ") + " Else "
		s.stmts = nil
	case "EndIf":
	case "For":
		e := expr(s.pop())
		st := expr(s.pop())
		s.stmt("For " + s.forVar + " = " + st + " To " + e)
	case "ForStep":
		step := expr(s.pop())
		e := expr(s.pop())
		st := expr(s.pop())
		s.stmt("For " + s.forVar + " = " + st + " To " + e + " Step " + step)
	case "ForEach", "ForEachAs":
		s.stmt("For Each " + s.forVar + " In " + expr(s.pop()))
	case "Next":
		s.stmt("Next")
	case "NextVar":
		s.stmt("Next " + s.forVar)
	case "Do":
		s.stmt("Do")
	case "DoWhile":
		s.stmt("Do While " + expr(s.pop()))
	case "DoUntil":
		s.stmt("Do Until " + expr(s.pop()))
	case "Loop":
		s.stmt("Loop")
	case "LoopWhile":
		s.stmt("Loop While " + expr(s.pop()))
	case "LoopUntil":
		s.stmt("Loop Until " + expr(s.pop()))
	case "While":
		s.stmt("While " + expr(s.pop()))
	case "Wend":
		s.stmt("Wend")
	case "SelectCase":
		s.stmt("Select Case " + expr(s.pop()))
	case "Case":
		s.cases = append(s.cases, expr(s.pop()))
	case "CaseTo":
		hi := expr(s.pop())
		s.cases = append(s.cases, expr(s.pop())+" To "+hi)
	case "CaseDone":
		s.stmt("Case " + strings.Join(s.cases, ", "))
		s.cases = nil
	case "CaseElse":
		s.stmt("Case Else")
	case "EndSelect":
		s.stmt("End Select")
	case "With":
		s.stmt("With " + expr(s.pop()))
	case "EndWith":
		s.stmt("End With")
	case "ExitDo":
		s.stmt("Exit Do")
	case "ExitFor":
		s.stmt("Exit For")
	case "ExitFunc":
		s.stmt("Exit Function")
	case "ExitProp":
		s.stmt("Exit Property")
	case "ExitSub":
		s.stmt("Exit Sub")
	case "GoTo":
		s.stmt("GoTo " + s.name(in))
	case "GoSub":
		s.stmt("GoSub " + s.name(in))
	case "Return":
		s.stmt("Return")
	case "End":
		s.stmt("End")
	case "Stop":
		s.stmt("Stop")
	case "OnError":
		switch in.Type {
		case 1:
			s.stmt("On Error Resume Next")
		case 2:
			s.stmt("On Error GoTo 0")
		default:
			s.stmt("On Error GoTo " + s.name(in))
		}
	case "Resume":
		switch in.Type {
		case 1:
			s.stmt("Resume Next")
		case 0:
			s.stmt("Resume " + s.name(in))
		default:
			s.stmt("Resume")
		}
	case "Error":
		s.stmt("Error " + expr(s.pop()))
	case "DoEvents":
		s.stmt("DoEvents")
	case "Redim", "RedimAs", "MemRedim", "MemRedimAs", "MemRedimWith", "MemRedimAsWith":
		s.redim(in)
	case "Erase":
		s.stmt("Erase " + argList(s.popN(max(s.count(in), 1))))
	case "Mid", "MidB":
		args := s.popN(3)
		v := expr(s.pop())
		s.stmt(call(strings.TrimSuffix(in.Op, ""), args) + " = " + v)
	case "LSet", "RSet":
		target := expr(s.pop())
		s.stmt(in.Op + " " + target + " = " + expr(s.pop()))

	// Print, Debug.Print and file I/O.
	case "Debug":
		s.push(markDebug)
	case "PrintObj":
		obj := s.pop()
		head := "Print "
		if obj == markDebug {
			head = "Debug.Print "
		} else if obj != "" {
			head = expr(obj) + ".Print "
		}
		s.print, s.printOn = []string{head}, true
	case "PrintChan":
		s.print, s.printOn = []string{"Print " + expr(s.pop()) + ", "}, true
	case "WriteChan":
		s.print, s.printOn = []string{"Write " + expr(s.pop()) + ", "}, true
	case "PrintItemNL", "PrintItemSemi", "PrintItemComma":
		item := expr(s.pop())
		sep := map[string]string{"PrintItemNL": "", "PrintItemSemi": "; ", "PrintItemComma": ", "}[in.Op]
		s.print = append(s.print, item+sep)
	case "PrintNL", "PrintEoS":
	case "PrintSemi":
		s.print = append(s.print, "; ")
	case "PrintComma":
		s.print = append(s.print, ", ")
	case "PrintSpc":
		s.print = append(s.print, "Spc("+expr(s.pop())+"); ")
	case "PrintTab", "PrintTabComma":
		s.print = append(s.print, "Tab("+expr(s.pop())+"); ")
	case "Open":
		s.open(in)
	case "Close":
		n := s.count(in)
		if n == 0 {
			s.stmt("Close")
		} else {
			s.stmt("Close " + argList(s.popN(n)))
		}
	case "CloseAll":
		s.stmt("Close")
	case "GetRec", "PutRec":
		v := expr(s.pop())
		rec := expr(s.pop())
		ch := expr(s.pop())
		s.stmt(strings.TrimSuffix(in.Op, "Rec") + " " + ch + ", " + rec + ", " + v)
	case "Input", "InputDone":
	case "InputItem":
		s.stmt("Input " + expr(s.pop()))
	case "LineInput":
		v := expr(s.pop())
		s.stmt("Line Input " + expr(s.pop()) + ", " + v)
	case "Seek":
		pos := expr(s.pop())
		s.stmt("Seek " + expr(s.pop()) + ", " + pos)
	case "Lock", "Unlock":
		s.stmt(in.Op + " " + expr(s.pop()))
	case "Name":
		to := expr(s.pop())
		s.stmt("Name " + expr(s.pop()) + " As " + to)
	default:
		return false
	}
	return !s.bad
}

func (s *lineState) callStmt(in Instr, target string, args []string) {
	if in.Type < 16 {
		s.stmt("Call " + call(target, args))
		return
	}
	if a := argList(args); a != "" {
		s.stmt(target + " " + a)
		return
	}
	s.stmt(target)
}

// appendDecl adds a variable to the Dim statement of the line.
func (s *lineState) appendDecl(v string) {
	if n := len(s.stmts); n > 0 {
		last := s.stmts[n-1]
		if isDimHead(last) {
			s.stmts[n-1] = last + " " + v
			return
		}
		if strings.Contains(last, " ") && dimLike(last) {
			s.stmts[n-1] = last + ", " + v
			return
		}
	}
	s.stmt("Dim " + v)
}

var dimHeads = []string{"Dim", "Global", "Public", "Private", "Static", "Const", "Global Const", "Public Const", "Private Const"}

func isDimHead(s string) bool {
	for _, h := range dimHeads {
		if s == h {
			return true
		}
	}
	return false
}

func dimLike(s string) bool {
	for _, h := range dimHeads {
		if strings.HasPrefix(s, h+" ") {
			return true
		}
	}
	return false
}

func dimKeyword(t int) string {
	kw := "Dim"
	switch {
	case t&0x04 != 0:
		kw = "Global"
	case t&0x08 != 0:
		kw = "Public"
	case t&0x10 != 0:
		kw = "Private"
	case t&0x20 != 0:
		kw = "Static"
	}
	if t&0x01 != 0 {
		if kw == "Dim" {
			return "Const"
		}
		kw += " Const"
	}
	return kw
}

func (s *lineState) redim(in Instr) {
	dims := s.count(in)
	if dims <= 0 || dims > 60 {
		dims = 1
	}
	bounds := make([]string, dims)
	for i := dims - 1; i >= 0; i-- {
		hi := expr(s.pop())
		lo := s.pop()
		if lo == markOptionBase || lo == "" {
			bounds[i] = hi
		} else {
			bounds[i] = expr(lo) + " To " + hi
		}
	}
	target := s.name(in)
	if strings.HasPrefix(in.Op, "Mem") {
		if strings.HasSuffix(in.Op, "With") {
			target = "." + target
		} else {
			target = expr(s.pop()) + "." + target
		}
	}
	kw := "ReDim "
	if in.Type&16 != 0 {
		kw += "Preserve "
	}
	text := kw + target + "(" + strings.Join(bounds, ", ") + ")"
	if strings.Contains(in.Op, "As") && in.Import != "" {
		text += " As " + in.Import
	}
	s.stmt(text)
}

func (s *lineState) open(in Instr) {
	mode := s.count(in)
	var m string
	switch {
	case mode&0x01 != 0:
		m = "Input"
	case mode&0x02 != 0:
		m = "Output"
	case mode&0x04 != 0:
		m = "Random"
	case mode&0x08 != 0:
		m = "Append"
	case mode&0xFF == 0x20:
		m = "Binary"
	}
	reclen := expr(s.pop())
	ch := expr(s.pop())
	file := expr(s.pop())
	text := "Open " + file
	if m != "" {
		text += " For " + m
	}
	text += " As " + ch
	if reclen != "" {
		text += " Len = " + reclen
	}
	s.stmt(text)
}

// String renders the instruction for diagnostics.
func (in Instr) String() string {
	return fmt.Sprintf("%s(%d) %v %v", in.Op, in.Type, in.Names, in.Words)
}
