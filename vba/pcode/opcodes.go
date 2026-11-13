// Package pcode reads the compiled form of VBA modules (the "performance
// cache" stored before the compressed source in each module stream) and
// rebuilds VBA source from it. Office executes this p-code rather than the
// source text when the VBA version matches, so VBA stomping (replacing or
// erasing the source) hides the real macro from source-based tools.
//
// The p-code format is undocumented. The opcode numbering, operand kinds and
// table offsets used here are facts of the format as published by Vesselin
// Bontchev's research (https://github.com/bontchev/pcodedmp); this package
// is an independent implementation.
package pcode

// operand kinds that follow an opcode word.
type operand byte

const (
	opName    operand = iota // identifier reference (16 bits)
	opWord                   // immediate 16-bit value
	opImport                 // object table reference (16 bits)
	opFunc                   // indirect table offset of a procedure (32 bits)
	opVar                    // indirect table offset of a variable (32 bits)
	opRecord                 // indirect table offset of a user type (32 bits)
	opType                   // indirect table offset of a type descriptor (32 bits)
	opContext                // context (32 bits, 64 on 64-bit Office)
)

type opInfo struct {
	name     string
	operands []operand
	// variable is set for opcodes followed by a 16-bit length and that
	// many bytes (padded to an even count): string literals, comments.
	variable bool
}

// opTable is indexed by the VBA7 opcode number; older versions are mapped
// onto it by normalizeOpcode.
var opTable = buildOpTable()

func buildOpTable() []opInfo {
	n := []operand{opName}
	w := []operand{opWord}
	nw := []operand{opName, opWord}
	w2 := []operand{opWord, opWord}
	w4 := []operand{opWord, opWord, opWord, opWord}
	imp := []operand{opImport}
	redim := []operand{opName, opWord, opType}
	t := []opInfo{
		{"Imp", nil, false}, {"Eqv", nil, false}, {"Xor", nil, false}, {"Or", nil, false},
		{"And", nil, false}, {"Eq", nil, false}, {"Ne", nil, false}, {"Le", nil, false},
		{"Ge", nil, false}, {"Lt", nil, false}, {"Gt", nil, false}, {"Add", nil, false},
		{"Sub", nil, false}, {"Mod", nil, false}, {"IDiv", nil, false}, {"Mul", nil, false},
		{"Div", nil, false}, {"Concat", nil, false}, {"Like", nil, false}, {"Pwr", nil, false},
		{"Is", nil, false}, {"Not", nil, false}, {"UMi", nil, false}, {"FnAbs", nil, false},
		{"FnFix", nil, false}, {"FnInt", nil, false}, {"FnSgn", nil, false}, {"FnLen", nil, false},
		{"FnLenB", nil, false}, {"Paren", nil, false}, {"Sharp", nil, false}, {"LdLHS", n, false},
		{"Ld", n, false}, {"MemLd", n, false}, {"DictLd", n, false}, {"IndexLd", w, false},
		{"ArgsLd", nw, false}, {"ArgsMemLd", nw, false}, {"ArgsDictLd", nw, false}, {"St", n, false},
		{"MemSt", n, false}, {"DictSt", n, false}, {"IndexSt", w, false}, {"ArgsSt", nw, false},
		{"ArgsMemSt", nw, false}, {"ArgsDictSt", nw, false}, {"Set", n, false}, {"MemSet", n, false},
		{"DictSet", n, false}, {"IndexSet", w, false}, {"ArgsSet", nw, false}, {"ArgsMemSet", nw, false},
		{"ArgsDictSet", nw, false}, {"MemLdWith", n, false}, {"DictLdWith", n, false}, {"ArgsMemLdWith", nw, false},
		{"ArgsDictLdWith", nw, false}, {"MemStWith", n, false}, {"DictStWith", n, false}, {"ArgsMemStWith", nw, false},
		{"ArgsDictStWith", nw, false}, {"MemSetWith", n, false}, {"DictSetWith", n, false}, {"ArgsMemSetWith", nw, false},
		{"ArgsDictSetWith", nw, false}, {"ArgsCall", nw, false}, {"ArgsMemCall", nw, false}, {"ArgsMemCallWith", nw, false},
		{"ArgsArray", nw, false}, {"Assert", nil, false}, {"BoS", w, false}, {"BoSImplicit", nil, false},
		{"BoL", nil, false}, {"LdAddressOf", n, false}, {"MemAddressOf", n, false}, {"Case", nil, false},
		{"CaseTo", nil, false}, {"CaseGt", nil, false}, {"CaseLt", nil, false}, {"CaseGe", nil, false},
		{"CaseLe", nil, false}, {"CaseNe", nil, false}, {"CaseEq", nil, false}, {"CaseElse", nil, false},
		{"CaseDone", nil, false}, {"Circle", w, false}, {"Close", w, false}, {"CloseAll", nil, false},
		{"Coerce", nil, false}, {"CoerceVar", nil, false}, {"Context", []operand{opContext}, false}, {"Debug", nil, false},
		{"DefType", w2, false}, {"Dim", nil, false}, {"DimImplicit", nil, false}, {"Do", nil, false},
		{"DoEvents", nil, false}, {"DoUntil", nil, false}, {"DoWhile", nil, false}, {"Else", nil, false},
		{"ElseBlock", nil, false}, {"ElseIfBlock", nil, false}, {"ElseIfTypeBlock", imp, false}, {"End", nil, false},
		{"EndContext", nil, false}, {"EndFunc", nil, false}, {"EndIf", nil, false}, {"EndIfBlock", nil, false},
		{"EndImmediate", nil, false}, {"EndProp", nil, false}, {"EndSelect", nil, false}, {"EndSub", nil, false},
		{"EndType", nil, false}, {"EndWith", nil, false}, {"Erase", w, false}, {"Error", nil, false},
		{"EventDecl", []operand{opFunc}, false}, {"RaiseEvent", nw, false}, {"ArgsMemRaiseEvent", nw, false}, {"ArgsMemRaiseEventWith", nw, false},
		{"ExitDo", nil, false}, {"ExitFor", nil, false}, {"ExitFunc", nil, false}, {"ExitProp", nil, false},
		{"ExitSub", nil, false}, {"FnCurDir", nil, false}, {"FnDir", nil, false}, {"Empty0", nil, false},
		{"Empty1", nil, false}, {"FnError", nil, false}, {"FnFormat", nil, false}, {"FnFreeFile", nil, false},
		{"FnInStr", nil, false}, {"FnInStr3", nil, false}, {"FnInStr4", nil, false}, {"FnInStrB", nil, false},
		{"FnInStrB3", nil, false}, {"FnInStrB4", nil, false}, {"FnLBound", w, false}, {"FnMid", nil, false},
		{"FnMidB", nil, false}, {"FnStrComp", nil, false}, {"FnStrComp3", nil, false}, {"FnStringVar", nil, false},
		{"FnStringStr", nil, false}, {"FnUBound", w, false}, {"For", nil, false}, {"ForEach", nil, false},
		{"ForEachAs", imp, false}, {"ForStep", nil, false}, {"FuncDefn", []operand{opFunc}, false}, {"FuncDefnSave", []operand{opFunc}, false},
		{"GetRec", nil, false}, {"GoSub", n, false}, {"GoTo", n, false}, {"If", nil, false},
		{"IfBlock", nil, false}, {"TypeOf", imp, false}, {"IfTypeBlock", imp, false}, {"Implements", w4, false},
		{"Input", nil, false}, {"InputDone", nil, false}, {"InputItem", nil, false}, {"Label", n, false},
		{"Let", nil, false}, {"Line", w, false}, {"LineCont", nil, true}, {"LineInput", nil, false},
		{"LineNum", n, false}, {"LitCy", w4, false}, {"LitDate", w4, false}, {"LitDefault", nil, false},
		{"LitDI2", w, false}, {"LitDI4", w2, false}, {"LitDI8", w4, false}, {"LitHI2", w, false},
		{"LitHI4", w2, false}, {"LitHI8", w4, false}, {"LitNothing", nil, false}, {"LitOI2", w, false},
		{"LitOI4", w2, false}, {"LitOI8", w4, false}, {"LitR4", w2, false}, {"LitR8", w4, false},
		{"LitSmallI2", nil, false}, {"LitStr", nil, true}, {"LitVarSpecial", nil, false}, {"Lock", nil, false},
		{"Loop", nil, false}, {"LoopUntil", nil, false}, {"LoopWhile", nil, false}, {"LSet", nil, false},
		{"Me", nil, false}, {"MeImplicit", nil, false}, {"MemRedim", redim, false}, {"MemRedimWith", redim, false},
		{"MemRedimAs", redim, false}, {"MemRedimAsWith", redim, false}, {"Mid", nil, false}, {"MidB", nil, false},
		{"Name", nil, false}, {"New", imp, false}, {"Next", nil, false}, {"NextVar", nil, false},
		{"OnError", n, false}, {"OnGosub", nil, true}, {"OnGoto", nil, true}, {"Open", w, false},
		{"Option", nil, false}, {"OptionBase", nil, false}, {"ParamByVal", nil, false}, {"ParamOmitted", nil, false},
		{"ParamNamed", n, false}, {"PrintChan", nil, false}, {"PrintComma", nil, false}, {"PrintEoS", nil, false},
		{"PrintItemComma", nil, false}, {"PrintItemNL", nil, false}, {"PrintItemSemi", nil, false}, {"PrintNL", nil, false},
		{"PrintObj", nil, false}, {"PrintSemi", nil, false}, {"PrintSpc", nil, false}, {"PrintTab", nil, false},
		{"PrintTabComma", nil, false}, {"PSet", w, false}, {"PutRec", nil, false}, {"QuoteRem", w, true},
		{"Redim", redim, false}, {"RedimAs", redim, false}, {"Reparse", nil, true}, {"Rem", nil, true},
		{"Resume", n, false}, {"Return", nil, false}, {"RSet", nil, false}, {"Scale", w, false},
		{"Seek", nil, false}, {"SelectCase", nil, false}, {"SelectIs", imp, false}, {"SelectType", nil, false},
		{"SetStmt", nil, false}, {"Stack", w2, false}, {"Stop", nil, false}, {"Type", []operand{opRecord}, false},
		{"Unlock", nil, false}, {"VarDefn", []operand{opVar}, false}, {"Wend", nil, false}, {"While", nil, false},
		{"With", nil, false}, {"WriteChan", nil, false}, {"ConstFuncExpr", nil, false}, {"LbConst", n, false},
		{"LbIf", nil, false}, {"LbElse", nil, false}, {"LbElseIf", nil, false}, {"LbEndIf", nil, false},
		{"LbMark", nil, false}, {"EndForVariable", nil, false}, {"StartForVariable", nil, false}, {"NewRedim", nil, false},
		{"StartWithExpr", nil, false}, {"SetOrSt", n, false}, {"EndEnum", nil, false}, {"Illegal", nil, false},
	}
	return t
}

// normalizeOpcode maps the opcode numbers of older VBA versions onto the
// VBA7 numbering used by opTable: later versions inserted opcodes, which
// shifted the ranges that follow them.
func normalizeOpcode(op int, vbaVer int, is64 bool) int {
	type shift struct{ lo, hi, add int }
	var shifts []shift
	switch {
	case vbaVer == 3:
		shifts = []shift{{0, 67, 0}, {68, 70, 2}, {71, 111, 4}, {112, 150, 8}, {151, 164, 9}, {165, 166, 10}, {167, 169, 11}, {170, 238, 12}, {239, 1023, 24}}
	case vbaVer == 5:
		shifts = []shift{{0, 68, 0}, {69, 71, 1}, {72, 112, 3}, {113, 151, 7}, {152, 165, 8}, {166, 167, 9}, {168, 170, 10}, {171, 1023, 11}}
	case !is64:
		shifts = []shift{{0, 173, 0}, {174, 175, 1}, {176, 178, 2}, {179, 1023, 3}}
	default:
		return op
	}
	for _, s := range shifts {
		if op >= s.lo && op <= s.hi {
			return op + s.add
		}
	}
	return op
}
