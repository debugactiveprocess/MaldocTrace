package pcode

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestOpTableSize(t *testing.T) {
	if len(opTable) != 264 || opTable[185].name != "LitStr" || opTable[263].name != "Illegal" {
		t.Fatalf("table has %d entries", len(opTable))
	}
}

func TestNormalizeOpcode(t *testing.T) {
	// 32-bit VBA7 p-code skips the opcodes that only 64-bit builds have.
	if normalizeOpcode(176, 7, false) != 178 || normalizeOpcode(176, 7, true) != 176 || normalizeOpcode(10, 6, false) != 10 {
		t.Fatal("bad mapping")
	}
}

// line helpers build instructions as Disassemble would.
func ins(op string, names ...string) Instr { return Instr{Op: op, Names: names} }
func insW(op string, w ...int) Instr       { return Instr{Op: op, Words: w} }
func lit(s string) Instr                   { return Instr{Op: "LitStr", Bytes: []byte(s)} }

func TestDecompileStatements(t *testing.T) {
	p := &Project{VBA: 7, Decode: latin1}
	sub := &FuncDecl{Name: "AutoOpen", Kind: "Sub"}
	m := &Module{Lines: []Line{
		{{Op: "FuncDefn", Func: sub}},
		{{Op: "Dim"}, {Op: "VarDefn", Var: &VarDecl{Name: "buf", Array: true, Type: "Byte"}, Words: []int{0}}},
		{insW("LitDI2", 0), insW("LitDI2", 10), {Op: "Dim"}, {Op: "VarDefn", Var: &VarDecl{Name: "fixed", Array: true, Type: "Byte"}, Words: []int{0}}},
		{{Op: "SetStmt"}, lit("WScript.Shell"), insW("ArgsLd", 1), {Op: "Set", Names: []string{"sh"}}},
		{lit("cmd /c "), lit(`calc "x"`), {Op: "Concat"}, ins("Ld", "sh"), {Op: "ArgsMemCall", Type: 16, Names: []string{"Run"}, Words: []int{1}}},
		{ins("Ld", "i"), insW("LitHI2", 0x2B), {Op: "Eq"}, {Op: "IfBlock"}},
		{{Op: "OnError", Type: 1}},
		{{Op: "EndIfBlock"}},
		{{Op: "StartForVariable"}, ins("Ld", "i"), {Op: "EndForVariable"}, insW("LitDI2", 1), insW("LitDI2", 3), {Op: "For"}},
		{insW("LitHI2", 0xFF), ins("Ld", "i"), {Op: "ArgsSt", Names: []string{"fixed"}, Words: []int{1}}},
		{{Op: "StartForVariable"}, ins("Ld", "i"), {Op: "EndForVariable"}, {Op: "NextVar"}},
		{{Op: "EndSub"}},
	}}
	// ArgsLd needs its name.
	m.Lines[3][2].Names = []string{"CreateObject"}
	got := Decompile(m, p)
	want := []string{
		"Sub AutoOpen()",
		"Dim buf() As Byte",
		"Dim fixed(0 To 10) As Byte",
		`Set sh = CreateObject("WScript.Shell")`,
		`sh.Run "cmd /c " & "calc ""x"""`,
		"If i = &H2B Then",
		"On Error Resume Next",
		"End If",
		"For i = 1 To 3",
		"fixed(i) = &HFF",
		"Next i",
		"End Sub",
	}
	lines := strings.Split(strings.TrimRight(got.Text, "\r\n"), "\r\n")
	if strings.Join(lines, "\n") != strings.Join(want, "\n") || got.Procedures != 1 || got.Unknown != 0 {
		t.Fatalf("got (%d procs, %d unknown):\n%s", got.Procedures, got.Unknown, got.Text)
	}
}

func TestDecompileDeclare(t *testing.T) {
	p := &Project{VBA: 7, Is64: true, Decode: latin1}
	decl := &FuncDecl{Name: "Alloc", Kind: "Function", Scope: "Private", Declare: true, PtrSafe: true, Lib: "ntdll",
		Alias: "ZwAllocateVirtualMemory", HasAs: true, Returns: "Long",
		Params: []Param{{Name: "h", ByVal: true, Type: "LongPtr"}, {Name: ""}}}
	got := Decompile(&Module{Lines: []Line{{{Op: "FuncDefn", Func: decl}}}}, p)
	want := `Private Declare PtrSafe Function Alloc Lib "ntdll" Alias "ZwAllocateVirtualMemory" (ByVal h As LongPtr) As Long`
	if strings.TrimSpace(got.Text) != want || got.Procedures != 0 {
		t.Fatalf("got %q (%d procs)", got.Text, got.Procedures)
	}
}

func TestUnknownInstructionIsComment(t *testing.T) {
	got := Decompile(&Module{Lines: []Line{{{Op: "Unknown"}}}}, &Project{VBA: 7, Decode: latin1})
	if got.Unknown != 1 || !strings.HasPrefix(got.Text, "' p-code not decompiled") {
		t.Fatalf("%+v", got)
	}
}

func TestParseProjectRejectsGarbage(t *testing.T) {
	if _, err := ParseProject([]byte("not a project"), false, nil); err == nil {
		t.Fatal("expected error")
	}
	b := make([]byte, 64)
	binary.LittleEndian.PutUint16(b, 0x61CC)
	binary.LittleEndian.PutUint16(b[2:], 0xB2)
	if p, _ := ParseProject(b, false, nil); p.VBA != 7 {
		t.Fatalf("version %d", p.VBA)
	}
}

func FuzzDisassemble(f *testing.F) {
	f.Add(make([]byte, 0x60), make([]byte, 0x40), false)
	hdr := make([]byte, 0x200)
	binary.LittleEndian.PutUint32(hdr[0x19:], 0x40)
	binary.LittleEndian.PutUint16(hdr[0x7C:], 0xCAFE)
	binary.LittleEndian.PutUint16(hdr[0x80:], 1)
	f.Add(hdr, []byte{0xCC, 0x61, 0xB2, 0}, true)
	f.Fuzz(func(t *testing.T, module, project []byte, is64 bool) {
		p, _ := ParseProject(project, is64, nil)
		if p.VBA < 6 {
			p.VBA = 7
		}
		if m, err := Disassemble(module, p); err == nil {
			Decompile(m, p)
		}
	})
}
