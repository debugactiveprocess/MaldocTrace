package payload

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// ClassifyFile names the kind of a file carried by a document (OLE
// package, OneNote attachment, email attachment) from its name and content:
// scripts and shortcuts that Windows runs on a double click, executables,
// documents. Script reports whether the content is script source whose text
// should be searched for commands and indicators.
func ClassifyFile(name string, b []byte) (kind string, script bool) {
	ext := strings.ToLower(name)
	if i := strings.LastIndex(ext, "."); i >= 0 {
		ext = ext[i:]
	} else {
		ext = ""
	}
	head := b
	if len(head) > 4096 {
		head = head[:4096]
	}
	low := strings.ToLower(string(head))
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		t, _ := describePE(b)
		return t, false
	case bytes.HasPrefix(b, []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0}):
		return "Windows shortcut (LNK)", false
	case bytes.HasPrefix(b, []byte("%PDF")):
		return "PDF document", false
	case bytes.HasPrefix(b, []byte{0xD0, 0xCF, 0x11, 0xE0}):
		return "OLE/CFB compound file", false
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		t, _ := describeZip(b)
		return t, false
	case bytes.HasPrefix(b, []byte(`{\rt`)):
		return "RTF document", false
	}
	if !looksText(head) {
		return "", false
	}
	switch {
	case ext == ".hta" || strings.Contains(low, "<hta:application"):
		return "HTML application (HTA) script", true
	case ext == ".wsf" || strings.Contains(low, "<job") && strings.Contains(low, "<script"):
		return "Windows Script File (WSF) script", true
	case ext == ".ps1" || ext == ".psm1":
		return "PowerShell script", true
	case ext == ".bat" || ext == ".cmd" || strings.HasPrefix(strings.TrimSpace(low), "@echo off"):
		return "batch script", true
	case ext == ".vbs" || ext == ".vbe":
		return "VBScript script", true
	case ext == ".js" || ext == ".jse":
		return "JScript script", true
	case ext == ".html" || ext == ".htm" || strings.Contains(low, "<script"):
		return "HTML with script", true
	case strings.Contains(low, "wscript.") || strings.Contains(low, "createobject("):
		return "VBScript/JScript script", true
	case strings.Contains(low, "powershell") || strings.Contains(low, "invoke-") || strings.Contains(low, "iex"):
		return "PowerShell or command script", true
	}
	return "text", false
}

// looksText reports mostly-printable UTF-8 or UTF-16 text.
func looksText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return true
	}
	if !utf8.Valid(b) && bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	bad := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0D && c < 0x20) {
			bad++
		}
	}
	return bad*20 < len(b)
}
