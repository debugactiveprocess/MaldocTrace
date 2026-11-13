package extractor

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

// rtfShellExplorer builds an RTF whose \objdata holds an OLE1 embedded
// object of the given class name whose native data is a CFB with the
// Shell.Explorer.1 root CLSID and a CONTENTS stream holding url (UTF-16).
func rtfShellExplorer(class, url string) string {
	contents := make([]byte, 0xB6)
	for _, c := range utf16.Encode([]rune(url)) {
		contents = binary.LittleEndian.AppendUint16(contents, c)
	}
	contents = append(contents, 0, 0)
	clsid := [16]byte{0xC3, 0x2A, 0xB2, 0xEA, 0xC1, 0x30, 0xCF, 0x11, 0xA7, 0xEB, 0x00, 0x00, 0xC0, 0x5B, 0xAE, 0x0B}
	native := cfbtest.SetRootCLSID(cfbtest.Build(cfbtest.Stream{Name: "CONTENTS", Data: contents}), clsid)
	var obj []byte
	u32 := func(v uint32) { obj = binary.LittleEndian.AppendUint32(obj, v) }
	u32(0x0501)
	u32(2)
	u32(uint32(len(class) + 1))
	obj = append(append(obj, class...), 0)
	u32(0)
	u32(0)
	u32(uint32(len(native)))
	obj = append(obj, native...)
	return `{\rtf1{\object\objemb\objw1\objh1{\*\objclass}{\*\objdata ` + hexString(obj) + `}}}`
}

func TestRTFShellExplorerObject(t *testing.T) {
	const url = `\\files.example.invalid@SSL\DavWWWRoot\doc.pdf.lnk`
	for name, class := range map[string]string{"named": "Shell.Explorer.1", "clsid only": "", "decoy name": "Paint.Picture"} {
		t.Run(name, func(t *testing.T) {
			res, _ := Extract(context.Background(), []byte(rtfShellExplorer(class, url)), nil)
			var browser, obj bool
			for _, e := range res.External {
				switch e.Kind {
				case "browser_object_url":
					browser = e.Target == url && e.Severity == "high" && strings.Contains(e.Detail, "CVE-2026-21509") &&
						strings.Contains(e.Detail, "NTLM")
				case "embedded_ole":
					obj = e.Severity == "high" && strings.Contains(e.Detail, "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}")
				case "embedded_url":
					if e.Target == url {
						t.Errorf("URL reported twice: %+v", e)
					}
				}
			}
			if !browser || !obj {
				t.Fatalf("external %+v", res.External)
			}
		})
	}
}

func TestFormatCLSID(t *testing.T) {
	c := [16]byte{0xC3, 0x2A, 0xB2, 0xEA, 0xC1, 0x30, 0xCF, 0x11, 0xA7, 0xEB, 0x00, 0x00, 0xC0, 0x5B, 0xAE, 0x0B}
	if got := formatCLSID(c); got != "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}" || oleClassCLSIDs[got] != "Shell.Explorer.1" {
		t.Fatalf("got %q", got)
	}
	if formatCLSID([16]byte{}) != "" {
		t.Fatal("zero CLSID should format as empty")
	}
}
