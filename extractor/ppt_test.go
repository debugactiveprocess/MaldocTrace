package extractor

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

func pptRecord(verInst, typ uint16, body []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, verInst)
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

// exOleObjStg wraps an OLE storage in a compressed ExOleObjStg record.
func exOleObjStg(storage []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(storage)
	w.Close()
	body := binary.LittleEndian.AppendUint32(nil, uint32(len(storage)))
	return pptRecord(0x0010, pptRecExOleObjStg, append(body, z.Bytes()...))
}

// A binary .ppt keeps its VBA project and its OLE objects in compressed
// ExOleObjStg records, nested in containers of the PowerPoint Document
// stream.
func TestPowerPointStorages(t *testing.T) {
	vba := cfbtest.BuildExact(cfbtest.VBAProject("", map[string]string{
		"Module1": "Attribute VB_Name = \"Module1\"\r\nSub Auto_Open()\r\n    Shell \"calc.exe\"\r\nEnd Sub\r\n",
	})...)
	obj := cfbtest.Build(
		cfbtest.Stream{Name: "\x01CompObj", Data: compObj("Package", "Package")},
		cfbtest.Stream{Name: "\x01Ole10Native", Data: ole10Native("run.vbs", `C:\run.vbs`, []byte("CreateObject(\"WScript.Shell\").Run \"calc\""))},
	)
	// Document container (0x03E8) > ExObjList (0x0409) > storages.
	list := pptRecord(0x000F, 0x0409, append(exOleObjStg(obj), pptRecord(0x0000, 0x0FF5, []byte{1, 2, 3, 4})...))
	doc := pptRecord(0x000F, 0x03E8, append(list, exOleObjStg(vba)...))
	ppt := cfbtest.Build(
		cfbtest.Stream{Name: "PowerPoint Document", Data: doc},
		cfbtest.Stream{Name: "Current User", Data: []byte{0}},
	)
	res, err := Extract(context.Background(), ppt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Modules) != 1 || !strings.Contains(res.Modules[0].Code, "calc.exe") ||
		!strings.HasPrefix(res.Modules[0].SourceFile, "PowerPoint Document/ExOleObjStg@") {
		t.Fatalf("modules %+v diags %+v", res.Modules, res.Diagnostics)
	}
	var pkg bool
	for _, e := range res.External {
		if e.Kind == "embedded_ole" && e.Severity == "high" && strings.Contains(e.Detail, "run.vbs") {
			pkg = true
		}
	}
	if !pkg || len(res.Embedded) == 0 {
		t.Fatalf("OLE package not reported: %+v %+v", res.External, res.Embedded)
	}
}

// A module present in the dir stream but missing from the PROJECT stream
// is hidden from the VBA editor yet still runs.
func TestHiddenModule(t *testing.T) {
	streams := cfbtest.VBAProject("Macros/", map[string]string{
		"Visible": "Attribute VB_Name = \"Visible\"\r\nSub A()\r\nEnd Sub\r\n",
		"Secret":  "Attribute VB_Name = \"Secret\"\r\nSub AutoOpen()\r\nEnd Sub\r\n",
	})
	for i, s := range streams {
		if s.Name == "Macros/PROJECT" {
			streams[i].Data = []byte("ID=\"{00000000-0000-0000-0000-000000000000}\"\r\nModule=Visible\r\nName=\"Project\"\r\n[Workspace]\r\nSecret=0, 0, 0, 0, C\r\n")
		}
	}
	res, err := Extract(context.Background(), cfbtest.BuildExact(append(streams, cfbtest.Stream{Name: "WordDocument", Data: make([]byte, 0x400)})...), nil)
	if err != nil {
		t.Fatal(err)
	}
	hidden := map[string]bool{}
	for _, m := range res.Modules {
		hidden[m.Name] = m.Hidden
	}
	if len(hidden) != 2 || !hidden["Secret"] || hidden["Visible"] {
		t.Fatalf("hidden = %v", hidden)
	}
}

func TestProjectStreamModules(t *testing.T) {
	got := projectStreamModules("ID=\"{1}\"\r\nDocument=ThisDocument/&H00000000\r\nModule=Mod1\r\nClass=Cls\r\nBaseClass=Form1\r\nName=\"P\"\r\n[Workspace]\r\nModule=NotAModule\r\n")
	for _, w := range []string{"thisdocument", "mod1", "cls", "form1"} {
		if !got[w] {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if got["notamodule"] || len(got) != 4 {
		t.Errorf("got %v", got)
	}
}

func TestStorageTimes(t *testing.T) {
	// 2026-01-26 12:00:00 UTC as a FILETIME.
	want := time.Date(2026, 1, 26, 12, 0, 0, 0, time.UTC)
	ft := uint64(want.UnixNano()/100) + 116444736000000000
	doc := cfbtest.SetRootTimes(cfbtest.Build(cfbtest.Stream{Name: "WordDocument", Data: make([]byte, 0x400)}), ft, ft+10_000_000)
	res, _ := Extract(context.Background(), doc, nil)
	if len(res.StorageTimes) != 1 || res.StorageTimes[0].Path != "Root Entry" || !res.StorageTimes[0].Created.Equal(want) ||
		!res.StorageTimes[0].Modified.Equal(want.Add(time.Second)) {
		t.Fatalf("times %+v", res.StorageTimes)
	}
	if !filetime(1).IsZero() || !filetime(0xFFFFFFFFFFFFFFFF).IsZero() {
		t.Fatal("implausible FILETIMEs must be ignored")
	}
}

func FuzzPowerPoint(f *testing.F) {
	f.Add(pptRecord(0x000F, 0x03E8, exOleObjStg([]byte("not a cfb"))))
	f.Add(pptRecord(0x0010, pptRecExOleObjStg, []byte{0xFF, 0xFF, 0xFF, 0x7F, 0x78, 0x9C}))
	f.Fuzz(func(t *testing.T, stream []byte) {
		lim := DefaultLimits()
		pptStorages(stream, &lim, &Result{})
	})
}
