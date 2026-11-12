package extractor

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// OneNote sections (.one, [MS-ONESTORE]) became a dropper format once Office
// blocked internet macros: a lure picture over an embedded HTA, batch file,
// script, shortcut or executable that runs on a double click. Embedded
// files live in FileDataStoreObject structures: a GUID header, the length,
// the data and a GUID footer. Their names are kept in separate property
// sets and are not recovered here; files are classified by content.

var (
	// {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}: .one file format
	oneNoteMagic = []byte{0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3}
	// {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}: FileDataStoreObject header
	oneNoteFileData = []byte{0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC}
)

const maxOneNoteFiles = 128

// OneNoteFile is a file embedded in a OneNote section.
type OneNoteFile struct {
	Offset int
	Data   []byte
}

// IsOneNote reports a OneNote section file.
func IsOneNote(data []byte) bool { return bytes.HasPrefix(data, oneNoteMagic) }

// OneNoteFiles returns the embedded files of a OneNote section.
func OneNoteFiles(data []byte) ([]OneNoteFile, []Diagnostic) {
	var out []OneNoteFile
	var diags []Diagnostic
	for from := 0; from < len(data); {
		i := bytes.Index(data[from:], oneNoteFileData)
		if i < 0 {
			break
		}
		p := from + i
		from = p + len(oneNoteFileData)
		// guidHeader (16), cbLength (8), unused (4), reserved (8), data.
		if p+36 > len(data) {
			break
		}
		n := binary.LittleEndian.Uint64(data[p+16:])
		start := p + 36
		if n == 0 || n > uint64(len(data)-start) {
			diags = append(diags, Diagnostic{Severity: "info", Stage: "onenote", Message: fmt.Sprintf("FileDataStoreObject at offset %d declares %d bytes past the end of the file", p, n)})
			continue
		}
		if len(out) >= maxOneNoteFiles {
			diags = append(diags, Diagnostic{Severity: "warning", Stage: "onenote", Message: fmt.Sprintf("more than %d embedded files; the rest were not read", maxOneNoteFiles)})
			break
		}
		out = append(out, OneNoteFile{Offset: p, Data: data[start : start+int(n)]})
		from = start + int(n)
	}
	return out, diags
}
