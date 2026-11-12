package extractor

import (
	"archive/zip"
	"bytes"
	"path"
	"sort"
	"strconv"
	"strings"
)

// EmbeddedFile is a file carried inside the analysed document: the payload
// of an OLE object (OLE Package data, an OOXML package, a PDF...) or an
// embedded document. The caller describes it and, for supported formats,
// analyses it recursively.
type EmbeddedFile struct {
	// Name is a short file name (package label or part name).
	Name string
	// Location is where it was found ("MBD002FAFC9/Package",
	// "word/embeddings/oleObject1.bin").
	Location string
	// Class is the OLE class or ProgID of the object that held it.
	Class string
	Data  []byte
	// HasVBA is set when the VBA of this file was already extracted into
	// the parent result (OOXML embeddings that are OLE documents).
	HasVBA bool
}

// maxEmbedded caps the embedded files collected from one document.
const maxEmbedded = 64

func (r *Result) addEmbedded(e EmbeddedFile) {
	if len(e.Data) == 0 {
		return
	}
	for _, x := range r.Embedded {
		if x.Location == e.Location {
			return
		}
	}
	if len(r.Embedded) >= maxEmbedded {
		r.addDiag("warning", "embedded", "too many embedded objects; the rest were not analysed")
		r.LimitsHit = append(r.LimitsHit, "MaxEmbedded")
		return
	}
	r.Embedded = append(r.Embedded, e)
}

// embedOLEObject records the file an OLE object carries.
func embedOLEObject(o *OLEObject, res *Result) {
	if len(o.Contents) == 0 {
		return
	}
	name := o.ContentsStream
	if p := o.Package; p != nil && o.ContentsStream == nameOle10Nat {
		name = firstNonEmpty(p.Label, baseName(p.Path), "package")
	}
	res.addEmbedded(EmbeddedFile{Name: name, Location: o.Location + "/" + printableName(o.ContentsStream), Class: o.Class(), Data: o.Contents})
}

// printableName renders a stream name with its control-character prefix
// (\x01Ole10Native) as text.
func printableName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 {
			b.WriteString("\\x0")
			b.WriteByte("0123456789abcdef"[r&15])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// scanOLEStorages inspects every storage of a CFB container that holds an
// OLE object (Word ObjectPool/_<id>, Excel MBD<id>, PowerPoint and other
// hosts), reports it and records the file it carries.
func scanOLEStorages(cfb *cfbReader, res *Result) int {
	n := 0
	for _, prefix := range oleStoragePrefixes(cfb, "") {
		// UserForm storages of the VBA project also carry \x01CompObj; they
		// are read as forms, not as embedded objects.
		if prefix == "" || strings.Contains(prefix, "VBA/") || strings.HasPrefix(prefix, "Macros/") ||
			strings.HasPrefix(prefix, "_VBA_PROJECT_CUR/") || strings.HasPrefix(prefix, "_VBA_PROJECT/") {
			continue
		}
		o := readOLEObject(cfb, prefix, strings.TrimSuffix(prefix, "/"))
		reportOLEObject(o, res)
		embedOLEObject(o, res)
		n++
	}
	return n
}

// scanOOXMLEmbedding handles one part of an OOXML embeddings folder: OLE
// objects (oleObject*.bin) are inspected like any OLE storage, other parts
// (embedded workbooks, documents, packages) are recorded as files.
func scanOOXMLEmbedding(name string, data []byte, lim *Limits, res *Result) {
	if !bytes.HasPrefix(data, cfbMagic) {
		res.addEmbedded(EmbeddedFile{Name: path.Base(name), Location: name, Data: data})
		return
	}
	cfb, err := parseCFB(data, lim)
	if err != nil {
		res.addDiag("info", "embedded", name+": "+err.Error())
		return
	}
	if cfb.find("WordDocument") != nil || cfb.find("Workbook") != nil || cfb.find("Book") != nil || cfb.find("PowerPoint Document") != nil {
		// A whole OLE document: its VBA was extracted with the parent by
		// openZip, the rest is analysed as a child.
		res.addEmbedded(EmbeddedFile{Name: path.Base(name), Location: name, Data: data, HasVBA: len(cfb.storageByLeafName("VBA")) > 0})
		return
	}
	o := readOLEObject(cfb, "", name)
	reportOLEObject(o, res)
	embedOLEObject(o, res)
	for _, prefix := range oleStoragePrefixes(cfb, "") {
		if prefix != "" {
			inner := readOLEObject(cfb, prefix, name+"/"+strings.TrimSuffix(prefix, "/"))
			reportOLEObject(inner, res)
			embedOLEObject(inner, res)
		}
	}
}

func isEmbeddingPart(name string) bool {
	return (strings.HasPrefix(name, "word/embeddings/") || strings.HasPrefix(name, "xl/embeddings/") ||
		strings.HasPrefix(name, "ppt/embeddings/")) && !strings.HasSuffix(name, "/")
}

// scanOOXMLEmbeddings walks the embeddings folders of an OOXML package.
func scanOOXMLEmbeddings(parts map[string]*zip.File, lim *Limits, res *Result) {
	var names []string
	for name := range parts {
		if isEmbeddingPart(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	n := 0
	for _, name := range names {
		f := parts[name]
		b, err := zipPart(f, lim)
		if err != nil {
			res.addDiag("info", "embedded", err.Error())
			continue
		}
		scanOOXMLEmbedding(f.Name, b, lim, res)
		n++
	}
	res.addCheck("OOXML embedded objects (" + strconv.Itoa(n) + ")")
}
