package emulation

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/runtime"
)

// wordDoc is the simulated body of the analysed document, shared by every
// ActiveDocument/ThisDocument reference so edits (Range.Delete, Range.Text =)
// are visible to later reads and to SaveAs. Positions are character offsets.
type wordDoc struct {
	text   []rune
	loaded bool
}

// SetDocumentText provides the extracted body text of the analysed document.
func (h *Host) SetDocumentText(text string) {
	h.doc = &wordDoc{text: []rune(text), loaded: true}
}

func (h *Host) document() *wordDoc {
	if h.doc == nil {
		h.doc = &wordDoc{}
	}
	return h.doc
}

// paragraph returns the [start,end) range of 1-based paragraph n, including
// its terminating "\r" as Word does.
func (d *wordDoc) paragraph(n int64) (int, int, bool) {
	if n < 1 {
		return 0, 0, false
	}
	start := 0
	for i := int64(1); ; i++ {
		end := start
		for end < len(d.text) && d.text[end] != '\r' {
			end++
		}
		if end < len(d.text) {
			end++ // include the paragraph mark
		}
		if i == n {
			return start, end, start < len(d.text) || (start == 0 && len(d.text) == 0)
		}
		if end >= len(d.text) {
			return 0, 0, false
		}
		start = end
	}
}

func (d *wordDoc) paragraphCount() int64 {
	if len(d.text) == 0 {
		return 1
	}
	n := int64(strings.Count(string(d.text), "\r"))
	if d.text[len(d.text)-1] != '\r' {
		n++
	}
	return n
}

func (d *wordDoc) clamp(start, end int) (int, int) {
	if start < 0 {
		start = 0
	}
	if end > len(d.text) {
		end = len(d.text)
	}
	if end < start {
		end = start
	}
	return start, end
}

// docRange is a Word Range over the shared document.
type docRange struct {
	h          *Host
	start, end int
}

func (h *Host) newRange(start, end int) runtime.Value {
	d := h.document()
	start, end = d.clamp(start, end)
	return runtime.VObject(&docRange{h: h, start: start, end: end})
}

func (o *docRange) TypeName() string { return "Range" }
func (o *docRange) Get(name string) runtime.Value {
	d := o.h.document()
	s, e := d.clamp(o.start, o.end)
	switch strings.ToLower(name) {
	case "text":
		if !d.loaded {
			return runtime.NewUnknown("document text not available")
		}
		return runtime.VString(string(d.text[s:e]))
	case "start":
		return runtime.VInt(int64(s))
	case "end":
		return runtime.VInt(int64(e))
	case "range":
		return runtime.VObject(o)
	case "paragraphs":
		return runtime.VObject(&paragraphs{h: o.h})
	}
	return runtime.NewUnknown("unsupported Range property " + name)
}
func (o *docRange) Set(name string, v runtime.Value) {
	if strings.EqualFold(name, "Text") {
		o.replace(v.CoerceString())
	}
}
func (o *docRange) replace(with string) {
	d := o.h.document()
	s, e := d.clamp(o.start, o.end)
	repl := []rune(with)
	d.text = append(append(append([]rune{}, d.text[:s]...), repl...), d.text[e:]...)
	o.h.rec("document_range_edit", nil, map[string]string{
		"start": strconv.Itoa(s), "end": strconv.Itoa(e),
		"removed_chars": strconv.Itoa(e - s), "inserted_chars": strconv.Itoa(len(repl)),
	})
	o.end = s + len(repl)
}
func (o *docRange) Call(name string, args []runtime.Value) runtime.Value {
	switch strings.ToLower(name) {
	case "delete", "cut":
		o.replace("")
		return runtime.VInt(1)
	case "inserttext":
		o.replace(argString(args, 0))
		return runtime.VEmpty
	case "insertafter":
		d := o.h.document()
		_, e := d.clamp(o.start, o.end)
		(&docRange{h: o.h, start: e, end: e}).replace(argString(args, 0))
		return runtime.VEmpty
	case "select", "copy", "collapse":
		return runtime.VEmpty
	}
	return runtime.NewUnknown("unsupported Range method " + name)
}

// paragraphs is the Paragraphs collection.
type paragraphs struct{ h *Host }

func (o *paragraphs) TypeName() string { return "Paragraphs" }
func (o *paragraphs) Get(name string) runtime.Value {
	if strings.EqualFold(name, "Count") {
		return runtime.VInt(o.h.document().paragraphCount())
	}
	return runtime.NewUnknown("unsupported Paragraphs property " + name)
}
func (o *paragraphs) Set(string, runtime.Value) {}
func (o *paragraphs) Call(name string, args []runtime.Value) runtime.Value {
	if strings.EqualFold(name, "Item") || name == "" {
		return o.h.paragraphValue(args)
	}
	return runtime.NewUnknown("unsupported Paragraphs method " + name)
}

func (h *Host) paragraphValue(args []runtime.Value) runtime.Value {
	n, ok := int64(0), false
	if len(args) > 0 {
		n, ok = args[0].CoerceInt()
	}
	if !ok {
		return runtime.NewUnknown("paragraph index unknown")
	}
	s, e, found := h.document().paragraph(n)
	if !found {
		return runtime.NewUnknown("paragraph " + strconv.FormatInt(n, 10) + " does not exist")
	}
	return runtime.VObject(&paragraph{r: &docRange{h: h, start: s, end: e}})
}

// paragraph is a single Paragraph; its text is reached through .Range.
type paragraph struct{ r *docRange }

func (o *paragraph) TypeName() string { return "Paragraph" }
func (o *paragraph) Get(name string) runtime.Value {
	if strings.EqualFold(name, "Range") {
		return runtime.VObject(o.r)
	}
	return o.r.Get(name)
}
func (o *paragraph) Set(name string, v runtime.Value) { o.r.Set(name, v) }
func (o *paragraph) Call(name string, args []runtime.Value) runtime.Value {
	return o.r.Call(name, args)
}

// documentObject is ActiveDocument/ThisDocument (and workbook aliases).
type documentObject struct {
	h    *Host
	name string
}

func (o *documentObject) TypeName() string { return o.name }
func (o *documentObject) Get(name string) runtime.Value {
	d := o.h.document()
	switch strings.ToLower(name) {
	case "name", "fullname", "path":
		return runtime.VString("")
	case "saved", "readonly":
		return runtime.VBool(false)
	case "content", "range":
		return o.h.newRange(0, len(d.text))
	case "paragraphs":
		return runtime.VObject(&paragraphs{h: o.h})
	case "sheets", "worksheets":
		return runtime.VObject(&sheetsCollection{h: o.h, onlyWorksheets: strings.EqualFold(name, "worksheets")})
	case "activesheet":
		return runtime.VObject(&sheetObject{h: o.h, s: o.h.workbook().active()})
	case "builtindocumentproperties":
		return runtime.VObject(&propCollection{h: o.h, kind: "builtin"})
	case "customdocumentproperties":
		return runtime.VObject(&propCollection{h: o.h, kind: "custom"})
	case "variables":
		return runtime.VObject(&propCollection{h: o.h, kind: "variable"})
	}
	return runtime.VEmpty
}
func (o *documentObject) Set(name string, v runtime.Value) {}
func (o *documentObject) Call(name string, args []runtime.Value) runtime.Value {
	return o.CallNamed(name, args, nil)
}

// CallNamed implements runtime.NamedCaller.
func (o *documentObject) CallNamed(name string, args []runtime.Value, names []string) runtime.Value {
	arg := func(pos int, named string) (runtime.Value, bool) {
		for i, n := range names {
			if strings.EqualFold(n, named) && i < len(args) {
				return args[i], true
			}
		}
		positional := 0
		for i := range args {
			if i < len(names) && names[i] != "" {
				continue
			}
			if positional == pos {
				return args[i], true
			}
			positional++
		}
		return runtime.Value{}, false
	}
	switch strings.ToLower(name) {
	case "range":
		d := o.h.document()
		start, end := int64(0), int64(len(d.text))
		if v, ok := arg(0, "Start"); ok {
			if n, ok := v.CoerceInt(); ok {
				start = n
			}
		}
		if v, ok := arg(1, "End"); ok {
			if n, ok := v.CoerceInt(); ok {
				end = n
			}
		}
		return o.h.newRange(int(start), int(end))
	case "paragraphs":
		return o.h.paragraphValue(args)
	case "sheets", "worksheets":
		if len(args) == 0 {
			return o.Get(name)
		}
		return o.h.lookupSheet(args[0], strings.EqualFold(name, "worksheets"))
	case "builtindocumentproperties", "customdocumentproperties", "variables":
		coll := o.Get(name)
		if len(args) == 0 {
			return coll
		}
		return coll.Obj.Call("", args)
	case "saveas", "saveas2":
		fileName, _ := arg(0, "FileName")
		format, hasFormat := arg(1, "FileFormat")
		path := fileName.CoerceString()
		extra := map[string]string{"api": "Document." + name}
		d := o.h.document()
		if d.loaded {
			// The saved file is the current body. Text formats write each
			// paragraph mark as CRLF; other formats are approximated by the
			// same text and flagged as such.
			content := strings.ReplaceAll(string(d.text), "\r", "\r\n")
			fmtNo, known := int64(-1), false
			if hasFormat {
				fmtNo, known = format.CoerceInt()
			}
			if !known || (fmtNo != 2 && fmtNo != 4 && fmtNo != 7) {
				extra["content_note"] = "document body as plain text (file format not modelled)"
			} else {
				extra["file_format"] = strconv.FormatInt(fmtNo, 10)
			}
			sum := sha256.Sum256([]byte(content))
			extra["content_hex"] = hex.EncodeToString([]byte(content))
			extra["content_sha256"] = hex.EncodeToString(sum[:])
		}
		o.h.Record(&runtime.Event{Type: "document_saveas", Raw: []string{path}, Resolved: []string{path}, Simulated: true, Extra: extra})
		return runtime.VEmpty
	case "close", "quit", "save":
		return runtime.VEmpty
	}
	return runtime.VUnknown
}

// wordConstants are the WdSaveFormat values macros pass by name.
var wordConstants = map[string]int64{
	"wdformatdocument": 0, "wdformattemplate": 1, "wdformattext": 2,
	"wdformattextlinebreaks": 3, "wdformatdostext": 4, "wdformatdostextlinebreaks": 5,
	"wdformatrtf": 6, "wdformatunicodetext": 7, "wdformathtml": 8,
	"wdformatwebarchive": 9, "wdformatfilteredhtml": 10, "wdformatxml": 11,
	"wdformatxmldocument": 12, "wdformatxmldocumentmacroenabled": 13,
	"wdformatdocumentdefault": 16, "wdformatpdf": 17,
}
