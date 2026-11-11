package extractor

import (
	"context"
	"fmt"
	"strings"
)

// Diagnostic is a non-fatal observation produced during extraction or later
// analysis. Severity is one of "info", "warning", "error".
type Diagnostic struct {
	Severity string `json:"severity"`
	Stage    string `json:"stage"`
	Message  string `json:"message"`
}

// Module is a single extracted VBA module.
type Module struct {
	Name       string     `json:"name"`
	StreamName string     `json:"stream_name,omitempty"`
	FileName   string     `json:"file_name"`
	Type       ModuleType `json:"-"`
	TypeName   string     `json:"type"`
	Codepage   uint16     `json:"codepage"`
	TextOffset uint32     `json:"text_offset,omitempty"`
	CodeRaw    []byte     `json:"-"`
	Code       string     `json:"code"`
	SourceFile string     `json:"source_file,omitempty"`
}

// Project is a VBA project found in a container.
type Project struct {
	Name       string `json:"name"`
	DirStream  string `json:"dir_stream"`
	SourceFile string `json:"source_file,omitempty"`
	Codepage   uint16 `json:"codepage"`
	SysKind    uint32 `json:"sys_kind"`
	LCID       uint32 `json:"lcid"`
}

// Result is the outcome of extraction. Modules and Projects are populated even
// when a later pipeline stage fails, so earlier evidence is never lost.
type Result struct {
	Forms       []FormControl `json:"forms,omitempty"`
	Format      Format        `json:"format"`
	Encrypted   bool          `json:"encrypted"`
	Projects    []*Project    `json:"projects,omitempty"`
	Modules     []*Module     `json:"modules,omitempty"`
	Diagnostics []Diagnostic  `json:"diagnostics,omitempty"`
	LimitsHit   []string      `json:"limits_hit,omitempty"`
	// DocumentText is the main-story body text of a Word document (paragraphs
	// end with "\r"); empty when the input is not a Word document.
	DocumentText string `json:"-"`
}

// HasModules reports whether any module source was extracted.
func (r *Result) HasModules() bool { return len(r.Modules) > 0 }

func (r *Result) addDiag(sev, stage, msg string) {
	r.Diagnostics = append(r.Diagnostics, Diagnostic{Severity: sev, Stage: stage, Message: msg})
}

// Extract runs the full extraction pipeline over a single input. ctx is used
// for cancellation; lim bounds resource usage. It returns a Result even when a
// step fails, so earlier evidence is preserved.
func Extract(ctx context.Context, data []byte, lim *Limits) (*Result, error) {
	l := DefaultLimits()
	if lim != nil {
		l = *lim
	}
	res := &Result{Format: Detect(data)}
	if int64(len(data)) > l.MaxInputSize {
		res.addDiag("error", "extract", "input exceeds MaxInputSize")
		res.LimitsHit = append(res.LimitsHit, "MaxInputSize")
		return res, Wrap("extract", ErrLimitExceeded)
	}

	switch res.Format {
	case FormatCFB:
		if err := extractFromCFB(ctx, data, "", &l, res); err != nil {
			return res, err
		}
	case FormatOOXML:
		if text, err := ooxmlDocumentText(data, &l); err != nil {
			res.addDiag("info", "doctext", "document text not extracted: "+err.Error())
		} else if text != "" {
			res.DocumentText = text
		}
		files, diags, err := openZip(data, &l)
		res.Diagnostics = append(res.Diagnostics, diags...)
		if err != nil {
			return res, err
		}
		for _, nf := range files {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			if err := extractFromCFB(ctx, nf.data, nf.name, &l, res); err != nil {
				res.addDiag("error", "extract", fmt.Sprintf("nested OLE %s: %v", nf.name, err))
			}
		}
	case FormatVBA:
		code := string(data)
		res.Modules = append(res.Modules, &Module{
			Name:     "Module1",
			FileName: "Module1.bas",
			Type:     ModuleTypeProcedural,
			TypeName: "procedural",
			Codepage: 65001,
			Code:     code,
			CodeRaw:  data,
		})
	default:
		res.addDiag("info", "extract", "unrecognised input format; no VBA extracted")
	}
	return res, nil
}

// extractFromCFB parses a CFB container and extracts any VBA projects it
// contains. sourceFile names the nested container (empty for the top level).
func extractFromCFB(ctx context.Context, data []byte, sourceFile string, lim *Limits, res *Result) error {
	cfb, err := parseCFB(data, lim)
	if err != nil {
		return err
	}
	if cfb.find("EncryptionInfo") != nil || cfb.find("EncryptedSummary") != nil {
		res.Encrypted = true
		res.addDiag("info", "extract", "container is encrypted (EncryptionInfo stream present)")
		return Wrap("extract", ErrEncrypted)
	}
	if sourceFile == "" && cfb.find("WordDocument") != nil {
		if text, err := wordBinaryText(cfb); err != nil {
			res.addDiag("info", "doctext", "document text not extracted: "+err.Error())
		} else {
			res.DocumentText = text
		}
	}
	storages := cfb.storageByLeafName("VBA")
	extractForms(cfb, sourceFile, res)
	if len(storages) == 0 {
		if dir := cfb.find("VBA/dir"); dir != nil {
			storages = append(storages, &cfbEntry{name: "VBA", objType: 1, path: "VBA"})
		} else if dir := cfb.find("dir"); dir != nil {
			storages = append(storages, &cfbEntry{name: "VBA", objType: 1, path: ""})
		}
	}
	if len(storages) == 0 {
		res.addDiag("info", "extract", "no VBA storage found in container")
		return nil
	}
	for _, s := range storages {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		vbaRoot := parentPath(s.path)
		extractVBAProject(ctx, cfb, vbaRoot, sourceFile, lim, res)
	}
	return nil
}

// parentPath returns the parent directory path of a storage path ("" for a
// top-level storage), with a trailing slash when non-empty.
func parentPath(p string) string {
	if p == "" || !strings.Contains(p, "/") {
		return ""
	}
	return p[:strings.LastIndex(p, "/")+1]
}

// extractVBAProject extracts one VBA project rooted at vbaRoot.
func extractVBAProject(ctx context.Context, cfb *cfbReader, vbaRoot, sourceFile string, lim *Limits, res *Result) {
	dirPath := vbaRoot + "VBA/dir"
	dirCompressed, err := cfb.readStream(dirPath)
	if err != nil {
		res.addDiag("warning", "extract", fmt.Sprintf("cannot read dir stream %q: %v", dirPath, err))
		return
	}
	dirData, err := decompressOVBA(dirCompressed, lim.MaxDecompressed)
	if err != nil {
		res.addDiag("warning", "extract", fmt.Sprintf("cannot decompress dir stream %q: %v", dirPath, err))
		return
	}
	proj, err := parseDir(dirData)
	if err != nil {
		res.addDiag("warning", "extract", fmt.Sprintf("cannot parse dir stream %q: %v", dirPath, err))
		return
	}
	p := &Project{
		Name:       proj.name,
		DirStream:  dirPath,
		SourceFile: sourceFile,
		Codepage:   proj.codepage,
		SysKind:    proj.sysKind,
		LCID:       proj.lcid,
	}
	res.Projects = append(res.Projects, p)

	for i := range proj.modules {
		if ctx.Err() != nil {
			return
		}
		rm := &proj.modules[i]
		codeRaw, code, ok := readModuleSource(cfb, vbaRoot, rm, proj.codepage, lim, res)
		if !ok {
			continue
		}
		m := &Module{
			Name:       firstNonEmpty(rm.nameUni, rm.name, "Module"),
			StreamName: firstNonEmpty(rm.streamNameUni, rm.streamName),
			Type:       rm.typ,
			TypeName:   moduleTypeName(rm.typ),
			Codepage:   proj.codepage,
			TextOffset: rm.textOffset,
			CodeRaw:    codeRaw,
			Code:       code,
			SourceFile: sourceFile,
		}
		m.FileName = m.Name + moduleExt(rm.typ)
		res.Modules = append(res.Modules, m)
	}
}

// readModuleSource locates and decompresses a module source stream.
func readModuleSource(cfb *cfbReader, vbaRoot string, rm *rawModule, cp uint16, lim *Limits, res *Result) ([]byte, string, bool) {
	names := []string{rm.streamNameUni, rm.streamName, rm.nameUni, rm.name}
	var streamBytes []byte
	for _, n := range names {
		if n == "" || n == "None" {
			continue
		}
		if b, err := cfb.readStream(vbaRoot + "VBA/" + n); err == nil {
			streamBytes = b
			break
		}
	}
	if streamBytes == nil {
		leaf := firstNonEmpty(rm.streamNameUni, rm.streamName, rm.nameUni, rm.name)
		for _, path := range cfb.listStreams() {
			if strings.Contains(path, "VBA/") && strings.EqualFold(leafName(path), leaf) {
				if b, err := cfb.readStream(path); err == nil {
					streamBytes = b
					break
				}
			}
		}
	}
	if streamBytes == nil {
		res.addDiag("warning", "extract", fmt.Sprintf("module %q source stream not found", rm.name))
		return nil, "", false
	}
	off := int(rm.textOffset)
	if off < 0 || off > len(streamBytes) {
		off = 0
	}
	codeRaw, err := decompressOVBA(streamBytes[off:], lim.MaxDecompressed)
	if err != nil {
		res.addDiag("warning", "extract", fmt.Sprintf("module %q decompression failed: %v", rm.name, err))
		return nil, "", false
	}
	if int64(len(codeRaw)) > lim.MaxModuleSize {
		res.addDiag("warning", "extract", fmt.Sprintf("module %q exceeds MaxModuleSize", rm.name))
		res.LimitsHit = append(res.LimitsHit, "MaxModuleSize")
		return nil, "", false
	}
	return codeRaw, decodeCodepage(cp, codeRaw), true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func moduleTypeName(t ModuleType) string {
	if t == ModuleTypeDocumentClassDesigner {
		return "document/class/designer"
	}
	return "procedural"
}

func moduleExt(t ModuleType) string {
	if t == ModuleTypeDocumentClassDesigner {
		return ".cls"
	}
	return ".bas"
}
