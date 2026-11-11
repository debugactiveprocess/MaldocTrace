package extractor

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// nestedFile is a nested OLE/CFB container found inside a ZIP archive.
type nestedFile struct {
	name string
	data []byte
}

// openZip scans a ZIP container and returns every entry whose content begins
// with the CFB magic (typically word/vbaProject.bin, but renamed variants are
// also accepted by content). Decompression-bomb protection is applied using
// the configured limits.
func openZip(data []byte, lim *Limits) ([]*nestedFile, []Diagnostic, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, Wrap("zip", err)
	}
	var files []*nestedFile
	var diags []Diagnostic
	if len(zr.File) > lim.MaxContainerEntries {
		diags = append(diags, Diagnostic{Severity: "warning", Stage: "zip", Message: fmt.Sprintf("archive has %d entries, limit %d", len(zr.File), lim.MaxContainerEntries)})
	}
	for i, f := range zr.File {
		if i >= lim.MaxContainerEntries {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Flags&0x1 != 0 {
			return nil, nil, Wrap("zip", ErrEncrypted)
		}
		if f.UncompressedSize64 > uint64(lim.MaxModuleSize) {
			diags = append(diags, Diagnostic{Severity: "info", Stage: "zip", Message: fmt.Sprintf("skipping large entry %s (%d bytes)", f.Name, f.UncompressedSize64)})
			continue
		}
		if f.CompressedSize64 > 0 && f.CompressedSize64*uint64(lim.MaxZipRatio) < f.UncompressedSize64 {
			diags = append(diags, Diagnostic{Severity: "warning", Stage: "zip", Message: fmt.Sprintf("skipping entry %s with suspicious compression ratio", f.Name)})
			continue
		}
		rc, err := f.Open()
		if err != nil {
			diags = append(diags, Diagnostic{Severity: "warning", Stage: "zip", Message: fmt.Sprintf("cannot open entry %s: %v", f.Name, err)})
			continue
		}
		head := make([]byte, 8)
		n, _ := io.ReadFull(rc, head)
		rc.Close()
		if n == 8 && bytes.Equal(head, cfbMagic) {
			rc2, err := f.Open()
			if err != nil {
				diags = append(diags, Diagnostic{Severity: "warning", Stage: "zip", Message: fmt.Sprintf("cannot open entry %s: %v", f.Name, err)})
				continue
			}
			body, err := io.ReadAll(io.LimitReader(rc2, lim.MaxModuleSize+1))
			rc2.Close()
			if err != nil {
				diags = append(diags, Diagnostic{Severity: "warning", Stage: "zip", Message: fmt.Sprintf("error reading %s: %v", f.Name, err)})
				continue
			}
			if int64(len(body)) > lim.MaxModuleSize {
				diags = append(diags, Diagnostic{Severity: "warning", Stage: "zip", Message: fmt.Sprintf("entry %s exceeds module size limit", f.Name)})
				continue
			}
			files = append(files, &nestedFile{name: f.Name, data: body})
		}
	}
	return files, diags, nil
}

// isVBAProjectName reports whether an archive entry name denotes a VBA project
// (used for the extract command's controlled naming).
func isVBAProjectName(name string) bool {
	n := strings.ToLower(name)
	base := n
	if i := strings.LastIndex(n, "/"); i >= 0 {
		base = n[i+1:]
	}
	return base == "vbaproject.bin"
}
