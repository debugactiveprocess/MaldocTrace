package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

// dumpEntry describes one file written by --dump-payloads.
type dumpEntry struct {
	File        string   `json:"file"`
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Category    string   `json:"category,omitempty"`
	FileType    string   `json:"file_type,omitempty"`
	Status      string   `json:"status,omitempty"`
	OriginPath  string   `json:"origin_path,omitempty"` // path the macro wrote (artifacts)
	DerivedFrom string   `json:"derived_from,omitempty"`
	ReportSHA   string   `json:"report_sha256,omitempty"` // as listed in the report
	FileSHA256  string   `json:"file_sha256"`             // of the bytes written here
	Size        int      `json:"size"`
	Details     []string `json:"details,omitempty"`
	Note        string   `json:"note,omitempty"`
}

type dumpManifest struct {
	Input     string      `json:"input"`
	SHA256    string      `json:"input_sha256"`
	Warning   string      `json:"warning"`
	Generated []dumpEntry `json:"files"`
}

const dumpWarning = "Files may be live malware. They are written with a neutral .bin/.txt extension and must only be handled in an isolated analysis environment."

// dumpTree dumps a report and the reports of the files found inside it.
func dumpTree(r *report.Report, dir string) ([]string, error) {
	written, err := dumpPayloads(r, dir)
	for _, c := range r.Children {
		if c.Report == nil {
			continue
		}
		w, cerr := dumpTree(c.Report, dir)
		written = append(written, w...)
		if err == nil {
			err = cerr
		}
	}
	return written, err
}

// dumpPayloads writes every decoded payload and reconstructed artifact of a
// report to <dir>/<input sha256>/ together with manifest.json. Extensions are
// neutral (.bin, or .txt for scripts) so nothing is executable by
// double-click. Existing files are never overwritten.
func dumpPayloads(r *report.Report, dir string) ([]string, error) {
	sub := filepath.Join(dir, r.File.SHA256)
	m := dumpManifest{Input: r.File.Path, SHA256: r.File.SHA256, Warning: dumpWarning}
	type item struct {
		name string
		data []byte
		e    dumpEntry
	}
	var items []item
	for _, p := range r.DecodedPayloads {
		if len(p.Raw) == 0 {
			continue
		}
		ext := ".bin"
		if p.Category == "script" || p.Category == "encoded_command" {
			ext = ".txt"
		}
		items = append(items, item{p.ID + ext, p.Raw, dumpEntry{
			ID: p.ID, Kind: p.Kind, Category: p.Category, FileType: p.FileType, Status: p.Status,
			DerivedFrom: p.DerivedFrom, ReportSHA: p.SHA256, Details: p.Details,
		}})
	}
	for i, a := range r.Artifacts {
		if len(a.Raw) == 0 {
			continue
		}
		id := fmt.Sprintf("artifact-%d", i+1)
		items = append(items, item{id + ".bin", a.Raw, dumpEntry{
			ID: id, Kind: "file written by the macro", OriginPath: a.Path, ReportSHA: a.SHA256,
		}})
	}
	if len(items) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return nil, err
	}
	paths := []string{filepath.Join(sub, "manifest.json")}
	for _, it := range items {
		paths = append(paths, filepath.Join(sub, it.name))
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return nil, fmt.Errorf("refusing to overwrite %s", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	var written []string
	for _, it := range items {
		dest := filepath.Join(sub, it.name)
		if err := writeNew(dest, it.data); err != nil {
			return written, err
		}
		sum := sha256.Sum256(it.data)
		it.e.File, it.e.FileSHA256, it.e.Size = it.name, hex.EncodeToString(sum[:]), len(it.data)
		if it.e.ReportSHA != "" && it.e.ReportSHA != it.e.FileSHA256 {
			if it.e.Category == "encoded_command" {
				it.e.Note = "report_sha256 covers the decoded UTF-16LE bytes; this file is the same script as UTF-8 text"
			} else {
				it.e.Note = "file content differs from the bytes hashed in the report"
			}
		}
		m.Generated = append(m.Generated, it.e)
		written = append(written, dest)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return written, err
	}
	dest := filepath.Join(sub, "manifest.json")
	if err := writeNew(dest, append(b, '\n')); err != nil {
		return written, err
	}
	return append(written, dest), nil
}

// writeNew creates a file that must not already exist.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
