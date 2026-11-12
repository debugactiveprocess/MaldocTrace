package payload

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
)

// describeZip identifies ZIP-based files: Java archives (main class, class
// count, packages), OOXML packages and plain archives (entry list). Entry
// contents other than the JAR manifest are not read.
func describeZip(b []byte) (string, []string) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return "ZIP archive (unreadable: " + err.Error() + ")", nil
	}
	var names []string
	classes := 0
	pkgs := map[string]int{}
	var manifest *zip.File
	for _, f := range zr.File {
		names = append(names, f.Name)
		switch {
		case strings.EqualFold(f.Name, "META-INF/MANIFEST.MF"):
			manifest = f
		case strings.HasSuffix(f.Name, ".class"):
			classes++
			if i := strings.LastIndex(f.Name, "/"); i > 0 {
				pkgs[strings.ReplaceAll(f.Name[:i], "/", ".")]++
			} else {
				pkgs["(default package)"]++
			}
		}
	}
	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	switch {
	case manifest != nil || classes > 0:
		facts := []string{fmt.Sprintf("entries=%d, classes=%d", len(names), classes)}
		if manifest != nil {
			for _, kv := range readManifest(manifest) {
				facts = append(facts, kv)
			}
		}
		if len(pkgs) > 0 {
			type pc struct {
				name string
				n    int
			}
			var list []pc
			for k, v := range pkgs {
				list = append(list, pc{k, v})
			}
			sort.Slice(list, func(i, j int) bool {
				return list[i].n > list[j].n || list[i].n == list[j].n && list[i].name < list[j].name
			})
			var top []string
			for i, p := range list {
				if i == 8 {
					top = append(top, fmt.Sprintf("... %d more", len(list)-i))
					break
				}
				top = append(top, fmt.Sprintf("%s (%d)", p.name, p.n))
			}
			facts = append(facts, "packages="+strings.Join(top, ", "))
		}
		return "Java archive (JAR)", facts
	case has("[Content_Types].xml"):
		return "OOXML package (ZIP)", []string{fmt.Sprintf("entries=%d", len(names))}
	}
	shown := names
	if len(shown) > 10 {
		shown = append(append([]string{}, shown[:10]...), fmt.Sprintf("... %d more", len(names)-10))
	}
	return "ZIP archive", []string{"entries=" + strings.Join(shown, ", ")}
}

// readManifest returns the interesting attributes of a JAR manifest.
func readManifest(f *zip.File) []string {
	if f.UncompressedSize64 > 1<<16 {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	var out []string
	sc := bufio.NewScanner(io.LimitReader(rc, 1<<16))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "main-class", "launcher-agent-class", "premain-class", "agent-class", "created-by", "class-path":
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, strings.TrimSpace(k)+"="+v)
			}
		}
	}
	return out
}
