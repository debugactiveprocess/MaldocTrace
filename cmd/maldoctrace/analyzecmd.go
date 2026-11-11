package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"maldoctrace"
	"maldoctrace/report"
	varuntime "maldoctrace/vba/runtime"
)

func runAnalyze(args []string) error {
	fs := flagSet("analyze")
	format := fs.String("format", "text", "output format: json, text, jsonl")
	recursive := fs.Bool("recursive", false, "recurse into directories")
	workers := fs.Int("workers", goruntime.NumCPU(), "parallel worker count")
	timeout := fs.Duration("timeout", 120*time.Second, "per-file analysis timeout")
	maxSteps := fs.Int("max-steps", 1_000_000, "interpreter step budget per module")
	inputFormat := fs.String("input-format", "", "force input format (vba)")
	showStrings := fs.Bool("show-strings", false, "text format: list reconstructed strings (deduplicated, with provenance)")
	dumpDir := fs.String("dump-payloads", "", "write decoded payloads and dropped files to `dir`/<sha256>/ (neutral extensions, with manifest.json)")
	if _, err := parse(fs, args); err != nil {
		if err == flag.ErrHelp {
			return err
		}
		return usagef("%v", err)
	}
	if fs.NArg() != 1 {
		return usagef("analyze requires a file or directory")
	}
	if *workers <= 0 || *timeout <= 0 || *maxSteps <= 0 {
		return usagef("--workers, --timeout, and --max-steps must be positive")
	}
	if *showStrings && *format != "text" {
		return usagef("--show-strings applies to --format text (JSON always includes decoded_strings)")
	}
	if *inputFormat != "" && *inputFormat != "vba" {
		return usagef("unknown --input-format %q", *inputFormat)
	}
	if *dumpDir != "" && fs.NArg() == 1 && *recursive {
		if inside, err := isWithin(*dumpDir, fs.Arg(0)); err == nil && inside {
			return usagef("--dump-payloads directory must not be inside the analysed directory")
		}
	}
	var dumpMu sync.Mutex
	dumpFailed := false
	post := func(r *report.Report) {
		if *dumpDir == "" {
			return
		}
		written, err := dumpPayloads(r, *dumpDir)
		dumpMu.Lock()
		defer dumpMu.Unlock()
		for _, w := range written {
			fmt.Fprintf(os.Stderr, "dumped %s\n", w)
		}
		if err != nil {
			dumpFailed = true
			fmt.Fprintf(os.Stderr, "error dumping payloads of %s: %v\n", r.File.Path, err)
		}
	}
	opts := maldoctrace.Options{
		Timeout:       *timeout,
		RuntimeLimits: varuntime.Limits{MaxSteps: *maxSteps, MaxLoopIterations: 100_000, MaxCallDepth: 200},
	}
	var files []string
	root := fs.Arg(0)
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !*recursive {
			return usagef("directory requires --recursive")
		}
		if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			files = append(files, p)
			return nil
		}); err != nil {
			return err
		}
	} else {
		files = append(files, root)
	}

	err = runFormat(*format, files, opts, *workers, *inputFormat, *showStrings, post)
	if err == nil && dumpFailed {
		err = fmt.Errorf("one or more payload dumps failed")
	}
	return err
}

func runFormat(format string, files []string, opts maldoctrace.Options, workers int, inputFormat string, showStrings bool, post func(*report.Report)) error {
	switch format {
	case "jsonl":
		return analyzeJSONL(files, opts, workers, inputFormat, post)
	case "json":
		if len(files) != 1 {
			return usagef("--format json expects a single file")
		}
		data, err := readFile(files[0])
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		r := analyzeOne(data, files[0], opts, inputFormat)
		post(r)
		return enc.Encode(r)
	case "text":
		for _, f := range files {
			data, err := readFile(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading %s: %v\n", f, err)
				continue
			}
			r := analyzeOne(data, f, opts, inputFormat)
			post(r)
			fmt.Println(report.RenderTextWith(r, report.TextOptions{ShowStrings: showStrings}))
		}
		return nil
	default:
		return usagef("unknown --format %q", format)
	}
}

func analyzeOne(data []byte, path string, opts maldoctrace.Options, inputFormat string) *report.Report {
	if inputFormat == "vba" {
		return maldoctrace.AnalyzeVBA(string(data), path, opts)
	}
	return maldoctrace.AnalyzeFromBytes(nil, data, path, opts)
}

func analyzeJSONL(files []string, opts maldoctrace.Options, workers int, inputFormat string, post func(*report.Report)) error {
	if workers <= 0 {
		return usagef("--workers must be positive")
	}
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				data, err := readFile(f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error reading %s: %v\n", f, err)
					continue
				}
				r := analyzeOne(data, f, opts, inputFormat)
				if post != nil {
					post(r)
				}
				mu.Lock()
				enc.Encode(r)
				mu.Unlock()
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	return nil
}

// isWithin reports whether path lies inside (or equals) root.
func isWithin(path, root string) (bool, error) {
	ap, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	ar, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(ar, ap)
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}
