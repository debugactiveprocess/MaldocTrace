package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/extractor"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func flagSet(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }

// parse reorders GNU-style flags that appear after positional arguments so the
// standard library flag package can parse them, then returns the positional
// arguments. Flag definitions determine which flags consume a value.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		name = strings.SplitN(name, "=", 2)[0]
		flagArgs = append(flagArgs, a)
		if f := fs.Lookup(name); f != nil && !strings.Contains(a, "=") {
			boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
			if !ok || !boolean.IsBoolFlag() {
				if i+1 == len(args) {
					return nil, fmt.Errorf("flag needs an argument: %s", a)
				}
				i++
				flagArgs = append(flagArgs, args[i])
			}
		}
	}
	all := append(flagArgs, "--")
	all = append(all, pos...)
	if err := fs.Parse(all); err != nil {
		return nil, err
	}
	return fs.Args(), nil
}

func runInspect(args []string) error {
	fs := flagSet("inspect")
	if _, err := parse(fs, args); err != nil {
		if err == flag.ErrHelp {
			return err
		}
		return usagef("%v", err)
	}
	if fs.NArg() != 1 {
		return usagef("inspect requires a file path")
	}
	data, err := readFile(fs.Arg(0))
	if err != nil {
		return err
	}
	res, diags := extractor.Inspect(data, nil)
	fmt.Printf("format: %s\n", res.Format)
	if len(res.Streams) > 0 {
		fmt.Printf("streams (%d):\n", len(res.Streams))
		for _, s := range res.Streams {
			fmt.Printf("  %s\n", s)
		}
	}
	fmt.Printf("vba projects: %d\n", len(res.Projects))
	for _, p := range res.Projects {
		fmt.Printf("  - %s\n", p)
	}
	fmt.Printf("modules (%d):\n", len(res.Modules))
	for _, m := range res.Modules {
		fmt.Printf("  - %s\n", m)
	}
	for _, d := range diags {
		fmt.Fprintf(os.Stderr, "[%s/%s] %s\n", d.Severity, d.Stage, d.Message)
	}
	return nil
}

func runExtract(args []string) error {
	fs := flagSet("extract")
	out := fs.String("out", "", "output directory")
	force := fs.Bool("force", false, "overwrite existing files")
	if _, err := parse(fs, args); err != nil {
		if err == flag.ErrHelp {
			return err
		}
		return usagef("%v", err)
	}
	if fs.NArg() != 1 || *out == "" {
		return usagef("extract requires a file and --out directory")
	}
	data, err := readFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	res, err := extractor.Extract(context.Background(), data, nil)
	if err != nil {
		return err
	}
	if res.Encrypted {
		return fmt.Errorf("file is encrypted; refusing to write a misleading empty extraction")
	}
	written := 0
	for _, m := range res.Modules {
		safe := sanitizeName(m.FileName)
		dest := filepath.Join(*out, safe)
		if _, err := os.Stat(dest); err == nil && !*force {
			return fmt.Errorf("refusing to overwrite %s (use --force)", dest)
		}
		if err := os.WriteFile(dest, []byte(m.Code), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", dest, len(m.Code))
		written++
	}
	if written == 0 {
		fmt.Fprintln(os.Stderr, "no modules extracted")
	}
	return nil
}

func sanitizeName(name string) string {
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			return '_'
		}
		if r < 0x20 {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(strings.TrimPrefix(name, "."))
	if name == "" {
		return "module.txt"
	}
	return name
}
