// Command maldocTrace is the command-line interface for the MaldocTrace VBA
// analysis library. JSON goes to stdout; diagnostics/logs go to stderr.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"maldoctrace"
)

const usageText = `MaldocTrace - defensive VBA macro analysis for Office documents

Usage:
  maldocTrace inspect <file>
  maldocTrace extract <file> --out <dir> [--force]
  maldocTrace analyze <file> [--format json|text|jsonl] [--timeout 30s] [--max-steps N] [--input-format vba] [--show-strings] [--dump-payloads DIR]
  maldocTrace analyze <dir> --recursive [--format jsonl] [--workers N]
  maldocTrace version

Exit codes:
  0  success (even when suspicious indicators are found)
  1  analysis/internal error
  2  usage error
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "--version", "-V":
		fmt.Printf("MaldocTrace %s\n", maldoctrace.Version)
		os.Exit(0)
	case "inspect":
		err = runInspect(os.Args[2:])
	case "extract":
		err = runExtract(os.Args[2:])
	case "analyze":
		err = runAnalyze(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if isUsage(err) {
			fmt.Fprintf(os.Stderr, "usage error: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type usageErr struct{ msg string }

func (u *usageErr) Error() string { return u.msg }

func usagef(format string, a ...interface{}) error {
	return &usageErr{msg: fmt.Sprintf(format, a...)}
}
func isUsage(err error) bool {
	_, ok := err.(*usageErr)
	return ok
}

var _ = flag.CommandLine
