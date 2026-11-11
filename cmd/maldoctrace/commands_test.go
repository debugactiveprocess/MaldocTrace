package main

import (
	"flag"
	"io"
	"reflect"
	"testing"

	"maldoctrace"
)

func TestParseInterspersedFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		pos     []string
		format  string
		workers int
		force   bool
		wantErr bool
	}{
		{"trailing", []string{"sample", "--format", "json"}, []string{"sample"}, "json", 1, false, false},
		{"equals", []string{"sample", "--format=json"}, []string{"sample"}, "json", 1, false, false},
		{"leading", []string{"--format", "json", "sample"}, []string{"sample"}, "json", 1, false, false},
		{"boolean", []string{"sample", "--force"}, []string{"sample"}, "text", 1, true, false},
		{"negative", []string{"sample", "--workers", "-1"}, []string{"sample"}, "text", -1, false, false},
		{"empty value", []string{"sample", "--format", ""}, []string{"sample"}, "", 1, false, false},
		{"terminator", []string{"--", "-sample", "--force"}, []string{"-sample", "--force"}, "text", 1, false, false},
		{"empty positional", []string{"", "-"}, []string{"", "-"}, "text", 1, false, false},
		{"missing value", []string{"sample", "--format"}, nil, "", 0, false, true},
		{"unknown trailing", []string{"sample", "--unknown"}, nil, "", 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			format := fs.String("format", "text", "")
			workers := fs.Int("workers", 1, "")
			force := fs.Bool("force", false, "")
			pos, err := parse(fs, tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(pos, tt.pos) || *format != tt.format || *workers != tt.workers || *force != tt.force {
				t.Fatalf("got positions=%q format=%q workers=%d force=%v", pos, *format, *workers, *force)
			}
		})
	}
}

func TestAnalyzeRejectsInvalidOptions(t *testing.T) {
	for _, args := range [][]string{
		{"missing", "--workers", "0"},
		{"missing", "--workers", "-1"},
		{"missing", "--timeout", "0s"},
		{"missing", "--max-steps", "-1"},
		{"missing", "--input-format", "unknown"},
		{"missing", "extra"},
		{"missing", "--show-strings", "--format", "json"},
		{"missing", "--show-strings", "--format", "jsonl"},
	} {
		if err := runAnalyze(args); !isUsage(err) {
			t.Errorf("%q: expected usage error, got %v", args, err)
		}
	}
	if err := analyzeJSONL([]string{"missing"}, maldoctrace.Options{}, 0, "", nil); !isUsage(err) {
		t.Fatalf("expected worker validation, got %v", err)
	}
}

func TestCommandHelp(t *testing.T) {
	for _, run := range []func([]string) error{runInspect, runExtract, runAnalyze} {
		if err := run([]string{"--help"}); err != flag.ErrHelp {
			t.Errorf("expected help, got %v", err)
		}
	}
}
