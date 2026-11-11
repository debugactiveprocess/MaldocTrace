package extractor

import (
	"context"
)

// InspectResult describes the structure of an input for the `inspect` command.
type InspectResult struct {
	Format   Format
	Streams  []string
	Projects []string
	Modules  []string
}

// Inspect lists container structure (streams/entries) and any VBA modules,
// without performing full analysis.
func Inspect(data []byte, lim *Limits) (*InspectResult, []Diagnostic) {
	l := DefaultLimits()
	if lim != nil {
		l = *lim
	}
	out := &InspectResult{Format: Detect(data)}
	switch out.Format {
	case FormatCFB:
		cfb, err := parseCFB(data, &l)
		if err != nil {
			return out, []Diagnostic{{Severity: "warning", Stage: "inspect", Message: err.Error()}}
		}
		out.Streams = cfb.listStreams()
		res, _ := Extract(context.Background(), data, &l)
		for _, p := range res.Projects {
			out.Projects = append(out.Projects, p.Name)
		}
		for _, m := range res.Modules {
			out.Modules = append(out.Modules, m.Name)
		}
	case FormatOOXML:
		files, diags, err := openZip(data, &l)
		if err != nil {
			return out, []Diagnostic{{Severity: "warning", Stage: "inspect", Message: err.Error()}}
		}
		for _, nf := range files {
			out.Streams = append(out.Streams, nf.name)
			sub, err := parseCFB(nf.data, &l)
			if err != nil {
				continue
			}
			out.Streams = append(out.Streams, sub.listStreams()...)
		}
		res, _ := Extract(context.Background(), data, &l)
		for _, p := range res.Projects {
			out.Projects = append(out.Projects, p.Name)
		}
		for _, m := range res.Modules {
			out.Modules = append(out.Modules, m.Name)
		}
		_ = diags
	case FormatVBA:
		out.Modules = []string{"Module1"}
	}
	return out, nil
}
