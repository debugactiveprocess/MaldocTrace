package maldoctrace

import (
	"fmt"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

// runStage executes one pipeline stage and converts a panic into a recorded
// error diagnostic. A crafted input that crashes one stage must never take
// down the process (or a whole batch) nor discard evidence gathered by
// earlier stages. It reports whether the stage completed normally.
func runStage(r *report.Report, stage string, fn func()) (ok bool) {
	defer func() {
		if p := recover(); p != nil {
			r.Status = "failed"
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
				Severity: "error",
				Stage:    stage,
				Message:  fmt.Sprintf("internal error (recovered panic): %v", p),
			})
			r.LimitsHit = append(r.LimitsHit, "panic:"+stage)
			ok = false
		}
	}()
	fn()
	return true
}

// safeFinalize runs post-processing (command recovery, payload decoding, IOC
// dedupe). If it panics, the raw evidence already in the report is kept and
// the report is still made consistent enough to serialise.
func safeFinalize(r *report.Report) {
	if runStage(r, "finalize", func() { finalizeReport(r) }) {
		return
	}
	r.OperationalStatus = "failed"
	r.SemanticCoverage = "partial"
	r.Indicators = r.IOCs
	r.Stats.IOCCount = len(r.IOCs)
}
