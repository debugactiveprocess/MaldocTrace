// Package extractor implements format detection and extraction of VBA
// projects from Microsoft Office document containers (CFB/OLE and OOXML/ZIP)
// and from plain-text VBA source files.
//
// The CFB reader and the MS-OVBA compression/record parsing implemented here
// are clean, original Go implementations guided by the public Microsoft
// specifications [MS-CFB] and [MS-OVBA] and by the behaviour of the
// BSD-licensed oletools (https://github.com/decalage2/oletools).
package extractor

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the extractor. Callers should use errors.Is to
// distinguish these conditions. None of these imply "no macros present".
var (
	// ErrEncrypted indicates the container is encrypted (e.g. OLE RC4 CryptoAPI
	// or an encrypted ZIP), and therefore VBA cannot be extracted. Absence of
	// extracted modules is NOT evidence of absence of macros in this case.
	ErrEncrypted = errors.New("container is encrypted or password protected")

	// ErrUnsupported indicates a well-formed container the tool does not yet
	// support. It is distinct from a malformed or truncated input.
	ErrUnsupported = errors.New("format is not supported")

	// ErrTruncated indicates the input was cut short while reading a required
	// structure.
	ErrTruncated = errors.New("file is truncated or malformed")

	// ErrLimitExceeded indicates a resource limit configured by the caller was
	// reached before the operation could complete.
	ErrLimitExceeded = errors.New("resource limit exceeded")
)

// AnalysisError is a typed error carrying a stage name and a human-readable
// message, so callers and the report layer can attribute failures to the
// pipeline stage that produced them.
type AnalysisError struct {
	Stage string // e.g. "extract", "cfb", "ovba.decompress", "zip"
	Err   error
}

func (e *AnalysisError) Error() string {
	if e.Stage == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Stage, e.Err)
}

func (e *AnalysisError) Unwrap() error { return e.Err }

// Wrap returns an *AnalysisError annotating err with stage.
func Wrap(stage string, err error) error {
	if err == nil {
		return nil
	}
	var ae *AnalysisError
	if errors.As(err, &ae) {
		return err
	}
	return &AnalysisError{Stage: stage, Err: err}
}
