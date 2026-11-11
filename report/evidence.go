package report

import "maldoctrace/vba/runtime"

type Source struct {
	Module    string `json:"module,omitempty"`
	Proc      string `json:"proc,omitempty"`
	Line      int    `json:"line,omitempty"`
	Col       int    `json:"col,omitempty"`
	Inherited bool   `json:"inherited"`
}
type Command struct {
	ID          string             `json:"id"`
	Kind        string             `json:"kind"`
	CommandLine string             `json:"command_line"`
	Receiver    string             `json:"receiver"`
	Method      string             `json:"method"`
	Arguments   []runtime.Argument `json:"arguments"`
	Source      Source             `json:"source"`
	CallChain   []string           `json:"call_chain,omitempty"`
	Discovery   string             `json:"discovery"`
	Execution   string             `json:"execution"`
	Resolution  string             `json:"resolution"`
	EvidenceIDs []string           `json:"evidence_ids"`
}
type DecodedPayload struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Category string `json:"category"` // encoded_command | script
	Language string `json:"language,omitempty"`
	Encoded  string `json:"encoded"`
	Content  string `json:"content"`
	// NormalizedContent is Content after static, non-executing rewriting
	// (see Normalization). IOCs are extracted from it when present.
	NormalizedContent string   `json:"normalized_content,omitempty"`
	Normalization     []string `json:"normalization,omitempty"`
	Functions         []string `json:"functions,omitempty"`
	// FileType identifies binary content (e.g. "PE32 DLL"); Facts lists header
	// facts; Details records how the payload was produced and used.
	FileType string   `json:"file_type,omitempty"`
	Facts    []string `json:"facts,omitempty"`
	Details  []string `json:"details,omitempty"`
	// Raw holds the payload bytes for --dump-payloads; Content is a display
	// form. Not serialised (JSON already carries Content).
	Raw         []byte   `json:"-"`
	Encoding    []string `json:"encoding"`
	DerivedFrom string   `json:"derived_from"`
	SHA256      string   `json:"sha256,omitempty"`
	Size        int      `json:"size"`
	Status      string   `json:"status"`
	Error       string   `json:"error,omitempty"`
	Depth       int      `json:"depth"`
}

// ScriptCall is an invocation of a function inside a script engine hosted by
// the macro (e.g. ScriptControl.Run "name"). It is not an OS command.
type ScriptCall struct {
	ID          string             `json:"id"`
	Engine      string             `json:"engine"`
	Language    string             `json:"language"`
	Method      string             `json:"method"`
	Function    string             `json:"function,omitempty"`
	Expression  string             `json:"expression,omitempty"`
	Arguments   []runtime.Argument `json:"arguments"`
	DefinedIn   string             `json:"defined_in,omitempty"` // payload ID of the script defining Function
	Source      Source             `json:"source"`
	CallChain   []string           `json:"call_chain,omitempty"`
	Execution   string             `json:"execution"`
	EvidenceIDs []string           `json:"evidence_ids"`
}
