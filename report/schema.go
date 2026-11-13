// Package report defines the versioned JSON schema and the human-readable text
// renderer for analysis results.
package report

import "github.com/debugactiveprocess/MaldocTrace/vba/runtime"

// SchemaVersion is the version of the JSON schema emitted by this tool.
const SchemaVersion = "1.7.0"

// Report is the top-level, self-contained analysis result for one file.
type Report struct {
	// Verdict summarises the evidence: malicious | suspicious | clean |
	// unknown (analysis incomplete and nothing found). RiskScore (0-100) and
	// VerdictReasons explain how it was reached.
	Verdict         string           `json:"verdict"`
	RiskScore       int              `json:"risk_score"`
	VerdictReasons  []string         `json:"verdict_reasons,omitempty"`
	Commands        []Command        `json:"commands"`
	DecodedPayloads []DecodedPayload `json:"decoded_payloads"`
	ScriptCalls     []ScriptCall     `json:"script_calls"`
	// StaticFindings are structural observations that need no emulation:
	// template injection, external OLE links, DDE fields, VBA stomping.
	StaticFindings []StaticFinding `json:"static_findings"`
	// MacroSheets lists Excel 4.0 (XLM) macro sheets and their formulas.
	MacroSheets []MacroSheet `json:"macro_sheets,omitempty"`
	// Properties are document properties and variables macros can read.
	Properties []Property `json:"document_properties,omitempty"`
	// StorageTimes are the creation/modification times of the CFB
	// storages (root, VBA project, OLE objects), for timelines.
	StorageTimes      []StorageTime `json:"storage_timestamps,omitempty"`
	Indicators        []IOC         `json:"indicators"`
	OperationalStatus string        `json:"operational_status"`
	SemanticCoverage  string        `json:"semantic_coverage"`
	SchemaVersion     string        `json:"schema_version"`
	ToolVersion       string        `json:"tool_version"`
	File              FileInfo      `json:"file"`
	Format            string        `json:"format"`
	Status            string        `json:"status"` // complete | partial | failed | timeout
	Macros            string        `json:"macros"` // present | absent | unknown
	Encrypted         bool          `json:"encrypted"`
	// Decryption tells how an encrypted document was opened (scheme and
	// the password that worked) or why it could not be.
	Decryption  *Decryption  `json:"decryption,omitempty"`
	Coverage    Coverage     `json:"coverage"`
	Projects    []Project    `json:"projects,omitempty"`
	Modules     []Module     `json:"modules,omitempty"`
	EntryPoints []EntryPoint `json:"entry_points,omitempty"`
	Decoded     []DecodedStr `json:"decoded_strings,omitempty"`
	Events      []Event      `json:"events,omitempty"`
	IOCs        []IOC        `json:"iocs,omitempty"`
	Artifacts   []Artifact   `json:"artifacts,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
	LimitsHit   []string     `json:"limits_hit,omitempty"`
	// Checks names the structures that were examined (macros, fields,
	// templates, embedded objects...), so a clean result says what it covers.
	Checks []string `json:"checks,omitempty"`
	// Children are the reports of files found inside this one: embedded
	// documents and objects, archive members, email attachments.
	Children   []Child `json:"children,omitempty"`
	DurationMs int64   `json:"duration_ms"`
	Stats      Stats   `json:"stats"`
}

// Child is the analysis of a file found inside the analysed one.
type Child struct {
	// Source tells where it came from: embedded_object, archive_member,
	// email_attachment, onenote_file...
	Source string `json:"source"`
	// Name is the member name, attachment file name or object location.
	Name   string  `json:"name"`
	Report *Report `json:"report"`
}

// FileInfo identifies the analysed input.
type FileInfo struct {
	Path   string `json:"path,omitempty"`
	Name   string `json:"name,omitempty"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Coverage declares which language features were exercised and the gaps found.
type Coverage struct {
	FormatsSupported    []string `json:"formats_supported"`
	ParsedProcedures    int      `json:"parsed_procedures"`
	EmulatedProcedures  int      `json:"emulated_procedures"`
	SupportedFeatures   []string `json:"supported_features"`
	UnsupportedFound    []string `json:"unsupported_found,omitempty"`
	ConditionalCompiled bool     `json:"conditional_compiled"`
}

// Project describes a VBA project found in the container.
type Project struct {
	Name       string `json:"name"`
	DirStream  string `json:"dir_stream,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
	Codepage   uint16 `json:"codepage,omitempty"`
	SysKind    uint32 `json:"sys_kind,omitempty"`
	LCID       uint32 `json:"lcid,omitempty"`
}

// Module describes one extracted module.
type Module struct {
	Name       string `json:"name"`
	FileName   string `json:"file_name,omitempty"`
	Type       string `json:"type,omitempty"`
	Codepage   uint16 `json:"codepage,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
	CodeLen    int    `json:"code_len"`
	// FromPCode is set when the code analysed was rebuilt from the
	// module's compiled p-code instead of its (stomped) source, and
	// PCodeSource holds that rebuilt code.
	FromPCode   bool   `json:"from_pcode,omitempty"`
	PCodeSource string `json:"pcode_source,omitempty"`
}

// EntryPoint is an auto-executable procedure.
type EntryPoint struct {
	Module  string `json:"module"`
	Proc    string `json:"proc"`
	Trigger string `json:"trigger,omitempty"`
	Line    int    `json:"line,omitempty"`
}

// DecodedStr is a reconstructed string with provenance and discovery method.
type DecodedStr struct {
	Value  string `json:"value"`
	Kind   string `json:"kind"`             // static | observed | heuristic | literal
	Method string `json:"method,omitempty"` // how it was rebuilt: literal, concatenation+Chr, ...
	Module string `json:"module,omitempty"`
	Proc   string `json:"proc,omitempty"`
	Line   int    `json:"line,omitempty"`
	Col    int    `json:"col,omitempty"`
}

// Event is a recorded (simulated) operational observation.
type Event struct {
	Receiver          string             `json:"receiver,omitempty"`
	Method            string             `json:"method,omitempty"`
	Arguments         []runtime.Argument `json:"arguments,omitempty"`
	CallChain         []string           `json:"call_chain,omitempty"`
	LocationInherited bool               `json:"location_inherited,omitempty"`
	ID                int                `json:"id"`
	Type              string             `json:"type"`
	Module            string             `json:"module,omitempty"`
	Proc              string             `json:"proc,omitempty"`
	Line              int                `json:"line,omitempty"`
	Col               int                `json:"col,omitempty"`
	Raw               []string           `json:"raw,omitempty"`
	Resolved          []string           `json:"resolved,omitempty"`
	Simulated         bool               `json:"simulated"`
	Speculative       bool               `json:"speculative"`
	Extra             map[string]string  `json:"extra,omitempty"`
}

// IOC is a deduplicated indicator with its occurrences and evidence.
type IOC struct {
	ID        string `json:"id,omitempty"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Discovery string `json:"discovery"` // literal | static | observed | heuristic
	// SameAs names the command or payload whose full text equals Value, so
	// renderers can print a reference instead of repeating it.
	SameAs string `json:"same_as,omitempty"`
	// PartOf names the recovered script this value is a fragment of.
	PartOf      string       `json:"part_of,omitempty"`
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence links an IOC to the exact evidence that produced it.
type Occurrence struct {
	Discovery  string `json:"discovery,omitempty"`
	EvidenceID string `json:"evidence_id,omitempty"`
	Module     string `json:"module,omitempty"`
	Proc       string `json:"proc,omitempty"`
	Line       int    `json:"line,omitempty"`
	Col        int    `json:"col,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	FromEvent  bool   `json:"from_event,omitempty"`
}

// Artifact is a reconstructed payload or file with its hash.
type Artifact struct {
	Name      string `json:"name,omitempty"`
	Path      string `json:"path,omitempty"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	Discovery string `json:"discovery"`
	Module    string `json:"module,omitempty"`
	Proc      string `json:"proc,omitempty"`
	// FileType and Facts identify the content (PE, JAR, script...).
	FileType string   `json:"file_type,omitempty"`
	Facts    []string `json:"facts,omitempty"`
	Raw      []byte   `json:"-"` // file content, for --dump-payloads
}

// Diagnostic is a non-fatal observation from any pipeline stage.
type Diagnostic struct {
	ID          string   `json:"id,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Severity    string   `json:"severity"`
	Stage       string   `json:"stage"`
	Module      string   `json:"module,omitempty"`
	Line        int      `json:"line,omitempty"`
	Message     string   `json:"message"`
}

// Stats summarises work performed.
type Stats struct {
	StepsExecuted      int `json:"steps_executed"`
	EventsRecorded     int `json:"events_recorded"`
	IOCCount           int `json:"ioc_count"`
	DecodedStringCount int `json:"decoded_string_count"`
	LoopLimitHits      int `json:"loop_limit_hits"`
}

// StaticFinding is a structural observation made without emulation.
type StaticFinding struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`     // template_injection | external_ole | dde | external_link | vba_stomping | ...
	Severity string `json:"severity"` // high | medium | low | info
	Location string `json:"location"` // container part or stream
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// Evidence lists supporting values (e.g. p-code strings missing from source).
	Evidence []string `json:"evidence,omitempty"`
}

// MacroSheet is an Excel 4.0 macro sheet.
type MacroSheet struct {
	Name       string       `json:"name"`
	Visibility string       `json:"visibility"` // visible | hidden | very_hidden
	Source     string       `json:"source,omitempty"`
	Formulas   []XLMFormula `json:"formulas"`
}

// XLMFormula is one formula cell of a macro sheet.
type XLMFormula struct {
	Cell    string `json:"cell"`
	Formula string `json:"formula"`
	Value   string `json:"value,omitempty"`
	// Undecoded is set when the formula tokens could not be fully decompiled.
	Undecoded bool `json:"undecoded,omitempty"`
}

// Property is a document property or document variable.
// StorageTime is a CFB storage's creation and modification time (RFC 3339,
// UTC; empty when unset).
type StorageTime struct {
	Path     string `json:"path"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
}

type Property struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Kind   string `json:"kind"` // builtin | custom | variable
	Source string `json:"source,omitempty"`
}

// Decryption describes the encryption of a document and the attempt to open
// it with candidate passwords.
type Decryption struct {
	Scheme    string `json:"scheme"`
	Decrypted bool   `json:"decrypted"`
	Password  string `json:"password,omitempty"`
	Note      string `json:"note,omitempty"`
}
