// Package finding defines the canonical Finding type produced by every check.
//
// Findings are the single source of truth that every downstream consumer
// (markdown report, xlsx checklist, pptx deck, diff tool, write-payload
// emitter, optional LLM narrator) operates on. The schema is intentionally
// stable — adding fields is fine, renaming or removing fields is not.
package finding

// Severity ranks finding importance. Used for sorting + downstream filtering.
type Severity string

const (
	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"
	SeverityLow    Severity = "Low"
	SeverityInfo   Severity = "Info"
)

// Evidence is the audit trail for a finding. Every recommendation must trace
// back to a specific data point in the raw bundle. Without evidence the
// finding is not allowed.
type Evidence struct {
	// Tool is the conceptual source of the data — usually the dt-ahr MCP tool
	// name that would have produced it (e.g. "dt_get_auto_tags"). The engine
	// itself doesn't call MCP tools, but the tool name keeps the connection
	// to the prompt's evidence discipline visible.
	Tool string `json:"tool"`

	// RawPath is the relative path under the bundle directory pointing at the
	// JSON file that contains the raw data this finding was derived from.
	// e.g. "raw/phase1-auto-tags.json"
	RawPath string `json:"raw_path"`

	// DataPoint is a one-line factual statement of the observation.
	// Counts, percentages, IDs, value excerpts. NOT interpretation.
	// e.g. "rule.value.name='team', occurrences across all entity types: 0"
	DataPoint string `json:"data_point"`
}

// Finding is the unit of output produced by every check.
type Finding struct {
	// ID is a stable identifier for the check that produced this finding.
	// e.g. "CHECK_AUTO_TAG_DEAD". Must match the check's RegisteredID().
	ID string `json:"id"`

	// Phase ties the finding back to the AHR phase it belongs to.
	// e.g. "Phase 1", "Phase 4.8".
	Phase string `json:"phase"`

	// Severity assigned by the check based on its scoring rubric.
	Severity Severity `json:"severity"`

	// Title is a one-line description for use in tables, summaries, etc.
	// Should mention the specific entity / rule / object id involved.
	Title string `json:"title"`

	// Description is a longer explanation suitable for a report. Optional.
	Description string `json:"description,omitempty"`

	// Evidence links the finding back to its source data. Required.
	Evidence Evidence `json:"evidence"`

	// Recommendation is the suggested action. Free text, but written as a
	// concrete imperative ("delete rule X" / "increase coverage of key Y").
	Recommendation string `json:"recommendation"`

	// EntityRef optionally identifies the specific entity or object the
	// finding is about. Useful for grouping findings by scope.
	EntityRef *EntityRef `json:"entity_ref,omitempty"`

	// FixTemplate optionally provides a payload skeleton the write MCP can
	// use to remediate the finding. Filled by checks that have a clean
	// remediation; left nil for findings that require human judgment.
	FixTemplate *FixTemplate `json:"fix_template,omitempty"`
}

// EntityRef points to a specific entity/object/rule the finding concerns.
type EntityRef struct {
	Kind string `json:"kind"` // "entity" | "settings_object" | "rule"
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// FixTemplate hints at the write-MCP shape needed to fix the finding.
// Concrete payload shaping (against dt_get_schema) happens in the
// write-payload emitter, not in the check itself.
type FixTemplate struct {
	WriteAction string                 `json:"write_action"` // "delete" | "create" | "update"
	SchemaID    string                 `json:"schema_id,omitempty"`
	ObjectID    string                 `json:"object_id,omitempty"`
	Hint        string                 `json:"hint,omitempty"`
	ValueHints  map[string]interface{} `json:"value_hints,omitempty"`
}
