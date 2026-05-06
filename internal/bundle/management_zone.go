package bundle

// ManagementZone is the relevant subset of a builtin:management-zones
// Settings 2.0 object. We capture the value.name (because that's what
// entities reference in their managementZones[].name field) and the
// objectId (for write-MCP fix templates that target the settings object).
type ManagementZone struct {
	ObjectID string             `json:"objectId"`
	SchemaID string             `json:"schemaId"`
	Scope    string             `json:"scope"`
	Modified int64              `json:"modified"`
	Value    ManagementZoneVal  `json:"value"`
}

// ManagementZoneVal is the value-side of a management-zones settings object.
// We only model name + description here — rule conditions are intentionally
// untyped because a full DSL evaluator is out of v1 scope.
type ManagementZoneVal struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Rules       []map[string]interface{} `json:"rules"`
}
