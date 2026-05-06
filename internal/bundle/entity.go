package bundle

// Entity is the relevant subset of a Dynatrace v2 entity (HOST, HOST_GROUP,
// PROCESS_GROUP, SERVICE, ...) as returned by /api/v2/entities. We capture
// only the fields the engine's checks need; the rest stays in the raw bundle.
//
// Fields are intentionally generic — the same struct serves every entity
// type. Type-specific properties live under Properties (a free-form map).
type Entity struct {
	EntityID        string                       `json:"entityId"`
	DisplayName     string                       `json:"displayName"`
	Type            string                       `json:"type"`
	Tags            []TagOccurrence              `json:"tags"`
	ManagementZones []ManagementZoneRef          `json:"managementZones"`
	Properties      map[string]interface{}       `json:"properties"`
	FromRelations   map[string][]RelationshipRef `json:"fromRelationships"`
	ToRelations     map[string][]RelationshipRef `json:"toRelationships"`
}

// ManagementZoneRef is the lightweight reference DT returns inside entity
// payloads when management zones are requested with `+managementZones`.
type ManagementZoneRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RelationshipRef is the per-relation entry in fromRelationships /
// toRelationships maps. Each map key is a relationship name (isInstanceOf,
// runsOn, calls, ...); each value is a list of referenced entities.
type RelationshipRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// HostGroupID returns the id of the host group this HOST belongs to,
// or "" if the host has no host group.
//
// Two paths because different DT Managed versions surface it differently:
//   - properties.hostGroupId (string)
//   - toRelationships.isInstanceOf[*] where type == HOST_GROUP
func (e Entity) HostGroupID() string {
	if v, ok := e.Properties["hostGroupId"].(string); ok && v != "" {
		return v
	}
	if v, ok := e.Properties["hostGroup"].(string); ok && v != "" {
		return v
	}
	if rels, ok := e.ToRelations["isInstanceOf"]; ok {
		for _, r := range rels {
			if r.Type == "HOST_GROUP" && r.ID != "" {
				return r.ID
			}
		}
	}
	return ""
}

// HasTagKey returns true if the entity carries any tag with the given key,
// regardless of value or context.
func (e Entity) HasTagKey(key string) bool {
	for _, t := range e.Tags {
		if t.Key == key {
			return true
		}
	}
	return false
}

// TagValue returns the first value found for the given tag key, or "" if
// the entity doesn't carry that key. If the entity has multiple tags with
// the same key (rare but possible across contexts), the first one wins.
func (e Entity) TagValue(key string) string {
	for _, t := range e.Tags {
		if t.Key == key {
			return t.Value
		}
	}
	return ""
}

// ProcessGroupID returns the id of the PROCESS_GROUP this PGI belongs to,
// or "" if no PG link is found. Different DT Managed versions surface this
// in different places — we check the common ones.
func (e Entity) ProcessGroupID() string {
	if v, ok := e.Properties["processGroupId"].(string); ok && v != "" {
		return v
	}
	for _, rels := range []map[string][]RelationshipRef{e.ToRelations, e.FromRelations} {
		if links, ok := rels["isInstanceOf"]; ok {
			for _, r := range links {
				if r.Type == "PROCESS_GROUP" && r.ID != "" {
					return r.ID
				}
			}
		}
	}
	return ""
}

// ManagementZoneNames returns the list of MZ names the entity is in.
// Useful for MZ overlap / dead checks.
func (e Entity) ManagementZoneNames() []string {
	out := make([]string, 0, len(e.ManagementZones))
	for _, mz := range e.ManagementZones {
		if mz.Name != "" {
			out = append(out, mz.Name)
		}
	}
	return out
}
