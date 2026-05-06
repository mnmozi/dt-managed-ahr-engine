// Package bundle loads the raw JSON files produced by dt-managed-ahr-collector
// into typed Go structs. The engine consumes a Bundle; it never touches
// Dynatrace directly. This separation keeps checks pure functions.
package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Bundle is the root in-memory representation of a collector output directory.
// Fields are populated lazily — only what the running checks actually need
// is loaded. Missing files are tolerated (the collector marks per-call errors
// in its report.md but the JSON file may still be empty/missing).
type Bundle struct {
	// Root is the absolute path to the bundle directory (the one containing
	// the `raw/` subdirectory and `report.md`).
	Root string

	// AutoTagRules is the list of builtin:tags.auto-tagging Settings 2.0 objects.
	AutoTagRules []AutoTagRule

	// TagsByEntityType maps an entity type (HOST, SERVICE, ...) to the
	// aggregated tag occurrences for that type, as returned by
	// /api/v2/tags?entitySelector=type(...).
	TagsByEntityType map[string][]TagOccurrence

	// EntitiesByType maps an entity type (HOST, HOST_GROUP, PROCESS_GROUP, ...)
	// to the full entity inventory for that type, populated from the
	// collector's combined `<step>-all.json` files.
	EntitiesByType map[string][]Entity

	// OneAgents is the list of OneAgent host entries from /api/v2/oneagents.
	// Used by checks that audit per-host module / monitoring-type / version state.
	OneAgents []OneAgent

	// APITokens is the inventory of API tokens. Used by token-hygiene checks.
	APITokens []APIToken

	// ManagementZones is the list of builtin:management-zones Settings 2.0
	// objects. Used by MZ-coverage / MZ-overlap / MZ-dead checks.
	ManagementZones []ManagementZone
}

// AutoTagRule is the relevant subset of a builtin:tags.auto-tagging settings object.
type AutoTagRule struct {
	ObjectID string         `json:"objectId"`
	SchemaID string         `json:"schemaId"`
	Scope    string         `json:"scope"`
	Modified int64          `json:"modified"`
	Value    AutoTagRuleVal `json:"value"`
}

// AutoTagRuleVal is the value field shape we care about. Auto-tagging schemas
// vary slightly across DT versions; we read only the fields we need and let
// the rest live in the raw JSON for fixers to consult later.
type AutoTagRuleVal struct {
	Name        string `json:"name"`        // The tag key the rule produces
	Description string `json:"description"` // Optional human description
	// Rules is intentionally loose — we don't evaluate condition logic in v1
	// of CHECK_AUTO_TAG_DEAD. Future checks can typed-decode this.
	Rules []map[string]interface{} `json:"rules"`
}

// TagOccurrence is one row from the /api/v2/tags aggregated response.
type TagOccurrence struct {
	Context              string `json:"context"`
	Key                  string `json:"key"`
	Value                string `json:"value"`
	StringRepresentation string `json:"stringRepresentation"`
}

// Load reads as much of the bundle as we currently need into memory.
// On missing files it sets the corresponding field to its zero value
// (empty slice / map) and continues — checks downstream must tolerate that.
func Load(bundleRoot string) (*Bundle, error) {
	abs, err := filepath.Abs(bundleRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve bundle path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat bundle dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("bundle path is not a directory: %s", abs)
	}

	b := &Bundle{
		Root:             abs,
		TagsByEntityType: map[string][]TagOccurrence{},
		EntitiesByType:   map[string][]Entity{},
	}

	if err := b.loadAutoTagRules(); err != nil {
		return nil, fmt.Errorf("load auto-tag rules: %w", err)
	}
	if err := b.loadTagsByEntityType(); err != nil {
		return nil, fmt.Errorf("load tags: %w", err)
	}
	if err := b.loadEntities(); err != nil {
		return nil, fmt.Errorf("load entities: %w", err)
	}
	if err := b.loadOneAgents(); err != nil {
		return nil, fmt.Errorf("load oneagents: %w", err)
	}
	if err := b.loadAPITokens(); err != nil {
		return nil, fmt.Errorf("load api tokens: %w", err)
	}
	if err := b.loadManagementZones(); err != nil {
		return nil, fmt.Errorf("load management zones: %w", err)
	}
	return b, nil
}

// mzListResponse mirrors the Settings 2.0 list-objects response when filtered
// to schemaIds=builtin:management-zones.
type mzListResponse struct {
	Items []ManagementZone `json:"items"`
}

// loadManagementZones reads phase3-management-zones.json. Tolerated missing.
func (b *Bundle) loadManagementZones() error {
	var resp mzListResponse
	if err := b.readJSONIfExists("phase3-management-zones.json", &resp); err != nil {
		return err
	}
	b.ManagementZones = append(b.ManagementZones, resp.Items...)
	return nil
}

// oneagentsResponse mirrors /api/v2/oneagents pagination response.
type oneagentsResponse struct {
	Hosts []OneAgent `json:"hosts"`
}

// loadOneAgents reads phase1-oneagents.json. The collector emits this file
// directly (not a multi-page combined file), so the response shape is the
// raw API response.
func (b *Bundle) loadOneAgents() error {
	var resp oneagentsResponse
	if err := b.readJSONIfExists("phase1-oneagents.json", &resp); err != nil {
		return err
	}
	b.OneAgents = append(b.OneAgents, resp.Hosts...)
	return nil
}

// apiTokensResponse mirrors /api/v2/apiTokens pagination response.
type apiTokensResponse struct {
	APITokens []APIToken `json:"apiTokens"`
}

// loadAPITokens reads phase46-api-tokens.json (collector convention).
func (b *Bundle) loadAPITokens() error {
	var resp apiTokensResponse
	if err := b.readJSONIfExists("phase46-api-tokens.json", &resp); err != nil {
		return err
	}
	b.APITokens = append(b.APITokens, resp.APITokens...)
	return nil
}

// entitySource describes one collector output file we know how to load
// into EntitiesByType. As more checks are added, more entries are added here.
type entitySource struct {
	File string // collector's combined output filename under raw/
	Type string // canonical entity type (uppercase)
}

var defaultEntitySources = []entitySource{
	{File: "phase1-hosts-all.json", Type: "HOST"},
	{File: "phase1-hostgroups-all.json", Type: "HOST_GROUP"},
	{File: "phase2-pgs-all.json", Type: "PROCESS_GROUP"},
	{File: "phase2-pgis-all.json", Type: "PROCESS_GROUP_INSTANCE"},
	{File: "phase4-services-all.json", Type: "SERVICE"},
}

// loadEntities walks the known entity sources and decodes the typed inventory.
// Missing files are tolerated — the corresponding entity-type slice stays empty.
func (b *Bundle) loadEntities() error {
	type combined struct {
		Items []Entity `json:"items"`
	}
	for _, src := range defaultEntitySources {
		var c combined
		if err := b.readJSONIfExists(src.File, &c); err != nil {
			return err
		}
		if len(c.Items) > 0 {
			b.EntitiesByType[src.Type] = append(b.EntitiesByType[src.Type], c.Items...)
		}
	}
	return nil
}

// rawPath returns the path under the bundle's `raw/` directory.
// Used both for reading files and for embedding pointers in finding evidence.
func (b *Bundle) rawPath(name string) string {
	return filepath.Join(b.Root, "raw", name)
}

// readJSONIfExists decodes the JSON at the given filename relative to raw/
// into out. If the file doesn't exist, returns nil (no error) — this matches
// the collector's tolerant behaviour where a missing schema yields no file.
func (b *Bundle) readJSONIfExists(name string, out interface{}) error {
	full := b.rawPath(name)
	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", full, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s: %w", full, err)
	}
	return nil
}

// settingsListResponse is the shape of /api/v2/settings/objects responses.
// We only care about items[*] — totalCount, nextPageKey are paging-only.
type settingsListResponse struct {
	Items []struct {
		ObjectID string         `json:"objectId"`
		SchemaID string         `json:"schemaId"`
		Scope    string         `json:"scope"`
		Modified int64          `json:"modified"`
		Value    AutoTagRuleVal `json:"value"`
	} `json:"items"`
}

// loadAutoTagRules reads phase1-auto-tags.json (the collector dumps
// builtin:tags.auto-tagging objects there).
func (b *Bundle) loadAutoTagRules() error {
	var resp settingsListResponse
	if err := b.readJSONIfExists("phase1-auto-tags.json", &resp); err != nil {
		return err
	}
	for _, it := range resp.Items {
		b.AutoTagRules = append(b.AutoTagRules, AutoTagRule{
			ObjectID: it.ObjectID,
			SchemaID: it.SchemaID,
			Scope:    it.Scope,
			Modified: it.Modified,
			Value:    it.Value,
		})
	}
	return nil
}

// tagsResponse is the shape of /api/v2/tags?entitySelector=type(...) responses.
type tagsResponse struct {
	TotalCount           int             `json:"totalCount"`
	MatchedEntitiesCount int             `json:"matchedEntitiesCount"`
	Tags                 []TagOccurrence `json:"tags"`
}

// loadTagsByEntityType walks the bundle's raw/ directory for any file
// matching `*-tags-<lowercase-type>.json` (the collector's naming scheme)
// and groups them by uppercase entity type.
func (b *Bundle) loadTagsByEntityType() error {
	rawDir := filepath.Join(b.Root, "raw")
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Match collector pattern: phase{n}-tags-{lowercase_entity_type}.json
		idx := strings.Index(name, "-tags-")
		if idx < 0 || !strings.HasSuffix(name, ".json") {
			continue
		}
		typeLower := strings.TrimSuffix(name[idx+len("-tags-"):], ".json")
		if typeLower == "" {
			continue
		}
		typeUpper := strings.ToUpper(typeLower)
		var resp tagsResponse
		if err := b.readJSONIfExists(name, &resp); err != nil {
			return err
		}
		b.TagsByEntityType[typeUpper] = append(b.TagsByEntityType[typeUpper], resp.Tags...)
	}
	return nil
}
