// strategy_coverage.go — given a proposed tagging strategy (per key: a list
// of extraction sources), simulate what coverage that strategy would
// achieve against the entity graph. Returns per-key, per-entity-type
// coverage % + the list of uncovered entities so the AI can decide whether
// to tighten the strategy or accept partial coverage.
//
// Pure function. No I/O. Same input → same output.
package tags

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/graph"
	"github.com/local/dt-managed-engine/internal/stats"
)

func init() {
	analyze.Register(StrategyCoverage{})
}

// StrategyCoverage is the analyzer.
type StrategyCoverage struct{}

func (StrategyCoverage) Kind() string { return "tags.strategy_coverage" }

func (StrategyCoverage) Description() string {
	return "Simulate a proposed tagging strategy against the entity graph: for each key + extraction source list, walk every entity and report whether a value can be extracted. Returns per-key per-type coverage % and the uncovered-entity list so the AI can refine the strategy."
}

// StrategyInput is what the consumer passes.
type StrategyInput struct {
	graph.Input
	Strategy map[string]KeyStrategy `json:"strategy"`
	// ScopeEntityTypes — when set, only simulate for these entity types
	// (e.g. ["HOST"] when the proposed rules only target hosts). Default:
	// all types.
	ScopeEntityTypes []string `json:"scopeEntityTypes,omitempty"`
}

// KeyStrategy describes how to extract values for one target key.
type KeyStrategy struct {
	// ExtractFrom is a list of source specs, tried in order. First match wins.
	//
	// Source grammar (kept small for v1):
	//   property:<field>                  — top-level property field, must be a string
	//   property:<field>:<subkey>         — nested map field, subkey lookup
	//   awsTag:<Key>                       — value of AWS tag with given key
	//   azureTag:<Key>                     — same for Azure
	//   gcpTag:<Key>                       — same for GCP
	//   k8sLabel:<key>                     — k8s label value
	//   envVar:<NAME>                      — env var value
	//   hostGroup.name                     — entity's host group name (string)
	//   hostName.token[N]                  — Nth token of hostname split on -_./
	//   containmentParent:tag:<key>        — value of given tag key on a containment parent
	//   containmentDescendantMajority:tag:<key>
	//                                      — majority value across descendants (≥66%)
	//   callGraphMajority:tag:<key>        — majority value across call-graph neighbors
	//   siblingTag:<key>                   — value of tag on a sibling (first non-empty)
	//   fallback:<literal-value>           — literal default when no other source produces
	ExtractFrom []string `json:"extractFrom"`
	// Fallback — if ExtractFrom yields nothing, use this literal as the value.
	// Implicit "fallback" alternative to using the "fallback:..." in ExtractFrom.
	Fallback string `json:"fallback,omitempty"`
}

// StrategyOutput is the simulator's result.
type StrategyOutput struct {
	CoveragePerKey      map[string]KeyCoverage `json:"coveragePerKey"`
	UncoveredEntities   []UncoveredEntity      `json:"uncoveredEntities"`
	AchievableCoverage  float64                `json:"achievableCoverage"`
	AppliedDefaults     StrategyAppliedDefaults `json:"appliedDefaults"`
}

// KeyCoverage is per-entity-type coverage for one key.
type KeyCoverage struct {
	// PerType: type → {covered, uncovered, coverage}
	PerType map[string]TypeCoverage `json:"perType"`
	// Overall across scoped entity types
	Overall TypeCoverage `json:"overall"`
}

// TypeCoverage is the covered/uncovered count + ratio for one slice.
type TypeCoverage struct {
	Covered   int     `json:"covered"`
	Uncovered int     `json:"uncovered"`
	Coverage  float64 `json:"coverage"`
}

// UncoveredEntity is an entity for which one or more strategy keys had no
// extractable value. Reasons are listed per missing key.
type UncoveredEntity struct {
	EntityID    string             `json:"entityId"`
	Type        string             `json:"type"`
	DisplayName string             `json:"displayName,omitempty"`
	MissingKeys []MissingKeyReason `json:"missingKeys"`
}

// MissingKeyReason explains why a key couldn't be extracted: which sources
// were tried, and what each returned (mostly "no match").
type MissingKeyReason struct {
	Key            string   `json:"key"`
	SourcesTried   []string `json:"sourcesTried"`
}

// StrategyAppliedDefaults echoes the actual scope used.
type StrategyAppliedDefaults struct {
	ScopeEntityTypes []string `json:"scopeEntityTypes"`
}

// Run is the analyzer entrypoint.
func (StrategyCoverage) Run(raw json.RawMessage) (any, error) {
	var in StrategyInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	if len(in.Strategy) == 0 {
		return nil, fmt.Errorf("strategy is required (provide at least one key with extractFrom)")
	}

	g := graph.Build(in.Input)

	// Resolve scope
	scopeSet := map[graph.EntityType]bool{}
	if len(in.ScopeEntityTypes) == 0 {
		scopeSet[graph.TypeHost] = true
		scopeSet[graph.TypeProcessGroup] = true
		scopeSet[graph.TypeProcessGroupInstance] = true
		scopeSet[graph.TypeService] = true
	} else {
		for _, t := range in.ScopeEntityTypes {
			scopeSet[graph.EntityType(t)] = true
		}
	}

	// Collect all scoped entities once
	scopedNodes := []*graph.Node{}
	for t := range scopeSet {
		scopedNodes = append(scopedNodes, g.ByType[t]...)
	}

	out := StrategyOutput{
		CoveragePerKey: map[string]KeyCoverage{},
		AppliedDefaults: StrategyAppliedDefaults{
			ScopeEntityTypes: sortedEntityTypeStrings(scopeSet),
		},
	}

	// Per-key, walk all scoped entities and try each extractor.
	// Track uncovered entities by id → missingKeys list (deferred to end).
	uncoveredByID := map[string]*UncoveredEntity{}

	keys := sortedKeys(in.Strategy)
	for _, key := range keys {
		strat := in.Strategy[key]
		kc := KeyCoverage{PerType: map[string]TypeCoverage{}}
		for t := range scopeSet {
			nodes := g.ByType[t]
			covered, uncovered := 0, 0
			for _, n := range nodes {
				value, _ := evaluateStrategy(n, strat, g, key)
				if value != "" {
					covered++
				} else {
					uncovered++
					if _, ok := uncoveredByID[n.ID]; !ok {
						uncoveredByID[n.ID] = &UncoveredEntity{
							EntityID:    n.ID,
							Type:        string(n.Type),
							DisplayName: n.DisplayName,
						}
					}
					uncoveredByID[n.ID].MissingKeys = append(uncoveredByID[n.ID].MissingKeys, MissingKeyReason{
						Key:          key,
						SourcesTried: strat.ExtractFrom,
					})
				}
			}
			ratio := 0.0
			if covered+uncovered > 0 {
				ratio = round2(float64(covered) / float64(covered+uncovered))
			}
			kc.PerType[string(t)] = TypeCoverage{Covered: covered, Uncovered: uncovered, Coverage: ratio}
		}
		// Overall across the scope
		totalCovered, totalUncovered := 0, 0
		for _, tc := range kc.PerType {
			totalCovered += tc.Covered
			totalUncovered += tc.Uncovered
		}
		overallRatio := 0.0
		if totalCovered+totalUncovered > 0 {
			overallRatio = round2(float64(totalCovered) / float64(totalCovered+totalUncovered))
		}
		kc.Overall = TypeCoverage{Covered: totalCovered, Uncovered: totalUncovered, Coverage: overallRatio}
		out.CoveragePerKey[key] = kc
	}

	// Achievable coverage: product / fraction of entities for which ALL keys
	// in the strategy got a value. (per-entity-perfect coverage.)
	allKeysCoveredCount := 0
	for _, n := range scopedNodes {
		ok := true
		for _, key := range keys {
			v, _ := evaluateStrategy(n, in.Strategy[key], g, key)
			if v == "" {
				ok = false
				break
			}
		}
		if ok {
			allKeysCoveredCount++
		}
	}
	if len(scopedNodes) > 0 {
		out.AchievableCoverage = round2(float64(allKeysCoveredCount) / float64(len(scopedNodes)))
	}

	// Flatten uncovered list, sorted by entity id for stability.
	for _, ue := range uncoveredByID {
		out.UncoveredEntities = append(out.UncoveredEntities, *ue)
	}
	sort.Slice(out.UncoveredEntities, func(i, j int) bool {
		return out.UncoveredEntities[i].EntityID < out.UncoveredEntities[j].EntityID
	})

	return out, nil
}

// evaluateStrategy runs a KeyStrategy against one node, returning the
// (value, sourceUsed) — empty if no source produced.
//
// Try ExtractFrom in order, first non-empty value wins. If none produces,
// fall back to KeyStrategy.Fallback if set.
func evaluateStrategy(n *graph.Node, s KeyStrategy, g *graph.Graph, key string) (string, string) {
	for _, src := range s.ExtractFrom {
		if v := evalSource(n, src, g); v != "" {
			return v, src
		}
	}
	if s.Fallback != "" {
		return s.Fallback, "fallback:" + s.Fallback
	}
	_ = key
	return "", ""
}

// evalSource interprets one source spec against a node. Returns the value
// the spec resolves to, or "" if it doesn't apply.
func evalSource(n *graph.Node, src string, g *graph.Graph) string {
	// Split spec into segments: "type:arg1:arg2"
	parts := strings.SplitN(src, ":", 3)
	if len(parts) == 0 {
		return ""
	}
	head := parts[0]
	switch head {
	case "property":
		if len(parts) < 2 {
			return ""
		}
		fieldName := parts[1]
		subkey := ""
		if len(parts) >= 3 {
			subkey = parts[2]
		}
		return resolveProperty(n.Properties, fieldName, subkey)

	case "awsTag":
		if len(parts) < 2 {
			return ""
		}
		return resolveTagArray(n.Properties, "awsTags", parts[1])

	case "azureTag":
		if len(parts) < 2 {
			return ""
		}
		return resolveTagArray(n.Properties, "azureTags", parts[1])

	case "gcpTag":
		if len(parts) < 2 {
			return ""
		}
		return resolveTagArray(n.Properties, "gcpTags", parts[1])

	case "k8sLabel":
		if len(parts) < 2 {
			return ""
		}
		return resolveMapField(n.Properties, "k8sLabels", parts[1])

	case "envVar":
		if len(parts) < 2 {
			return ""
		}
		return resolveMapField(n.Properties, "envVars", parts[1])

	case "hostGroup.name":
		v, _ := n.Properties["hostGroupName"].(string)
		return v

	case "hostName.token[N]":
		// Not a real spec by itself — handled below as hostName.token[<N>]
		return ""

	case "containmentParent":
		// containmentParent:tag:<key>
		if len(parts) < 3 || parts[1] != "tag" {
			return ""
		}
		k := parts[2]
		for _, p := range n.ContainmentParents {
			for _, v := range p.TagValues(k) {
				if v != "" {
					return v
				}
			}
		}
		return ""

	case "containmentDescendantMajority":
		if len(parts) < 3 || parts[1] != "tag" {
			return ""
		}
		k := parts[2]
		desc := graph.Descendants(n)
		v, _, _, ok := graph.MajorityValue(desc, k, 0.66)
		if !ok {
			return ""
		}
		return v

	case "callGraphMajority":
		if len(parts) < 3 || parts[1] != "tag" {
			return ""
		}
		k := parts[2]
		neigh := graph.CallNeighbors(n)
		v, _, _, ok := graph.MajorityValue(neigh, k, 0.66)
		if !ok {
			return ""
		}
		return v

	case "siblingTag":
		if len(parts) < 2 {
			return ""
		}
		k := parts[1]
		for _, s := range graph.Siblings(n) {
			for _, v := range s.TagValues(k) {
				if v != "" {
					return v
				}
			}
		}
		return ""

	case "fallback":
		if len(parts) < 2 {
			return ""
		}
		return parts[1]
	}

	// hostName.token[N] form
	if strings.HasPrefix(src, "hostName.token[") && strings.HasSuffix(src, "]") {
		idxStr := strings.TrimSuffix(strings.TrimPrefix(src, "hostName.token["), "]")
		idx := 0
		fmt.Sscanf(idxStr, "%d", &idx)
		hostName, _ := n.Properties["hostName"].(string)
		if hostName == "" {
			hostName = n.DisplayName
		}
		tokens := stats.TokenSplit(hostName)
		if idx >= 0 && idx < len(tokens) {
			return tokens[idx]
		}
		return ""
	}

	return ""
}

// resolveProperty walks Properties to find fieldName (and optional subkey).
func resolveProperty(props graph.Properties, fieldName, subkey string) string {
	if props == nil {
		return ""
	}
	v, ok := props[fieldName]
	if !ok {
		return ""
	}
	if subkey == "" {
		s, _ := v.(string)
		return s
	}
	if m, ok := v.(map[string]any); ok {
		if sv, ok := m[subkey].(string); ok {
			return sv
		}
	}
	return ""
}

// resolveMapField finds a nested map field and looks up the subkey.
// Equivalent to resolveProperty(props, fieldName, subkey) but factored for
// readability at call sites.
func resolveMapField(props graph.Properties, fieldName, subkey string) string {
	return resolveProperty(props, fieldName, subkey)
}

// resolveTagArray scans an [{key,value}] array under fieldName for an entry
// whose key matches `tagKey` (case-insensitive).
func resolveTagArray(props graph.Properties, fieldName, tagKey string) string {
	if props == nil {
		return ""
	}
	arr, ok := props[fieldName].([]any)
	if !ok {
		return ""
	}
	target := stats.Normalize(tagKey)
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		k, _ := obj["key"].(string)
		if stats.Normalize(k) == target {
			if v, ok := obj["value"].(string); ok {
				return v
			}
		}
	}
	return ""
}

func sortedKeys(m map[string]KeyStrategy) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedEntityTypeStrings(m map[graph.EntityType]bool) []string {
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}
