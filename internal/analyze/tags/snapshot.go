// Package tags contains analyzers operating on entity tags + the entity graph.
//
// snapshot.go — the foundation analyzer. Builds the entity graph from flat
// input, then computes:
//   - Per-entity-type counts (total, withZeroTags, withLowTags)
//   - Per-key taxonomy (coverage per type, distinct values, value-format
//     judgment, context distribution, sourcing auto-tag rules)
//   - Cross-key similarity clusters (typo / substring / case drift)
//   - Low-tag entities list and their subgraph (so AI can see the
//     neighborhood without traversing the tree)
//   - Per-key propagation hints (which entity types cover the key, which don't,
//     whether the call graph could help)
//
// Pure function. No I/O. Same input → same output.
package tags

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/graph"
	"github.com/local/dt-managed-engine/internal/stats"
)

func init() {
	analyze.Register(Snapshot{})
}

// Snapshot is the foundation analyzer for tag analysis.
type Snapshot struct{}

func (Snapshot) Kind() string { return "tags.snapshot" }

func (Snapshot) Description() string {
	return "Comprehensive snapshot of the tenant's tag state: per-type entity counts, per-key taxonomy (coverage, distinct values, value-format judgment, context-mix), key similarity clusters (typos/variants), low-tag entities, and a graph-aware low-tag subgraph for downstream signal extraction. Pure function over flat entity input + auto-tag rules."
}

// AutoTagRule is the relevant subset of a builtin:tags.auto-tagging Settings
// 2.0 object. Same shape as bundle.AutoTagRule but local to keep tags
// package decoupled from the bundle package.
type AutoTagRule struct {
	ObjectID string `json:"objectId"`
	Value    struct {
		Name string `json:"name"` // the tag key the rule produces
	} `json:"value"`
}

// Input is what the consumer passes in.
type Input struct {
	graph.Input
	AutoTagRules    []AutoTagRule `json:"autoTagRules,omitempty"`
	LowTagThreshold int           `json:"lowTagThreshold,omitempty"`
	// GraphMode controls how much of the entity graph appears in Output.
	// Default "low_tag_only" — emits a subgraph around low-tag entities.
	// "full" emits every node (heavy on big tenants). "none" emits no graph.
	GraphMode string `json:"graphMode,omitempty"`
}

// Output is the snapshot result.
type Output struct {
	EntitiesByType        map[string]EntityTypeStats `json:"entitiesByType"`
	Keys                  []KeyStats                 `json:"keys"`
	KeySimilarityClusters []SimilarityCluster        `json:"keySimilarityClusters"`
	LowTagEntities        map[string][]LowTagEntity  `json:"lowTagEntities"`
	LowTagSubgraph        *Subgraph                  `json:"lowTagSubgraph,omitempty"`
	PropagationHints      []PropagationHint          `json:"propagationHints"`
	AppliedDefaults       AppliedDefaults            `json:"appliedDefaults"`
}

// EntityTypeStats is the per-entity-type tagging headcount.
type EntityTypeStats struct {
	Total         int `json:"total"`
	WithZeroTags  int `json:"withZeroTags"`
	WithLowTags   int `json:"withLowTags"`
}

// KeyStats is the per-tag-key audit.
type KeyStats struct {
	Key                 string             `json:"key"`
	TotalOccurrences    int                `json:"totalOccurrences"`
	Coverage            map[string]float64 `json:"coverage"`            // per entity type
	DistinctValues      []string           `json:"distinctValues"`
	TopValues           []ValueCount       `json:"topValues"`
	ValueFormatJudgment string             `json:"valueFormatJudgment"` // "single" | "uniform" | "messy"
	ValueFormatIssues   []ValueFormatIssue `json:"valueFormatIssues,omitempty"`
	ContextDistribution map[string]int     `json:"contextDistribution"`
	SourcingRuleIDs     []string           `json:"sourcingRuleIds,omitempty"`
}

// ValueCount pairs a value with its occurrence count.
type ValueCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// ValueFormatIssue describes a drift pattern found within a key's values.
type ValueFormatIssue struct {
	Type   string     `json:"type"`   // "case_drift" | "separator_drift" | "mixed_drift"
	Groups [][]string `json:"groups"` // each group is values that normalize to the same string
}

// SimilarityCluster groups keys that look like the same intent.
type SimilarityCluster struct {
	Canonical        string           `json:"canonical"`        // longest/most-occurring variant
	Variants         []string         `json:"variants"`
	Evidence         []SimilarityEdge `json:"evidence"`
	TotalOccurrences int              `json:"totalOccurrences"`
}

// SimilarityEdge is the evidence linking two keys in a cluster.
type SimilarityEdge struct {
	Pair   [2]string `json:"pair"`
	Metric string    `json:"metric"`         // "levenshtein" | "substring" | "case_only"
	Score  *int      `json:"score,omitempty"`
	Ratio  *float64  `json:"ratio,omitempty"`
}

// LowTagEntity is a minimal reference to an entity that has ≤threshold tags.
type LowTagEntity struct {
	EntityID    string `json:"entityId"`
	DisplayName string `json:"displayName,omitempty"`
	TagCount    int    `json:"tagCount"`
}

// Subgraph is the structural picture around low-tag entities.
// Pre-computed parent/sibling/neighbor tag summaries so the AI doesn't
// have to walk the tree.
type Subgraph struct {
	Nodes []SubgraphNode `json:"nodes"`
}

// SubgraphNode is one entity in the subgraph, with pre-computed neighborhood
// tag summaries.
type SubgraphNode struct {
	EntityID               string                       `json:"entityId"`
	Type                   string                       `json:"type"`
	DisplayName            string                       `json:"displayName,omitempty"`
	TagCount               int                          `json:"tagCount"`
	Tags                   []graph.Tag                  `json:"tags,omitempty"`
	ContainmentParentIDs   []string                     `json:"containmentParentIds,omitempty"`
	ContainmentChildrenIDs []string                     `json:"containmentChildrenIds,omitempty"`
	CallsFromIDs           []string                     `json:"callsFromIds,omitempty"`
	CallsToIDs             []string                     `json:"callsToIds,omitempty"`
	// Per-relationship tag-value summaries: key → value → count.
	// These let the AI see "my parent has team:foo, 4 of 5 callers have team:payments"
	// without doing the walk itself.
	ParentTagDistribution   map[string]map[string]int `json:"parentTagDistribution,omitempty"`
	SiblingTagDistribution  map[string]map[string]int `json:"siblingTagDistribution,omitempty"`
	NeighborTagDistribution map[string]map[string]int `json:"neighborTagDistribution,omitempty"`
}

// PropagationHint is a per-key, per-entity-type coverage compare with a
// human-readable hint for the AI.
type PropagationHint struct {
	Key                 string   `json:"key"`
	FullyCoveredOn      []string `json:"fullyCoveredOn"`      // types where coverage ≥ 0.95
	PartiallyCoveredOn  []string `json:"partiallyCoveredOn"`  // types where 0.10 ≤ coverage < 0.95
	UncoveredOn         []string `json:"uncoveredOn"`         // types where coverage < 0.10
	CallGraphHint       string   `json:"callGraphHint,omitempty"`
}

// AppliedDefaults echoes the actual thresholds used so the consumer can audit.
type AppliedDefaults struct {
	LowTagThreshold int    `json:"lowTagThreshold"`
	GraphMode       string `json:"graphMode"`
}

// Run is the analyzer entrypoint.
func (Snapshot) Run(raw json.RawMessage) (any, error) {
	var in Input
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	lowTagThreshold := in.LowTagThreshold
	if lowTagThreshold < 0 {
		lowTagThreshold = 1
	}
	if in.LowTagThreshold == 0 {
		// 0 has ambiguous meaning: "use default" vs "literal 0". Treat 0 as "use default 1"
		// because the literal-zero case (only flag completely-untagged) is rarely useful.
		lowTagThreshold = 1
	}
	graphMode := in.GraphMode
	if graphMode == "" {
		graphMode = "low_tag_only"
	}

	g := graph.Build(in.Input)

	out := Output{
		EntitiesByType:   map[string]EntityTypeStats{},
		LowTagEntities:   map[string][]LowTagEntity{},
		PropagationHints: []PropagationHint{},
		AppliedDefaults: AppliedDefaults{
			LowTagThreshold: lowTagThreshold,
			GraphMode:       graphMode,
		},
	}

	// 1. Per-entity-type stats + low-tag entity collection.
	allLowTagNodes := []*graph.Node{}
	entityTypes := []graph.EntityType{graph.TypeHost, graph.TypeProcessGroup, graph.TypeProcessGroupInstance, graph.TypeService}
	for _, t := range entityTypes {
		nodes := g.ByType[t]
		total := len(nodes)
		zero, low := 0, 0
		lowList := make([]LowTagEntity, 0)
		for _, n := range nodes {
			tc := len(n.Tags)
			if tc == 0 {
				zero++
			}
			if tc <= lowTagThreshold {
				low++
				lowList = append(lowList, LowTagEntity{
					EntityID:    n.ID,
					DisplayName: n.DisplayName,
					TagCount:    tc,
				})
				allLowTagNodes = append(allLowTagNodes, n)
			}
		}
		out.EntitiesByType[string(t)] = EntityTypeStats{Total: total, WithZeroTags: zero, WithLowTags: low}
		if total > 0 {
			out.LowTagEntities[string(t)] = lowList
		}
	}

	// 2. Per-key taxonomy.
	out.Keys = computeKeyStats(g, in.AutoTagRules)

	// 3. Key similarity clusters.
	out.KeySimilarityClusters = computeKeySimilarityClusters(out.Keys)

	// 4. Propagation hints.
	out.PropagationHints = computePropagationHints(g, out.Keys)

	// 5. Low-tag subgraph (or skip if graphMode != "low_tag_only" / "full").
	if graphMode != "none" {
		out.LowTagSubgraph = buildSubgraph(g, allLowTagNodes, graphMode)
	}

	return out, nil
}

// computeKeyStats walks every entity in the graph, counts per-key occurrences
// per entity type, derives distinct values, top values, value-format judgment,
// and context distribution, then maps keys to sourcing auto-tag rules.
func computeKeyStats(g *graph.Graph, rules []AutoTagRule) []KeyStats {
	// Track per-key, per-entity-type:
	//   - distinct entity IDs that carry the key (for coverage)
	//   - distinct values seen + counts
	//   - context counts
	type aggregator struct {
		entityIdsByType map[graph.EntityType]map[string]bool
		valueCounts     map[string]int
		contextCounts   map[string]int
		totalOcc        int
	}
	agg := make(map[string]*aggregator) // key → aggregator

	for _, t := range []graph.EntityType{graph.TypeHost, graph.TypeProcessGroup, graph.TypeProcessGroupInstance, graph.TypeService} {
		for _, n := range g.ByType[t] {
			seenKey := map[string]bool{}
			for _, tag := range n.Tags {
				if tag.Key == "" {
					continue
				}
				a, ok := agg[tag.Key]
				if !ok {
					a = &aggregator{
						entityIdsByType: map[graph.EntityType]map[string]bool{},
						valueCounts:     map[string]int{},
						contextCounts:   map[string]int{},
					}
					agg[tag.Key] = a
				}
				// Coverage: count an entity once per key, even if it has the key with two values
				if !seenKey[tag.Key] {
					seenKey[tag.Key] = true
					if a.entityIdsByType[t] == nil {
						a.entityIdsByType[t] = map[string]bool{}
					}
					a.entityIdsByType[t][n.ID] = true
				}
				// Value + context counts: every occurrence
				if tag.Value != "" {
					a.valueCounts[tag.Value]++
				}
				ctx := tag.Context
				if ctx == "" {
					ctx = "UNKNOWN"
				}
				a.contextCounts[ctx]++
				a.totalOcc++
			}
		}
	}

	// Map auto-tag rules → key
	rulesByKey := map[string][]string{}
	for _, r := range rules {
		if r.Value.Name == "" {
			continue
		}
		rulesByKey[r.Value.Name] = append(rulesByKey[r.Value.Name], r.ObjectID)
	}

	// Stable order: keys sorted by total occurrences desc, then alpha.
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ki, kj := keys[i], keys[j]
		if agg[ki].totalOcc != agg[kj].totalOcc {
			return agg[ki].totalOcc > agg[kj].totalOcc
		}
		return ki < kj
	})

	out := make([]KeyStats, 0, len(keys))
	for _, k := range keys {
		a := agg[k]
		// Coverage per type
		coverage := map[string]float64{}
		for _, t := range []graph.EntityType{graph.TypeHost, graph.TypeProcessGroup, graph.TypeProcessGroupInstance, graph.TypeService} {
			total := len(g.ByType[t])
			if total == 0 {
				continue
			}
			withKey := len(a.entityIdsByType[t])
			coverage[string(t)] = round2(float64(withKey) / float64(total))
		}
		// Distinct values (sorted) + top values
		distinct := make([]string, 0, len(a.valueCounts))
		for v := range a.valueCounts {
			distinct = append(distinct, v)
		}
		sort.Strings(distinct)
		top := make([]ValueCount, 0, len(a.valueCounts))
		for v, c := range a.valueCounts {
			top = append(top, ValueCount{Value: v, Count: c})
		}
		sort.Slice(top, func(i, j int) bool {
			if top[i].Count != top[j].Count {
				return top[i].Count > top[j].Count
			}
			return top[i].Value < top[j].Value
		})
		if len(top) > 10 {
			top = top[:10]
		}
		// Value format judgment + issues
		judgment, issues := classifyValueFormat(distinct)
		ks := KeyStats{
			Key:                 k,
			TotalOccurrences:    a.totalOcc,
			Coverage:            coverage,
			DistinctValues:      distinct,
			TopValues:           top,
			ValueFormatJudgment: judgment,
			ValueFormatIssues:   issues,
			ContextDistribution: a.contextCounts,
			SourcingRuleIDs:     rulesByKey[k],
		}
		out = append(out, ks)
	}
	return out
}

// classifyValueFormat returns one of:
//   "single"  — exactly 1 distinct value
//   "uniform" — multiple distinct values; no two of them normalize to the same string
//   "messy"   — at least one pair of values normalizes to the same string
//               (= shape drift among what's logically the same value)
//
// When "messy", `issues` enumerates the drift groups categorized by type:
//   case_drift, separator_drift, mixed_drift.
func classifyValueFormat(values []string) (judgment string, issues []ValueFormatIssue) {
	if len(values) == 0 {
		return "single", nil
	}
	if len(values) == 1 {
		return "single", nil
	}

	// Group values by normalized form. Groups with >1 member = drift.
	groupsByNorm := map[string][]string{}
	for _, v := range values {
		n := stats.Normalize(v)
		groupsByNorm[n] = append(groupsByNorm[n], v)
	}
	driftGroups := [][]string{}
	for _, g := range groupsByNorm {
		if len(g) > 1 {
			// stable order within group
			sorted := append([]string(nil), g...)
			sort.Strings(sorted)
			driftGroups = append(driftGroups, sorted)
		}
	}
	if len(driftGroups) == 0 {
		return "uniform", nil
	}

	// Categorize each drift group.
	caseGroups := [][]string{}
	sepGroups := [][]string{}
	mixedGroups := [][]string{}
	for _, group := range driftGroups {
		caseOnly := true
		sepOnly := true
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				a, b := group[i], group[j]
				if !sameAfterLowercase(a, b) {
					caseOnly = false
				}
				if !sameAfterStrippingSeparators(a, b) {
					sepOnly = false
				}
			}
		}
		switch {
		case caseOnly:
			caseGroups = append(caseGroups, group)
		case sepOnly:
			sepGroups = append(sepGroups, group)
		default:
			mixedGroups = append(mixedGroups, group)
		}
	}
	if len(caseGroups) > 0 {
		issues = append(issues, ValueFormatIssue{Type: "case_drift", Groups: caseGroups})
	}
	if len(sepGroups) > 0 {
		issues = append(issues, ValueFormatIssue{Type: "separator_drift", Groups: sepGroups})
	}
	if len(mixedGroups) > 0 {
		issues = append(issues, ValueFormatIssue{Type: "mixed_drift", Groups: mixedGroups})
	}
	return "messy", issues
}

// sameAfterLowercase reports whether a and b match after lowercasing only.
func sameAfterLowercase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ac, bc := a[i], b[i]
		if ac >= 'A' && ac <= 'Z' {
			ac += 32
		}
		if bc >= 'A' && bc <= 'Z' {
			bc += 32
		}
		if ac != bc {
			return false
		}
	}
	return true
}

// sameAfterStrippingSeparators reports whether a and b match after replacing
// any of `-_.` with nothing (and lowercasing).
func sameAfterStrippingSeparators(a, b string) bool {
	strip := func(s string) string {
		out := make([]byte, 0, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c == '-' || c == '_' || c == '.' {
				continue
			}
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			out = append(out, c)
		}
		return string(out)
	}
	return strip(a) == strip(b)
}

// computeKeySimilarityClusters groups keys that look like the same intent.
// Uses Levenshtein for typo detection + SubstringContainment for expansion
// variants + NormalizedEqual for case/separator drift.
func computeKeySimilarityClusters(keys []KeyStats) []SimilarityCluster {
	if len(keys) < 2 {
		return []SimilarityCluster{}
	}

	// Union-find over key names. Edge if any similarity rule fires.
	parent := map[string]string{}
	find := func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	for _, k := range keys {
		parent[k.Key] = k.Key
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	// Track evidence per pair so we can emit it at the end.
	type pairEvidence struct {
		a, b   string
		metric string
		score  int
		ratio  float64
	}
	var evidences []pairEvidence

	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			a, b := keys[i].Key, keys[j].Key
			merged := false
			if stats.NormalizedEqual(a, b) {
				union(a, b)
				evidences = append(evidences, pairEvidence{a, b, "case_only", 0, 0})
				merged = true
			}
			if !merged && stats.LikelyTypo(a, b) {
				d := stats.Levenshtein(stats.Normalize(a), stats.Normalize(b))
				union(a, b)
				evidences = append(evidences, pairEvidence{a, b, "levenshtein", d, 0})
				merged = true
			}
			if !merged {
				if ratio := stats.SubstringContainment(a, b); ratio >= 0.20 {
					union(a, b)
					evidences = append(evidences, pairEvidence{a, b, "substring", 0, ratio})
				}
			}
		}
	}

	// Build clusters from union-find: group keys by their root.
	clustersByRoot := map[string][]string{}
	for _, k := range keys {
		root := find(k.Key)
		clustersByRoot[root] = append(clustersByRoot[root], k.Key)
	}
	// Map cluster name → total occurrences
	occByKey := map[string]int{}
	for _, k := range keys {
		occByKey[k.Key] = k.TotalOccurrences
	}

	out := []SimilarityCluster{}
	for _, members := range clustersByRoot {
		if len(members) < 2 {
			continue
		}
		// Sort members alphabetically for stable output
		sort.Strings(members)
		// Pick canonical: highest total occurrences, tiebreak by alpha
		canonical := members[0]
		for _, m := range members {
			if occByKey[m] > occByKey[canonical] {
				canonical = m
			}
		}
		// Gather evidences whose pair is fully inside this cluster
		memberSet := map[string]bool{}
		for _, m := range members {
			memberSet[m] = true
		}
		clusterEvidence := []SimilarityEdge{}
		totalOcc := 0
		for _, m := range members {
			totalOcc += occByKey[m]
		}
		for _, ev := range evidences {
			if memberSet[ev.a] && memberSet[ev.b] {
				edge := SimilarityEdge{Pair: [2]string{ev.a, ev.b}, Metric: ev.metric}
				switch ev.metric {
				case "levenshtein":
					s := ev.score
					edge.Score = &s
				case "substring":
					r := round2(ev.ratio)
					edge.Ratio = &r
				}
				clusterEvidence = append(clusterEvidence, edge)
			}
		}
		// Sort evidence for stability
		sort.Slice(clusterEvidence, func(i, j int) bool {
			if clusterEvidence[i].Pair[0] != clusterEvidence[j].Pair[0] {
				return clusterEvidence[i].Pair[0] < clusterEvidence[j].Pair[0]
			}
			return clusterEvidence[i].Pair[1] < clusterEvidence[j].Pair[1]
		})
		out = append(out, SimilarityCluster{
			Canonical:        canonical,
			Variants:         members,
			Evidence:         clusterEvidence,
			TotalOccurrences: totalOcc,
		})
	}
	// Sort clusters by total occurrences desc
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalOccurrences != out[j].TotalOccurrences {
			return out[i].TotalOccurrences > out[j].TotalOccurrences
		}
		return out[i].Canonical < out[j].Canonical
	})
	return out
}

// computePropagationHints classifies coverage of each key across entity
// types, surfacing where a key is well-rolled-out vs missing.
func computePropagationHints(g *graph.Graph, keys []KeyStats) []PropagationHint {
	const (
		fullThreshold    = 0.95
		partialThreshold = 0.10
	)
	out := []PropagationHint{}
	for _, k := range keys {
		hint := PropagationHint{Key: k.Key}
		for _, t := range []graph.EntityType{graph.TypeHost, graph.TypeProcessGroup, graph.TypeProcessGroupInstance, graph.TypeService} {
			cov, ok := k.Coverage[string(t)]
			if !ok {
				continue
			}
			switch {
			case cov >= fullThreshold:
				hint.FullyCoveredOn = append(hint.FullyCoveredOn, string(t))
			case cov >= partialThreshold:
				hint.PartiallyCoveredOn = append(hint.PartiallyCoveredOn, string(t))
			default:
				hint.UncoveredOn = append(hint.UncoveredOn, string(t))
			}
		}
		// Call-graph hint for SERVICEs uncovered or partial.
		hint.CallGraphHint = generateCallGraphHint(g, k.Key)
		out = append(out, hint)
	}
	return out
}

// generateCallGraphHint returns a short human-readable hint if untagged
// services have tagged callers (or callees) for this key. Empty otherwise.
func generateCallGraphHint(g *graph.Graph, key string) string {
	taggedNeighborOfUntagged := 0
	for _, svc := range g.ByType[graph.TypeService] {
		if svc.HasTagKey(key) {
			continue
		}
		for _, neighbor := range graph.CallNeighbors(svc) {
			if neighbor.HasTagKey(key) {
				taggedNeighborOfUntagged++
				break
			}
		}
	}
	if taggedNeighborOfUntagged == 0 {
		return ""
	}
	return fmt.Sprintf("%d untagged services have at least one call-graph neighbor tagged with %q — likely inheritable via auto-tag rule",
		taggedNeighborOfUntagged, key)
}

// buildSubgraph produces the structural picture around low-tag entities.
// For "low_tag_only" mode, includes the low-tag entities + their immediate
// containment parents/children + call neighbors.
// For "full" mode, includes every node in the graph.
func buildSubgraph(g *graph.Graph, lowTagNodes []*graph.Node, mode string) *Subgraph {
	if mode == "full" {
		return buildFullSubgraph(g)
	}
	// low_tag_only: seeds = lowTagNodes; include each seed's immediate
	// parents/children/call neighbors. Already-included entities don't
	// duplicate.
	included := map[string]bool{}
	expand := func(n *graph.Node) {
		if n == nil {
			return
		}
		included[n.ID] = true
		for _, p := range n.ContainmentParents {
			included[p.ID] = true
		}
		for _, c := range n.ContainmentChildren {
			included[c.ID] = true
		}
		for _, x := range graph.CallNeighbors(n) {
			included[x.ID] = true
		}
	}
	for _, n := range lowTagNodes {
		expand(n)
	}
	return collectSubgraph(g, included)
}

func buildFullSubgraph(g *graph.Graph) *Subgraph {
	included := map[string]bool{}
	for id := range g.ByID {
		included[id] = true
	}
	return collectSubgraph(g, included)
}

func collectSubgraph(g *graph.Graph, included map[string]bool) *Subgraph {
	nodes := make([]SubgraphNode, 0, len(included))
	for id := range included {
		n := g.ByID[id]
		if n == nil {
			continue
		}
		sn := SubgraphNode{
			EntityID:    n.ID,
			Type:        string(n.Type),
			DisplayName: n.DisplayName,
			TagCount:    len(n.Tags),
			Tags:        n.Tags,
		}
		for _, p := range n.ContainmentParents {
			sn.ContainmentParentIDs = append(sn.ContainmentParentIDs, p.ID)
		}
		for _, c := range n.ContainmentChildren {
			sn.ContainmentChildrenIDs = append(sn.ContainmentChildrenIDs, c.ID)
		}
		for _, x := range n.CallsFrom {
			sn.CallsFromIDs = append(sn.CallsFromIDs, x.ID)
		}
		for _, x := range n.CallsTo {
			sn.CallsToIDs = append(sn.CallsToIDs, x.ID)
		}
		sn.ParentTagDistribution = tagDistributionByKey(n.ContainmentParents)
		sn.SiblingTagDistribution = tagDistributionByKey(graph.Siblings(n))
		sn.NeighborTagDistribution = tagDistributionByKey(graph.CallNeighbors(n))
		nodes = append(nodes, sn)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].EntityID < nodes[j].EntityID })
	return &Subgraph{Nodes: nodes}
}

// tagDistributionByKey returns key → value → count across a node list.
// Returns nil if the result would be empty (so JSON omits the field).
func tagDistributionByKey(nodes []*graph.Node) map[string]map[string]int {
	out := map[string]map[string]int{}
	for _, n := range nodes {
		for _, t := range n.Tags {
			if t.Key == "" {
				continue
			}
			if out[t.Key] == nil {
				out[t.Key] = map[string]int{}
			}
			val := t.Value
			if val == "" {
				val = "<no-value>"
			}
			out[t.Key][val]++
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// round2 rounds to 2 decimal places. Keeps coverage floats stable.
func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
