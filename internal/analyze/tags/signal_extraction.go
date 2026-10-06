// signal_extraction.go — for low-tag entities + target keys, walk both the
// entity's properties AND the graph (parents / descendants / siblings /
// call neighbors) to produce ranked candidate values with deterministic
// confidence.
//
// Pure function. The AI doesn't walk the graph — it reads this analyzer's
// output and makes the semantic call ("does this candidate make sense?").
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
	analyze.Register(SignalExtraction{})
}

// SignalExtraction is the analyzer.
type SignalExtraction struct{}

func (SignalExtraction) Kind() string { return "tags.signal_extraction" }

func (SignalExtraction) Description() string {
	return "For target keys + entities, extract candidate values from properties AND graph neighbors (containment + call edges). Returns ranked candidates with deterministic confidence (boosted by existing-tag-value matches, ownership-directory matches, multi-source corroboration). The AI reads candidates and decides which to apply; never walks the graph itself."
}

// ExtractionInput is what consumers pass in.
type ExtractionInput struct {
	graph.Input
	// EntitiesToProcess limits which entities we extract for. If empty, ALL
	// entities are processed (heavy on big tenants).
	EntitiesToProcess []EntityRef `json:"entitiesToProcess,omitempty"`
	// TargetKeys are the tag keys we're trying to find values for. Required.
	TargetKeys []string `json:"targetKeys"`
	// ExistingTagValues per key — values already present on other entities.
	// Engine boosts confidence when a candidate matches an existing value.
	ExistingTagValues map[string][]string `json:"existingTagValues,omitempty"`
	// OwnershipTeams — names from builtin:ownership.teams (the directory).
	// Engine boosts confidence on team-like keys when value matches.
	OwnershipTeams []string `json:"ownershipTeams,omitempty"`
	// CallGraphMajorityThreshold — fraction of neighbors needed to count as a
	// majority signal. Default 0.66.
	CallGraphMajorityThreshold float64 `json:"callGraphMajorityThreshold,omitempty"`
	// ConsensusMinConfidence — minimum confidence for a value to be the
	// consensus pick. Default 0.70.
	ConsensusMinConfidence float64 `json:"consensusMinConfidence,omitempty"`
	// ConsensusMinSources — minimum distinct sources agreeing for consensus.
	// Default 2.
	ConsensusMinSources int `json:"consensusMinSources,omitempty"`
}

// EntityRef is a minimal pointer to a specific entity by id.
type EntityRef struct {
	ID string `json:"id"`
}

// ExtractionOutput is the analyzer result.
type ExtractionOutput struct {
	Entities        []EntityExtraction       `json:"entities"`
	Summary         ExtractionSummary        `json:"summary"`
	AppliedDefaults ExtractionAppliedDefaults `json:"appliedDefaults"`
}

// EntityExtraction is per-entity extraction output.
type EntityExtraction struct {
	EntityID    string                       `json:"entityId"`
	Type        string                       `json:"type"`
	DisplayName string                       `json:"displayName,omitempty"`
	// Candidates keyed by target key → ranked list (desc confidence).
	Candidates map[string][]Candidate `json:"candidates"`
	// Consensus per key — the engine's best guess if confidence + source
	// count thresholds are met. Empty if no consensus.
	Consensus map[string]ConsensusValue `json:"consensus,omitempty"`
}

// Candidate is one ranked candidate value for one target key.
type Candidate struct {
	Source     string   `json:"source"`     // e.g. "property:envVar:OWNING_TEAM", "graph:parentTag:HOST-A"
	Value      string   `json:"value"`
	Confidence float64  `json:"confidence"`
	Factors    []string `json:"factors,omitempty"` // why this confidence (audit trail)
	// Evidence may be present when the source needs explanation, e.g.
	// for call-graph majority: "4 of 5 callers agree".
	Evidence string `json:"evidence,omitempty"`
}

// ConsensusValue is the consensus pick for one key on one entity.
type ConsensusValue struct {
	Value          string   `json:"value"`
	Confidence     float64  `json:"confidence"` // highest among sources contributing
	SourceCount    int      `json:"sourceCount"`
	ContributingSources []string `json:"contributingSources"`
}

// ExtractionSummary is the roll-up.
type ExtractionSummary struct {
	ProcessedEntities       int                    `json:"processedEntities"`
	EntitiesWithCandidates  int                    `json:"entitiesWithCandidates"`
	EntitiesWithConsensus   int                    `json:"entitiesWithConsensus"`
	EntitiesWithNoCandidates int                   `json:"entitiesWithNoCandidates"`
	ConsensusCountByKey     map[string]int         `json:"consensusCountByKey"`
}

// ExtractionAppliedDefaults shows the actual thresholds used.
type ExtractionAppliedDefaults struct {
	CallGraphMajorityThreshold float64  `json:"callGraphMajorityThreshold"`
	ConsensusMinConfidence     float64  `json:"consensusMinConfidence"`
	ConsensusMinSources        int      `json:"consensusMinSources"`
	TargetKeys                 []string `json:"targetKeys"`
}

// Confidence scoring tuned for clarity. Tweak as we observe real data.
const (
	baseScorePropertyDirectMatch = 0.60 // env var named exactly the target key
	baseScorePropertyContains    = 0.50 // env var contains the target key (OWNING_TEAM for "team")
	baseScoreParentContainment   = 0.55
	baseScoreSiblingMajority     = 0.40
	baseScoreCallGraphMajority   = 0.35
	baseScoreDescendantMajority  = 0.45
	bonusExistingTagValueMatch   = 0.20
	bonusOwnershipDirectoryMatch = 0.20
	bonusValueNormalizeMatch     = 0.10
	bonusMultiSourceCorroboration = 0.10
	maxMultiSourceBoost          = 0.30
	confidenceCap                = 1.00
)

// Run is the analyzer entrypoint.
func (SignalExtraction) Run(raw json.RawMessage) (any, error) {
	var in ExtractionInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	if len(in.TargetKeys) == 0 {
		return nil, fmt.Errorf("targetKeys is required (provide at least one key)")
	}
	majorityT := in.CallGraphMajorityThreshold
	if majorityT <= 0 || majorityT > 1 {
		majorityT = 0.66
	}
	consMin := in.ConsensusMinConfidence
	if consMin <= 0 || consMin > 1 {
		consMin = 0.70
	}
	consSrc := in.ConsensusMinSources
	if consSrc < 1 {
		consSrc = 2
	}

	g := graph.Build(in.Input)

	// Pre-index lookups
	existingValueSet := map[string]map[string]bool{}
	existingValueNormSet := map[string]map[string]bool{}
	for k, vs := range in.ExistingTagValues {
		existingValueSet[k] = map[string]bool{}
		existingValueNormSet[k] = map[string]bool{}
		for _, v := range vs {
			existingValueSet[k][v] = true
			existingValueNormSet[k][stats.Normalize(v)] = true
		}
	}
	ownershipSet := map[string]bool{}
	ownershipNormSet := map[string]bool{}
	for _, t := range in.OwnershipTeams {
		ownershipSet[t] = true
		ownershipNormSet[stats.Normalize(t)] = true
	}

	// Resolve which entities to process
	targets := resolveTargets(g, in.EntitiesToProcess)

	out := ExtractionOutput{
		Entities: []EntityExtraction{},
		Summary: ExtractionSummary{
			ConsensusCountByKey: map[string]int{},
		},
		AppliedDefaults: ExtractionAppliedDefaults{
			CallGraphMajorityThreshold: majorityT,
			ConsensusMinConfidence:     consMin,
			ConsensusMinSources:        consSrc,
			TargetKeys:                 in.TargetKeys,
		},
	}

	for _, n := range targets {
		ext := extractForEntity(n, in.TargetKeys, existingValueSet, existingValueNormSet, ownershipSet, ownershipNormSet, majorityT)
		// Compute consensus
		ext.Consensus = map[string]ConsensusValue{}
		for _, k := range in.TargetKeys {
			cands := ext.Candidates[k]
			if cv, ok := pickConsensus(cands, consMin, consSrc); ok {
				ext.Consensus[k] = cv
				out.Summary.ConsensusCountByKey[k]++
			}
		}
		if len(ext.Consensus) == 0 {
			ext.Consensus = nil // omitempty
		}

		out.Summary.ProcessedEntities++
		anyCands := false
		for _, list := range ext.Candidates {
			if len(list) > 0 {
				anyCands = true
				break
			}
		}
		if anyCands {
			out.Summary.EntitiesWithCandidates++
		} else {
			out.Summary.EntitiesWithNoCandidates++
		}
		if ext.Consensus != nil {
			out.Summary.EntitiesWithConsensus++
		}
		out.Entities = append(out.Entities, ext)
	}

	// Stable order
	sort.Slice(out.Entities, func(i, j int) bool {
		return out.Entities[i].EntityID < out.Entities[j].EntityID
	})

	return out, nil
}

// resolveTargets returns the nodes for the requested entity ids, or all
// nodes if EntitiesToProcess is empty.
func resolveTargets(g *graph.Graph, refs []EntityRef) []*graph.Node {
	if len(refs) == 0 {
		out := make([]*graph.Node, 0, len(g.ByID))
		for _, n := range g.ByID {
			out = append(out, n)
		}
		return out
	}
	out := make([]*graph.Node, 0, len(refs))
	for _, r := range refs {
		if n := g.ByID[r.ID]; n != nil {
			out = append(out, n)
		}
	}
	return out
}

// extractForEntity computes candidates for one entity + every target key.
func extractForEntity(
	n *graph.Node,
	targetKeys []string,
	existingValues map[string]map[string]bool,
	existingValuesNorm map[string]map[string]bool,
	ownership map[string]bool,
	ownershipNorm map[string]bool,
	majorityT float64,
) EntityExtraction {
	ext := EntityExtraction{
		EntityID:    n.ID,
		Type:        string(n.Type),
		DisplayName: n.DisplayName,
		Candidates:  map[string][]Candidate{},
	}
	for _, key := range targetKeys {
		// Don't extract if the entity already has this tag (caller should
		// usually filter, but be defensive).
		if n.HasTagKey(key) {
			continue
		}
		all := []Candidate{}
		// Source 1: properties
		all = append(all, extractFromProperties(n, key)...)
		// Source 2: containment parents — direct ancestors with the key
		for _, p := range n.ContainmentParents {
			for _, v := range p.TagValues(key) {
				if v == "" {
					continue
				}
				all = append(all, Candidate{
					Source:     fmt.Sprintf("graph:parentTag:%s:%s", p.Type, p.ID),
					Value:      v,
					Confidence: baseScoreParentContainment,
					Factors:    []string{"parent-containment-tag"},
				})
			}
		}
		// Source 3: descendant majority
		descendants := graph.Descendants(n)
		if v, count, total, ok := graph.MajorityValue(descendants, key, majorityT); ok {
			all = append(all, Candidate{
				Source:     "graph:descendantMajority",
				Value:      v,
				Confidence: baseScoreDescendantMajority,
				Factors:    []string{"descendant-majority"},
				Evidence:   fmt.Sprintf("%d of %d descendants with this key agree", count, total),
			})
		}
		// Source 4: sibling majority
		siblings := graph.Siblings(n)
		if v, count, total, ok := graph.MajorityValue(siblings, key, majorityT); ok {
			all = append(all, Candidate{
				Source:     "graph:siblingMajority",
				Value:      v,
				Confidence: baseScoreSiblingMajority,
				Factors:    []string{"sibling-majority"},
				Evidence:   fmt.Sprintf("%d of %d siblings with this key agree", count, total),
			})
		}
		// Source 5: call-graph majority
		neighbors := graph.CallNeighbors(n)
		if v, count, total, ok := graph.MajorityValue(neighbors, key, majorityT); ok {
			all = append(all, Candidate{
				Source:     "graph:callGraphMajority",
				Value:      v,
				Confidence: baseScoreCallGraphMajority,
				Factors:    []string{"call-graph-majority"},
				Evidence:   fmt.Sprintf("%d of %d call neighbors with this key agree", count, total),
			})
		}

		// Apply value-match bonuses, ownership-directory bonus,
		// multi-source corroboration bonus.
		all = applyBonuses(all, key, existingValues, existingValuesNorm, ownership, ownershipNorm)
		// Sort by confidence desc, then by source for stability
		sort.SliceStable(all, func(i, j int) bool {
			if all[i].Confidence != all[j].Confidence {
				return all[i].Confidence > all[j].Confidence
			}
			return all[i].Source < all[j].Source
		})
		if len(all) > 0 {
			ext.Candidates[key] = all
		}
	}
	return ext
}

// extractFromProperties looks for keys in the entity's Properties bag that
// match the target key (direct or contains-match).
//
// Recognized property field shapes:
//   - Plain string fields whose name contains the target key
//     ("envVars" / "metadata" map of string→string is also walked)
//   - Maps where the key matches and the value is a string
//   - Arrays of {key, value} objects (AWS/Azure tag style)
//
// All matching is done on normalized field names (lowercase + alnum only).
func extractFromProperties(n *graph.Node, key string) []Candidate {
	if n.Properties == nil {
		return nil
	}
	keyNorm := stats.Normalize(key)
	out := []Candidate{}

	walk := func(prefix, fieldName string, value any) {
		// Scalar string value
		v, ok := value.(string)
		if !ok || v == "" {
			return
		}
		fnNorm := stats.Normalize(fieldName)
		if fnNorm == keyNorm {
			out = append(out, Candidate{
				Source:     fmt.Sprintf("property:%s%s", prefix, fieldName),
				Value:      v,
				Confidence: baseScorePropertyDirectMatch,
				Factors:    []string{"property-direct-match"},
			})
		} else if strings.Contains(fnNorm, keyNorm) {
			out = append(out, Candidate{
				Source:     fmt.Sprintf("property:%s%s", prefix, fieldName),
				Value:      v,
				Confidence: baseScorePropertyContains,
				Factors:    []string{"property-contains-match"},
			})
		}
	}

	for fieldName, fieldVal := range n.Properties {
		switch fv := fieldVal.(type) {
		case string:
			walk("", fieldName, fv)
		case map[string]any:
			// Nested map (envVars, k8sLabels, metadata, etc.)
			for k, v := range fv {
				walk(fieldName+":", k, v)
			}
		case []any:
			// Array of {key, value} objects (awsTags / azureTags / etc.)
			for _, item := range fv {
				obj, ok := item.(map[string]any)
				if !ok {
					continue
				}
				kStr, _ := obj["key"].(string)
				vStr, _ := obj["value"].(string)
				if kStr == "" {
					continue
				}
				walk(fieldName+":", kStr, vStr)
			}
		}
	}
	return out
}

// applyBonuses adjusts each candidate's confidence based on:
//   - whether the value exists exactly in existingValues[key]
//   - whether it normalize-matches an existing value
//   - whether it appears in the ownership directory (for team-like keys)
//   - multi-source corroboration (multiple distinct sources agreeing on
//     the same value)
//
// Returns a new slice with adjusted confidences; original is not mutated.
func applyBonuses(
	cands []Candidate,
	key string,
	existingValues map[string]map[string]bool,
	existingValuesNorm map[string]map[string]bool,
	ownership map[string]bool,
	ownershipNorm map[string]bool,
) []Candidate {
	if len(cands) == 0 {
		return cands
	}
	// Count distinct sources per value for corroboration boost.
	sourcesPerValue := map[string]map[string]bool{}
	for _, c := range cands {
		if sourcesPerValue[c.Value] == nil {
			sourcesPerValue[c.Value] = map[string]bool{}
		}
		sourcesPerValue[c.Value][c.Source] = true
	}

	out := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		c2 := c
		boost := 0.0
		// Existing value match
		if existingValues[key] != nil && existingValues[key][c2.Value] {
			boost += bonusExistingTagValueMatch
			c2.Factors = append(c2.Factors, "existing-tag-value-match")
		} else if existingValuesNorm[key] != nil && existingValuesNorm[key][stats.Normalize(c2.Value)] {
			boost += bonusValueNormalizeMatch
			c2.Factors = append(c2.Factors, "existing-tag-value-normalize-match")
		}
		// Ownership directory match — only meaningful for team-like keys.
		// We apply this bonus when the consumer provided an ownership list,
		// regardless of the key name. The consumer decides which keys are
		// team-like by what they pass in.
		if len(ownership) > 0 {
			if ownership[c2.Value] {
				boost += bonusOwnershipDirectoryMatch
				c2.Factors = append(c2.Factors, "ownership-directory-match")
			} else if ownershipNorm[stats.Normalize(c2.Value)] {
				boost += bonusValueNormalizeMatch
				c2.Factors = append(c2.Factors, "ownership-directory-normalize-match")
			}
		}
		// Multi-source corroboration
		distinctSources := len(sourcesPerValue[c2.Value])
		if distinctSources > 1 {
			extra := float64(distinctSources-1) * bonusMultiSourceCorroboration
			if extra > maxMultiSourceBoost {
				extra = maxMultiSourceBoost
			}
			boost += extra
			c2.Factors = append(c2.Factors, fmt.Sprintf("multi-source-corroboration:%d", distinctSources))
		}
		c2.Confidence += boost
		if c2.Confidence > confidenceCap {
			c2.Confidence = confidenceCap
		}
		c2.Confidence = round2(c2.Confidence)
		out = append(out, c2)
	}
	return out
}

// pickConsensus selects the top candidate as consensus if it meets the
// minimum confidence + distinct-source thresholds.
//
// Rule: highest-confidence candidate value; confidence must reach
// consMin; the value must appear in ≥ consSrc distinct sources.
func pickConsensus(cands []Candidate, consMin float64, consSrc int) (ConsensusValue, bool) {
	if len(cands) == 0 {
		return ConsensusValue{}, false
	}
	// cands is sorted desc by confidence. Find the top value's source count.
	top := cands[0]
	if top.Confidence < consMin {
		return ConsensusValue{}, false
	}
	sources := []string{}
	for _, c := range cands {
		if c.Value == top.Value {
			sources = append(sources, c.Source)
		}
	}
	if len(sources) < consSrc {
		return ConsensusValue{}, false
	}
	sort.Strings(sources)
	return ConsensusValue{
		Value:               top.Value,
		Confidence:          top.Confidence,
		SourceCount:         len(sources),
		ContributingSources: sources,
	}, true
}
