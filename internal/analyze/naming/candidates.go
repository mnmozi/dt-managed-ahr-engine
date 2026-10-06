// candidates.go — shared types + ranking primitives for naming candidates.
//
// Every analyzer in this package emits the same per-entity shape:
//
//   { entityId, currentName, genericReason, candidates[], topCandidate,
//     decision: "high_confidence" | "ambiguous" | "no_signal" }
//
// "Candidate" is the unit of evidence: a proposed name + the source it came
// from + a confidence score 0..1 + a human-readable evidence string.
//
// The bucketing thresholds are constants here so they're easy to tune
// after we see real-cluster data.
package naming

import (
	"sort"
	"strings"
)

// Confidence-bucket thresholds. Tuned conservatively — better to ask the
// operator than to mass-rename based on weak evidence.
const (
	// HighConfidenceMin is the minimum confidence for the top candidate to
	// qualify as "high_confidence". Combined with HighConfidenceGap below.
	HighConfidenceMin = 0.80

	// HighConfidenceGap is the minimum gap between the top and the
	// runner-up. Without a clear winner we drop to "ambiguous".
	HighConfidenceGap = 0.20

	// AmbiguousMin is the minimum top-candidate confidence for "ambiguous".
	// Below this we emit "no_signal" — refuse to suggest anything.
	AmbiguousMin = 0.40
)

// Candidate is one proposed name with its evidence.
type Candidate struct {
	Source     string  `json:"source"`     // e.g. "jar.filename", "k8s.container", "cli.arg.name"
	Name       string  `json:"name"`       // the proposed name itself
	Confidence float64 `json:"confidence"` // 0..1
	Evidence   string  `json:"evidence"`   // human-readable raw fact
}

// Decision is the engine's recommendation for how to handle this entity.
// Mirrors the AI/human interaction lattice — the MCP write tool enforces
// which decider is allowed per decision.
type Decision string

const (
	DecisionHighConfidence Decision = "high_confidence" // engine picks; operator approves
	DecisionAmbiguous      Decision = "ambiguous"       // AI/operator picks from slate
	DecisionNoSignal       Decision = "no_signal"       // refuse to suggest; manual review
)

// EntityNamingReport is the per-entity output shape, identical across
// process-group, host, and host-group analyzers.
type EntityNamingReport struct {
	EntityID      string      `json:"entityId"`
	EntityType    string      `json:"entityType"`
	CurrentName   string      `json:"currentName"`
	GenericReason string      `json:"genericReason"` // why we flagged it
	Candidates    []Candidate `json:"candidates"`
	TopCandidate  string      `json:"topCandidate,omitempty"` // empty when decision = no_signal
	Decision      Decision    `json:"decision"`
	// Corroborating lists candidates that MATCH the entity's current name —
	// not renames, but evidence the current name is right ("k8s container
	// agrees"). Always emitted when present.
	Corroborating []Candidate `json:"corroborating,omitempty"`
	// RejectedCandidates lists every candidate a branch produced that the
	// central filter dropped, with the reason. Populated only when the
	// analyzer input sets explain=true — it exists so an operator asking
	// "why did/didn't X get a recommendation?" always has a written answer,
	// without per-case diagnostics code.
	RejectedCandidates []RejectedCandidate `json:"rejectedCandidates,omitempty"`
}

// RejectedCandidate is a candidate plus the filter rule that dropped it.
type RejectedCandidate struct {
	Candidate
	Reason string `json:"reason"`
}

// filterCandidates applies the universal candidate rules in one place —
// every analyzer (PG / host / service) funnels through here via
// finishReport, so a new rule lands everywhere at once:
//
//	1. empty        — the raw value normalized to nothing
//	2. self         — proposing the entity's current name back is noise
//	3. too long     — >40 chars is not a name anyone applies as a tag
//	4. generic      — bare techs / port-only names name nothing
//	   (exempt for source "tech.only": that branch is deliberately a
//	   bare-tech last resort, e.g. PG ":80" → "nginx" is useful)
//
// Returns kept (rename suggestions), corroborating (candidates matching
// the current name — evidence it's right), and rejected with reasons.
func filterCandidates(raw []Candidate, currentName string) ([]Candidate, []Candidate, []RejectedCandidate) {
	self := cleanName(currentName)
	kept := make([]Candidate, 0, len(raw))
	corroborating := []Candidate{}
	rejected := []RejectedCandidate{}
	for _, c := range raw {
		switch {
		case strings.TrimSpace(c.Name) == "":
			rejected = append(rejected, RejectedCandidate{c, "raw value normalized to an empty name"})
		case self != "" && c.Name == self:
			corroborating = append(corroborating, c)
		case len(c.Name) > 40:
			rejected = append(rejected, RejectedCandidate{c, "candidate exceeds 40 chars — not a usable tag value"})
		case c.Source != "tech.only" && isGenericCandidate(c.Name):
			rejected = append(rejected, RejectedCandidate{c, "candidate is itself generic (bare technology / port-only)"})
		default:
			kept = append(kept, c)
		}
	}
	return kept, corroborating, rejected
}

// BucketAndRank takes the raw candidate list for one entity, sorts it by
// confidence descending, drops duplicates (same name, keep the highest-
// confidence source), and assigns the decision bucket. Returns the sorted
// candidates and the decision.
//
// Duplicate handling matters because multiple sources commonly agree —
// e.g. JarFile says "orders-svc" and KubernetesContainer says "orders-svc".
// When they agree we keep the higher-confidence one and discard the dup;
// we do NOT boost the confidence past 1.0 (keeps the score interpretable).
func BucketAndRank(raw []Candidate) ([]Candidate, Decision) {
	if len(raw) == 0 {
		return nil, DecisionNoSignal
	}

	// Sort descending by confidence (stable so source order is preserved on ties).
	sorted := make([]Candidate, len(raw))
	copy(sorted, raw)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Confidence > sorted[j].Confidence
	})

	// Dedupe by name, keeping the first (highest-confidence) occurrence.
	seen := make(map[string]struct{}, len(sorted))
	deduped := make([]Candidate, 0, len(sorted))
	for _, c := range sorted {
		if _, ok := seen[c.Name]; ok {
			continue
		}
		seen[c.Name] = struct{}{}
		deduped = append(deduped, c)
	}

	top := deduped[0]
	if top.Confidence < AmbiguousMin {
		return deduped, DecisionNoSignal
	}
	if len(deduped) == 1 {
		if top.Confidence >= HighConfidenceMin {
			return deduped, DecisionHighConfidence
		}
		return deduped, DecisionAmbiguous
	}
	runnerUp := deduped[1]
	gap := top.Confidence - runnerUp.Confidence
	if top.Confidence >= HighConfidenceMin && gap >= HighConfidenceGap {
		return deduped, DecisionHighConfidence
	}
	return deduped, DecisionAmbiguous
}

// finishReport packages a bucketed list into the per-entity report shape.
// By default returns nil for non-generic entities (focused output for the
// AHR flow). With includeUnflagged=true (the auditAll mode) a report is
// built for EVERY entity — genericReason stays "" for healthy names, and
// the candidates become advisory suggestions the operator may ignore.
// All candidate filtering happens HERE via filterCandidates — branches
// emit raw candidates and stay filter-free. Corroborating candidates
// (matching the current name) always ride along; rejected ones only with
// explain=true.
func finishReport(entityID, entityType, currentName, genericReason string, raw []Candidate, explain, includeUnflagged bool) *EntityNamingReport {
	if genericReason == "" && !includeUnflagged {
		return nil
	}
	filtered, corroborating, rejected := filterCandidates(raw, currentName)
	candidates, decision := BucketAndRank(filtered)
	top := ""
	if decision != DecisionNoSignal && len(candidates) > 0 {
		top = candidates[0].Name
	}
	rep := &EntityNamingReport{
		EntityID:      entityID,
		EntityType:    entityType,
		CurrentName:   currentName,
		GenericReason: genericReason,
		Candidates:    candidates,
		TopCandidate:  top,
		Decision:      decision,
		Corroborating: corroborating,
	}
	if explain {
		rep.RejectedCandidates = rejected
	}
	return rep
}
