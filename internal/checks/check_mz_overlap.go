// Check: CHECK_MZ_OVERLAP
//
// Two management zones with substantial entity overlap (Jaccard similarity
// above the threshold) are likely either:
//   - the same logical scope expressed twice (consolidate)
//   - parent/child scopes that should be made disjoint
//   - a recent split where the old MZ wasn't retired
//
// Some overlap is legitimate (a HOST can validly be in both an "env: prod" MZ
// and a "team: payments" MZ — they describe orthogonal things). The
// interesting overlap is when two MZs share a large fraction of the SAME
// entities, which suggests they're describing the same thing.
//
// Logic:
//   1. Build mzName → set of entityIds across loaded entity types.
//   2. For every pair (A, B) of MZs where both have at least
//      OverlapMinSize entities, compute Jaccard = |A ∩ B| / |A ∪ B|.
//   3. If Jaccard >= OverlapThreshold, emit one finding per pair.
//
// Pair findings are deduplicated by ordering pair names alphabetically.
package checks

import (
	"fmt"
	"sort"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

const (
	// OverlapMinSize avoids flagging pairs where both MZs are tiny — Jaccard
	// is unstable on small sets.
	OverlapMinSize = 5
	// OverlapThreshold is the Jaccard similarity at or above which two MZs
	// are considered substantially overlapping.
	OverlapThreshold = 0.5
)

// MZOverlap is the registered check.
type MZOverlap struct{}

func (MZOverlap) ID() string    { return "CHECK_MZ_OVERLAP" }
func (MZOverlap) Phase() string { return "Phase 3" }

func (c MZOverlap) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.EntitiesByType) == 0 {
		return nil
	}

	// Build mzName → set(entityId).
	mzMembers := map[string]map[string]bool{}
	for _, entities := range b.EntitiesByType {
		for _, e := range entities {
			for _, mz := range e.ManagementZones {
				if mz.Name == "" {
					continue
				}
				if mzMembers[mz.Name] == nil {
					mzMembers[mz.Name] = map[string]bool{}
				}
				mzMembers[mz.Name][e.EntityID] = true
			}
		}
	}

	if len(mzMembers) < 2 {
		return nil
	}

	// Stable iteration over MZ names.
	names := make([]string, 0, len(mzMembers))
	for n := range mzMembers {
		if len(mzMembers[n]) >= OverlapMinSize {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	var findings []finding.Finding
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			a, b := names[i], names[j]
			setA, setB := mzMembers[a], mzMembers[b]

			intersection := 0
			for id := range setA {
				if setB[id] {
					intersection++
				}
			}
			union := len(setA) + len(setB) - intersection
			if union == 0 {
				continue
			}
			jaccard := float64(intersection) / float64(union)
			if jaccard < OverlapThreshold {
				continue
			}

			findings = append(findings, finding.Finding{
				ID:       c.ID(),
				Phase:    c.Phase(),
				Severity: finding.SeverityLow,
				Title: fmt.Sprintf(
					"Management zones %q and %q substantially overlap (Jaccard=%.2f, intersection=%d, union=%d)",
					a, b, jaccard, intersection, union,
				),
				Description: fmt.Sprintf(
					"MZs %q (%d entities) and %q (%d entities) share %d entities — Jaccard "+
						"similarity %.2f, at or above the %.2f threshold for substantial overlap. "+
						"They likely describe the same logical scope, are a parent/child pair "+
						"that should be made disjoint, or a recent split where the old MZ wasn't "+
						"retired. Consolidate or scope-narrow.",
					a, len(setA), b, len(setB), intersection, jaccard, OverlapThreshold,
				),
				Evidence: finding.Evidence{
					Tool:    "dt_get_management_zones + entity inventory",
					RawPath: "raw/phase3-management-zones.json",
					DataPoint: fmt.Sprintf(
						"mzA=%q sizeA=%d mzB=%q sizeB=%d intersection=%d union=%d jaccard=%.4f",
						a, len(setA), b, len(setB), intersection, union, jaccard,
					),
				},
				Recommendation: fmt.Sprintf(
					"Review MZs %q and %q. If they describe the same scope, consolidate. "+
						"If one is a parent of the other, narrow the rules so they're disjoint. "+
						"If both are intentional and overlap is expected, ratify (no action needed).",
					a, b,
				),
				EntityRef: &finding.EntityRef{
					Kind: "rule",
					ID:   fmt.Sprintf("MZ_PAIR/%s/%s", a, b),
					Name: fmt.Sprintf("%s ↔ %s", a, b),
				},
			})
		}
	}
	return findings
}
