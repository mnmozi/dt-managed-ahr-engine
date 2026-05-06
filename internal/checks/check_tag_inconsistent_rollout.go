// Check: CHECK_TAG_INCONSISTENT_ROLLOUT
//
// A tag key with coverage in the 25–75% band on a given entity type is the
// most diagnostic tagging finding in the AHR. It says: someone TRIED to
// roll the tag out, made meaningful progress, and stopped. That's worse
// than "didn't try at all" (clear signal: nobody owns it) and worse than
// "consensus" (clear signal: it's canonical).
//
// Most accounts have a small number of these. Each one is worth flagging
// because it forces a decision: complete the rollout, or retire the key.
//
// Logic:
//   For each entity type with at least MinEntityCountForCoverage entities in
//   the bundle, count how many of them carry each tag key. If coverage is in
//   the [InconsistentLow, InconsistentHigh) band, emit one finding per
//   (entity_type, key) combination.
//
// Thresholds are constants (versioned with the engine) — not arbitrary
// per-customer settings. If we discover specific industry verticals need
// different bands, we'll add a per-account-config override later.
package checks

import (
	"fmt"
	"sort"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

const (
	// InconsistentLow is the lower bound of the diagnostic band. Below this,
	// the key is "long-tail / ad-hoc" — different finding category.
	InconsistentLow = 0.25
	// InconsistentHigh is the upper bound. At-or-above this, the key is at
	// least "incomplete consensus" — different finding category.
	InconsistentHigh = 0.75
	// MinEntityCountForCoverage avoids flagging on tiny populations where
	// 1–2 missing entities throw the percentage around. Below this many
	// entities, percentages aren't meaningful enough to act on.
	MinEntityCountForCoverage = 10
)

// TagInconsistentRollout is the registered check.
type TagInconsistentRollout struct{}

func (TagInconsistentRollout) ID() string    { return "CHECK_TAG_INCONSISTENT_ROLLOUT" }
func (TagInconsistentRollout) Phase() string { return "Phase 1" }

func (c TagInconsistentRollout) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.EntitiesByType) == 0 {
		return nil
	}

	var findings []finding.Finding

	// Stable order across entity types so findings are reproducible.
	var entityTypes []string
	for t := range b.EntitiesByType {
		entityTypes = append(entityTypes, t)
	}
	sort.Strings(entityTypes)

	for _, entityType := range entityTypes {
		entities := b.EntitiesByType[entityType]
		total := len(entities)
		if total < MinEntityCountForCoverage {
			continue
		}

		// Count entities per tag key.
		keyCounts := map[string]int{}
		for _, e := range entities {
			seen := map[string]bool{} // an entity tagged with the same key twice still only counts once
			for _, t := range e.Tags {
				if t.Key == "" || seen[t.Key] {
					continue
				}
				seen[t.Key] = true
				keyCounts[t.Key]++
			}
		}

		// Stable order across keys.
		var keys []string
		for k := range keyCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			count := keyCounts[key]
			coverage := float64(count) / float64(total)
			if coverage < InconsistentLow || coverage >= InconsistentHigh {
				continue
			}

			findings = append(findings, finding.Finding{
				ID:       c.ID(),
				Phase:    c.Phase(),
				Severity: severityForInconsistentRollout(coverage),
				Title: fmt.Sprintf(
					"Tag key %q has inconsistent rollout on %s (%.0f%% coverage, %d of %d entities)",
					key, entityType, coverage*100, count, total,
				),
				Description: fmt.Sprintf(
					"Tag key %q is present on %d of %d %s entities (%.0f%%) — inside the "+
						"%.0f-%.0f%% inconsistent-rollout band. The org started rolling this "+
						"key out but didn't finish. Decide: is this canonical (and we should "+
						"close the gap) or experimental (and we should retire it)?",
					key, count, total, entityType, coverage*100,
					InconsistentLow*100, InconsistentHigh*100,
				),
				Evidence: finding.Evidence{
					Tool:    "dynatrace_managed_discover_entities + per-entity tags",
					RawPath: rawPathForEntityType(entityType),
					DataPoint: fmt.Sprintf(
						"entityType=%s key=%q withKey=%d total=%d coverage=%.2f",
						entityType, key, count, total, coverage,
					),
				},
				Recommendation: fmt.Sprintf(
					"Decide whether %q is canonical for %s entities. If yes: extend the "+
						"auto-tag rule conditions (or the manual-tagging process) so the "+
						"remaining %d entities pick it up. If no: retire the tag from the "+
						"%d entities currently carrying it.",
					key, entityType, total-count, count,
				),
				EntityRef: &finding.EntityRef{
					Kind: "rule",
					ID:   fmt.Sprintf("%s/%s", entityType, key),
					Name: key,
				},
			})
		}
	}

	return findings
}

// severityForInconsistentRollout maps coverage within the band to severity.
// 25–50%: Medium (heavy lift to complete; might be the right time to retire)
// 50–75%: Low (closer to consensus; usually finish the rollout)
func severityForInconsistentRollout(coverage float64) finding.Severity {
	if coverage < 0.50 {
		return finding.SeverityMedium
	}
	return finding.SeverityLow
}

func rawPathForEntityType(entityType string) string {
	switch entityType {
	case "HOST":
		return "raw/phase1-hosts-all.json"
	case "HOST_GROUP":
		return "raw/phase1-hostgroups-all.json"
	case "PROCESS_GROUP":
		return "raw/phase2-pgs-all.json"
	case "PROCESS_GROUP_INSTANCE":
		return "raw/phase2-pgis-all.json"
	case "SERVICE":
		return "raw/phase4-services-all.json"
	}
	return "raw/<entity-type-specific>.json"
}
