// Check: CHECK_AUTO_TAG_OVERBROAD
//
// An auto-tag rule is "overbroad" when the tag key it produces ends up on a
// dominant share of entities of at least one type — typically a sign that
// the rule's conditions are too generic (or absent), so the rule applies to
// almost everything instead of the intended subset.
//
// Heuristic, v1:
//
//   For each rule, look at every entity type loaded in the bundle. Compute
//   what percentage of entities of that type carry the rule's produced
//   tag key. If the highest-coverage type sits above the OverbroadCoverageThreshold
//   AND has at least MinEntityCountForSignal entities, flag the rule.
//
//   This intentionally produces false positives on legitimate "applies to
//   everything" tags (e.g. an `env` tag in a single-environment cluster).
//   The recommendation is to REVIEW, not to delete, so the CSE can confirm
//   intent. Better to flag and review than to miss a genuine misconfiguration.
//
//   v2 could narrow this by also requiring that the rule has no condition
//   tighter than "type matches X" — but evaluating rule conditions is a
//   bigger surface to maintain and we deferred it.
package checks

import (
	"fmt"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

const (
	// OverbroadCoverageThreshold is the per-entity-type coverage at or above
	// which a rule is considered overbroad. 0.95 = 95% of entities of that type.
	OverbroadCoverageThreshold = 0.95
	// MinEntityCountForSignal avoids flagging on tiny populations where one
	// or two entities skew the percentage. With <10 entities, the data is too
	// noisy to draw conclusions.
	MinEntityCountForSignal = 10
)

// AutoTagOverbroad is the registered check.
type AutoTagOverbroad struct{}

func (AutoTagOverbroad) ID() string    { return "CHECK_AUTO_TAG_OVERBROAD" }
func (AutoTagOverbroad) Phase() string { return "Phase 1" }

func (c AutoTagOverbroad) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.AutoTagRules) == 0 || len(b.EntitiesByType) == 0 {
		return nil
	}

	var findings []finding.Finding
	for _, rule := range b.AutoTagRules {
		key := rule.Value.Name
		if key == "" {
			continue
		}

		var (
			worstType        string
			worstCoverage    float64
			worstWith        int
			worstTotal       int
		)
		for entityType, entities := range b.EntitiesByType {
			total := len(entities)
			if total < MinEntityCountForSignal {
				continue
			}
			withKey := 0
			for _, e := range entities {
				if e.HasTagKey(key) {
					withKey++
				}
			}
			coverage := float64(withKey) / float64(total)
			if coverage > worstCoverage {
				worstType = entityType
				worstCoverage = coverage
				worstWith = withKey
				worstTotal = total
			}
		}
		if worstCoverage < OverbroadCoverageThreshold {
			continue
		}

		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityMedium,
			Title: fmt.Sprintf(
				"Auto-tag rule producing %q covers %.0f%% of %s entities — likely overbroad",
				key, worstCoverage*100, worstType,
			),
			Description: fmt.Sprintf(
				"Settings 2.0 object %s defines auto-tag rule producing tag key %q. "+
					"On %s entities, %d of %d (%.0f%%) currently carry this tag, at or above the %.0f%% "+
					"threshold for considering a rule overbroad. This may be intentional (e.g. an "+
					"env tag in a single-env cluster) — confirm before remediating.",
				rule.ObjectID, key, worstType, worstWith, worstTotal,
				worstCoverage*100, OverbroadCoverageThreshold*100,
			),
			Evidence: finding.Evidence{
				Tool:    "dt_get_auto_tags + dynatrace_managed_discover_entities",
				RawPath: "raw/phase1-auto-tags.json",
				DataPoint: fmt.Sprintf(
					"objectId=%s value.name=%q coverage=%d/%d=%.2f%% on %s",
					rule.ObjectID, key, worstWith, worstTotal, worstCoverage*100, worstType,
				),
			},
			Recommendation: fmt.Sprintf(
				"Review rule %s. If the broad coverage is intentional, ratify it (no action needed). "+
					"If not, tighten the rule's conditions so it only applies to the intended subset.",
				rule.ObjectID,
			),
			EntityRef: &finding.EntityRef{
				Kind: "settings_object",
				ID:   rule.ObjectID,
				Name: key,
			},
			FixTemplate: &finding.FixTemplate{
				WriteAction: "update",
				SchemaID:    rule.SchemaID,
				ObjectID:    rule.ObjectID,
				Hint:        "Tighten rule.value.rules[*].conditions to scope down. No automated payload — depends on intent.",
			},
		})
	}
	return findings
}
