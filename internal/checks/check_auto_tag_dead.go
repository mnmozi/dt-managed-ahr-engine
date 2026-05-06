// Check: CHECK_AUTO_TAG_DEAD
//
// An auto-tag rule is considered dead when the tag key it produces does not
// appear on any entity in the cluster. This is a strong signal that the
// rule's conditions match nothing — either the conditions reference a
// renamed/decommissioned attribute, or the rule was authored against an
// inventory that no longer exists.
//
// Approximation tradeoff (v1):
//
//   We don't evaluate auto-tag rule conditions against the entity inventory
//   directly — that would require a condition DSL evaluator and would be
//   correct but expensive. Instead we use observed effect:
//   "if this key is on zero entities, the rule isn't currently producing
//   any tags." This conflates "rule is dead" with "another rule produces
//   the same key" — a future check (CHECK_AUTO_TAG_DUPLICATE) covers that
//   from the other side.
//
//   Also, multiple rules can write to the same tag key. If rule A is alive
//   producing key X and rule B is dead producing key X, this check sees
//   key X as alive and reports neither. That's an acceptable v1 false-
//   negative; CHECK_AUTO_TAG_DUPLICATE will catch the multi-rule case.
package checks

import (
	"fmt"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

// AutoTagDead is the registered check.
type AutoTagDead struct{}

// ID is the stable identifier the check emits in its findings.
func (AutoTagDead) ID() string { return "CHECK_AUTO_TAG_DEAD" }

// Phase is the AHR phase this check belongs to.
func (AutoTagDead) Phase() string { return "Phase 1" }

// Run executes the check against a parsed bundle and returns zero or more
// findings. It is a pure function: same bundle in → same findings out.
func (c AutoTagDead) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.AutoTagRules) == 0 {
		return nil
	}

	// Build the set of tag keys that appear on any entity in the bundle.
	// We look at both data sources so the check is robust even when only one
	// is populated:
	//   1. The /api/v2/tags aggregated response (TagsByEntityType)
	//   2. The per-entity tag arrays from the entity inventory (EntitiesByType)
	// In production bundles both are present; in test fixtures usually one is.
	activeKeys := map[string]bool{}
	for _, occurrences := range b.TagsByEntityType {
		for _, t := range occurrences {
			if t.Key != "" {
				activeKeys[t.Key] = true
			}
		}
	}
	for _, entities := range b.EntitiesByType {
		for _, e := range entities {
			for _, t := range e.Tags {
				if t.Key != "" {
					activeKeys[t.Key] = true
				}
			}
		}
	}

	var findings []finding.Finding
	for _, rule := range b.AutoTagRules {
		key := rule.Value.Name
		if key == "" {
			// Rule with no produced key — separate hygiene issue, not this check's
			// concern. Skip.
			continue
		}
		if activeKeys[key] {
			continue
		}
		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityLow,
			Title: fmt.Sprintf(
				"Auto-tag rule produces tag key %q but no entity in the cluster carries that key",
				key,
			),
			Description: fmt.Sprintf(
				"Settings 2.0 object %s (schemaId %s) defines auto-tag rule producing tag key %q. "+
					"Across all entity types in the bundle, zero entities currently carry this tag. "+
					"The rule is most likely dead — its conditions match no entities.",
				rule.ObjectID, rule.SchemaID, key,
			),
			Evidence: finding.Evidence{
				Tool:    "dt_get_auto_tags + dt_list_tags_for_entity",
				RawPath: "raw/phase1-auto-tags.json",
				DataPoint: fmt.Sprintf(
					"objectId=%s value.name=%q occurrences-on-any-entity=0",
					rule.ObjectID, key,
				),
			},
			Recommendation: fmt.Sprintf(
				"Review rule %s. If the conditions still represent a valid intent, fix them so they "+
					"match the current entity inventory. If the rule is no longer needed, delete it.",
				rule.ObjectID,
			),
			EntityRef: &finding.EntityRef{
				Kind: "settings_object",
				ID:   rule.ObjectID,
				Name: key,
			},
			FixTemplate: &finding.FixTemplate{
				WriteAction: "delete",
				SchemaID:    rule.SchemaID,
				ObjectID:    rule.ObjectID,
				Hint:        "Confirm with rule owner before deleting; consider disabling first.",
			},
		})
	}
	return findings
}
