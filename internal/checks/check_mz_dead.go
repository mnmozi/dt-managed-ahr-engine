// Check: CHECK_MZ_DEAD
//
// A management zone that contains zero entities is dead. Either:
//   - the rules reference an attribute that no longer exists (renamed host group,
//     deleted tag key, decommissioned cloud account)
//   - the rules were authored against a future-state architecture that never
//     happened
//   - the entities the rules targeted have all been retired
//
// Dead MZs accumulate over years, clutter the UI, and break alerting profiles
// that reference them. Cleanup is straightforward: delete or update.
//
// Logic:
//   For every management-zone Settings 2.0 object in the bundle, check if any
//   loaded entity (across all entity types) carries this MZ's name in its
//   managementZones[]. If none do — fire.
//
// Caveats (v1):
//   - We compute membership from the entity inventory the bundle contains.
//     If the bundle only loaded HOST and HOST_GROUP, an MZ that only contains
//     services would be wrongly flagged as dead. We mitigate by loading
//     PG/PGI/SERVICE entity types in the default bundle sources, which covers
//     the typical AHR scope. MZs scoped to entity types we don't load (e.g.
//     SYNTHETIC_LOCATION) may produce false positives — that's an accepted
//     v1 tradeoff documented in this check's evidence.
package checks

import (
	"fmt"
	"sort"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

// MZDead is the registered check.
type MZDead struct{}

func (MZDead) ID() string    { return "CHECK_MZ_DEAD" }
func (MZDead) Phase() string { return "Phase 3" }

func (c MZDead) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.ManagementZones) == 0 {
		return nil
	}

	// Build set of MZ names referenced by any loaded entity.
	referencedMZs := map[string]bool{}
	for _, entities := range b.EntitiesByType {
		for _, e := range entities {
			for _, mz := range e.ManagementZones {
				if mz.Name != "" {
					referencedMZs[mz.Name] = true
				}
			}
		}
	}

	// Stable order so findings are reproducible.
	mzs := make([]bundle.ManagementZone, len(b.ManagementZones))
	copy(mzs, b.ManagementZones)
	sort.Slice(mzs, func(i, j int) bool { return mzs[i].Value.Name < mzs[j].Value.Name })

	var findings []finding.Finding
	for _, mz := range mzs {
		name := mz.Value.Name
		if name == "" {
			continue
		}
		if referencedMZs[name] {
			continue
		}
		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityLow,
			Title: fmt.Sprintf(
				"Management zone %q matches no entities in the bundle — likely dead",
				name,
			),
			Description: fmt.Sprintf(
				"Settings 2.0 object %s defines management zone %q. Across all loaded entity "+
					"types (HOST, HOST_GROUP, PROCESS_GROUP, PROCESS_GROUP_INSTANCE, SERVICE), "+
					"zero entities reference this MZ name. The MZ's rules likely target an "+
					"attribute that no longer exists (renamed host group, deleted tag key, "+
					"decommissioned cloud account) or entities that have all been retired.",
				mz.ObjectID, name,
			),
			Evidence: finding.Evidence{
				Tool:    "dt_get_management_zones + entity inventory",
				RawPath: "raw/phase3-management-zones.json",
				DataPoint: fmt.Sprintf(
					"objectId=%s value.name=%q referencingEntities=0 (across loaded types)",
					mz.ObjectID, name,
				),
			},
			Recommendation: fmt.Sprintf(
				"Review MZ %q. If the rules reference attributes that no longer exist, either "+
					"update the rules to match the current inventory or delete the MZ. "+
					"Before deleting, search for alerting profiles or dashboards that reference "+
					"this MZ — orphan references will silently break.",
				name,
			),
			EntityRef: &finding.EntityRef{
				Kind: "settings_object",
				ID:   mz.ObjectID,
				Name: name,
			},
			FixTemplate: &finding.FixTemplate{
				WriteAction: "delete",
				SchemaID:    mz.SchemaID,
				ObjectID:    mz.ObjectID,
				Hint:        "Delete only after confirming no alerting profile / dashboard references this MZ name.",
			},
		})
	}
	return findings
}
