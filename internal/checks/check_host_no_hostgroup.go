// Check: CHECK_HOST_NO_HOSTGROUP
//
// Hosts with no host group are an immediate hygiene problem:
//   - they fall outside any group-scoped management zone, alerting profile, or rule
//   - they break ownership inheritance from host group → host
//   - DT_TAGS / DT_CLUSTER_ID propagation often relies on host-group context
//
// Logic:
//   For every HOST entity in the bundle, check both common ways DT exposes
//   host-group membership (properties.hostGroupId / hostGroup, or
//   toRelationships.isInstanceOf with type=HOST_GROUP). If neither is set,
//   emit one Medium finding per host.
package checks

import (
	"fmt"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

// HostNoHostGroup is the registered check.
type HostNoHostGroup struct{}

func (HostNoHostGroup) ID() string    { return "CHECK_HOST_NO_HOSTGROUP" }
func (HostNoHostGroup) Phase() string { return "Phase 1" }

func (c HostNoHostGroup) Run(b *bundle.Bundle) []finding.Finding {
	hosts := b.EntitiesByType["HOST"]
	if len(hosts) == 0 {
		return nil
	}

	var findings []finding.Finding
	for _, h := range hosts {
		if h.HostGroupID() != "" {
			continue
		}
		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityMedium,
			Title: fmt.Sprintf(
				"Host %q (%s) is not a member of any host group",
				h.DisplayName, h.EntityID,
			),
			Description: fmt.Sprintf(
				"HOST entity %s has no host group reference (neither properties.hostGroupId "+
					"nor toRelationships.isInstanceOf -> HOST_GROUP). This host falls outside "+
					"any group-scoped MZ, alerting profile, or rule keyed on host group.",
				h.EntityID,
			),
			Evidence: finding.Evidence{
				Tool:      "dynatrace_managed_discover_entities type(HOST)",
				RawPath:   "raw/phase1-hosts-all.json",
				DataPoint: fmt.Sprintf("entityId=%s displayName=%q hostGroup=<none>", h.EntityID, h.DisplayName),
			},
			Recommendation: fmt.Sprintf(
				"Assign host %s to an appropriate host group via OneAgent install argument "+
					"`--set-host-group=<name>` or `oneagentctl --set-host-group <name>`. "+
					"Host groups are the most stable signal for downstream MZ / alerting / tag rules.",
				h.EntityID,
			),
			EntityRef: &finding.EntityRef{
				Kind: "entity",
				ID:   h.EntityID,
				Name: h.DisplayName,
			},
		})
	}
	return findings
}
