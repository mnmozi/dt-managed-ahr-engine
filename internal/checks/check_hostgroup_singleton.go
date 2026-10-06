// Check: CHECK_HOSTGROUP_SINGLETON
//
// A host group containing exactly one host is almost always either:
//   - a leftover from a decommissioned environment
//   - a per-host group used as a tagging hack instead of a tag
//   - a misconfiguration where multiple hosts SHOULD share a group but don't
//
// Single-host host groups defeat the entire purpose of host groups (sharing
// scope across machines), so flagging them is high-signal hygiene.
//
// Logic:
//   1. Group every HOST entity in the bundle by its HostGroupID().
//   2. Hosts with no host group are excluded (CHECK_HOST_NO_HOSTGROUP covers them).
//   3. For each group with exactly 1 member, emit one finding referencing the
//      host group id and the lone host.
//
// Note: this check uses host MEMBERSHIP, not the HOST_GROUP entity inventory.
// A HOST_GROUP entity that no host references is a different (rarer) issue
// covered by CHECK_HOSTGROUP_DEAD in a future iteration.
package checks

import (
	"fmt"
	"sort"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

// HostGroupSingleton is the registered check.
type HostGroupSingleton struct{}

func (HostGroupSingleton) ID() string    { return "CHECK_HOSTGROUP_SINGLETON" }
func (HostGroupSingleton) Phase() string { return "Phase 1" }

func (c HostGroupSingleton) Run(b *bundle.Bundle) []finding.Finding {
	hosts := b.EntitiesByType["HOST"]
	if len(hosts) == 0 {
		return nil
	}

	// Group hosts by host group id (skipping hosts with no host group).
	type groupMember struct {
		EntityID    string
		DisplayName string
	}
	groupedHosts := map[string][]groupMember{}
	for _, h := range hosts {
		hgID := h.HostGroupID()
		if hgID == "" {
			continue
		}
		groupedHosts[hgID] = append(groupedHosts[hgID], groupMember{
			EntityID:    h.EntityID,
			DisplayName: h.DisplayName,
		})
	}

	// Optional: lookup table from HOST_GROUP id -> displayName, when the
	// HOST_GROUP entity is in the bundle. Lets the finding read more naturally.
	hgNames := map[string]string{}
	for _, hg := range b.EntitiesByType["HOST_GROUP"] {
		hgNames[hg.EntityID] = hg.DisplayName
	}

	// Stable order so findings are reproducible.
	var hgIDs []string
	for id, members := range groupedHosts {
		if len(members) == 1 {
			hgIDs = append(hgIDs, id)
		}
	}
	sort.Strings(hgIDs)

	var findings []finding.Finding
	for _, hgID := range hgIDs {
		member := groupedHosts[hgID][0]
		hgName := hgNames[hgID]
		hgDisplay := hgID
		if hgName != "" {
			hgDisplay = fmt.Sprintf("%q (%s)", hgName, hgID)
		}

		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityLow,
			Title: fmt.Sprintf(
				"Host group %s contains only one host (%s)",
				hgDisplay, member.EntityID,
			),
			Description: fmt.Sprintf(
				"Host group %s has exactly one member host: %q (%s). Single-host host groups "+
					"defeat the purpose of grouping (sharing scope across machines) and are usually "+
					"either decommissioned-environment leftovers, per-host tagging hacks, or a "+
					"misconfiguration where peer hosts should share the same group.",
				hgDisplay, member.DisplayName, member.EntityID,
			),
			Evidence: finding.Evidence{
				Tool:    "dynatrace_managed_discover_entities type(HOST)",
				RawPath: "raw/phase1-hosts-all.json",
				DataPoint: fmt.Sprintf(
					"hostGroupId=%s memberCount=1 sole=%s",
					hgID, member.EntityID,
				),
			},
			Recommendation: fmt.Sprintf(
				"Review host group %s. If decommissioned, retire it. If the lone host should be "+
					"in a peer group with other hosts, reassign via oneagentctl. If per-host scoping "+
					"is genuinely needed, prefer host-level tags over single-host groups.",
				hgID,
			),
			EntityRef: &finding.EntityRef{
				Kind: "entity",
				ID:   hgID,
				Name: hgName,
			},
		})
	}
	return findings
}
