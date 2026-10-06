// hostgroups.go — the "hostgroups.coverage_audit" analyzer.
//
// Unlike hosts/PG naming analyzers, this layer has nothing to NAME — it
// audits consistency of host-group membership. Host groups can only be
// changed via OneAgent reconfig (--set-host-group=X), so this layer
// doesn't have a write tool either; it pairs with an MCP-side export
// tool that emits the shell commands the operator runs.
//
// Five detection categories:
//
//   hostsWithoutGroup           — host has empty hostGroupName/Id
//   splitFleets                 — same fleetKey, scattered across groups
//   singleMemberLikelyTypos     — 1-member group whose name is near
//                                 (Levenshtein ≤ 2) a populated group
//   genericGroupNames           — group named "default"/"prod"/"linux"/…
//   namingDrift                 — multiple groups normalize to the same
//                                 canonical string (case/order/punct)
//
// All inputs are deterministic — same flat graph in, same report out.
package naming

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/graph"
)

func init() {
	analyze.Register(HostGroups{})
}

// HostGroups is the analyzer entrypoint.
type HostGroups struct{}

// Kind dispatched via engine_analyze.
func (HostGroups) Kind() string { return "hostgroups.coverage_audit" }

// Description shown by engine_list.
func (HostGroups) Description() string {
	return "Audit host-group hygiene. Detects (1) hosts with no host group assigned, (2) split fleets — hosts with identical workload running in different host groups (often because some were installed before the group was named), (3) single-member host groups whose name is within edit-distance 2 of a populated group (likely typos), (4) generic group names (default/prod/linux/etc.), (5) naming drift — multiple groups that normalize to the same canonical name. Host-group membership cannot be changed via Dynatrace API; pair this analyzer with dt_export_hostgroup_remediation to generate oneagentctl shell commands. Pure function over flat graph input."
}

// HostGroupsInput is the analyzer's input.
type HostGroupsInput struct {
	graph.Input
	// MinFleetSize controls the smallest fleet (same fleetKey) that we
	// report as "split". Default 2. Below this, single-host "fleets" are
	// noise.
	MinFleetSize int `json:"minFleetSize,omitempty"`
	// MaxEditDistance controls the typo-detection threshold. Default 2.
	MaxEditDistance int `json:"maxEditDistance,omitempty"`
}

// HostGroupsOutput is the analyzer result. Each category gets its own
// array so the operator can pick which findings to act on.
type HostGroupsOutput struct {
	HostsWithoutGroup       []HostWithoutGroup       `json:"hostsWithoutGroup"`
	SplitFleets             []SplitFleet             `json:"splitFleets"`
	SingleMemberLikelyTypos []LikelyTypoGroup        `json:"singleMemberLikelyTypos"`
	GenericGroupNames       []GenericGroup           `json:"genericGroupNames"`
	NamingDrift             []NamingDriftCluster     `json:"namingDrift"`
	Counts                  HostGroupsCounts         `json:"counts"`
	AppliedDefaults         HostGroupsDefaults       `json:"appliedDefaults"`
}

type HostWithoutGroup struct {
	HostID          string `json:"hostId"`
	DisplayName     string `json:"displayName,omitempty"`
	FleetSuggestion string `json:"fleetSuggestion,omitempty"` // when fleet-mates have a dominant group
	Evidence        string `json:"evidence,omitempty"`
}

type SplitFleet struct {
	FleetKey            string         `json:"fleetKey"`
	MemberCount         int            `json:"memberCount"`
	CurrentDistribution map[string]int `json:"currentDistribution"`
	SuggestedGroup      string         `json:"suggestedGroup,omitempty"`
	HostsToReassign     []HostReassign `json:"hostsToReassign"`
}

type HostReassign struct {
	HostID       string `json:"hostId"`
	DisplayName  string `json:"displayName,omitempty"`
	CurrentGroup string `json:"currentGroup,omitempty"` // "" means <none>
	NewGroup     string `json:"newGroup"`
	Reason       string `json:"reason"`
}

type LikelyTypoGroup struct {
	GroupName             string `json:"groupName"`
	MemberCount           int    `json:"memberCount"`
	NearestPopulatedGroup string `json:"nearestPopulatedGroup"`
	NearestMemberCount    int    `json:"nearestMemberCount"`
	EditDistance          int    `json:"editDistance"`
}

type GenericGroup struct {
	GroupName   string `json:"groupName"`
	MemberCount int    `json:"memberCount"`
	Reason      string `json:"reason"`
}

type NamingDriftCluster struct {
	Normalized       string         `json:"normalized"`
	Variants         []string       `json:"variants"`
	TotalMembers     int            `json:"totalMembers"`
	PerVariantCounts map[string]int `json:"perVariantCounts"`
}

type HostGroupsCounts struct {
	TotalHosts              int `json:"totalHosts"`
	TotalHostGroups         int `json:"totalHostGroups"`
	HostsWithoutGroup       int `json:"hostsWithoutGroup"`
	SplitFleets             int `json:"splitFleets"`
	SingleMemberLikelyTypos int `json:"singleMemberLikelyTypos"`
	GenericGroupNames       int `json:"genericGroupNames"`
	NamingDriftClusters     int `json:"namingDriftClusters"`
}

type HostGroupsDefaults struct {
	MinFleetSize    int `json:"minFleetSize"`
	MaxEditDistance int `json:"maxEditDistance"`
}

// Group names that carry no operational signal. Detected case-insensitively.
var genericGroupNameSet = map[string]string{
	"default":    "default placeholder name",
	"unassigned": "unassigned placeholder name",
	"none":       "placeholder name",
	"prod":       "name carries env only — no team / app",
	"production": "name carries env only",
	"dev":        "name carries env only",
	"development": "name carries env only",
	"test":       "name carries env only",
	"staging":    "name carries env only",
	"qa":         "name carries env only",
	"linux":      "name is just the OS",
	"windows":    "name is just the OS",
	"main":       "placeholder name",
	"misc":       "placeholder name",
}

// Run is the analyzer's pure entrypoint.
//
//nolint:funlen // single linear scan over hosts; splitting it would obscure flow
func (HostGroups) Run(raw json.RawMessage) (any, error) {
	var in HostGroupsInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	if in.MinFleetSize <= 0 {
		in.MinFleetSize = 2
	}
	if in.MaxEditDistance <= 0 {
		in.MaxEditDistance = 2
	}

	out := HostGroupsOutput{
		HostsWithoutGroup:       []HostWithoutGroup{},
		SplitFleets:             []SplitFleet{},
		SingleMemberLikelyTypos: []LikelyTypoGroup{},
		GenericGroupNames:       []GenericGroup{},
		NamingDrift:             []NamingDriftCluster{},
		Counts: HostGroupsCounts{
			TotalHosts: len(in.Hosts),
		},
		AppliedDefaults: HostGroupsDefaults{
			MinFleetSize:    in.MinFleetSize,
			MaxEditDistance: in.MaxEditDistance,
		},
	}

	// Build host-group membership map: groupName → []hostIdx (into in.Hosts).
	// Empty group name means "no group assigned"; we track those separately.
	groupMembers := map[string][]int{}
	hostsNoGroup := []int{}
	hostGroupByHostID := map[string]string{}
	for i, h := range in.Hosts {
		gname := stringProp(h.Properties, "hostGroupName")
		if gname == "" {
			hostsNoGroup = append(hostsNoGroup, i)
			hostGroupByHostID[h.ID] = ""
			continue
		}
		groupMembers[gname] = append(groupMembers[gname], i)
		hostGroupByHostID[h.ID] = gname
	}
	out.Counts.TotalHostGroups = len(groupMembers)

	// Re-run fleet detection (cheap; analyzers are pure → re-compute is the
	// clean way to avoid shared state across analyzer calls).
	pgEv := buildHostPGEvidence(in.Input)

	// ----- Category 1: hosts without a group -----
	// For each, see if its fleet-mates have a dominant group → suggest it.
	for _, i := range hostsNoGroup {
		h := in.Hosts[i]
		entry := HostWithoutGroup{HostID: h.ID, DisplayName: h.DisplayName}
		if ev, ok := pgEv[h.ID]; ok && ev.fleetKey != "" {
			if g, count := dominantGroupForFleet(ev.fleetKey, pgEv, hostGroupByHostID); g != "" && count >= 2 {
				entry.FleetSuggestion = g
				entry.Evidence = "fleet match with " + itoa(count) + " hosts already in '" + g + "'"
			}
		}
		out.HostsWithoutGroup = append(out.HostsWithoutGroup, entry)
	}
	out.Counts.HostsWithoutGroup = len(out.HostsWithoutGroup)

	// ----- Category 2: split fleets -----
	// For each fleetKey with ≥ minFleetSize members, compute the
	// hostGroupName distribution. If > 1 distinct group (counting "<none>"),
	// emit a SplitFleet finding.
	fleetMembers := map[string][]string{} // fleetKey → []hostId
	for hostID, ev := range pgEv {
		if ev.fleetKey == "" {
			continue
		}
		fleetMembers[ev.fleetKey] = append(fleetMembers[ev.fleetKey], hostID)
	}
	// Stable iteration order on fleetKey.
	fleetKeys := make([]string, 0, len(fleetMembers))
	for k := range fleetMembers {
		fleetKeys = append(fleetKeys, k)
	}
	sort.Strings(fleetKeys)
	for _, fk := range fleetKeys {
		members := fleetMembers[fk]
		if len(members) < in.MinFleetSize {
			continue
		}
		dist := map[string]int{}
		for _, hid := range members {
			g := hostGroupByHostID[hid]
			label := g
			if label == "" {
				label = "<none>"
			}
			dist[label]++
		}
		if len(dist) < 2 {
			continue // single group — not split
		}
		// Suggested group = plurality winner among real groups (not <none>).
		suggested := ""
		topCount := 0
		for g, c := range dist {
			if g == "<none>" {
				continue
			}
			if c > topCount {
				topCount = c
				suggested = g
			}
		}
		// Hosts to reassign: every member not already in the suggested group.
		reassigns := []HostReassign{}
		for _, hid := range members {
			if hostGroupByHostID[hid] == suggested {
				continue
			}
			h := findHostByID(in.Hosts, hid)
			cur := hostGroupByHostID[hid]
			reassigns = append(reassigns, HostReassign{
				HostID:       hid,
				DisplayName:  h.DisplayName,
				CurrentGroup: cur,
				NewGroup:     suggested,
				Reason:       "split fleet — " + itoa(topCount) + " of " + itoa(len(members)) + " fleet-mates already in '" + suggested + "'",
			})
		}
		sort.SliceStable(reassigns, func(i, j int) bool {
			return reassigns[i].HostID < reassigns[j].HostID
		})
		out.SplitFleets = append(out.SplitFleets, SplitFleet{
			FleetKey:            fk,
			MemberCount:         len(members),
			CurrentDistribution: dist,
			SuggestedGroup:      suggested,
			HostsToReassign:     reassigns,
		})
	}
	out.Counts.SplitFleets = len(out.SplitFleets)

	// ----- Category 3: single-member-likely-typos -----
	// For each 1-member group, find the nearest populated (≥ 5 members)
	// group by Levenshtein. If distance ≤ MaxEditDistance, emit.
	groupNames := make([]string, 0, len(groupMembers))
	for n := range groupMembers {
		groupNames = append(groupNames, n)
	}
	sort.Strings(groupNames)
	const populatedThreshold = 5
	for _, name := range groupNames {
		if len(groupMembers[name]) != 1 {
			continue
		}
		bestName := ""
		bestDist := 1 << 30
		for _, other := range groupNames {
			if other == name {
				continue
			}
			if len(groupMembers[other]) < populatedThreshold {
				continue
			}
			d := levenshtein(name, other)
			if d < bestDist {
				bestDist = d
				bestName = other
			}
		}
		if bestName != "" && bestDist <= in.MaxEditDistance {
			out.SingleMemberLikelyTypos = append(out.SingleMemberLikelyTypos, LikelyTypoGroup{
				GroupName:             name,
				MemberCount:           1,
				NearestPopulatedGroup: bestName,
				NearestMemberCount:    len(groupMembers[bestName]),
				EditDistance:          bestDist,
			})
		}
	}
	out.Counts.SingleMemberLikelyTypos = len(out.SingleMemberLikelyTypos)

	// ----- Category 4: generic group names -----
	for _, name := range groupNames {
		reason, isGeneric := genericGroupNameSet[strings.ToLower(strings.TrimSpace(name))]
		if !isGeneric {
			continue
		}
		out.GenericGroupNames = append(out.GenericGroupNames, GenericGroup{
			GroupName:   name,
			MemberCount: len(groupMembers[name]),
			Reason:      reason,
		})
	}
	out.Counts.GenericGroupNames = len(out.GenericGroupNames)

	// ----- Category 5: naming drift clusters -----
	// Normalize each group name (lowercase, strip non-alphanumerics, sort
	// dash-separated segments). Group by normalized form. ≥ 2 variants → cluster.
	byNorm := map[string][]string{}
	for _, name := range groupNames {
		n := normalizeGroupName(name)
		if n == "" {
			continue
		}
		byNorm[n] = append(byNorm[n], name)
	}
	normKeys := make([]string, 0, len(byNorm))
	for k := range byNorm {
		normKeys = append(normKeys, k)
	}
	sort.Strings(normKeys)
	for _, nk := range normKeys {
		variants := byNorm[nk]
		if len(variants) < 2 {
			continue
		}
		sort.Strings(variants)
		perVariant := map[string]int{}
		total := 0
		for _, v := range variants {
			perVariant[v] = len(groupMembers[v])
			total += len(groupMembers[v])
		}
		out.NamingDrift = append(out.NamingDrift, NamingDriftCluster{
			Normalized:       nk,
			Variants:         variants,
			TotalMembers:     total,
			PerVariantCounts: perVariant,
		})
	}
	out.Counts.NamingDriftClusters = len(out.NamingDrift)

	return out, nil
}

// dominantGroupForFleet returns the most common hostGroupName among the
// fleet's members (excluding "<none>"), along with the member count.
// Returns ("", 0) when no real group dominates.
func dominantGroupForFleet(fleetKey string, pgEv map[string]*hostPGEvidence, hostGroupByHostID map[string]string) (string, int) {
	dist := map[string]int{}
	for hostID, ev := range pgEv {
		if ev.fleetKey != fleetKey {
			continue
		}
		g := hostGroupByHostID[hostID]
		if g == "" {
			continue
		}
		dist[g]++
	}
	bestG := ""
	bestC := 0
	for g, c := range dist {
		if c > bestC {
			bestC = c
			bestG = g
		}
	}
	return bestG, bestC
}

// findHostByID scans for a host by id. We could maintain an index, but
// fleet sizes are small and this is called once per reassign.
func findHostByID(hosts []graph.Host, id string) graph.Host {
	for _, h := range hosts {
		if h.ID == id {
			return h
		}
	}
	return graph.Host{}
}

// normalizeGroupName collapses orders-prod / Orders-Prod / orders_prod /
// prod-orders to one canonical form for drift detection. Lowercase,
// split on any non-alphanumeric, sort segments, join.
func normalizeGroupName(s string) string {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return ""
	}
	// Split into alphanumeric tokens.
	tokens := []string{}
	cur := strings.Builder{}
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	if len(tokens) == 0 {
		return ""
	}
	sort.Strings(tokens)
	return strings.Join(tokens, "")
}

// levenshtein is a small DP implementation. Group names are short so the
// O(n*m) cost is trivial. Returns the number of single-character edits
// (insertions, deletions, substitutions) needed to transform a → b.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

