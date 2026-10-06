package graph

import (
	"sort"
	"testing"
)

func sampleInput() Input {
	// Tree:
	//   HOST-1
	//     PG-A
	//       PGI-A1 — backs SERVICE-X
	//       PGI-A2 — backs SERVICE-X, SERVICE-Y
	//   HOST-2
	//     PG-B
	//       PGI-B1 — backs SERVICE-Z
	//
	// Call edges:
	//   SERVICE-X calls SERVICE-Y
	//   SERVICE-Y calls SERVICE-Z
	return Input{
		Hosts: []Host{
			{ID: "HOST-1", Tags: []Tag{{Key: "team", Value: "foo"}, {Key: "env", Value: "prod"}}},
			{ID: "HOST-2", Tags: []Tag{{Key: "env", Value: "staging"}}},
		},
		ProcessGroups: []ProcessGroup{
			{ID: "PG-A", HostID: "HOST-1"},
			{ID: "PG-B", HostID: "HOST-2", Tags: []Tag{{Key: "tech", Value: "java"}}},
		},
		ProcessGroupInstances: []ProcessGroupInstance{
			{ID: "PGI-A1", HostID: "HOST-1", PGID: "PG-A", ServiceIDs: []string{"SERVICE-X"}},
			{ID: "PGI-A2", HostID: "HOST-1", PGID: "PG-A", ServiceIDs: []string{"SERVICE-X", "SERVICE-Y"}},
			{ID: "PGI-B1", HostID: "HOST-2", PGID: "PG-B", ServiceIDs: []string{"SERVICE-Z"}, Tags: []Tag{{Key: "team", Value: "bar"}}},
		},
		Services: []Service{
			{ID: "SERVICE-X", PgiIDs: []string{"PGI-A1", "PGI-A2"}, CallsServiceIDs: []string{"SERVICE-Y"}},
			{ID: "SERVICE-Y", PgiIDs: []string{"PGI-A2"}, CallsServiceIDs: []string{"SERVICE-Z"}, Tags: []Tag{{Key: "team", Value: "foo"}}},
			{ID: "SERVICE-Z", PgiIDs: []string{"PGI-B1"}},
		},
	}
}

func TestBuild_GraphCounts(t *testing.T) {
	g := Build(sampleInput())
	// Containment edges (12 total):
	//   HOST-1 → PG-A                                    (1)
	//   HOST-2 → PG-B                                    (2)
	//   HOST-1 → PGI-A1, PG-A → PGI-A1                   (3, 4)
	//   HOST-1 → PGI-A2, PG-A → PGI-A2                   (5, 6)
	//   HOST-2 → PGI-B1, PG-B → PGI-B1                   (7, 8)
	//   PGI-A1 → SERVICE-X                               (9)
	//   PGI-A2 → SERVICE-X, PGI-A2 → SERVICE-Y           (10, 11)
	//   PGI-B1 → SERVICE-Z                               (12)
	if g.ContainmentEdges != 12 {
		t.Errorf("ContainmentEdges = %d, want 12", g.ContainmentEdges)
	}
	// Call edges:
	//   SERVICE-X → SERVICE-Y
	//   SERVICE-Y → SERVICE-Z
	if g.CallEdges != 2 {
		t.Errorf("CallEdges = %d, want 2", g.CallEdges)
	}
	if len(g.ByType[TypeHost]) != 2 {
		t.Errorf("hosts count = %d, want 2", len(g.ByType[TypeHost]))
	}
	if len(g.ByType[TypeService]) != 3 {
		t.Errorf("services count = %d, want 3", len(g.ByType[TypeService]))
	}
}

func TestAncestors_Service(t *testing.T) {
	g := Build(sampleInput())
	// SERVICE-X is backed by PGI-A1 and PGI-A2.
	// Both run on HOST-1 / PG-A.
	// Ancestors should be {PGI-A1, PGI-A2, HOST-1, PG-A} — deduplicated.
	svc := g.ByID["SERVICE-X"]
	ancestors := Ancestors(svc)
	ids := nodeIDs(ancestors)
	sort.Strings(ids)
	want := []string{"HOST-1", "PG-A", "PGI-A1", "PGI-A2"}
	if !stringsEqual(ids, want) {
		t.Errorf("Ancestors(SERVICE-X) = %v, want %v", ids, want)
	}
}

func TestDescendants_Host(t *testing.T) {
	g := Build(sampleInput())
	host := g.ByID["HOST-1"]
	descendants := Descendants(host)
	ids := nodeIDs(descendants)
	sort.Strings(ids)
	// HOST-1 contains: PG-A, PGI-A1, PGI-A2, SERVICE-X (backed by both PGIs),
	// SERVICE-Y (backed by PGI-A2). Total: 5.
	want := []string{"PG-A", "PGI-A1", "PGI-A2", "SERVICE-X", "SERVICE-Y"}
	if !stringsEqual(ids, want) {
		t.Errorf("Descendants(HOST-1) = %v, want %v", ids, want)
	}
}

func TestSiblings(t *testing.T) {
	g := Build(sampleInput())
	// PGI-A1's parents are PG-A and HOST-1.
	// PG-A's children: PGI-A1, PGI-A2 → sibling = PGI-A2.
	// HOST-1's children: PG-A, PGI-A1, PGI-A2 → siblings = PG-A, PGI-A2.
	// Union (excluding self): PG-A, PGI-A2.
	pgi := g.ByID["PGI-A1"]
	siblings := Siblings(pgi)
	ids := nodeIDs(siblings)
	sort.Strings(ids)
	want := []string{"PG-A", "PGI-A2"}
	if !stringsEqual(ids, want) {
		t.Errorf("Siblings(PGI-A1) = %v, want %v", ids, want)
	}
}

func TestCallNeighbors(t *testing.T) {
	g := Build(sampleInput())
	// SERVICE-Y is called by SERVICE-X and calls SERVICE-Z.
	svc := g.ByID["SERVICE-Y"]
	neighbors := CallNeighbors(svc)
	ids := nodeIDs(neighbors)
	sort.Strings(ids)
	want := []string{"SERVICE-X", "SERVICE-Z"}
	if !stringsEqual(ids, want) {
		t.Errorf("CallNeighbors(SERVICE-Y) = %v, want %v", ids, want)
	}
}

func TestMajorityValue(t *testing.T) {
	g := Build(sampleInput())
	// Across all services: SERVICE-Y has team:foo, others have no team.
	// Total nodes with values = 1. count = 1. majority = 1/1 = 100%.
	svcs := g.ByType[TypeService]
	value, count, total, ok := MajorityValue(svcs, "team", 0.66)
	if !ok {
		t.Errorf("MajorityValue: expected ok=true")
	}
	if value != "foo" {
		t.Errorf("MajorityValue value = %q, want foo", value)
	}
	if count != 1 || total != 1 {
		t.Errorf("MajorityValue count/total = %d/%d, want 1/1", count, total)
	}
}

func TestLowTagFilter(t *testing.T) {
	g := Build(sampleInput())
	// Hosts: HOST-1 has 2 tags, HOST-2 has 1. With threshold 1, HOST-2 qualifies.
	hosts := g.ByType[TypeHost]
	low := LowTagFilter(hosts, 1)
	if len(low) != 1 || low[0].ID != "HOST-2" {
		t.Errorf("LowTagFilter(hosts, 1) = %v, want [HOST-2]", nodeIDs(low))
	}
	// With threshold 0, only zero-tag nodes qualify. None of the hosts qualify.
	low0 := LowTagFilter(hosts, 0)
	if len(low0) != 0 {
		t.Errorf("LowTagFilter(hosts, 0) = %v, want empty", nodeIDs(low0))
	}
}

func TestMissingRelationship_Tolerated(t *testing.T) {
	// A SERVICE referencing a PGI that isn't in the input should be tolerated.
	in := Input{
		Services: []Service{
			{ID: "SERVICE-A", PgiIDs: []string{"PGI-NOT-IN-INPUT"}},
		},
	}
	g := Build(in)
	if g.ContainmentEdges != 0 {
		t.Errorf("expected 0 containment edges (PGI not present); got %d", g.ContainmentEdges)
	}
	svc := g.ByID["SERVICE-A"]
	if svc == nil {
		t.Fatal("SERVICE-A should still be in the graph")
	}
	if len(svc.ContainmentParents) != 0 {
		t.Errorf("expected no parents; got %d", len(svc.ContainmentParents))
	}
}

// helpers

func nodeIDs(nodes []*Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.ID
	}
	return out
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
