package checks

import (
	"testing"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

func TestMZOverlap_FlagsOverlappingPair(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "mz-overlap"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := MZOverlap{}.Run(b)

	// Fixture:
	// - "prod" has 8 hosts (1-8)
	// - "prod-and-monitored" has 7 hosts (1-7)
	// - "team-payments" has 5 hosts (9-13)
	// (prod, prod-and-monitored): intersection=7, union=8, jaccard=0.875 → fires
	// (prod, team-payments): intersection=0 → no fire
	// (prod-and-monitored, team-payments): intersection=0 → no fire
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "CHECK_MZ_OVERLAP" {
		t.Errorf("wrong ID: %s", f.ID)
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("expected Low, got %s", f.Severity)
	}
	if f.EntityRef == nil || f.EntityRef.ID != "MZ_PAIR/prod/prod-and-monitored" {
		t.Errorf("expected pair prod/prod-and-monitored, got %+v", f.EntityRef)
	}
}

func TestMZOverlap_BelowThresholdSilent(t *testing.T) {
	// Build: A and B have 8 entities each, intersect on 1 → jaccard ~ 1/15 ≈ 0.067 → silent.
	a := []bundle.ManagementZoneRef{{Name: "A"}}
	b := []bundle.ManagementZoneRef{{Name: "B"}}
	both := []bundle.ManagementZoneRef{{Name: "A"}, {Name: "B"}}
	ents := []bundle.Entity{}
	for i := 0; i < 7; i++ {
		ents = append(ents, bundle.Entity{EntityID: idFromIndex(i), ManagementZones: a})
	}
	for i := 7; i < 14; i++ {
		ents = append(ents, bundle.Entity{EntityID: idFromIndex(i), ManagementZones: b})
	}
	ents = append(ents, bundle.Entity{EntityID: "HOST-SHARED", ManagementZones: both})
	bndl := &bundle.Bundle{EntitiesByType: map[string][]bundle.Entity{"HOST": ents}}
	if got := (MZOverlap{}).Run(bndl); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}

func TestMZOverlap_BelowMinSizeSilent(t *testing.T) {
	// Both MZs have only 4 entities — under OverlapMinSize of 5 → silent regardless of overlap.
	a := []bundle.ManagementZoneRef{{Name: "A"}}
	b := []bundle.ManagementZoneRef{{Name: "B"}}
	both := []bundle.ManagementZoneRef{{Name: "A"}, {Name: "B"}}
	ents := []bundle.Entity{}
	for i := 0; i < 3; i++ {
		ents = append(ents, bundle.Entity{EntityID: idFromIndex(i), ManagementZones: a})
	}
	for i := 3; i < 6; i++ {
		ents = append(ents, bundle.Entity{EntityID: idFromIndex(i), ManagementZones: b})
	}
	ents = append(ents, bundle.Entity{EntityID: "HOST-Z", ManagementZones: both})
	bndl := &bundle.Bundle{EntitiesByType: map[string][]bundle.Entity{"HOST": ents}}
	if got := (MZOverlap{}).Run(bndl); len(got) != 0 {
		t.Fatalf("expected 0 findings on below-min-size MZs, got %d", len(got))
	}
	_ = finding.SeverityLow // keep finding import alive across all tests in package
}
