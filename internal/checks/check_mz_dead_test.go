package checks

import (
	"testing"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

func TestMZDead_FlagsUnreferencedMZs(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "mz-dead"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := MZDead{}.Run(b)

	// Fixture: 3 MZs (production, decommissioned-2022-DC, team-payments).
	// Hosts reference production + team-payments. So decommissioned-2022-DC is dead.
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "CHECK_MZ_DEAD" {
		t.Errorf("wrong ID: %s", f.ID)
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("expected Low, got %s", f.Severity)
	}
	if f.EntityRef == nil || f.EntityRef.Name != "decommissioned-2022-DC" {
		t.Errorf("expected decommissioned-2022-DC, got %+v", f.EntityRef)
	}
}

func TestMZDead_NoMZsNoFindings(t *testing.T) {
	b := &bundle.Bundle{}
	if got := (MZDead{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestMZDead_AllMZsReferencedNoFindings(t *testing.T) {
	b := &bundle.Bundle{
		ManagementZones: []bundle.ManagementZone{
			{ObjectID: "obj-prod", Value: bundle.ManagementZoneVal{Name: "production"}},
		},
		EntitiesByType: map[string][]bundle.Entity{
			"HOST": {
				{EntityID: "HOST-1", ManagementZones: []bundle.ManagementZoneRef{{Name: "production"}}},
			},
		},
	}
	if got := (MZDead{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}
