package checks

import (
	"testing"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

func TestHostNoHostGroup_FindsOrphans(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "host-no-hostgroup"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	got := HostNoHostGroup{}.Run(b)

	// Fixture has 4 hosts: 2 with a host group, 2 without. Expect 2 findings.
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.ID != "CHECK_HOST_NO_HOSTGROUP" {
			t.Errorf("wrong ID: %s", f.ID)
		}
		if f.Severity != finding.SeverityMedium {
			t.Errorf("wrong Severity: %s", f.Severity)
		}
		if f.EntityRef == nil || f.EntityRef.Kind != "entity" {
			t.Errorf("missing entity_ref: %+v", f.EntityRef)
		}
	}

	wantOrphans := map[string]bool{"HOST-CCCC": true, "HOST-DDDD": true}
	for _, f := range got {
		if f.EntityRef == nil || !wantOrphans[f.EntityRef.ID] {
			t.Errorf("unexpected orphan in finding: %+v", f.EntityRef)
		}
		delete(wantOrphans, f.EntityRef.ID)
	}
	if len(wantOrphans) != 0 {
		t.Errorf("missed orphans: %v", wantOrphans)
	}
}

func TestHostNoHostGroup_AllAssignedProducesNoFinding(t *testing.T) {
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{
			"HOST": {
				{EntityID: "HOST-1", Properties: map[string]interface{}{"hostGroupId": "HG-1"}},
				{EntityID: "HOST-2", ToRelations: map[string][]bundle.RelationshipRef{"isInstanceOf": {{ID: "HG-2", Type: "HOST_GROUP"}}}},
			},
		},
	}
	got := HostNoHostGroup{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestHostNoHostGroup_NoHostsProducesNoFinding(t *testing.T) {
	b := &bundle.Bundle{}
	got := HostNoHostGroup{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}
