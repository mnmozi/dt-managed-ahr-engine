package checks

import (
	"testing"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

func TestHostGroupSingleton_FindsSingletonGroups(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "hostgroup-singleton"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	got := HostGroupSingleton{}.Run(b)

	// Fixture: HOST_GROUP-PROD has 3 hosts (healthy), HOST_GROUP-DECOM has 1,
	// HOST_GROUP-ADHOC has 1. Expect 2 findings.
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.ID != "CHECK_HOSTGROUP_SINGLETON" {
			t.Errorf("wrong ID: %s", f.ID)
		}
		if f.Severity != finding.SeverityLow {
			t.Errorf("wrong Severity: %s", f.Severity)
		}
	}

	wantSingletons := map[string]bool{"HOST_GROUP-DECOM": true, "HOST_GROUP-ADHOC": true}
	for _, f := range got {
		if f.EntityRef == nil || !wantSingletons[f.EntityRef.ID] {
			t.Errorf("unexpected singleton hg in finding: %+v", f.EntityRef)
		}
		delete(wantSingletons, f.EntityRef.ID)
	}
	if len(wantSingletons) != 0 {
		t.Errorf("missed singletons: %v", wantSingletons)
	}
}

func TestHostGroupSingleton_NoSingletonsProducesNoFinding(t *testing.T) {
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{
			"HOST": {
				{EntityID: "HOST-1", Properties: map[string]interface{}{"hostGroupId": "HG-1"}},
				{EntityID: "HOST-2", Properties: map[string]interface{}{"hostGroupId": "HG-1"}},
				{EntityID: "HOST-3", Properties: map[string]interface{}{"hostGroupId": "HG-2"}},
				{EntityID: "HOST-4", Properties: map[string]interface{}{"hostGroupId": "HG-2"}},
			},
		},
	}
	got := HostGroupSingleton{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestHostGroupSingleton_HostsWithoutHostGroupAreIgnored(t *testing.T) {
	// CHECK_HOST_NO_HOSTGROUP covers orphans; the singleton check must not
	// double-report them as a separate (anonymous) singleton "group".
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{
			"HOST": {
				{EntityID: "HOST-ORPHAN-1"},
				{EntityID: "HOST-ORPHAN-2"},
			},
		},
	}
	got := HostGroupSingleton{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings on all-orphans bundle, got %d", len(got))
	}
}
