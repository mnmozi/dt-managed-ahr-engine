package checks

import (
	"testing"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

func TestFullStackNoLogs_FindsBothShapes(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "fullstack-no-logs"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := FullStackNoLogs{}.Run(b)

	// Fixture: 4 hosts. Two should fire — fullstack-no-log-module (no module
	// at all) and fullstack-log-disabled (module disabled).
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	wantHosts := map[string]bool{"HOST-BBBB": true, "HOST-CCCC": true}
	for _, f := range got {
		if f.ID != "CHECK_FULLSTACK_NO_LOGS" {
			t.Errorf("wrong ID: %s", f.ID)
		}
		if f.Severity != finding.SeverityMedium {
			t.Errorf("wrong Severity: %s", f.Severity)
		}
		if f.EntityRef == nil || !wantHosts[f.EntityRef.ID] {
			t.Errorf("unexpected host in finding: %+v", f.EntityRef)
		}
		delete(wantHosts, f.EntityRef.ID)
	}
	if len(wantHosts) != 0 {
		t.Errorf("missed hosts: %v", wantHosts)
	}
}

func TestFullStackNoLogs_InfraOnlyHostNotFlagged(t *testing.T) {
	// INFRASTRUCTURE-mode host with no log module is intentional, not a finding.
	b := &bundle.Bundle{
		OneAgents: []bundle.OneAgent{
			{
				HostInfo:       bundle.OneAgentHostInfo{HostName: "infra-host", EntityID: "HOST-1"},
				MonitoringType: "INFRASTRUCTURE",
				Modules:        []bundle.OneAgentModule{{ModuleType: "OS", Enabled: true}},
			},
		},
	}
	if got := (FullStackNoLogs{}).Run(b); len(got) != 0 {
		t.Fatalf("infra-only host should not fire, got %d findings", len(got))
	}
}

func TestFullStackNoLogs_NoOneAgentsNoFindings(t *testing.T) {
	b := &bundle.Bundle{}
	if got := (FullStackNoLogs{}).Run(b); len(got) != 0 {
		t.Fatalf("empty bundle: %d", len(got))
	}
}
