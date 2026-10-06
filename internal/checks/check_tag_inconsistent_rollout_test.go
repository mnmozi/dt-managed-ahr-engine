package checks

import (
	"testing"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

func TestTagInconsistentRollout_DetectsBandKey(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "inconsistent-rollout"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := TagInconsistentRollout{}.Run(b)

	// Fixture: 10 hosts. env=100% (consensus, ratify), team=50% (band → fire),
	// experimental=10% (long tail). Expect exactly 1 finding for `team`.
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "CHECK_TAG_INCONSISTENT_ROLLOUT" {
		t.Errorf("wrong ID: %s", f.ID)
	}
	if f.Severity != finding.SeverityLow {
		// 50% lands in the upper-half band (Low severity).
		t.Errorf("expected Low for 50%% coverage, got %s", f.Severity)
	}
	if f.EntityRef == nil || f.EntityRef.Name != "team" {
		t.Errorf("expected entity_ref.name=team, got %+v", f.EntityRef)
	}
}

func TestTagInconsistentRollout_BelowMinEntityCountSilent(t *testing.T) {
	// Only 5 hosts — below MinEntityCountForCoverage (10), should silence.
	hosts := make([]bundle.Entity, 5)
	for i := 0; i < 5; i++ {
		hosts[i] = bundle.Entity{
			EntityID: idFromIndex(i),
			Type:     "HOST",
			Tags: []bundle.TagOccurrence{
				{Context: "CONTEXTLESS", Key: "team", Value: "x"}, // 100% coverage but on tiny set
			},
		}
	}
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{"HOST": hosts},
	}
	got := TagInconsistentRollout{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings on tiny population, got %d", len(got))
	}
}

func TestTagInconsistentRollout_LowerHalfBandIsMedium(t *testing.T) {
	// 30% coverage — should fire as Medium.
	hosts := make([]bundle.Entity, 10)
	for i := 0; i < 10; i++ {
		e := bundle.Entity{EntityID: idFromIndex(i), Type: "HOST"}
		if i < 3 { // 3/10 = 30% — in band, lower half
			e.Tags = []bundle.TagOccurrence{{Context: "CONTEXTLESS", Key: "owner", Value: "x"}}
		}
		hosts[i] = e
	}
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{"HOST": hosts},
	}
	got := TagInconsistentRollout{}.Run(b)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Severity != finding.SeverityMedium {
		t.Errorf("expected Medium for 30%% coverage, got %s", got[0].Severity)
	}
}

func TestTagInconsistentRollout_OutsideBandSilent(t *testing.T) {
	// 100% coverage on 10 hosts — outside band, silent.
	hosts := make([]bundle.Entity, 10)
	for i := 0; i < 10; i++ {
		hosts[i] = bundle.Entity{
			EntityID: idFromIndex(i),
			Type:     "HOST",
			Tags:     []bundle.TagOccurrence{{Context: "CONTEXTLESS", Key: "env", Value: "prod"}},
		}
	}
	b := &bundle.Bundle{EntitiesByType: map[string][]bundle.Entity{"HOST": hosts}}
	if got := (TagInconsistentRollout{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 on consensus key, got %d", len(got))
	}
}
