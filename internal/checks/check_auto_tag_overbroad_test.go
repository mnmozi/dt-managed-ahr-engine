package checks

import (
	"testing"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

func TestAutoTagOverbroad_DetectsOverbroadRule(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "overbroad-autotag"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	got := AutoTagOverbroad{}.Run(b)

	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "CHECK_AUTO_TAG_OVERBROAD" {
		t.Errorf("wrong ID: %s", f.ID)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("wrong Severity: %s", f.Severity)
	}
	if f.EntityRef == nil || f.EntityRef.Name != "monitored" {
		t.Errorf("wrong entity_ref.name, got %+v", f.EntityRef)
	}
	if f.FixTemplate == nil || f.FixTemplate.WriteAction != "update" {
		t.Errorf("expected update fix template, got %+v", f.FixTemplate)
	}
}

func TestAutoTagOverbroad_HealthyRuleProducesNoFinding(t *testing.T) {
	// Reuse the healthy-autotag-rule fixture: 1 rule, 0 hosts in EntitiesByType
	// (no phase1-hosts-all.json), so coverage cannot be computed -> no findings.
	b, err := bundle.Load(goldenPath(t, "healthy-autotag-rule"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	got := AutoTagOverbroad{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestAutoTagOverbroad_BelowThresholdProducesNoFinding(t *testing.T) {
	// Construct an in-memory bundle where coverage is 80% — below 95% threshold.
	b := &bundle.Bundle{
		AutoTagRules: []bundle.AutoTagRule{
			{ObjectID: "obj-1", SchemaID: "builtin:tags.auto-tagging", Value: bundle.AutoTagRuleVal{Name: "team"}},
		},
		EntitiesByType: map[string][]bundle.Entity{
			"HOST": makeHostsWithKey(10, 8, "team"), // 8 of 10 hosts carry "team" = 80%
		},
	}
	got := AutoTagOverbroad{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings at 80%% coverage, got %d", len(got))
	}
}

// makeHostsWithKey constructs n hosts where the first `withKey` of them carry
// the given tag key. Helper for in-memory bundle assembly.
func makeHostsWithKey(n, withKey int, key string) []bundle.Entity {
	out := make([]bundle.Entity, n)
	for i := 0; i < n; i++ {
		e := bundle.Entity{
			EntityID: idFromIndex(i),
			Type:     "HOST",
		}
		if i < withKey {
			e.Tags = []bundle.TagOccurrence{{Context: "CONTEXTLESS", Key: key, Value: "x"}}
		}
		out[i] = e
	}
	return out
}

func idFromIndex(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return "HOST-X" + string(digits[i])
	}
	return "HOST-X" + string(digits[i/10]) + string(digits[i%10])
}
