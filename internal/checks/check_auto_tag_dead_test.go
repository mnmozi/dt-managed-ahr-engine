package checks

import (
	"path/filepath"
	"testing"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

// goldenPath returns the absolute path to a fixture bundle directory.
func goldenPath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", name, "bundle"))
	if err != nil {
		t.Fatalf("resolve golden path: %v", err)
	}
	return abs
}

func TestAutoTagDead_DetectsDeadRule(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "dead-autotag-rule"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	got := AutoTagDead{}.Run(b)

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "CHECK_AUTO_TAG_DEAD" {
		t.Errorf("wrong ID: %s", f.ID)
	}
	if f.Phase != "Phase 1" {
		t.Errorf("wrong Phase: %s", f.Phase)
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("wrong Severity: %s", f.Severity)
	}
	if f.EntityRef == nil || f.EntityRef.Name != "decommissioned-team" {
		t.Errorf("expected EntityRef.Name=decommissioned-team, got %+v", f.EntityRef)
	}
	if f.FixTemplate == nil || f.FixTemplate.WriteAction != "delete" {
		t.Errorf("expected delete fix template, got %+v", f.FixTemplate)
	}
	if f.Evidence.RawPath != "raw/phase1-auto-tags.json" {
		t.Errorf("wrong evidence raw_path: %s", f.Evidence.RawPath)
	}
	if f.Evidence.DataPoint == "" {
		t.Errorf("evidence DataPoint must not be empty")
	}
}

func TestAutoTagDead_HealthyRuleProducesNoFinding(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "healthy-autotag-rule"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	got := AutoTagDead{}.Run(b)

	if len(got) != 0 {
		t.Fatalf("expected 0 findings on healthy fixture, got %d: %+v", len(got), got)
	}
}

func TestAutoTagDead_EmptyBundleNoFindings(t *testing.T) {
	// Sanity check: a bundle with no auto-tag rules at all should produce
	// no findings (and no panic on the empty-key shortcut).
	b := &bundle.Bundle{
		TagsByEntityType: map[string][]bundle.TagOccurrence{},
	}
	got := AutoTagDead{}.Run(b)
	if len(got) != 0 {
		t.Fatalf("empty bundle should yield no findings, got %d", len(got))
	}
}
