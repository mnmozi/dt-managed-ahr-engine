package checks

import (
	"testing"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

func TestPGPgisSpanEnvs_FlagsMixedPG(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "pg-pgis-span-envs"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := PGPgisSpanEnvs{}.Run(b)

	// Fixture has PROCESS_GROUP-MIXED with PGIs in env=prod and env=staging,
	// PROCESS_GROUP-CLEAN with PGIs only in env=prod. Expect 1 finding for MIXED.
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.ID != "CHECK_PG_PGIS_SPAN_ENVS" {
		t.Errorf("wrong ID: %s", f.ID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected High, got %s", f.Severity)
	}
	if f.EntityRef == nil || f.EntityRef.ID != "PROCESS_GROUP-MIXED" {
		t.Errorf("expected PROCESS_GROUP-MIXED, got %+v", f.EntityRef)
	}
}

func TestPGPgisSpanEnvs_PgisWithoutEnvTagAreIgnored(t *testing.T) {
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{
			"PROCESS_GROUP_INSTANCE": {
				{EntityID: "PGI-1", ToRelations: map[string][]bundle.RelationshipRef{"isInstanceOf": {{ID: "PG-X", Type: "PROCESS_GROUP"}}}},
				{EntityID: "PGI-2", ToRelations: map[string][]bundle.RelationshipRef{"isInstanceOf": {{ID: "PG-X", Type: "PROCESS_GROUP"}}}},
			},
		},
	}
	if got := (PGPgisSpanEnvs{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 findings on no-env-tag PGIs, got %d", len(got))
	}
}

func TestPGPgisSpanEnvs_AllSameEnvNoFinding(t *testing.T) {
	b := &bundle.Bundle{
		EntitiesByType: map[string][]bundle.Entity{
			"PROCESS_GROUP_INSTANCE": {
				{
					EntityID: "PGI-1",
					Tags:     []bundle.TagOccurrence{{Context: "ENVIRONMENT", Key: "env", Value: "prod"}},
					ToRelations: map[string][]bundle.RelationshipRef{"isInstanceOf": {{ID: "PG-X", Type: "PROCESS_GROUP"}}},
				},
				{
					EntityID: "PGI-2",
					Tags:     []bundle.TagOccurrence{{Context: "ENVIRONMENT", Key: "env", Value: "prod"}},
					ToRelations: map[string][]bundle.RelationshipRef{"isInstanceOf": {{ID: "PG-X", Type: "PROCESS_GROUP"}}},
				},
			},
		},
	}
	if got := (PGPgisSpanEnvs{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 findings on single-env PG, got %d", len(got))
	}
}
