package checks

import (
	"testing"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

func TestTokenNeverUsed_FixtureProducesExpectedFindings(t *testing.T) {
	b, err := bundle.Load(goldenPath(t, "never-used-token"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := TokenNeverUsed{}.Run(b)

	// Fixture: 4 tokens.
	// - tok-active: lastUsedDate present → silent
	// - tok-stale-readonly: never-used, old, low-priv → Low finding
	// - tok-stale-writeconfig: never-used, old, high-priv → Medium finding
	// - tok-fresh-unused: never-used but younger than 14d → silent
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}

	got_lows, got_meds := 0, 0
	wantIDs := map[string]bool{"tok-stale-readonly": true, "tok-stale-writeconfig": true}
	for _, f := range got {
		if f.ID != "CHECK_TOKEN_NEVER_USED" {
			t.Errorf("wrong ID: %s", f.ID)
		}
		if f.EntityRef == nil || !wantIDs[f.EntityRef.ID] {
			t.Errorf("unexpected token in finding: %+v", f.EntityRef)
		}
		delete(wantIDs, f.EntityRef.ID)

		switch f.EntityRef.ID {
		case "tok-stale-readonly":
			got_lows++
			if f.Severity != finding.SeverityLow {
				t.Errorf("expected Low for read-only stale token, got %s", f.Severity)
			}
		case "tok-stale-writeconfig":
			got_meds++
			if f.Severity != finding.SeverityMedium {
				t.Errorf("expected Medium for write-priv stale token, got %s", f.Severity)
			}
		}
	}
	if got_lows != 1 || got_meds != 1 {
		t.Errorf("expected exactly 1 Low and 1 Medium, got lows=%d meds=%d", got_lows, got_meds)
	}
	if len(wantIDs) != 0 {
		t.Errorf("missed expected token findings: %v", wantIDs)
	}
}

func TestTokenNeverUsed_NoTokensNoFindings(t *testing.T) {
	b := &bundle.Bundle{}
	if got := (TokenNeverUsed{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 findings on empty bundle, got %d", len(got))
	}
}

func TestTokenNeverUsed_AllUsedNoFindings(t *testing.T) {
	used := "2026-04-29T08:30:00Z"
	b := &bundle.Bundle{
		APITokens: []bundle.APIToken{
			{ID: "t1", Name: "n1", CreationDate: "2024-01-01T00:00:00Z", LastUsedDate: &used, Scopes: []string{"WriteConfig"}},
		},
	}
	if got := (TokenNeverUsed{}).Run(b); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}
