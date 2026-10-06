// Check: CHECK_TOKEN_NEVER_USED
//
// API tokens that were issued but never used represent unrealized attack
// surface — somebody requested them, they got minted, and nobody touched
// them. Either:
//   - the workflow they were meant for is dead (rotation candidate)
//   - they were issued speculatively (cleanup candidate)
//   - they're rotating-not-yet-used credentials (legitimate, but worth confirming)
//
// In all three cases the right response is to surface them so a human can
// decide. We don't auto-rotate or auto-revoke from this check.
//
// Logic:
//
//	For every API token in the bundle, if LastUsedDate is nil/empty AND the
//	token has been around for at least MinAgeDaysForNeverUsed, emit a finding.
//	Severity is Medium for tokens with WriteConfig-class scopes (more
//	dangerous if compromised) and Low otherwise.
//
// The age guard prevents firing on tokens minted minutes ago that just
// haven't been used YET because the integration is still being set up.
package checks

import (
	"fmt"
	"sort"
	"time"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

const (
	// MinAgeDaysForNeverUsed is how long a token has to exist before we
	// consider "never used" suspicious. Below this, it's just freshly minted.
	MinAgeDaysForNeverUsed = 14
)

// highPrivilegeScopes lists token scopes that elevate the severity of a
// stale/unused token. Compromise of one of these is materially worse than
// compromise of a read-only token.
var highPrivilegeScopes = map[string]bool{
	"WriteConfig":                   true,
	"settings.write":                true,
	"tenantTokenManagement.create":  true,
	"tenantTokenManagement.delete":  true,
	"credentialVault.write":         true,
	"TenantTokenRotationServiceAPI": true,
	"oneAgents.write":               true,
	"oneAgents.delete":              true,
}

// TokenNeverUsed is the registered check.
type TokenNeverUsed struct{}

func (TokenNeverUsed) ID() string    { return "CHECK_TOKEN_NEVER_USED" }
func (TokenNeverUsed) Phase() string { return "Phase 4.6" }

func (c TokenNeverUsed) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.APITokens) == 0 {
		return nil
	}

	// Age is measured against the bundle's reference time, never the wall
	// clock — same bundle, same findings, whenever it is evaluated.
	now := b.Now()
	cutoff := now.AddDate(0, 0, -MinAgeDaysForNeverUsed)

	// Sort tokens by ID so output is reproducible.
	tokens := make([]bundle.APIToken, len(b.APITokens))
	copy(tokens, b.APITokens)
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].ID < tokens[j].ID })

	var findings []finding.Finding
	for _, t := range tokens {
		if t.LastUsedDate != nil && *t.LastUsedDate != "" {
			continue
		}
		// Skip tokens younger than the threshold.
		created, ok := parseTime(t.CreationDate)
		if !ok {
			// If we can't parse the creation date, err on the side of flagging
			// (it likely means the token has been around a while — older than
			// any sensible recent-format).
		} else if created.After(cutoff) {
			continue
		}

		ageDays := int(now.Sub(created).Hours() / 24)
		isHighPriv := false
		for _, s := range t.Scopes {
			if highPrivilegeScopes[s] {
				isHighPriv = true
				break
			}
		}
		severity := finding.SeverityLow
		if isHighPriv {
			severity = finding.SeverityMedium
		}

		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: severity,
			Title: fmt.Sprintf(
				"API token %q (id %s) has never been used (age ~%d days, %d scopes)",
				t.Name, t.ID, ageDays, len(t.Scopes),
			),
			Description: fmt.Sprintf(
				"Token %q created on %s by %s has no recorded last-used date. "+
					"It has been around for %d days. Either the integration that needs "+
					"it is dead, the token was issued speculatively, or it's a "+
					"rotation-pending credential. Confirm with the owner; if not in "+
					"active use, revoke.",
				t.Name, t.CreationDate, ownerOrUnknown(t.Owner), ageDays,
			),
			Evidence: finding.Evidence{
				Tool:    "dt_get_api_tokens",
				RawPath: "raw/phase46-api-tokens.json",
				DataPoint: fmt.Sprintf(
					"id=%s name=%q owner=%s ageDays=%d highPriv=%t scopeCount=%d",
					t.ID, t.Name, ownerOrUnknown(t.Owner), ageDays, isHighPriv, len(t.Scopes),
				),
			},
			Recommendation: fmt.Sprintf(
				"Contact %s (owner) to confirm whether token %q is still needed. "+
					"If yes, document its purpose and rotate. If no, revoke via "+
					"`/api/v2/apiTokens/%s` DELETE.",
				ownerOrUnknown(t.Owner), t.Name, t.ID,
			),
			EntityRef: &finding.EntityRef{
				Kind: "settings_object",
				ID:   t.ID,
				Name: t.Name,
			},
			FixTemplate: &finding.FixTemplate{
				WriteAction: "delete",
				Hint:        "DELETE /api/v2/apiTokens/{id} — confirm with owner first.",
			},
		})
	}

	return findings
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func ownerOrUnknown(s string) string {
	if s == "" {
		return "<unknown>"
	}
	return s
}
