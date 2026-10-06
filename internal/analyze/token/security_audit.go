// Package token contains analyzers operating on /api/v2/apiTokens data.
//
// security_audit.go — classifies tokens against common security findings:
//   - no expiration date set
//   - expired (expirationDate in the past)
//   - never used (no lastUsedDate)
//   - stale (lastUsedDate > N days ago)
//   - high privilege (one of a known write/admin scope set)
//   - disabled
// Plus scope distribution and owner distribution.
//
// Pure function. The consumer fetches /api/v2/apiTokens and passes the result
// in along with `nowMillis` (reference time) so behaviour is reproducible —
// the same input bytes always produce the same output bytes regardless of
// when the analyzer runs.
package token

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/local/dt-managed-engine/internal/analyze"
)

func init() {
	analyze.Register(SecurityAudit{})
}

// SecurityAudit is the analyzer.
type SecurityAudit struct{}

func (SecurityAudit) Kind() string { return "token.security_audit" }

func (SecurityAudit) Description() string {
	return "Classify API tokens against common security findings: no-expiration, expired, never-used, stale-usage, high-privilege (write/admin scopes), disabled. Returns counts + samples per category, plus scope and owner distributions. Pure function — consumer provides nowMillis reference time for reproducibility."
}

// DefaultStaleUsageDays is what `staleUsageThresholdDays` falls back to when
// the consumer doesn't provide it. Matches the historical TS value.
const DefaultStaleUsageDays = 90

// DefaultHighPrivScopes matches the historical TS list.
// Consumers can override via input.HighPrivilegeScopes.
var DefaultHighPrivScopes = []string{
	"WriteConfig",
	"settings.write",
	"tenantTokenManagement.create",
	"tenantTokenManagement.delete",
	"credentialVault.write",
	"TenantTokenRotationServiceAPI",
}

// Input is the analyzer input shape.
type Input struct {
	// ApiTokens mirrors /api/v2/apiTokens `apiTokens[]`.
	ApiTokens []Token `json:"apiTokens"`

	// NowMillis is the reference time (Unix epoch ms) for "expired" and
	// "stale" classification. REQUIRED for purity — without it the analyzer
	// would have to read the wall clock and lose determinism.
	NowMillis int64 `json:"nowMillis"`

	// StaleUsageThresholdDays — a token last used more than this many days
	// ago counts as stale. Defaults to DefaultStaleUsageDays (90) if zero.
	StaleUsageThresholdDays int `json:"staleUsageThresholdDays,omitempty"`

	// HighPrivilegeScopes — scopes that mark a token as high-priv.
	// Defaults to DefaultHighPrivScopes if empty.
	HighPrivilegeScopes []string `json:"highPrivilegeScopes,omitempty"`
}

// Token is the relevant subset of /api/v2/apiTokens entries.
type Token struct {
	ID                  string   `json:"id,omitempty"`
	Name                string   `json:"name,omitempty"`
	Owner               string   `json:"owner,omitempty"`
	Enabled             *bool    `json:"enabled,omitempty"` // pointer so missing != false
	PersonalAccessToken bool     `json:"personalAccessToken,omitempty"`
	CreationDate        string   `json:"creationDate,omitempty"`
	ExpirationDate      *string  `json:"expirationDate,omitempty"` // pointer so missing != ""
	LastUsedDate        *string  `json:"lastUsedDate,omitempty"`   // pointer so missing != ""
	Scopes              []string `json:"scopes,omitempty"`
	ModifiedDate        string   `json:"modifiedDate,omitempty"`
}

// Output is the analyzer result shape.
type Output struct {
	TotalTokens       int             `json:"totalTokens"`
	ScopeDistribution map[string]int  `json:"scopeDistribution"`
	OwnerDistribution map[string]int  `json:"ownerDistribution"`
	Findings          FindingsSummary `json:"findings"`
	// AppliedDefaults echoes the actual threshold + high-priv list used,
	// so the consumer can see what we classified against.
	AppliedDefaults AppliedDefaults `json:"appliedDefaults"`
}

// FindingsSummary groups the security-classification results.
//
// Each category has a count and a "sample" (up to 50 entries) with summary
// fields useful for triage. The samples mirror the historical TS shape.
type FindingsSummary struct {
	NoExpirationCount      int          `json:"noExpirationCount"`
	NoExpirationSample     []TokenRow   `json:"noExpirationSample"`
	ExpiredCount           int          `json:"expiredCount"`
	ExpiredSample          []TokenRow   `json:"expiredSample"`
	NeverUsedCount         int          `json:"neverUsedCount"`
	NeverUsedSample        []TokenRow   `json:"neverUsedSample"`
	StaleUsageCount        int          `json:"staleUsageCount"`
	StaleUsageSample       []TokenRow   `json:"staleUsageSample"`
	HighPrivilegeCount     int          `json:"highPrivilegeCount"`
	HighPrivilegeSample    []TokenRow   `json:"highPrivilegeSample"`
	DisabledCount          int          `json:"disabledCount"`
}

// AppliedDefaults shows which values were actually used for classification.
type AppliedDefaults struct {
	StaleUsageThresholdDays int      `json:"staleUsageThresholdDays"`
	HighPrivilegeScopes     []string `json:"highPrivilegeScopes"`
	NowMillis               int64    `json:"nowMillis"`
}

// TokenRow is a per-token summary emitted in each sample. Mirrors the
// historical TS `trim()` output exactly so external behavior is preserved.
type TokenRow struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	Enabled        *bool    `json:"enabled,omitempty"`
	ExpirationDate *string  `json:"expirationDate,omitempty"`
	LastUsedDate   *string  `json:"lastUsedDate,omitempty"`
	AgeDays        *int     `json:"ageDays,omitempty"`
	UnusedDays     *int     `json:"unusedDays,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}

const sampleCap = 50

// Run is the analyzer entrypoint.
func (SecurityAudit) Run(raw json.RawMessage) (any, error) {
	var in Input
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	if in.NowMillis == 0 {
		return nil, fmt.Errorf("nowMillis is required (analyzer must be pure; pass Date.now() from the consumer)")
	}

	staleThreshold := in.StaleUsageThresholdDays
	if staleThreshold <= 0 {
		staleThreshold = DefaultStaleUsageDays
	}
	highPrivScopes := in.HighPrivilegeScopes
	if len(highPrivScopes) == 0 {
		highPrivScopes = DefaultHighPrivScopes
	}
	highPrivSet := map[string]bool{}
	for _, s := range highPrivScopes {
		highPrivSet[s] = true
	}

	out := Output{
		ScopeDistribution: map[string]int{},
		OwnerDistribution: map[string]int{},
		AppliedDefaults: AppliedDefaults{
			StaleUsageThresholdDays: staleThreshold,
			HighPrivilegeScopes:     highPrivScopes,
			NowMillis:               in.NowMillis,
		},
	}

	for _, t := range in.ApiTokens {
		out.TotalTokens++

		// Scope distribution
		for _, s := range t.Scopes {
			out.ScopeDistribution[s]++
		}

		// Owner distribution — "?" for missing
		owner := t.Owner
		if owner == "" {
			owner = "?"
		}
		out.OwnerDistribution[owner]++

		// Classification
		row := toRow(t, in.NowMillis)

		switch {
		case t.ExpirationDate == nil:
			out.Findings.NoExpirationCount++
			if len(out.Findings.NoExpirationSample) < sampleCap {
				out.Findings.NoExpirationSample = append(out.Findings.NoExpirationSample, row)
			}
		default:
			if d := daysFromNow(*t.ExpirationDate, in.NowMillis); d != nil && *d > 0 {
				out.Findings.ExpiredCount++
				if len(out.Findings.ExpiredSample) < sampleCap {
					out.Findings.ExpiredSample = append(out.Findings.ExpiredSample, row)
				}
			}
		}

		switch {
		case t.LastUsedDate == nil:
			out.Findings.NeverUsedCount++
			if len(out.Findings.NeverUsedSample) < sampleCap {
				out.Findings.NeverUsedSample = append(out.Findings.NeverUsedSample, row)
			}
		default:
			if d := daysFromNow(*t.LastUsedDate, in.NowMillis); d != nil && *d > staleThreshold {
				out.Findings.StaleUsageCount++
				if len(out.Findings.StaleUsageSample) < sampleCap {
					out.Findings.StaleUsageSample = append(out.Findings.StaleUsageSample, row)
				}
			}
		}

		for _, s := range t.Scopes {
			if highPrivSet[s] {
				out.Findings.HighPrivilegeCount++
				if len(out.Findings.HighPrivilegeSample) < sampleCap {
					out.Findings.HighPrivilegeSample = append(out.Findings.HighPrivilegeSample, row)
				}
				break
			}
		}

		if t.Enabled != nil && !*t.Enabled {
			out.Findings.DisabledCount++
		}
	}

	return out, nil
}

func toRow(t Token, nowMillis int64) TokenRow {
	row := TokenRow{
		ID:             t.ID,
		Name:           t.Name,
		Owner:          t.Owner,
		Enabled:        t.Enabled,
		ExpirationDate: t.ExpirationDate,
		LastUsedDate:   t.LastUsedDate,
		Scopes:         t.Scopes,
	}
	if t.CreationDate != "" {
		if d := daysFromNow(t.CreationDate, nowMillis); d != nil {
			row.AgeDays = d
		}
	}
	if t.LastUsedDate != nil {
		if d := daysFromNow(*t.LastUsedDate, nowMillis); d != nil {
			row.UnusedDays = d
		}
	}
	return row
}

// daysFromNow parses an ISO-8601 timestamp and returns days since (positive)
// or until (negative) the given nowMillis. Returns nil on parse failure.
func daysFromNow(iso string, nowMillis int64) *int {
	iso = strings.TrimSpace(iso)
	if iso == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		// Try a couple of common alternative formats Dynatrace might emit.
		t, err = time.Parse("2006-01-02T15:04:05Z", iso)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05.000Z", iso)
			if err != nil {
				return nil
			}
		}
	}
	diff := nowMillis - t.UnixMilli()
	d := int(diff / 86400000)
	return &d
}
