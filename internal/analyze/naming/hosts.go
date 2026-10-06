// hosts.go — the "hosts.naming_audit" analyzer.
//
// For every host with a generic display name, combine:
//
//   - candidates extracted from the host's own properties (cloud tags,
//     k8s labels, FQDN) — from host_candidates.go
//   - candidates derived from the host's process groups (dominant PG,
//     top-N, fleet membership, bastion / shared-infra hints) — from
//     host_pg_evidence.go
//
// The two streams concatenate; BucketAndRank dedupes by name (so when
// AWS tag "Name=orders-api" agrees with the dominant PG "orders-api",
// we surface one candidate at the higher confidence).
//
// Output shape is identical to the PG analyzer — operators see the same
// per-entity report layout across all naming-hygiene tools.
package naming

import (
	"encoding/json"
	"fmt"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/graph"
)

func init() {
	analyze.Register(Hosts{})
}

// Hosts is the analyzer entrypoint.
type Hosts struct{}

// Kind dispatched via engine_analyze.
func (Hosts) Kind() string { return "hosts.naming_audit" }

// Description shown by engine_list.
func (Hosts) Description() string {
	return "Audit host display names. Flags hosts whose name is generic (cloud-provider default like ip-10-0-1-23 / gke-prod-pool-xxx, bare technology, localhost) and extracts ranked candidate names from BOTH the host's own properties (AWS/GCP/Azure tags, Kubernetes labels, FQDN) AND its process groups (dominant non-system PG, top-N app PG names, fleet-match across same-PG-set hosts, bastion/shared-infra hints). Returns per-entity reports with confidence buckets (high_confidence / ambiguous / no_signal). Run BEFORE tagging — name-based tag rules are unreliable when hosts have cloud-default names. Pure function over flat graph input."
}

// HostsInput is the analyzer's input. Same flat graph shape used by the
// PG analyzer; we consume hosts + processGroups.
type HostsInput struct {
	graph.Input
	// MaxCandidates limits the candidates emitted per entity (default 5).
	MaxCandidates int `json:"maxCandidates,omitempty"`
	// Explain attaches rejectedCandidates (with written reasons) to every
	// report, so "why no suggestion?" always has an answer. Default false.
	Explain bool `json:"explain,omitempty"`
	// AuditAll emits a report for EVERY entity, not just generic-named
	// ones. Healthy entities get advisory candidates + corroborations and
	// genericReason stays empty. Pattern tables will always lag new techs;
	// this mode lets the operator judge every entity themselves. Default
	// false (focused output).
	AuditAll bool `json:"auditAll,omitempty"`
}

// HostsOutput is the analyzer result.
type HostsOutput struct {
	Reports         []EntityNamingReport `json:"reports"`
	Counts          HostsNamingCounts    `json:"counts"`
	AppliedDefaults Defaults             `json:"appliedDefaults"`
}

// HostsNamingCounts is the per-bucket summary across the report set.
type HostsNamingCounts struct {
	TotalHosts     int `json:"totalHosts"`
	Generic        int `json:"generic"`
	HighConfidence int `json:"highConfidence"`
	Ambiguous      int `json:"ambiguous"`
	NoSignal       int `json:"noSignal"`
}

// Run is the analyzer's pure entrypoint.
func (Hosts) Run(raw json.RawMessage) (any, error) {
	var in HostsInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	maxCandidates := in.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 5
	}

	out := HostsOutput{
		Reports: []EntityNamingReport{},
		Counts: HostsNamingCounts{
			TotalHosts: len(in.Hosts),
		},
		AppliedDefaults: Defaults{
			HighConfidenceMin: HighConfidenceMin,
			HighConfidenceGap: HighConfidenceGap,
			AmbiguousMin:      AmbiguousMin,
			MaxCandidates:     maxCandidates,
		},
	}

	// Build PG-derived evidence once (includes fleet detection across hosts).
	pgEvidence := buildHostPGEvidence(in.Input)

	for _, h := range in.Hosts {
		reason := IsGeneric(h.DisplayName, GenericKindHost)
		if reason == "" && !in.AuditAll {
			continue
		}
		if reason != "" {
			out.Counts.Generic++
		}

		// Merge: own-properties candidates + PG-evidence candidates.
		raw := extractHostOwnCandidates(h)
		if ev, ok := pgEvidence[h.ID]; ok {
			raw = append(raw, ev.allCands...)
		}
		if len(raw) > maxCandidates*2 {
			// Pre-trim before bucket/dedupe so we don't push noise through.
			raw = raw[:maxCandidates*2]
		}

		report := finishReport(h.ID, string(graph.TypeHost), h.DisplayName, reason, raw, in.Explain, in.AuditAll)
		if report == nil {
			continue
		}
		// Apply maxCandidates AFTER bucketing so we keep the top N by confidence.
		if len(report.Candidates) > maxCandidates {
			report.Candidates = report.Candidates[:maxCandidates]
		}
		if reason != "" { // buckets summarize FLAGGED entities only
			switch report.Decision {
			case DecisionHighConfidence:
				out.Counts.HighConfidence++
			case DecisionAmbiguous:
				out.Counts.Ambiguous++
			case DecisionNoSignal:
				out.Counts.NoSignal++
			}
		}
		out.Reports = append(out.Reports, *report)
	}

	return out, nil
}
