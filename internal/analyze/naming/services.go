// services.go — the "services.naming_audit" analyzer.
//
// For every service with a generic display name, collect candidates from
// the graph around it (endpoints, backing PGIs, backing PGs, sole caller,
// host context) and emit a per-entity report with a confidence bucket.
//
// Output shape is identical to the PG and host analyzers — operators see
// the same per-entity layout across all naming-hygiene tools, and the
// same dt_apply_*_clarifying_tag lattice applies.
package naming

import (
	"encoding/json"
	"fmt"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/graph"
)

func init() {
	analyze.Register(Services{})
}

// Services is the analyzer entrypoint.
type Services struct{}

// Kind dispatched via engine_analyze.
func (Services) Kind() string { return "services.naming_audit" }

// Description shown by engine_list.
func (Services) Description() string {
	return "Audit service display names. Flags services whose name is generic (port-only like :80 / 8080, bare protocol like HTTP, bare technology like nginx, Dynatrace defaults like 'Requests executed in HTTP', localhost) and extracts ranked candidate names from the graph around each service: SERVICE_METHOD endpoint paths and class stems (Phase B), backing PGI K8s container / image / JarFile, backing PG display name (when not itself generic), sole inbound caller (1:1 tiebreaker), and host context. Returns per-entity reports with confidence buckets (high_confidence | ambiguous | no_signal). Run alongside dt_audit_process_group_naming — they share the same graph fetch. Pure function over flat graph input."
}

// ServicesInput is the analyzer's input.
type ServicesInput struct {
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

// ServicesOutput is the analyzer result.
type ServicesOutput struct {
	Reports         []EntityNamingReport `json:"reports"`
	Counts          ServicesNamingCounts `json:"counts"`
	AppliedDefaults Defaults             `json:"appliedDefaults"`
}

// ServicesNamingCounts is the per-bucket summary across the report set.
type ServicesNamingCounts struct {
	TotalServices  int `json:"totalServices"`
	Generic        int `json:"generic"`
	HighConfidence int `json:"highConfidence"`
	Ambiguous      int `json:"ambiguous"`
	NoSignal       int `json:"noSignal"`
}

// Run is the analyzer's pure entrypoint.
func (Services) Run(raw json.RawMessage) (any, error) {
	var in ServicesInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	maxCandidates := in.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 5
	}

	out := ServicesOutput{
		Reports: []EntityNamingReport{},
		Counts: ServicesNamingCounts{
			TotalServices: len(in.Services),
		},
		AppliedDefaults: Defaults{
			HighConfidenceMin: HighConfidenceMin,
			HighConfidenceGap: HighConfidenceGap,
			AmbiguousMin:      AmbiguousMin,
			MaxCandidates:     maxCandidates,
		},
	}

	// Build the graph-traversal index once.
	ctx := buildServiceGraphContext(in.Input)

	for _, svc := range in.Services {
		reason := IsGeneric(svc.DisplayName, GenericKindService)
		if reason == "" && !in.AuditAll {
			continue
		}
		if reason != "" {
			out.Counts.Generic++
		}

		raw := extractServiceCandidates(svc, ctx)
		// Defensive pre-trim: a service with hundreds of endpoints could
		// otherwise inflate `cands` enough to slow BucketAndRank. Trim to
		// 2x so the dedupe pass still lands on the strongest candidates.
		if len(raw) > maxCandidates*2 {
			raw = raw[:maxCandidates*2]
		}

		report := finishReport(svc.ID, string(graph.TypeService), svc.DisplayName, reason, raw, in.Explain, in.AuditAll)
		if report == nil {
			continue
		}
		// Apply maxCandidates AFTER bucketing so we keep the top N by
		// confidence, not the first N by branch order.
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
