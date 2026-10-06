// Package runner orchestrates a full checks run against a loaded bundle.
//
// Per the engine/consumer split: the runner produces findings + counts and
// returns them in registration-determined order. Sorting for display is the
// caller's responsibility (CLI consumer, MCP consumer, etc.) — runner does
// pure aggregation, not presentation.
package runner

import (
	"sort"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/checks"
	"github.com/local/dt-managed-engine/internal/finding"
)

// Result is the structured output of a full run.
type Result struct {
	BundleRoot string            `json:"bundle_root"`
	Engine     EngineMeta        `json:"engine"`
	Counts     Counts            `json:"counts"`
	Findings   []finding.Finding `json:"findings"`
}

// EngineMeta records what produced the result.
type EngineMeta struct {
	Version       string `json:"version"`
	ChecksApplied int    `json:"checks_applied"`
}

// Counts give a quick summary consumers can render without walking findings[].
type Counts struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Run executes every registered check and returns a Result.
// Findings are returned in check-registration order. Consumers that want a
// different order call SortBySeverity (or sort themselves).
func Run(b *bundle.Bundle, version string) Result {
	all := checks.All()
	var findings []finding.Finding
	for _, c := range all {
		findings = append(findings, c.Run(b)...)
	}
	return Finalize(b.Root, version, len(all), findings)
}

// Finalize wraps a pre-computed findings slice into a Result with counts.
// Does NOT sort — sort is a presentation concern.
func Finalize(bundleRoot, version string, checksApplied int, findings []finding.Finding) Result {
	return Result{
		BundleRoot: bundleRoot,
		Engine: EngineMeta{
			Version:       version,
			ChecksApplied: checksApplied,
		},
		Counts:   countBySeverity(findings),
		Findings: findings,
	}
}

// SortBySeverity sorts findings in place: Severity (High > Medium > Low > Info),
// then check ID, then entity ref ID. The canonical "human-readable" sort.
// Both the assess CLI and the MCP consumer use this; third-party consumers
// are free to use a different sort.
func SortBySeverity(f []finding.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		ri, rj := severityRank(f[i].Severity), severityRank(f[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if f[i].ID != f[j].ID {
			return f[i].ID < f[j].ID
		}
		var ei, ej string
		if f[i].EntityRef != nil {
			ei = f[i].EntityRef.ID
		}
		if f[j].EntityRef != nil {
			ej = f[j].EntityRef.ID
		}
		return ei < ej
	})
}

func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityHigh:
		return 0
	case finding.SeverityMedium:
		return 1
	case finding.SeverityLow:
		return 2
	case finding.SeverityInfo:
		return 3
	}
	return 4
}

func countBySeverity(f []finding.Finding) Counts {
	var c Counts
	for _, x := range f {
		c.Total++
		switch x.Severity {
		case finding.SeverityHigh:
			c.High++
		case finding.SeverityMedium:
			c.Medium++
		case finding.SeverityLow:
			c.Low++
		case finding.SeverityInfo:
			c.Info++
		}
	}
	return c
}
