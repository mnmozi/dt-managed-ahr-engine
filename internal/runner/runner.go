// Package runner orchestrates a full checks run against a loaded bundle.
package runner

import (
	"sort"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/checks"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

// Result is the structured output of a full run. It's what gets serialized
// to findings.json. Keep field names stable — downstream consumers depend on them.
type Result struct {
	BundleRoot string             `json:"bundle_root"`
	Engine     EngineMeta         `json:"engine"`
	Counts     Counts             `json:"counts"`
	Findings   []finding.Finding  `json:"findings"`
}

// EngineMeta records what produced the result.
// Useful for debugging and for diff-tool semantic versioning later.
type EngineMeta struct {
	Version       string `json:"version"`
	ChecksApplied int    `json:"checks_applied"`
}

// Counts give a quick summary that consumers can render without walking
// the full findings array.
type Counts struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Run executes every registered check against the bundle and returns a Result.
// Order: findings sorted by Severity (High > Medium > Low > Info), then by ID,
// then by EntityRef.ID for stability.
func Run(b *bundle.Bundle, version string) Result {
	all := checks.All()
	var findings []finding.Finding
	for _, c := range all {
		findings = append(findings, c.Run(b)...)
	}
	sortFindings(findings)

	return Result{
		BundleRoot: b.Root,
		Engine: EngineMeta{
			Version:       version,
			ChecksApplied: len(all),
		},
		Counts:   countBySeverity(findings),
		Findings: findings,
	}
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

func sortFindings(f []finding.Finding) {
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
