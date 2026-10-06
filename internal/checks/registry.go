// Package checks contains the deterministic AHR checks.
//
// Each check satisfies the Check interface and lives in its own file
// (check_<name>.go) with a sibling _test.go using a golden fixture.
// The registry below is the single place new checks are wired in.
package checks

import (
	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

// Check is the contract every check must satisfy.
type Check interface {
	// ID is the stable identifier emitted on every produced finding.
	ID() string
	// Phase is the AHR phase this check belongs to (used for grouping in
	// reports and for filtering when running a single phase).
	Phase() string
	// Run is a pure function: same bundle in → same findings out.
	Run(b *bundle.Bundle) []finding.Finding
}

// All returns every registered check. New checks get added here and
// nowhere else — the runner discovers them via this function.
func All() []Check {
	return []Check{
		AutoTagDead{},
		AutoTagOverbroad{},
		HostNoHostGroup{},
		HostGroupSingleton{},
		FullStackNoLogs{},
		TagInconsistentRollout{},
		TokenNeverUsed{},
		PGPgisSpanEnvs{},
		MZDead{},
		MZOverlap{},
	}
}
