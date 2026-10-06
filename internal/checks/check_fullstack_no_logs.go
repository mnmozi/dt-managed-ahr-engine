// Check: CHECK_FULLSTACK_NO_LOGS
//
// A host running OneAgent in FULL_STACK monitoring mode is paying for full-stack
// observability — but if its log monitoring module is disabled or absent, log
// data isn't being captured. This is a silent coverage gap: the customer is
// paying full-stack rates and missing logs from those hosts.
//
// Two failure shapes are detected:
//  1. The host has no log module at all (older OneAgent missing the module
//     entirely, or never installed).
//  2. The host has a log module but it's disabled.
//
// Either way the symptom for the customer is identical and the remediation is
// the same: enable / install the log module for FULL_STACK hosts that should
// be sending logs, OR downgrade the host to INFRASTRUCTURE mode if logs were
// intentionally excluded.
package checks

import (
	"fmt"

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/finding"
)

// FullStackNoLogs is the registered check.
type FullStackNoLogs struct{}

func (FullStackNoLogs) ID() string    { return "CHECK_FULLSTACK_NO_LOGS" }
func (FullStackNoLogs) Phase() string { return "Phase 1" }

func (c FullStackNoLogs) Run(b *bundle.Bundle) []finding.Finding {
	if len(b.OneAgents) == 0 {
		return nil
	}

	// An inventory where NO host reports any module is "module data
	// unavailable" (observed live: Managed 1.346 serves only /api/v1/oneagents,
	// which returns modules:[] for every host), not "every host has logs
	// disabled". Flagging each host would be N false positives; say it once.
	if !anyModuleData(b.OneAgents) {
		return []finding.Finding{{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityInfo,
			Title:    "OneAgent module data unavailable — log-module coverage could not be evaluated",
			Description: fmt.Sprintf(
				"None of the %d OneAgent entries in the bundle carries a modules[] list, so "+
					"per-host log-module state is unknown. This is a data-source limitation "+
					"(the OneAgents API on this Managed version omits module details), not "+
					"evidence that log monitoring is off.",
				len(b.OneAgents),
			),
			Evidence: finding.Evidence{
				Tool:      "dt_get_oneagent_module_status",
				RawPath:   "raw/phase1-oneagents.json",
				DataPoint: fmt.Sprintf("oneagents=%d hostsWithModules=0", len(b.OneAgents)),
			},
			Recommendation: "Assess log coverage from HOST entity properties instead " +
				"(logFileStatus / logSourceState via dt_get_process_properties or " +
				"raw/phase1-hosts-all.json), or from builtin:logmonitoring.* settings.",
		}}
	}

	var findings []finding.Finding
	for _, oa := range b.OneAgents {
		if oa.MonitoringType != "FULL_STACK" {
			continue
		}
		if oa.HasEnabledLogModule() {
			continue
		}

		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityMedium,
			Title: fmt.Sprintf(
				"Host %q is in FULL_STACK monitoring mode but log monitoring is disabled or missing",
				oa.HostInfo.HostName,
			),
			Description: fmt.Sprintf(
				"OneAgent on host %s (%s) reports monitoringType=FULL_STACK but no log "+
					"monitoring module is enabled. Full-stack hosts are billed for full coverage; "+
					"missing log capture means a paid-for capability isn't being used.",
				oa.HostInfo.HostName, oa.HostInfo.EntityID,
			),
			Evidence: finding.Evidence{
				Tool:    "dt_get_oneagent_module_status",
				RawPath: "raw/phase1-oneagents.json",
				DataPoint: fmt.Sprintf(
					"hostName=%s entityId=%s monitoringType=FULL_STACK enabledLogModule=false",
					oa.HostInfo.HostName, oa.HostInfo.EntityID,
				),
			},
			Recommendation: fmt.Sprintf(
				"On host %s, enable the OneAgent log monitoring module — either via "+
					"`builtin:host.process-monitoring` overrides or by re-running the OneAgent "+
					"installer with log monitoring included. If log capture is intentionally "+
					"disabled on this host, downgrade monitoringType from FULL_STACK to "+
					"INFRASTRUCTURE to avoid paying for a capability that isn't used.",
				oa.HostInfo.HostName,
			),
			EntityRef: &finding.EntityRef{
				Kind: "entity",
				ID:   oa.HostInfo.EntityID,
				Name: oa.HostInfo.HostName,
			},
		})
	}
	return findings
}

// anyModuleData reports whether at least one OneAgent entry carries module
// details. Zero across the whole inventory means the source omitted them.
func anyModuleData(agents []bundle.OneAgent) bool {
	for _, oa := range agents {
		if len(oa.Modules) > 0 {
			return true
		}
	}
	return false
}
