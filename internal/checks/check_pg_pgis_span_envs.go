// Check: CHECK_PG_PGIS_SPAN_ENVS
//
// A process group whose process-group-instances span multiple environments
// (e.g. PGIs tagged env=prod AND env=staging under the same PG) is almost
// always wrong: the PG identity is too coarse, treating prod and non-prod
// runs of the same code as one entity. This produces:
//   - alerts that fire across all envs at once
//   - SLOs that mix prod and staging traffic
//   - dashboards that conflate environments
//
// Standard remediation is a PG detection rule that splits the PG by an
// env-revealing signal (DT_CLUSTER_ID env var, host group, k8s namespace, etc.).
//
// Logic:
//   For every PROCESS_GROUP_INSTANCE entity, look up its env tag value.
//   Group PGI env values by parent PG (via PGI.ProcessGroupID()).
//   If a PG has >= 2 distinct non-empty env values across its PGIs, fire.
//
// PGIs without an env tag are ignored — they neither prove nor disprove
// the spanning. A separate check (CHECK_TAG_INCONSISTENT_ROLLOUT) covers
// the missing-env-tag case.
package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/finding"
)

// EnvTagKey is the canonical environment-discrimination tag key.
// Different orgs may use a different key — this is the v1 default.
const EnvTagKey = "env"

// PGPgisSpanEnvs is the registered check.
type PGPgisSpanEnvs struct{}

func (PGPgisSpanEnvs) ID() string    { return "CHECK_PG_PGIS_SPAN_ENVS" }
func (PGPgisSpanEnvs) Phase() string { return "Phase 2" }

func (c PGPgisSpanEnvs) Run(b *bundle.Bundle) []finding.Finding {
	pgis := b.EntitiesByType["PROCESS_GROUP_INSTANCE"]
	if len(pgis) == 0 {
		return nil
	}

	// Build PG id → set of distinct env values across its PGIs.
	type pgState struct {
		envValues map[string]bool
		exemplars []string // entityIds we'll cite in evidence (cap at small N)
	}
	byPG := map[string]*pgState{}

	for _, pgi := range pgis {
		envVal := strings.TrimSpace(pgi.TagValue(EnvTagKey))
		if envVal == "" {
			continue
		}
		pgID := pgi.ProcessGroupID()
		if pgID == "" {
			continue
		}
		st := byPG[pgID]
		if st == nil {
			st = &pgState{envValues: map[string]bool{}}
			byPG[pgID] = st
		}
		if !st.envValues[envVal] {
			st.envValues[envVal] = true
			if len(st.exemplars) < 4 {
				st.exemplars = append(st.exemplars, fmt.Sprintf("%s(env=%s)", pgi.EntityID, envVal))
			}
		}
	}

	// Lookup table from PROCESS_GROUP id -> displayName for nicer titles.
	pgNames := map[string]string{}
	for _, pg := range b.EntitiesByType["PROCESS_GROUP"] {
		pgNames[pg.EntityID] = pg.DisplayName
	}

	// Stable order so output is reproducible.
	var pgIDs []string
	for id, st := range byPG {
		if len(st.envValues) >= 2 {
			pgIDs = append(pgIDs, id)
		}
	}
	sort.Strings(pgIDs)

	var findings []finding.Finding
	for _, pgID := range pgIDs {
		st := byPG[pgID]
		envList := make([]string, 0, len(st.envValues))
		for v := range st.envValues {
			envList = append(envList, v)
		}
		sort.Strings(envList)

		display := pgID
		if name := pgNames[pgID]; name != "" {
			display = fmt.Sprintf("%q (%s)", name, pgID)
		}

		findings = append(findings, finding.Finding{
			ID:       c.ID(),
			Phase:    c.Phase(),
			Severity: finding.SeverityHigh,
			Title: fmt.Sprintf(
				"Process group %s spans %d environments: %s",
				display, len(envList), strings.Join(envList, ", "),
			),
			Description: fmt.Sprintf(
				"Process group %s contains process-group-instances tagged with %d distinct "+
					"%q values: %s. PGIs from different environments shouldn't share a PG — "+
					"this conflates env-specific telemetry into a single grouping. The fix is "+
					"a PG detection rule that splits on a stable env-revealing signal (env var, "+
					"host group, k8s namespace) so each env gets its own PG.",
				display, len(envList), EnvTagKey, strings.Join(envList, ", "),
			),
			Evidence: finding.Evidence{
				Tool:    "dynatrace_managed_discover_entities type(PROCESS_GROUP_INSTANCE)",
				RawPath: "raw/phase2-pgis-all.json",
				DataPoint: fmt.Sprintf(
					"processGroupId=%s envValues=[%s] exemplarPGIs=[%s]",
					pgID, strings.Join(envList, ","), strings.Join(st.exemplars, ", "),
				),
			},
			Recommendation: fmt.Sprintf(
				"Add a PG detection rule (Settings 2.0 builtin:process-group.advanced-detection-rule) "+
					"scoped to PG %s that splits on %q (or a stable proxy: DT_CLUSTER_ID, "+
					"host group, k8s namespace). Validate with dt_validate_settings before applying.",
				pgID, EnvTagKey,
			),
			EntityRef: &finding.EntityRef{
				Kind: "entity",
				ID:   pgID,
				Name: pgNames[pgID],
			},
			FixTemplate: &finding.FixTemplate{
				WriteAction: "create",
				SchemaID:    "builtin:process-group.advanced-detection-rule",
				Hint:        "Create a split rule keyed on env-revealing signal. No automatic payload — depends on which signal is most stable on this PGI's hosts.",
			},
		})
	}
	return findings
}
