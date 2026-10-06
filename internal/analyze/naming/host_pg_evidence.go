// host_pg_evidence.go — derive host naming candidates from the host's
// process groups. The most load-bearing piece of new logic in the hosts
// layer.
//
// Three signals come out of this file:
//
//   1. Dominant-PG name
//      When a host has exactly one non-system app/infra PG, that PG's
//      name (or its best candidate, if the PG itself is generically
//      named) is the strongest host-naming evidence. Confidence: 0.88.
//
//   2. Top-2 concatenation
//      When a host has 2 app PGs (e.g. "orders-api" + "orders-sidecar"),
//      either name alone is a good candidate (0.55 each). We don't
//      concatenate aggressively — operators have to choose.
//
//   3. Fleet-mate match
//      Hosts running the exact same set of non-system PG names (by name
//      hash) are a fleet. If the fleet has ≥ 3 members AND a clear
//      dominant PG, every member gets a high-confidence candidate.
//      Confidence: 0.85 (slightly below dominant-PG because membership
//      could be coincidental on small fleets).
//
//   4. Refusal: many unrelated app PGs (>3) → shared-infra label, low
//      confidence. The host is genuinely a mixed-workload box.
//
//   5. Refusal: only system PGs → bastion / jumphost suggestion at very
//      low confidence (0.35) so operator sees it but it falls into the
//      no_signal bucket.
//
// All inputs are deterministic — the same flat graph yields the same
// candidates, every time.
package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/local/dt-managed-engine/internal/graph"
)

// hostPGEvidence carries the result of classifying one host's PGs into
// the three kinds + emitting candidate names. Built once per host.
type hostPGEvidence struct {
	hostID    string
	appPGs    []graph.ProcessGroup
	infraPGs  []graph.ProcessGroup
	systemPGs []graph.ProcessGroup
	allCands  []Candidate
	// fleetKey is the deterministic hash of the host's non-system PG name
	// set. Hosts with identical fleetKeys are fleet-mates.
	fleetKey string
}

// buildHostPGEvidence groups PGs by host, classifies them, and computes
// per-host candidate sets + fleet keys. Returns a map keyed by hostID.
// Pure — input slice is not mutated.
func buildHostPGEvidence(in graph.Input) map[string]*hostPGEvidence {
	byHost := make(map[string]*hostPGEvidence, len(in.Hosts))
	for _, h := range in.Hosts {
		byHost[h.ID] = &hostPGEvidence{hostID: h.ID}
	}

	for _, pg := range in.ProcessGroups {
		ev, ok := byHost[pg.HostID]
		if !ok {
			// PG belongs to a host that isn't in the input — skip.
			continue
		}
		switch ClassifyPG(pg) {
		case PGKindApp:
			ev.appPGs = append(ev.appPGs, pg)
		case PGKindInfra:
			ev.infraPGs = append(ev.infraPGs, pg)
		case PGKindSystem:
			ev.systemPGs = append(ev.systemPGs, pg)
		}
	}

	// Compute fleet keys + emit per-host candidates.
	for _, ev := range byHost {
		ev.fleetKey = computeFleetKey(ev)
		ev.allCands = emitPGEvidenceCandidates(ev)
	}

	// Apply fleet boost: every host whose fleet has ≥ 3 members AND a
	// clear dominant PG name across the fleet gets a fleet candidate.
	applyFleetBoost(byHost)

	return byHost
}

// computeFleetKey is sha256(sorted-non-system-PG-names) truncated to 16
// hex chars. Two hosts produce the same key iff they run the exact same
// set of non-system PGs. We sort + dedupe inside so order doesn't matter.
func computeFleetKey(ev *hostPGEvidence) string {
	names := make([]string, 0, len(ev.appPGs)+len(ev.infraPGs))
	for _, pg := range ev.appPGs {
		names = append(names, pg.DisplayName)
	}
	for _, pg := range ev.infraPGs {
		names = append(names, pg.DisplayName)
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	// Dedupe in-place.
	uniq := names[:0]
	var last string
	for _, n := range names {
		if n != last {
			uniq = append(uniq, n)
			last = n
		}
	}
	h := sha256.Sum256([]byte(strings.Join(uniq, "\x00")))
	return hex.EncodeToString(h[:])[:16]
}

// emitPGEvidenceCandidates produces per-host candidates from the PG
// classification result. Does NOT include the fleet candidate — that's
// added after we've seen every host.
func emitPGEvidenceCandidates(ev *hostPGEvidence) []Candidate {
	cands := []Candidate{}

	// Refusal cases first — they shape what we emit.
	if len(ev.appPGs) == 0 && len(ev.infraPGs) == 0 {
		// Only system PGs (or no PGs at all). Likely bastion / jump host.
		if len(ev.systemPGs) > 0 {
			cands = append(cands, Candidate{
				Source:     "bastion.hint",
				Name:       "bastion",
				Confidence: 0.35,
				Evidence:   "only system processes detected (sshd / systemd / OneAgent / cron / etc.)",
			})
		}
		return cands
	}

	// Mixed-workload host (many app PGs from different teams).
	if len(ev.appPGs) > 3 {
		cands = append(cands, Candidate{
			Source:     "shared-infra.hint",
			Name:       "shared-infra",
			Confidence: 0.30,
			Evidence:   "host runs many unrelated app PGs (>3) — likely shared infrastructure",
		})
		return cands
	}

	// Dominant app PG case: exactly one app PG.
	if len(ev.appPGs) == 1 {
		name := bestNameForPG(ev.appPGs[0])
		if name != "" {
			cands = append(cands, Candidate{
				Source:     "dominant.app.pg",
				Name:       name,
				Confidence: 0.88,
				Evidence:   "host runs a single app PG: " + ev.appPGs[0].DisplayName,
			})
		}
	}

	// Two-or-three app PGs case: each one is a candidate (medium).
	if len(ev.appPGs) == 2 || len(ev.appPGs) == 3 {
		for _, pg := range ev.appPGs {
			name := bestNameForPG(pg)
			if name == "" {
				continue
			}
			cands = append(cands, Candidate{
				Source:     "top-n.app.pg",
				Name:       name,
				Confidence: 0.55,
				Evidence:   "one of " + plural(len(ev.appPGs), "app PG") + " on this host: " + pg.DisplayName,
			})
		}
	}

	// Infra-only host (databases, caches, queues).
	if len(ev.appPGs) == 0 && len(ev.infraPGs) >= 1 {
		// Use the first non-generic infra PG name.
		for _, pg := range ev.infraPGs {
			name := bestNameForPG(pg)
			if name == "" {
				continue
			}
			cands = append(cands, Candidate{
				Source:     "dominant.infra.pg",
				Name:       name,
				Confidence: 0.65,
				Evidence:   "host runs an infra PG: " + pg.DisplayName,
			})
			break
		}
	}

	return cands
}

// applyFleetBoost adds a "fleet.match" candidate to every host whose
// fleet has ≥ 3 members AND every member already has a top candidate
// agreeing on the name. The fleet name is the dominant PG name shared
// across the fleet.
func applyFleetBoost(byHost map[string]*hostPGEvidence) {
	const minFleetSize = 3
	const fleetConfidence = 0.85

	// Bucket hosts by fleetKey.
	buckets := map[string][]*hostPGEvidence{}
	for _, ev := range byHost {
		if ev.fleetKey == "" {
			continue
		}
		buckets[ev.fleetKey] = append(buckets[ev.fleetKey], ev)
	}

	for _, fleet := range buckets {
		if len(fleet) < minFleetSize {
			continue
		}
		// Need a stable name: pick the highest-confidence candidate from
		// the first host's existing candidates. If everyone agrees, the
		// boost is safe.
		var fleetName string
		if len(fleet[0].allCands) > 0 {
			// Use the highest-conf candidate from member 0.
			best := fleet[0].allCands[0]
			for _, c := range fleet[0].allCands {
				if c.Confidence > best.Confidence {
					best = c
				}
			}
			fleetName = best.Name
		}
		if fleetName == "" {
			continue
		}
		for _, ev := range fleet {
			ev.allCands = append(ev.allCands, Candidate{
				Source:     "fleet.match",
				Name:       fleetName,
				Confidence: fleetConfidence,
				Evidence:   plural(len(fleet), "host") + " run the same PG set; fleet name from first member",
			})
		}
	}
}

// bestNameForPG returns the name to use when this PG is being cited as
// evidence for a HOST. If the PG's display name is already specific, use
// it directly. If the PG's name is generic, run the PG candidate
// extractor and use its top candidate (so a "java" PG with a JarFile
// "/opt/orders/orders-api.jar" contributes "orders-api" to the host's
// candidates, not "java").
func bestNameForPG(pg graph.ProcessGroup) string {
	if IsGeneric(pg.DisplayName, GenericKindProcessGroup) == "" {
		// Healthy PG name — use as-is.
		return cleanName(pg.DisplayName)
	}
	// Recurse into PG candidate extractor for a better name. We pass a
	// zero-value graph context: when naming a HOST from its PGs we only
	// want the PG's OWN-property candidates, not a second hop back out to
	// services / host (that would be circular — the host is what we're
	// naming). The zero ctx disables branches 8-10.
	pgCands, _, _ := filterCandidates(extractPGCandidates(pg, pgGraphContext{}), pg.DisplayName)
	if len(pgCands) == 0 {
		return ""
	}
	sorted, decision := BucketAndRank(pgCands)
	if decision == DecisionNoSignal || len(sorted) == 0 {
		return ""
	}
	return sorted[0].Name
}

// plural is a tiny grammar helper so messages read naturally.
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	// dumb but enough for "PG"/"host"
	return itoa(n) + " " + word + "s"
}

// itoa avoids pulling in strconv just for plural strings.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
