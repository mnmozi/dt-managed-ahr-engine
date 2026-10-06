// service_candidates.go — candidate extraction for the
// services.naming_audit analyzer.
//
// A SERVICE in Dynatrace's model sits downstream of its backing PGIs. The
// richest naming signals therefore live on the graph around it, not on
// its own properties:
//
//   - endpoints      → URL paths the service serves (Phase-B path/class
//                      analysis shared with the PG analyzer)
//   - backing PGI    → KubernetesContainerName / image / JarFile
//   - backing PG     → the PG's display name (when not itself generic)
//   - sole caller    → single inbound caller's display name (0.30 tiebreaker)
//   - host context   → meaningful root of the host name (0.40 tiebreaker)
//
// Branches append independently — finishReport → BucketAndRank handles
// sort + dedupe, so branch order is cosmetic.
package naming

import (
	"strings"

	"github.com/local/dt-managed-engine/internal/graph"
)

// serviceGraphContext holds the index maps that let extractServiceCandidates
// walk SERVICE → PGI → PG and PGI → HOST without re-scanning the flat
// input once per service.
//
// Zero-value is safe: all branches no-op when their maps are nil. This
// matters for tests that exercise the function with a synthetic context.
type serviceGraphContext struct {
	pgiByID     map[string]graph.ProcessGroupInstance
	pgByID      map[string]graph.ProcessGroup
	hostByID    map[string]graph.Host
	serviceByID map[string]graph.Service
}

// buildServiceGraphContext indexes the flat input for service-centric
// traversal. O(N) over the inputs.
func buildServiceGraphContext(in graph.Input) serviceGraphContext {
	ctx := serviceGraphContext{
		pgiByID:     make(map[string]graph.ProcessGroupInstance, len(in.ProcessGroupInstances)),
		pgByID:      make(map[string]graph.ProcessGroup, len(in.ProcessGroups)),
		hostByID:    make(map[string]graph.Host, len(in.Hosts)),
		serviceByID: make(map[string]graph.Service, len(in.Services)),
	}
	for _, pgi := range in.ProcessGroupInstances {
		ctx.pgiByID[pgi.ID] = pgi
	}
	for _, pg := range in.ProcessGroups {
		ctx.pgByID[pg.ID] = pg
	}
	for _, h := range in.Hosts {
		ctx.hostByID[h.ID] = h
	}
	for _, s := range in.Services {
		ctx.serviceByID[s.ID] = s
	}
	return ctx
}

// extractServiceCandidates is the per-service heuristic table. Confidence
// numbers mirror the PG analyzer where the signals overlap (endpoints, K8s
// container, image, jar) so a service and its backing PG see the same
// evidence at the same strength.
func extractServiceCandidates(svc graph.Service, ctx serviceGraphContext) []Candidate {
	cands := []Candidate{}

	// 0. The display name itself often EMBEDS the identity inside a
	//    Dynatrace default shell. Two shapes, both name-derived:
	//
	//    "Catalina/localhost (/tariff)"            → context root "tariff"
	//    "uvicorn order-service-* on port 80"      → de-prefixed "order-service"
	dn := strings.TrimSpace(svc.DisplayName)
	if m := parenSuffixRegex.FindString(dn); m != "" {
		inner := strings.Trim(strings.TrimSpace(m), "() \t")
		seg := strings.Trim(inner, "/")
		if seg != "" && meaningfulPathSeg(strings.ToLower(seg)) {
			cands = append(cands, Candidate{
				Source:     "name.context-root",
				Name:       cleanName(seg),
				Confidence: 0.80,
				Evidence:   "context root in display name: " + m,
			})
		}
	}
	base := parenSuffixRegex.ReplaceAllString(dn, "")
	if pm := onPortNameRegex.FindStringSubmatch(base); pm != nil {
		base = strings.TrimSpace(pm[1])
	}
	if fields := strings.Fields(base); len(fields) >= 2 {
		dropped := 0
		for dropped < len(fields)-1 && genericNameToken(strings.ToLower(fields[dropped])) {
			dropped++
		}
		if dropped > 0 {
			rest := strings.Join(fields[dropped:], "-")
			if name := cleanName(rest); name != "" {
				cands = append(cands, Candidate{
					Source:     "name.embedded",
					Name:       name,
					Confidence: 0.82,
					Evidence:   "workload identity embedded in display name after tech prefix: " + svc.DisplayName,
				})
			}
		}
	}

	// 1. Endpoints — reuses the PG analyzer's Phase-B path/class analysis.
	//    Strongest deterministic signal when present.
	cands = append(cands, endpointNameCandidates(svc.ID, svc.Endpoints)...)

	// 2. Backing PGIs — K8s metadata + image + jar live on the instance.
	//    We don't dedupe PGIs here; BucketAndRank collapses duplicate names
	//    later, and the redundant evidence helps an operator see "two PGIs
	//    confirm this".
	seenPG := make(map[string]struct{})
	seenHost := make(map[string]struct{})
	for _, pgiID := range svc.PgiIDs {
		pgi, ok := ctx.pgiByID[pgiID]
		if !ok {
			continue
		}

		k8sName := stringProp(pgi.Properties, "KubernetesContainerName")
		if k8sName == "" {
			k8sName = metadataProp(pgi.Properties, "KUBERNETES_CONTAINER_NAME", "CONTAINER_NAME")
		}
		if k8sName != "" {
			name := cleanName(k8sName)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "backing.pgi.k8s",
					Name:       name,
					Confidence: 0.88,
					Evidence:   "backing PGI " + pgiID + " KubernetesContainerName=" + k8sName,
				})
			}
		}
		if v := stringProp(pgi.Properties, "DockerContainerImageName"); v != "" {
			name := cleanName(imageTail(v))
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "backing.pgi.image",
					Name:       name,
					Confidence: 0.80,
					Evidence:   "backing PGI " + pgiID + " DockerContainerImageName=" + v,
				})
			}
		}
		pgiJar := stringProp(pgi.Properties, "JarFile")
		if pgiJar == "" {
			pgiJar = metadataProp(pgi.Properties, "JAVA_JAR_FILE", "JAR_FILE")
		}
		if pgiJar != "" {
			name := cleanName(jarBasename(pgiJar))
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "backing.pgi.jar",
					Name:       name,
					Confidence: 0.80,
					Evidence:   "backing PGI " + pgiID + " JarFile=" + pgiJar,
				})
			}
		}

		// Collect the distinct PG IDs and host IDs across the backing PGIs
		// for the next two branches. Walking the PGIs once is cheaper than
		// a separate pass.
		if pgi.PGID != "" {
			seenPG[pgi.PGID] = struct{}{}
		}
		if pgi.HostID != "" {
			seenHost[pgi.HostID] = struct{}{}
		}
	}

	// 3. Backing PGs — the PG's display name when it's itself meaningful.
	//    Double gate: skip the PG when IsGeneric flags it (so a generic
	//    PG never proposes itself as the service name), AND when
	//    isGenericCandidate would filter the cleaned form. Confidence 0.75
	//    keeps a sole PG hint at "ambiguous" — services and PGs aren't the
	//    same concept; the operator should review.
	for pgID := range seenPG {
		pg, ok := ctx.pgByID[pgID]
		if !ok {
			continue
		}
		if IsGeneric(pg.DisplayName, GenericKindProcessGroup) != "" {
			continue
		}
		name := cleanName(pg.DisplayName)
		if name == "" {
			continue
		}
		cands = append(cands, Candidate{
			Source:     "backing.pg.name",
			Name:       name,
			Confidence: 0.75,
			Evidence:   "backed by PG " + pgID + " (" + pg.DisplayName + ")",
		})
	}

	// 3b. Web context root — "/orders-api" style, operator-configured on
	//     the web server. Skip the bare "/" and noise segments. Observed
	//     live: nginx default vhost has contextRoot "/" (useless).
	if root := stringProp(svc.Properties, "contextRoot"); len(root) > 1 {
		seg := strings.Trim(root, "/")
		if seg != "" && meaningfulPathSeg(strings.ToLower(seg)) {
			name := cleanName(seg)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "context.root",
					Name:       name,
					Confidence: 0.78,
					Evidence:   "contextRoot=" + root,
				})
			}
		}
	}

	// 4. Sole inbound caller — only fires at 1:1 fan-in. A cluster of
	//    callers tells you nothing (matches the PG analyzer's branch 11).
	if len(svc.CalledByServiceIDs) == 1 {
		if caller, ok := ctx.serviceByID[svc.CalledByServiceIDs[0]]; ok {
			name := cleanName(caller.DisplayName)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "sole.caller",
					Name:       name,
					Confidence: 0.30,
					Evidence:   "sole inbound caller is " + caller.DisplayName,
				})
			}
		}
	}

	// 5. Host context — meaningful segment of each backing host's name.
	//    extractMeaningfulHostSegment already returns "" for cloud-default
	//    and localhost names, so a host called "ip-10-0-1-23" silently
	//    contributes nothing.
	for hostID := range seenHost {
		host, ok := ctx.hostByID[hostID]
		if !ok {
			continue
		}
		seg := extractMeaningfulHostSegment(host.DisplayName)
		if seg == "" {
			continue
		}
		cands = append(cands, Candidate{
			Source:     "host.context",
			Name:       seg,
			Confidence: 0.40,
			Evidence:   "runs on host " + hostID + " (" + host.DisplayName + ")",
		})
	}

	return cands
}
