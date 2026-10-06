// processgroups.go — the "processgroups.naming_audit" analyzer.
//
// For every process group in the input that has a generic display name,
// extract ranked candidate names and emit a per-entity report with a
// confidence bucket. Pure function, no I/O.
//
// Candidate sources fall in two families:
//
// SELF — read straight off the PG's own properties:
//   k8s.container       KubernetesContainerName property                  → 0.92
//   image.tail          DockerContainerImageName, last path segment       → 0.85
//   jar.filename        JarFile property, basename minus .jar             → 0.85
//   cli.arg.name        CommandLineArguments with --name=/--service=/--app= → 0.80
//   java.mainclass      JavaMainClass last segment, ApiCase → snake/kebab → 0.70
//   exec.basename       Executable property, basename                     → 0.55
//   tech.only           softwareTechnologies first .type (low signal)     → 0.30
//
// GRAPH — walked from the PG outward (Phase A: PGI children, backed
// services, host). The PG itself is often named "java" while the richer
// signal lives on adjacent nodes — K8s metadata is on the PGI, the
// human-meaningful name is on the SERVICE, and the host gives a weak
// hint:
//   pgi.k8s.container   child PGI's KubernetesContainerName               → 0.88
//   pgi.jar.filename    child PGI's JarFile (PGIs sometimes carry it when
//                       the PG doesn't)                                   → 0.83
//   backed.service      display name of a SERVICE this PG's PGIs back     → 0.80
//   host.context        meaningful segment of the PG's host name (weak —
//                       a host runs many PGs, tiebreaker only)            → 0.45
//
// The analyzer never returns a healthy PG. Output is only entities flagged
// generic — the operator/AI sees a focused list, not the full inventory.
package naming

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/graph"
)

func init() {
	analyze.Register(ProcessGroups{})
}

// ProcessGroups is the analyzer entrypoint.
type ProcessGroups struct{}

// Kind is the stable identifier dispatched via engine_analyze.
func (ProcessGroups) Kind() string { return "processgroups.naming_audit" }

// Description appears in engine_list output.
func (ProcessGroups) Description() string {
	return "Audit process group display names. Flags PGs whose name is generic (port-only, bare technology, Dynatrace default) and extracts ranked candidate names from BOTH the PG's own properties (JarFile / KubernetesContainerName / Executable / CommandLineArguments / JavaMainClass / image) AND the graph around it (child PGIs' K8s metadata, the display names of SERVICEs the PG backs, and its host). Returns per-entity reports with confidence buckets (high_confidence / ambiguous / no_signal) so the operator can apply naming rules selectively. Pure function over flat graph input."
}

// Input is the analyzer's input. Same flat shape as the tag analyzers —
// we only consume processGroups but accept the full graph input so callers
// can share one fetcher for naming + tag work.
type Input struct {
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

// Output is the analyzer result.
type Output struct {
	// Reports holds one entry per generic-named PG; healthy PGs are omitted.
	Reports []EntityNamingReport `json:"reports"`
	// Counts is a quick summary the operator scans first.
	Counts NamingCounts `json:"counts"`
	// AppliedDefaults echoes the actual thresholds used (for reproducibility).
	AppliedDefaults Defaults `json:"appliedDefaults"`
}

// NamingCounts is the per-bucket summary across the report set.
type NamingCounts struct {
	TotalProcessGroups int `json:"totalProcessGroups"`
	Generic            int `json:"generic"`
	HighConfidence     int `json:"highConfidence"`
	Ambiguous          int `json:"ambiguous"`
	NoSignal           int `json:"noSignal"`
}

// Defaults echoes the threshold constants in the output for traceability.
type Defaults struct {
	HighConfidenceMin float64 `json:"highConfidenceMin"`
	HighConfidenceGap float64 `json:"highConfidenceGap"`
	AmbiguousMin      float64 `json:"ambiguousMin"`
	MaxCandidates     int     `json:"maxCandidates"`
}

// Run is the analyzer's pure entrypoint. Same input → same output.
func (ProcessGroups) Run(raw json.RawMessage) (any, error) {
	var in Input
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}
	maxCandidates := in.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 5
	}

	out := Output{
		Reports: []EntityNamingReport{},
		Counts: NamingCounts{
			TotalProcessGroups: len(in.ProcessGroups),
		},
		AppliedDefaults: Defaults{
			HighConfidenceMin: HighConfidenceMin,
			HighConfidenceGap: HighConfidenceGap,
			AmbiguousMin:      AmbiguousMin,
			MaxCandidates:     maxCandidates,
		},
	}

	// Build the graph-traversal index once (PG → PGI → SERVICE, PG → HOST).
	// Cheap: a few maps over the flat input. Reused for every generic PG.
	ctx := buildPGGraphContext(in.Input)

	for _, pg := range in.ProcessGroups {
		reason := IsGeneric(pg.DisplayName, GenericKindProcessGroup)
		if reason == "" && !in.AuditAll {
			continue
		}
		if reason != "" {
			out.Counts.Generic++
		}
		raw := extractPGCandidates(pg, ctx)
		report := finishReport(pg.ID, string(graph.TypeProcessGroup), pg.DisplayName, reason, raw, in.Explain, in.AuditAll)
		if report == nil {
			continue
		}
		// Cap AFTER bucketing so we keep the top N by confidence.
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

// ----- graph traversal context --------------------------------------------

// pgGraphContext holds the index maps that let extractPGCandidates walk
// PG → PGI → SERVICE and PG → HOST without re-scanning the flat input
// once per PG. Built once per analyzer call.
//
// A zero-value pgGraphContext (all nil maps) is safe — the graph branches
// in extractPGCandidates simply produce nothing. host_pg_evidence.go
// relies on that when it reuses extractPGCandidates for host evidence.
type pgGraphContext struct {
	pgisByPG    map[string][]graph.ProcessGroupInstance // pgId → child PGIs
	serviceByID map[string]graph.Service                // serviceId → service
	hostByID    map[string]graph.Host                   // hostId → host
}

// buildPGGraphContext indexes the flat input for PG-centric traversal.
func buildPGGraphContext(in graph.Input) pgGraphContext {
	ctx := pgGraphContext{
		pgisByPG:    make(map[string][]graph.ProcessGroupInstance),
		serviceByID: make(map[string]graph.Service, len(in.Services)),
		hostByID:    make(map[string]graph.Host, len(in.Hosts)),
	}
	for _, pgi := range in.ProcessGroupInstances {
		if pgi.PGID != "" {
			ctx.pgisByPG[pgi.PGID] = append(ctx.pgisByPG[pgi.PGID], pgi)
		}
	}
	for _, s := range in.Services {
		ctx.serviceByID[s.ID] = s
	}
	for _, h := range in.Hosts {
		ctx.hostByID[h.ID] = h
	}
	return ctx
}

// ----- candidate extraction -----------------------------------------------

// argFlagRegex matches CLI args of the form --name=foo or --service foo
// (handled by a second pass).
var argFlagRegex = regexp.MustCompile(`^--?(name|service|app|application|component|module)=(.+)$`)

// extractPGCandidates is the per-PG heuristic table. The confidence
// numbers are conservative — they're the floor we'd defend in a code
// review. Tune up only after seeing real cluster behavior.
//
// Branches 1-7 read the PG's own properties. Branches 8-10 walk the graph
// via `ctx` (child PGIs, backed services, host). Each branch appends to
// `cands` independently — the bucketing step in finishReport handles
// dedupe and ranking. A zero-value ctx disables the graph branches.
func extractPGCandidates(pg graph.ProcessGroup, ctx pgGraphContext) []Candidate {
	cands := []Candidate{}
	props := pg.Properties

	// 1. KubernetesContainerName — when present it's almost always the
	//    operator-chosen name (k8s controllers require it).
	if v := stringProp(props, "KubernetesContainerName"); v != "" {
		name := cleanName(v)
		if name != "" {
			cands = append(cands, Candidate{
				Source:     "k8s.container",
				Name:       name,
				Confidence: 0.92,
				Evidence:   "KubernetesContainerName=" + v,
			})
		}
	}

	// 2. Docker / container image — take the last path segment, drop the tag.
	if v := stringProp(props, "DockerContainerImageName"); v != "" {
		name := imageTail(v)
		if name != "" {
			cands = append(cands, Candidate{
				Source:     "image.tail",
				Name:       cleanName(name),
				Confidence: 0.85,
				Evidence:   "DockerContainerImageName=" + v,
			})
		}
	}
	if v := stringProp(props, "DockerContainerName"); v != "" {
		name := cleanName(v)
		if name != "" {
			cands = append(cands, Candidate{
				Source:     "container.name",
				Name:       name,
				Confidence: 0.80,
				Evidence:   "DockerContainerName=" + v,
			})
		}
	}

	// 3. JarFile — Java apps. Drop .jar, take basename. Live Managed
	//    (1.341) exposes this via the metadata[] k/v array, not a
	//    top-level property — check both.
	jarFile := stringProp(props, "JarFile")
	if jarFile == "" {
		jarFile = metadataProp(props, "JAVA_JAR_FILE", "JAR_FILE", "EXE_PATH_JAR")
	}
	if jarFile != "" {
		name := jarBasename(jarFile)
		if name != "" {
			cands = append(cands, Candidate{
				Source:     "jar.filename",
				Name:       cleanName(name),
				Confidence: 0.85,
				Evidence:   "JarFile=" + jarFile,
			})
		}
	}

	// 4. CommandLineArguments — sniff for --name=, --service=, --app= etc.
	//    Live Managed exposes argv as metadata[COMMAND_LINE_ARGS] (one
	//    string); the top-level property shapes are kept as fallbacks.
	args := stringSliceProp(props, "CommandLineArguments")
	if len(args) == 0 {
		args = stringSliceProp(props, "commandLine")
	}
	if cli := stringProp(props, "CommandLine"); cli != "" {
		args = append(args, splitCommandLine(cli)...)
	}
	if cli := metadataProp(props, "COMMAND_LINE_ARGS"); cli != "" {
		args = append(args, splitCommandLine(cli)...)
	}
	for i, a := range args {
		if m := argFlagRegex.FindStringSubmatch(a); m != nil {
			name := cleanName(m[2])
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "cli.arg." + m[1],
					Name:       name,
					Confidence: 0.80,
					Evidence:   "argv: " + a,
				})
			}
			continue
		}
		// Pair form: --name foo (look ahead by one).
		if i+1 < len(args) {
			next := args[i+1]
			if isPairFlagName(a) && !strings.HasPrefix(next, "-") {
				name := cleanName(next)
				if name != "" {
					cands = append(cands, Candidate{
						Source:     "cli.arg.pair",
						Name:       name,
						Confidence: 0.75,
						Evidence:   "argv: " + a + " " + next,
					})
				}
			}
		}
	}

	// 5. JavaMainClass — last segment of the FQCN. metadata[] fallback.
	mainClass := stringProp(props, "JavaMainClass")
	if mainClass == "" {
		mainClass = metadataProp(props, "JAVA_MAIN_CLASS")
	}
	if mainClass != "" {
		segs := strings.Split(mainClass, ".")
		if last := segs[len(segs)-1]; last != "" {
			name := camelToKebab(last)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "java.mainclass",
					Name:       name,
					Confidence: 0.70,
					Evidence:   "JavaMainClass=" + mainClass,
				})
			}
		}
	}

	// 6. Executable — last fallback. Low confidence because it's often
	//    just "python" or "java". metadata[] EXE_PATH/EXE_NAME fallback.
	exe := stringProp(props, "Executable")
	if exe == "" {
		exe = metadataProp(props, "EXE_PATH", "EXE_NAME")
	}
	if exe != "" {
		base := path.Base(exe)
		if base != "" {
			cands = append(cands, Candidate{
				Source:     "exec.basename",
				Name:       cleanName(base),
				Confidence: 0.55,
				Evidence:   "Executable=" + exe,
			})
		}
	}

	// 6b. awsNameTag — the EC2 Name tag as surfaced on the entity.
	//     Observed live on Managed 1.341 PGIs/PGs of plain-EC2 hosts.
	//     Operator-chosen, so decent confidence — but it names the VM,
	//     not necessarily the process, hence below the k8s/jar sources.
	if v := stringProp(props, "awsNameTag"); v != "" {
		name := cleanName(v)
		if name != "" {
			cands = append(cands, Candidate{
				Source:     "aws.name-tag",
				Name:       name,
				Confidence: 0.65,
				Evidence:   "awsNameTag=" + v,
			})
		}
	}

	// 7. softwareTechnologies — very weak signal but better than nothing.
	//    Guard on SELF-emptiness only (graph branches haven't run yet);
	//    a 0.30 tech hint alongside a strong graph candidate is harmless,
	//    it just sorts to the bottom.
	techs := extractTechTypes(props)
	if len(techs) > 0 && len(cands) == 0 {
		cands = append(cands, Candidate{
			Source:     "tech.only",
			Name:       strings.ToLower(techs[0]),
			Confidence: 0.30,
			Evidence:   "softwareTechnologies[0].type=" + techs[0],
		})
	}

	// ----- graph branches (Phase A): PGI children, backed services, host -----
	cands = append(cands, extractPGGraphCandidates(pg, ctx)...)

	return cands
}

// extractPGGraphCandidates walks the graph around one PG and emits the
// candidates that the PG's own properties can't see. Split out from
// extractPGCandidates to keep that function readable. Returns nil when
// ctx has no graph data (zero-value ctx).
func extractPGGraphCandidates(pg graph.ProcessGroup, ctx pgGraphContext) []Candidate {
	cands := []Candidate{}

	// 8. Child PGIs — K8s container metadata + JarFile live on the
	//    instance, not the group. A PG named "java" routinely has PGIs
	//    that carry the real KubernetesContainerName.
	childPGIs := ctx.pgisByPG[pg.ID]
	for _, pgi := range childPGIs {
		if v := stringProp(pgi.Properties, "KubernetesContainerName"); v != "" {
			name := cleanName(v)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "pgi.k8s.container",
					Name:       name,
					Confidence: 0.88,
					Evidence:   "child PGI " + pgi.ID + " KubernetesContainerName=" + v,
				})
			}
		}
		pgiJar := stringProp(pgi.Properties, "JarFile")
		if pgiJar == "" {
			pgiJar = metadataProp(pgi.Properties, "JAVA_JAR_FILE", "JAR_FILE")
		}
		if pgiJar != "" {
			name := jarBasename(pgiJar)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "pgi.jar.filename",
					Name:       cleanName(name),
					Confidence: 0.83,
					Evidence:   "child PGI " + pgi.ID + " JarFile=" + pgiJar,
				})
			}
		}
	}

	// 9 + 11. Backed services — PG → PGI → SERVICE. For each distinct
	//    service the PG backs we emit up to three kinds of candidate:
	//      9a  the service's display name (when meaningful)            0.80
	//      9b  endpoint-path analysis (Phase B) — the URL paths it
	//          serves, works even when the display name is generic     0.65–0.72
	//      11  sole inbound caller — weak tiebreaker, only when the
	//          service has exactly ONE caller                          0.30
	//    Dedupe service ids: many PGIs of one PG back the same service.
	seenSvc := make(map[string]struct{})
	for _, pgi := range childPGIs {
		for _, svcID := range pgi.ServiceIDs {
			if _, dup := seenSvc[svcID]; dup {
				continue
			}
			seenSvc[svcID] = struct{}{}
			svc, ok := ctx.serviceByID[svcID]
			if !ok {
				continue
			}
			// 9a. Service display name.
			name := cleanName(svc.DisplayName)
			if name != "" {
				cands = append(cands, Candidate{
					Source:     "backed.service",
					Name:       name,
					Confidence: 0.80,
					Evidence:   "backs service " + svcID + " (" + svc.DisplayName + ")",
				})
			}
			// 9b. Endpoint-path analysis — the strongest Phase B signal.
			cands = append(cands, endpointNameCandidates(svcID, svc.Endpoints)...)
			// 11. Sole inbound caller — weak tiebreaker. A fan-in of many
			//     callers tells you nothing; only a 1:1 caller is a hint.
			if len(svc.CalledByServiceIDs) == 1 {
				if caller, cok := ctx.serviceByID[svc.CalledByServiceIDs[0]]; cok {
					cname := cleanName(caller.DisplayName)
					if cname != "" {
						cands = append(cands, Candidate{
							Source:     "inbound.caller",
							Name:       cname,
							Confidence: 0.30,
							Evidence:   "sole caller of backed service " + svcID + " is " + caller.DisplayName,
						})
					}
				}
			}
		}
	}

	// 10. Host context — the PG's host name root. Weak: a host runs many
	//     PGs, so this only ever acts as a tiebreaker. Skipped when the
	//     host name is itself generic (extractMeaningfulHostSegment
	//     returns "" for cloud-default / localhost names).
	if pg.HostID != "" {
		if host, ok := ctx.hostByID[pg.HostID]; ok {
			if seg := extractMeaningfulHostSegment(host.DisplayName); seg != "" {
				cands = append(cands, Candidate{
					Source:     "host.context",
					Name:       seg,
					Confidence: 0.45,
					Evidence:   "runs on host " + pg.HostID + " (" + host.DisplayName + ")",
				})
			}
		}
	}

	return cands
}

// ----- endpoint-path analysis (Phase B) -----------------------------------

var (
	// versionSegRegex matches path version segments: v1, v2, v12, …
	versionSegRegex = regexp.MustCompile(`^v\d+$`)
	// numericSegRegex matches all-numeric path segments.
	numericSegRegex = regexp.MustCompile(`^\d+$`)
	// pathParamRegex matches path parameters: {id}, :id, * (a wildcard).
	pathParamRegex = regexp.MustCompile(`^(\{.*\}|:.+|\*)$`)
)

// endpointNoiseSegs are path segments that carry no naming signal — they
// appear across every service regardless of what it does.
var endpointNoiseSegs = map[string]struct{}{
	"api": {}, "apis": {}, "rest": {}, "service": {}, "services": {},
	"public": {}, "internal": {}, "static": {}, "health": {}, "healthz": {},
	"ping": {}, "status": {}, "metrics": {}, "actuator": {}, "www": {},
	// Health-probe path segments — "/health/ready" must not suggest
	// "ready" as a service name (found live on a Quarkus readiness probe).
	"ready": {}, "readyz": {}, "readiness": {},
	"live": {}, "livez": {}, "liveness": {}, "started": {}, "startup": {},
}

// httpVerbs is the set of leading tokens we strip off "VERB /path"
// endpoint strings.
var httpVerbs = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {},
	"DELETE": {}, "HEAD": {}, "OPTIONS": {}, "TRACE": {},
}

// endpointNameCandidates derives candidate names from a service's
// SERVICE_METHOD endpoint strings. Two forms are handled:
//
//	"GET /api/v1/orders/{id}"  → path analysis → "orders"
//	"OrdersController.list"     → class stem   → "orders"
//
// The path analysis counts, per endpoint, which meaningful segments
// appear, and picks the segment present in the most endpoints. A segment
// in ALL endpoints scores 0.72; a majority scores 0.65. Generic results
// are filtered.
func endpointNameCandidates(serviceID string, endpoints []string) []Candidate {
	if len(endpoints) == 0 {
		return nil
	}
	segEndpointCount := map[string]int{} // segment → # endpoints containing it
	classStems := map[string]int{}       // class stem → occurrence count
	pathEndpoints := 0

	for _, ep := range endpoints {
		if path := endpointPath(ep); path != "" {
			pathEndpoints++
			seen := map[string]struct{}{}
			for _, seg := range strings.Split(path, "/") {
				s := strings.ToLower(strings.TrimSpace(seg))
				if !meaningfulPathSeg(s) {
					continue
				}
				if _, dup := seen[s]; dup {
					continue
				}
				seen[s] = struct{}{}
				segEndpointCount[s]++
			}
			continue
		}
		if stem := classStemOf(ep); stem != "" {
			classStems[stem]++
		}
	}

	cands := []Candidate{}

	// Path-segment winner. Deterministic tie-break: alphabetical.
	if pathEndpoints > 0 {
		bestSeg, bestCount := "", 0
		for seg, c := range segEndpointCount {
			if c > bestCount || (c == bestCount && seg < bestSeg) {
				bestSeg, bestCount = seg, c
			}
		}
		if bestSeg != "" && bestCount*2 >= pathEndpoints {
			conf := 0.65
			if bestCount == pathEndpoints {
				conf = 0.72
			}
			cands = append(cands, Candidate{
				Source:     "backed.service.endpoint",
				Name:       cleanName(bestSeg),
				Confidence: conf,
				Evidence: fmt.Sprintf("service %s: path segment '%s' in %d/%d endpoints",
					serviceID, bestSeg, bestCount, pathEndpoints),
			})
		}
	}

	// Class-stem winner (the "function names" signal).
	bestStem, bestStemCount := "", 0
	for stem, c := range classStems {
		if c > bestStemCount || (c == bestStemCount && stem < bestStem) {
			bestStem, bestStemCount = stem, c
		}
	}
	if bestStem != "" {
		cands = append(cands, Candidate{
			Source:     "backed.service.method-class",
			Name:       cleanName(bestStem),
			Confidence: 0.65,
			Evidence:   fmt.Sprintf("service %s: method class stem '%s'", serviceID, bestStem),
		})
	}

	// No filtering here — the central filterCandidates pass (via
	// finishReport) applies the generic/self/length rules and records
	// rejections for explain mode.
	return cands
}

// endpointPath returns the URL-path portion of an endpoint string, or ""
// when the endpoint isn't path-shaped. Handles four live shapes:
//
//	"GET /api/orders"                       → "/api/orders"
//	"/api/orders"                           → "/api/orders"  (Managed emits bare paths)
//	"http://10.0.0.5:7000/events"      → "/events"      (outbound-call endpoints)
//	"OrdersController.list"                 → ""              (class ref, not a path)
//
// SQL statements ("SELECT … FROM t WHERE a/b") are rejected because their
// pre-slash prefix is neither empty, an HTTP verb, nor a URL scheme.
func endpointPath(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}
	// Absolute URL: strip scheme://host[:port] and keep the path.
	if i := strings.Index(ep, "://"); i > 0 && !strings.ContainsAny(ep[:i], " /") {
		rest := ep[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return ""
		}
		return rest[j:]
	}
	i := strings.IndexByte(ep, '/')
	if i < 0 {
		return ""
	}
	prefix := strings.TrimSpace(ep[:i])
	if prefix == "" {
		return ep[i:]
	}
	if _, ok := httpVerbs[strings.ToUpper(prefix)]; ok {
		return ep[i:]
	}
	return ""
}

// meaningfulPathSeg reports whether a path segment carries naming signal.
func meaningfulPathSeg(s string) bool {
	if len(s) < 2 {
		return false
	}
	if _, noise := endpointNoiseSegs[s]; noise {
		return false
	}
	if versionSegRegex.MatchString(s) ||
		numericSegRegex.MatchString(s) ||
		pathParamRegex.MatchString(s) {
		return false
	}
	return true
}

// classSuffixes are dropped from a class identifier to leave the domain
// stem (OrdersController → Orders).
var classSuffixes = []string{
	"Controller", "Service", "Handler", "Resource", "Endpoint", "Api", "Impl",
}

// classStemOf extracts the domain stem from a "Class.method" or
// "pkg.Class.method" endpoint string. Returns "" when ep isn't of that
// shape (has a slash or a space → it's a path, not a class reference).
func classStemOf(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" || strings.ContainsAny(ep, "/ ") {
		return ""
	}
	parts := strings.Split(ep, ".")
	if len(parts) < 2 {
		return ""
	}
	class := parts[len(parts)-2] // last segment is the method name
	for _, suf := range classSuffixes {
		class = strings.TrimSuffix(class, suf)
	}
	if class == "" {
		return ""
	}
	return camelToKebab(class)
}

// ----- name normalization -------------------------------------------------

var (
	camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	nonNameChar   = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	multiDash     = regexp.MustCompile(`-{2,}`)
)

// cleanName normalizes a raw candidate into something a Dynatrace naming
// rule will accept. Lowercase, hyphenated, no surrounding junk.
// Consecutive duplicate tokens collapse: Dynatrace PG names like
// "Redis redis-*" or "nginx nginx-proxy-*" otherwise clean into
// "redis-redis" / "nginx-nginx-proxy".
func cleanName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = nonNameChar.ReplaceAllString(s, "-")
	s = multiDash.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	s = strings.ToLower(s)
	toks := strings.Split(s, "-")
	out := toks[:0]
	for _, t := range toks {
		if len(out) > 0 && out[len(out)-1] == t {
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, "-")
}

// camelToKebab converts ApiOrderService → api-order-service. Used for
// JavaMainClass last-segment candidates.
func camelToKebab(s string) string {
	with := camelBoundary.ReplaceAllString(s, "$1-$2")
	return strings.ToLower(with)
}

// jarBasename strips path + extension from a JarFile property.
func jarBasename(p string) string {
	base := path.Base(p)
	if i := strings.LastIndex(base, "."); i > 0 {
		base = base[:i]
	}
	return base
}

// imageTail handles "registry.example.com/team/app:1.2.3" → "app".
func imageTail(img string) string {
	// Drop tag.
	if i := strings.LastIndex(img, ":"); i > 0 {
		// Skip the colon in the registry port (registry:5000/path).
		if !strings.Contains(img[i+1:], "/") {
			img = img[:i]
		}
	}
	// Take last path segment.
	if i := strings.LastIndex(img, "/"); i >= 0 {
		img = img[i+1:]
	}
	return img
}

// splitCommandLine is a naive shell-arg splitter — enough for sniffing
// --name=foo or --service foo. We don't try to handle quoted whitespace
// perfectly; if it's a problem we'll add a real lexer.
func splitCommandLine(cmd string) []string {
	fields := strings.Fields(cmd)
	return fields
}

func isPairFlagName(arg string) bool {
	for _, candidate := range []string{
		"--name", "--service", "--app", "--application",
		"--component", "--module", "-n",
	} {
		if arg == candidate {
			return true
		}
	}
	return false
}

// isGenericCandidate filters out candidate strings that are themselves
// just generic tech names. Stops us from "suggesting" python → python.
// onPortSuffixCandidateRegex matches the "-on-port-8080" / " on port 8080"
// tail that survives cleanName() on Dynatrace default service names.
var onPortSuffixCandidateRegex = regexp.MustCompile(`[-\s]on[-\s]port[-\s]\d{1,5}$`)

func isGenericCandidate(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	lower = strings.Trim(lower, "_")
	// "gunicorn-on-port-7100" is exactly as informationless as "gunicorn".
	lower = onPortSuffixCandidateRegex.ReplaceAllString(lower, "")
	if lower == "" {
		return true
	}
	// Unusable rather than generic: a 50-char candidate (cleaned FQCN-style
	// PG names like "io.quarkus...QuarkusEntryPoint keycloak-*") is not a
	// name anyone would apply. Cap keeps suggestions tag-value sized.
	if len(lower) > 40 {
		return true
	}
	if _, ok := commonBareTechs[lower]; ok {
		return true
	}
	if _, ok := genericWords[lower]; ok {
		return true
	}
	if portOnlyRegex.MatchString(lower) {
		return true
	}
	return false
}
