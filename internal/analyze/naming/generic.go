// Package naming contains analyzers for naming hygiene — process groups,
// hosts, and host groups. The goal is to detect entities whose display name
// gives no operational signal (e.g. ":80", "python", "ip-10-0-1-23") and
// produce ranked candidate names extracted deterministically from each
// entity's properties.
//
// generic.go — shared "is this name generic?" rules. Pure functions, no I/O.
// Same input → same output. Each rule returns a `genericReason` string when
// it fires, or "" when it doesn't. The first non-empty reason wins.
package naming

import (
	"regexp"
	"strings"
)

// GenericKind is the entity kind being checked. Different kinds tolerate
// different generic patterns (e.g. a bare "java" name is more suspicious
// for a process group than for a host).
type GenericKind string

const (
	GenericKindProcessGroup GenericKind = "PROCESS_GROUP"
	GenericKindHost         GenericKind = "HOST"
	GenericKindService      GenericKind = "SERVICE"
)

// bareProtocolRegex matches service names that are nothing more than a
// transport protocol — Dynatrace emits these when the detected name is
// just "HTTP" or "HTTPS". commonBareTechs doesn't include them because it
// is technology-flavored (servers / runtimes), not protocol-flavored.
var bareProtocolRegex = regexp.MustCompile(`^https?$`)

// commonBareTechs is the set of names that are nothing more than a runtime
// or daemon name. A process group called "python" or "java" tells you which
// language the process is in — and nothing else.
var commonBareTechs = map[string]struct{}{
	"java": {}, "python": {}, "python2": {}, "python3": {},
	"node": {}, "nodejs": {}, "node.js": {},
	"ruby": {}, "go": {}, "golang": {},
	"php": {}, "php-fpm": {}, "perl": {},
	"nginx": {}, "httpd": {}, "apache2": {}, "apache": {},
	"haproxy": {}, "envoy": {}, "varnish": {},
	"postgres": {}, "postgresql": {}, "mysql": {}, "mariadb": {},
	"redis": {}, "memcached": {}, "mongod": {}, "mongodb": {},
	"kafka": {}, "elasticsearch": {}, "zookeeper": {},
	"systemd": {}, "sshd": {}, "cron": {}, "crond": {}, "dbus": {},
	// WSGI / ASGI / Rack / app servers — the process is the server, the
	// app it hosts is the name we're after. Found live: a PG literally
	// named "gunicorn" slipped through the original list.
	"gunicorn": {}, "uvicorn": {}, "uwsgi": {}, "celery": {},
	"puma": {}, "unicorn": {}, "sidekiq": {},
	"tomcat": {}, "catalina": {}, "dotnet": {}, "deno": {}, "bun": {},
	"supervisord": {}, "pm2": {},
	// JVM network frameworks — Dynatrace names undetected web services
	// after the framework ("Netty on 0:0:0:0:0:0:0:0:*"). Found live.
	"netty": {}, "jetty": {}, "vertx": {}, "vert.x": {}, "undertow": {},
}

// genericWords are role-words that name a KIND of process, not a workload.
// A service called "server" or "worker" tells you nothing about which
// server or whose worker. Deliberately conservative: role-ish names that
// still carry identity in small systems (frontend, backend, gateway) are
// NOT here — flagging a service genuinely named "frontend" annoys more
// than it helps.
var genericWords = map[string]struct{}{
	"server": {}, "app": {}, "application": {}, "main": {},
	"worker": {}, "client": {}, "daemon": {}, "service": {},
	"process": {}, "web": {}, "api": {}, "test": {}, "demo": {},
}

// cloudHostDefaultPatterns are hostname patterns that cloud providers
// assign by default. They contain no team / app / env signal.
var cloudHostDefaultPatterns = []*regexp.Regexp{
	// AWS EC2: ip-10-0-1-23, ec2-1-2-3-4.region.compute.amazonaws.com
	regexp.MustCompile(`^ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}(\..+)?$`),
	regexp.MustCompile(`^ec2-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.`),
	// GCP GKE: gke-<cluster>-<pool>-<hex>-<hex>
	regexp.MustCompile(`^gke-[\w-]+-[a-f0-9]{8}-[a-z0-9]{4}$`),
	// Azure: vmss<digits>, hex-only names
	regexp.MustCompile(`^vmss[0-9a-f]{6,}$`),
	regexp.MustCompile(`^[a-f0-9]{32,}$`),
	// Container short id (12 hex chars on its own)
	regexp.MustCompile(`^[a-f0-9]{12}$`),
}

// localhostNames are universally generic.
var localhostNames = map[string]struct{}{
	"localhost":         {},
	"localhost.localdomain": {},
	"linux":             {},
	"ubuntu":            {},
	"debian":            {},
	"centos":            {},
	"rhel":              {},
	"unknown":           {},
	"":                  {},
}

// portOnlyRegex matches names that are nothing but a colon + port number,
// or a port number with a generic suffix. Dynatrace sometimes uses these
// for services with no detected name — live examples: ":80" and "_:80"
// (web-server virtual host with no server_name).
var portOnlyRegex = regexp.MustCompile(`^_*:?\d{1,5}( process)?$`)

// onPortNameRegex captures "<base> on port <N>" — the Dynatrace default
// for web-request services. The base is re-checked: "gunicorn on port
// 7100" is generic (bare tech + port), "order-service on port 80" is not.
var onPortNameRegex = regexp.MustCompile(`(?i)^(.*?)\s+on port \d{1,5}$`)

// onAddressNameRegex captures "<base> on <bind-address>" — the other
// Dynatrace default shape, e.g. "Netty on 0:0:0:0:0:0:0:0:*" (IPv6
// any-address + wildcard port) or "Tomcat on 10.0.1.5:8080". The address
// part is digits/hex/colons/dots/brackets/wildcards only, so workload
// names like "orders on kubernetes" don't match.
var onAddressNameRegex = regexp.MustCompile(`(?i)^(.*?)\s+on\s+[0-9a-f:.\*\[\]]+$`)

// parenSuffixRegex matches a trailing parenthesized segment — Tomcat-style
// service names carry the deployed context root there:
// "Catalina/localhost (/tariff)".
var parenSuffixRegex = regexp.MustCompile(`\s*\([^)]*\)\s*$`)

// nameTokenSplit breaks a display name into tokens for the all-generic
// check: slashes, whitespace, colons, globs.
var nameTokenSplit = regexp.MustCompile(`[/\s:*()]+`)

// genericNameToken reports whether one display-name token carries no
// workload identity on its own (technology, localhost, protocol, number,
// or the connective words in Dynatrace default shapes).
func genericNameToken(tok string) bool {
	if tok == "" || tok == "on" || tok == "port" || tok == "process" || tok == "_" {
		return true
	}
	if _, ok := commonBareTechs[tok]; ok {
		return true
	}
	if _, ok := genericWords[tok]; ok {
		return true
	}
	if _, ok := localhostNames[tok]; ok {
		return true
	}
	if bareProtocolRegex.MatchString(tok) {
		return true
	}
	if regexp.MustCompile(`^[0-9]+$`).MatchString(tok) {
		return true
	}
	return false
}

// allNameTokensGeneric reports whether EVERY token of the name is generic
// — "Catalina/localhost" is (catalina + localhost), "Order Service" isn't
// (order carries identity).
func allNameTokensGeneric(s string) bool {
	toks := nameTokenSplit.Split(strings.ToLower(s), -1)
	sawToken := false
	for _, t := range toks {
		if t == "" {
			continue
		}
		sawToken = true
		if !genericNameToken(t) {
			return false
		}
	}
	return sawToken
}

// dynatraceDefaultRegex matches the synthetic names Dynatrace generates
// when it can't detect anything better.
var dynatraceDefaultRegex = regexp.MustCompile(
	`^(Requests executed in|Requests to unmonitored hosts|Java process|Python process|Node\.?js process|\.NET process)\b`,
)

// IsGeneric returns a non-empty "reason" string when the given name is
// considered generic for the given entity kind. Returns "" when the name
// looks specific enough to be useful.
//
// The check is conservative: false positives cost us a manual review;
// false negatives miss naming-hygiene opportunities. We err on the side of
// flagging.
func IsGeneric(name string, kind GenericKind) string {
	trimmed := strings.TrimSpace(name)
	lower := strings.ToLower(trimmed)

	if _, ok := localhostNames[lower]; ok {
		return "name is a generic localhost/runtime label"
	}
	if portOnlyRegex.MatchString(trimmed) {
		return "name is only a port number"
	}
	if dynatraceDefaultRegex.MatchString(trimmed) {
		return "name matches a Dynatrace default-generated pattern"
	}

	switch kind {
	case GenericKindProcessGroup:
		if _, ok := commonBareTechs[lower]; ok {
			return "name is a bare technology / runtime"
		}
		if _, ok := genericWords[lower]; ok {
			return "name is a generic role-word with no workload identity"
		}
		// All-numeric or all-hex with no other signal.
		if regexp.MustCompile(`^[0-9]+$`).MatchString(trimmed) {
			return "name is all-numeric"
		}
		if regexp.MustCompile(`^[a-f0-9]{8,}$`).MatchString(lower) {
			return "name is hex-only — likely a container or process id"
		}
	case GenericKindHost:
		for _, re := range cloudHostDefaultPatterns {
			if re.MatchString(trimmed) {
				return "name matches a cloud-provider default pattern"
			}
		}
		// Bare techs are also generic for hosts.
		if _, ok := commonBareTechs[lower]; ok {
			return "name is a bare technology / runtime"
		}
	case GenericKindService:
		// A service named "nginx" / "http" / "java" tells you which server
		// or runtime handles requests — and nothing about what the service
		// is for. portOnlyRegex + dynatraceDefaultRegex above already cover
		// ":80" / "_:80" and "Requests executed in HTTP".
		if _, ok := commonBareTechs[lower]; ok {
			return "name is a bare technology / runtime"
		}
		if _, ok := genericWords[lower]; ok {
			return "name is a generic role-word with no workload identity"
		}
		if bareProtocolRegex.MatchString(lower) {
			return "name is a bare transport protocol"
		}
		if regexp.MustCompile(`^[0-9]+$`).MatchString(trimmed) {
			return "name is all-numeric"
		}
		// "<base> on port <N>" — generic iff the base alone is generic.
		// "gunicorn on port 7100" → flagged; "order-service on port 80"
		// → base identifies the workload, leave it alone.
		if m := onPortNameRegex.FindStringSubmatch(trimmed); m != nil {
			base := strings.TrimSpace(m[1])
			if base == "" || IsGeneric(base, GenericKindService) != "" {
				return "name is a generic technology plus port"
			}
		}
		// "<base> on <bind-address>" — same rule for address-shaped tails,
		// e.g. "Netty on 0:0:0:0:0:0:0:0:*".
		if m := onAddressNameRegex.FindStringSubmatch(trimmed); m != nil {
			base := strings.TrimSpace(m[1])
			if base == "" || IsGeneric(base, GenericKindService) != "" {
				return "name is a generic technology plus bind address"
			}
		}
		// All-tokens-generic names: strip any "(/context-root)" suffix and
		// check whether what remains is pure technology/role noise —
		// "Catalina/localhost (/tariff)" → "Catalina/localhost" → generic;
		// "python server" → generic. Paren content resurfaces as a candidate.
		if stripped := parenSuffixRegex.ReplaceAllString(trimmed, ""); allNameTokensGeneric(stripped) {
			if stripped != trimmed {
				return "name is a technology shell; identity only in the context-root suffix"
			}
			return "name is composed only of generic/technology words"
		}
		// Tech-prefixed composites: "uvicorn order-service-* on port 80" —
		// the base is not generic as a whole, but its FIRST token is a bare
		// tech and real identity follows. Flag so the de-prefixed remainder
		// can be suggested instead.
		if m := onPortNameRegex.FindStringSubmatch(trimmed); m != nil {
			fields := strings.Fields(strings.TrimSpace(m[1]))
			if len(fields) >= 2 && genericNameToken(strings.ToLower(fields[0])) {
				return "name is a technology-prefixed default (tech + workload + port)"
			}
		}
	}

	return ""
}
