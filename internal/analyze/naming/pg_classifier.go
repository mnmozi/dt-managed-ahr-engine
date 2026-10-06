// pg_classifier.go — classify a process group as "app", "infra", or
// "system" from its technology signal. Used by both processgroups.go (to
// rank app-PG candidates higher than infra/system) and hosts.go (to pick
// the "dominant" PG when naming a host from its processes).
//
// Source of truth is the Dynatrace `softwareTechnologies` property — an
// array of `{type, edition, version}` objects. We also fall back to
// keyword sniffing on the display name when the technology array is empty
// or unhelpful (older OneAgent versions don't populate it).
package naming

import (
	"strings"

	"github.com/local/dt-managed-engine/internal/graph"
)

// PGKind is the coarse classification.
type PGKind string

const (
	PGKindApp     PGKind = "app"     // a piece of someone's application
	PGKindInfra   PGKind = "infra"   // shared infrastructure (web/db/cache/queue)
	PGKindSystem  PGKind = "system"  // OS / agent / cron / sshd
	PGKindUnknown PGKind = "unknown" // not enough signal
)

// appTechs are technologies that indicate "this PG is application code."
// Includes language runtimes — the JAR / script / image is the app.
var appTechs = map[string]struct{}{
	"JAVA": {}, "DOTNET": {}, "DOTNET_CORE": {},
	"NODE_JS": {}, "NODEJS": {},
	"PYTHON": {}, "RUBY": {}, "GO": {}, "GOLANG": {},
	"PHP": {}, "PERL": {},
	"TOMCAT": {}, "JETTY": {}, "WILDFLY": {}, "WEBLOGIC": {}, "WEBSPHERE": {},
	"GLASSFISH": {}, "IIS": {}, "SPRING_BOOT": {},
}

// infraTechs are shared-infrastructure technologies.
var infraTechs = map[string]struct{}{
	"NGINX": {}, "APACHE_HTTPD": {}, "APACHE": {}, "HAPROXY": {},
	"VARNISH": {}, "ENVOY": {},
	"POSTGRES": {}, "POSTGRESQL": {}, "MYSQL": {}, "MARIADB": {},
	"MONGODB": {}, "ORACLE_DB": {}, "MSSQL": {}, "DB2": {},
	"REDIS": {}, "MEMCACHED": {},
	"KAFKA": {}, "RABBITMQ": {}, "ACTIVEMQ": {},
	"ELASTICSEARCH": {}, "SOLR": {}, "CASSANDRA": {},
	"ZOOKEEPER": {}, "ETCD": {}, "CONSUL": {},
}

// systemTechs are OS / agent / supervisor processes that shouldn't drive
// naming decisions for the host.
var systemTechs = map[string]struct{}{
	"ONEAGENT": {}, "DYNATRACE_ONEAGENT": {},
	"SYSTEMD": {}, "INIT": {}, "CRON": {}, "CRONIE": {}, "SSHD": {},
	"DBUS": {}, "RSYSLOG": {}, "JOURNALD": {},
}

// nameKeywords let us classify when softwareTechnologies is missing.
// Ordered: longer / more specific patterns first to avoid mis-classifying
// "postgres-exporter" as infra (it's an app monitoring postgres).
var infraNameKeywords = []string{
	"nginx", "haproxy", "envoy", "varnish",
	"postgres", "postgresql", "mysql", "mariadb", "mongo", "redis",
	"memcached", "kafka", "rabbitmq", "elasticsearch", "cassandra",
	"zookeeper", "etcd", "consul", "httpd", "apache",
}
var systemNameKeywords = []string{
	"oneagent", "systemd", "sshd", "cron", "dbus", "journald", "syslog",
}

// ClassifyPG returns the kind of a process group based on its properties
// and (as a fallback) its display name. Used by the host naming layer to
// pick the dominant non-system PG for naming purposes.
func ClassifyPG(pg graph.ProcessGroup) PGKind {
	// 1) Look at softwareTechnologies first (most reliable).
	for _, t := range extractTechTypes(pg.Properties) {
		upper := strings.ToUpper(t)
		if _, ok := appTechs[upper]; ok {
			return PGKindApp
		}
		if _, ok := infraTechs[upper]; ok {
			return PGKindInfra
		}
		if _, ok := systemTechs[upper]; ok {
			return PGKindSystem
		}
	}

	// 2) Strong app signal: presence of JarFile / JavaMainClass / script main.
	if hasNonEmptyStringProp(pg.Properties, "JarFile") ||
		hasNonEmptyStringProp(pg.Properties, "JavaMainClass") ||
		hasNonEmptyStringProp(pg.Properties, "KubernetesContainerName") {
		return PGKindApp
	}

	// 3) Fall back to name keyword sniff.
	lower := strings.ToLower(pg.DisplayName)
	for _, kw := range systemNameKeywords {
		if strings.Contains(lower, kw) {
			return PGKindSystem
		}
	}
	for _, kw := range infraNameKeywords {
		if strings.Contains(lower, kw) {
			return PGKindInfra
		}
	}

	return PGKindUnknown
}

// extractTechTypes pulls the `type` field from each entry in the
// `softwareTechnologies` property. Tolerant of the various shapes
// Dynatrace returns (array of objects, single object, missing).
func extractTechTypes(props graph.Properties) []string {
	if props == nil {
		return nil
	}
	v, ok := props["softwareTechnologies"]
	if !ok || v == nil {
		return nil
	}
	out := []string{}
	switch arr := v.(type) {
	case []any:
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["type"].(string); ok && t != "" {
					out = append(out, t)
				}
			} else if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case map[string]any:
		if t, ok := arr["type"].(string); ok && t != "" {
			out = append(out, t)
		}
	case string:
		if arr != "" {
			out = append(out, arr)
		}
	}
	return out
}

// hasNonEmptyStringProp is a tiny defensive helper — Properties is
// map[string]any, so direct casts panic on nil / wrong type.
func hasNonEmptyStringProp(props graph.Properties, key string) bool {
	if props == nil {
		return false
	}
	v, ok := props[key]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s != ""
}

// stringProp returns the property as a string when it is one, otherwise "".
func stringProp(props graph.Properties, key string) string {
	if props == nil {
		return ""
	}
	v, ok := props[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// metadataProp reads Dynatrace's `metadata` property — an array of
// {key, value} objects carrying process facts like EXE_NAME, EXE_PATH,
// COMMAND_LINE_ARGS, JAVA_JAR_FILE, JAVA_MAIN_CLASS. Observed live on
// Managed 1.341: these do NOT appear as top-level properties; the
// metadata array is the only place they exist. Returns the value for the
// first key in `keys` that is present, or "".
func metadataProp(props graph.Properties, keys ...string) string {
	if props == nil {
		return ""
	}
	v, ok := props["metadata"]
	if !ok || v == nil {
		return ""
	}
	arr, ok := v.([]any)
	if !ok {
		return ""
	}
	for _, want := range keys {
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			k, _ := m["key"].(string)
			if k != want {
				continue
			}
			if val, ok := m["value"].(string); ok && val != "" {
				return val
			}
		}
	}
	return ""
}

// stringSliceProp coerces the property at key to []string, tolerating the
// usual shape soup (array of strings, single string, array of objects with
// a "value" field).
func stringSliceProp(props graph.Properties, key string) []string {
	if props == nil {
		return nil
	}
	v, ok := props[key]
	if !ok || v == nil {
		return nil
	}
	out := []string{}
	switch arr := v.(type) {
	case []any:
		for _, item := range arr {
			switch x := item.(type) {
			case string:
				if x != "" {
					out = append(out, x)
				}
			case map[string]any:
				if s, ok := x["value"].(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	case string:
		if arr != "" {
			out = append(out, arr)
		}
	}
	return out
}
