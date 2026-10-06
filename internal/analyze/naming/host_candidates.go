// host_candidates.go — extract naming candidates for a HOST entity from
// its OWN properties only (no PG cross-reference). Two source families:
//
//   1. Cloud-provider tags / labels (AWS / GCP / Azure / Kubernetes node)
//   2. Detected hostnames (FQDN, DNS names) when they carry a meaningful
//      non-cloud-default segment
//
// The cross-entity evidence (dominant PG, fleet membership) lives in
// host_pg_evidence.go — keeping the two separate makes the heuristic table
// easier to read and test.
package naming

import (
	"regexp"
	"strings"

	"github.com/local/dt-managed-engine/internal/graph"
)

// awsNameTagKeys are AWS tag keys that commonly carry a useful name.
// Ordered by reliability — the first match wins (so we don't double-count
// the same fact).
var awsNameTagKeys = []string{
	"Name",
	"Application",
	"App",
	"Service",
	"aws:autoscaling:groupName",
	"kubernetes.io/cluster/",
}

// gcpLabelKeys are GCP labels that commonly carry a useful name.
var gcpLabelKeys = []string{"name", "app", "application", "service", "component"}

// azureTagKeys are Azure resource tags.
var azureTagKeys = []string{"Name", "Application", "Service"}

// extractHostOwnCandidates pulls candidates from the host's OWN properties.
// Returns a list ordered as the rules fire (BucketAndRank will sort).
func extractHostOwnCandidates(h graph.Host) []Candidate {
	cands := []Candidate{}
	props := h.Properties

	// 1. AWS tags — most reliable when the team has tagged the EC2 instance.
	if v := extractAWSTag(props, "Name"); v != "" {
		if name := cleanName(v); name != "" {
			cands = append(cands, Candidate{
				Source:     "aws.tag.Name",
				Name:       name,
				Confidence: 0.92,
				Evidence:   "awsTag Name=" + v,
			})
		}
	}
	if v := extractAWSTag(props, "Application"); v != "" {
		if name := cleanName(v); name != "" {
			cands = append(cands, Candidate{
				Source:     "aws.tag.Application",
				Name:       name,
				Confidence: 0.90,
				Evidence:   "awsTag Application=" + v,
			})
		}
	}
	if v := extractAWSTag(props, "aws:autoscaling:groupName"); v != "" {
		// ASG names are often the canonical fleet identifier — high signal.
		if name := cleanName(stripCommonASGSuffixes(v)); name != "" {
			cands = append(cands, Candidate{
				Source:     "aws.asg",
				Name:       name,
				Confidence: 0.88,
				Evidence:   "awsTag aws:autoscaling:groupName=" + v,
			})
		}
	}

	// 2. Kubernetes node labels — when the host runs a kubelet, Dynatrace
	//    exposes node labels (or at least the node name).
	if v := stringProp(props, "KubernetesNodeName"); v != "" {
		if name := cleanName(v); name != "" {
			cands = append(cands, Candidate{
				Source:     "k8s.node",
				Name:       name,
				Confidence: 0.85,
				Evidence:   "KubernetesNodeName=" + v,
			})
		}
	}
	if v := extractK8sLabel(props, "app"); v != "" {
		if name := cleanName(v); name != "" {
			cands = append(cands, Candidate{
				Source:     "k8s.label.app",
				Name:       name,
				Confidence: 0.80,
				Evidence:   "k8sLabel app=" + v,
			})
		}
	}

	// 3. GCP labels.
	for _, key := range gcpLabelKeys {
		if v := extractGCPLabel(props, key); v != "" {
			if name := cleanName(v); name != "" {
				cands = append(cands, Candidate{
					Source:     "gcp.label." + key,
					Name:       name,
					Confidence: 0.85,
					Evidence:   "gcpLabel " + key + "=" + v,
				})
				break // one GCP label is enough; avoid stacking duplicates
			}
		}
	}

	// 4. Azure tags.
	for _, key := range azureTagKeys {
		if v := extractAzureTag(props, key); v != "" {
			if name := cleanName(v); name != "" {
				cands = append(cands, Candidate{
					Source:     "azure.tag." + key,
					Name:       name,
					Confidence: 0.85,
					Evidence:   "azureTag " + key + "=" + v,
				})
				break
			}
		}
	}

	// 5. FQDN / DNS — when the hostname carries a meaningful prefix, use it.
	//    e.g. "orders-api-01.prod.internal" → "orders-api-01"
	for _, dns := range stringSliceProp(props, "dnsNames") {
		if name := extractMeaningfulHostSegment(dns); name != "" {
			cands = append(cands, Candidate{
				Source:     "fqdn",
				Name:       name,
				Confidence: 0.55,
				Evidence:   "dnsNames entry " + dns,
			})
			break // one is enough
		}
	}
	// Also check detectedName when distinct from displayName.
	if dn := stringProp(props, "detectedName"); dn != "" && dn != h.DisplayName {
		if name := extractMeaningfulHostSegment(dn); name != "" {
			cands = append(cands, Candidate{
				Source:     "fqdn.detected",
				Name:       name,
				Confidence: 0.50,
				Evidence:   "detectedName=" + dn,
			})
		}
	}

	return cands
}

// extractAWSTag finds an AWS tag by key. Dynatrace stores awsTags as
// either []any of {key, value} maps or a flat map[string]any. Tolerant of
// both. Empty result on miss.
func extractAWSTag(props graph.Properties, key string) string {
	if props == nil {
		return ""
	}
	v, ok := props["awsTags"]
	if !ok {
		return ""
	}
	return findKVValue(v, key)
}

// extractGCPLabel handles GCP labels which Dynatrace usually emits as a
// flat map.
func extractGCPLabel(props graph.Properties, key string) string {
	if props == nil {
		return ""
	}
	v, ok := props["gcpLabels"]
	if !ok {
		return ""
	}
	return findKVValue(v, key)
}

// extractAzureTag finds an Azure tag.
func extractAzureTag(props graph.Properties, key string) string {
	if props == nil {
		return ""
	}
	v, ok := props["azureTags"]
	if !ok {
		return ""
	}
	return findKVValue(v, key)
}

// extractK8sLabel pulls a Kubernetes node label.
func extractK8sLabel(props graph.Properties, key string) string {
	if props == nil {
		return ""
	}
	v, ok := props["kubernetesLabels"]
	if !ok {
		return ""
	}
	return findKVValue(v, key)
}

// findKVValue scans the wide shape soup Dynatrace returns for tag/label
// collections and returns the value for the given key, or "".
//
// Shapes handled:
//   []any of {key, value} maps
//   []any of "key=value" strings
//   map[string]any (key → string-or-stringer value)
func findKVValue(v any, key string) string {
	switch coll := v.(type) {
	case []any:
		for _, item := range coll {
			switch it := item.(type) {
			case map[string]any:
				k, _ := it["key"].(string)
				if k == key {
					if val, ok := it["value"].(string); ok {
						return val
					}
				}
			case string:
				if i := strings.Index(it, "="); i > 0 && it[:i] == key {
					return it[i+1:]
				}
			}
		}
	case map[string]any:
		if val, ok := coll[key].(string); ok {
			return val
		}
	}
	return ""
}

// stripCommonASGSuffixes drops the random-looking suffix terraform / CDK
// tend to append to ASG names (e.g. "orders-api-asg-A1B2C3D4-1234567890").
// Conservative — only strips the obvious patterns.
func stripCommonASGSuffixes(s string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`-asg$`),
		regexp.MustCompile(`-asg-[A-Z0-9]{8,}.*$`),
		regexp.MustCompile(`-[0-9]{10,}$`),
	}
	for _, re := range patterns {
		s = re.ReplaceAllString(s, "")
	}
	return s
}

// extractMeaningfulHostSegment takes a hostname / FQDN and returns the
// leading segment when it carries non-cloud-default information. Returns
// "" when the leading segment matches a cloud-default pattern (so we
// don't suggest "ip-10-0-1-23" as the "candidate" for "ip-10-0-1-23").
func extractMeaningfulHostSegment(hostname string) string {
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return ""
	}
	// Take leading label (before first dot).
	first := trimmed
	if i := strings.Index(trimmed, "."); i > 0 {
		first = trimmed[:i]
	}
	// Reject when it matches the cloud-default rules.
	if reason := IsGeneric(first, GenericKindHost); reason != "" {
		return ""
	}
	return cleanName(first)
}
