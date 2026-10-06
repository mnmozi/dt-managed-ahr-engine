package naming

import (
	"testing"
)

// BucketAndRank is the only piece of pure logic that's worth unit-testing
// directly — everything else is exercised through the golden fixtures.
// The bucket boundaries are the highest-leverage code in the package.
func TestBucketAndRank(t *testing.T) {
	cases := []struct {
		name     string
		raw      []Candidate
		wantTop  string
		wantDec  Decision
		wantLen  int
	}{
		{
			name:    "empty input is no_signal",
			raw:     nil,
			wantTop: "",
			wantDec: DecisionNoSignal,
			wantLen: 0,
		},
		{
			name: "high confidence single candidate >= 0.80",
			raw: []Candidate{
				{Source: "x", Name: "orders-api", Confidence: 0.85},
			},
			wantTop: "orders-api",
			wantDec: DecisionHighConfidence,
			wantLen: 1,
		},
		{
			name: "high confidence: top 0.92 vs runner-up 0.70 (gap 0.22)",
			raw: []Candidate{
				{Source: "k8s", Name: "orders-api", Confidence: 0.92},
				{Source: "jar", Name: "orders-svc", Confidence: 0.70},
			},
			wantTop: "orders-api",
			wantDec: DecisionHighConfidence,
			wantLen: 2,
		},
		{
			name: "ambiguous: top 0.92 vs runner-up 0.85 (gap < 0.20)",
			raw: []Candidate{
				{Source: "k8s", Name: "orders-api", Confidence: 0.92},
				{Source: "jar", Name: "orders-svc", Confidence: 0.85},
			},
			wantTop: "orders-api",
			wantDec: DecisionAmbiguous,
			wantLen: 2,
		},
		{
			name: "ambiguous: top is 0.60 (below high min)",
			raw: []Candidate{
				{Source: "x", Name: "maybe", Confidence: 0.60},
			},
			wantTop: "maybe",
			wantDec: DecisionAmbiguous,
			wantLen: 1,
		},
		{
			// Note: BucketAndRank still returns the candidate list so the
			// caller can show evidence even when decision is no_signal.
			// finishReport is the layer that hides topCandidate.
			name: "no_signal: top is 0.35 (below ambiguous min)",
			raw: []Candidate{
				{Source: "x", Name: "nope", Confidence: 0.35},
			},
			wantTop: "nope",
			wantDec: DecisionNoSignal,
			wantLen: 1,
		},
		{
			name: "duplicate names are deduped, keeping the higher confidence",
			raw: []Candidate{
				{Source: "a", Name: "orders-api", Confidence: 0.85},
				{Source: "b", Name: "orders-api", Confidence: 0.70},
			},
			wantTop: "orders-api",
			wantDec: DecisionHighConfidence,
			wantLen: 1,
		},
		{
			name: "sorted descending; 0.95 vs 0.65 = 0.30 gap → high_confidence",
			raw: []Candidate{
				{Source: "a", Name: "low", Confidence: 0.50},
				{Source: "b", Name: "mid", Confidence: 0.65},
				{Source: "c", Name: "high", Confidence: 0.95},
			},
			wantTop: "high",
			wantDec: DecisionHighConfidence,
			wantLen: 3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, dec := BucketAndRank(tc.raw)
			if len(got) != tc.wantLen {
				t.Fatalf("len(got)=%d want %d (got=%+v)", len(got), tc.wantLen, got)
			}
			if dec != tc.wantDec {
				t.Fatalf("decision=%q want %q", dec, tc.wantDec)
			}
			if tc.wantLen > 0 && got[0].Name != tc.wantTop {
				t.Fatalf("top=%q want %q", got[0].Name, tc.wantTop)
			}
		})
	}
}

// IsGeneric checks — covers the rule table in generic.go.
func TestIsGeneric(t *testing.T) {
	cases := []struct {
		name  string
		input string
		kind  GenericKind
		want  bool // true = expect non-empty reason
	}{
		{"empty pg", "", GenericKindProcessGroup, true},
		{"bare java pg", "java", GenericKindProcessGroup, true},
		{"bare python3 pg", "python3", GenericKindProcessGroup, true},
		{"port-only pg", ":80", GenericKindProcessGroup, true},
		{"port-only with suffix", "80 process", GenericKindProcessGroup, true},
		{"dynatrace default", "Java process 1234", GenericKindProcessGroup, true},
		{"hex-only pg", "deadbeefcafe", GenericKindProcessGroup, true},
		{"all-numeric pg", "12345", GenericKindProcessGroup, true},
		{"bare word pg", "server", GenericKindProcessGroup, true},
		{"orders-api pg (healthy)", "orders-api", GenericKindProcessGroup, false},
		{"camelcase pg (healthy)", "OrdersApi", GenericKindProcessGroup, false},

		{"aws ec2 host default", "ip-10-0-1-23", GenericKindHost, true},
		{"gcp gke host default", "gke-prod-pool-a1b2c3d4-xy12", GenericKindHost, true},
		{"localhost host", "localhost", GenericKindHost, true},
		{"hex host", "abcdef0123456789abcdef0123456789", GenericKindHost, true},
		{"team-named host (healthy)", "orders-api-01", GenericKindHost, false},

		{"port-only service", ":80", GenericKindService, true},
		{"underscore port service", "_:80", GenericKindService, true},
		{"tech on port service", "gunicorn on port 7100", GenericKindService, true},
		{"tech on ipv6 bind service", "Netty on 0:0:0:0:0:0:0:0:*", GenericKindService, true},
		{"tech on ipv4 bind service", "Tomcat on 10.0.1.5:8080", GenericKindService, true},
		{"bare tech service", "Redis", GenericKindService, true},
		{"unmonitored-hosts default", "Requests to unmonitored hosts", GenericKindService, true},
		{"workload on port (healthy)", "order-service on port 80", GenericKindService, false},
		{"named service (healthy)", "checkout", GenericKindService, false},
		{"tomcat shell with context root", "Catalina/localhost (/tariff)", GenericKindService, true},
		{"tech-prefixed composite", "uvicorn order-service-* on port 80", GenericKindService, true},
		{"identity + paren (healthy)", "billing-api (/v2)", GenericKindService, false},
		{"generic word on port", "server on port 7000", GenericKindService, true},
		{"bare generic word", "server", GenericKindService, true},
		{"all-generic multiword", "python server", GenericKindService, true},
		{"role word with identity (healthy)", "orders worker", GenericKindService, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsGeneric(tc.input, tc.kind)
			if (got != "") != tc.want {
				t.Fatalf("IsGeneric(%q,%s)=%q (generic=%v) want generic=%v",
					tc.input, tc.kind, got, got != "", tc.want)
			}
		})
	}
}
