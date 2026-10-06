package oneagent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/local/dt-managed-engine/internal/analyze"
	// underscore import to register the analyzer via init() — without it
	// analyze.Get("oneagent.distribution") returns nil.
	_ "github.com/local/dt-managed-engine/internal/analyze/oneagent"
)

// TestDistribution_GoldenFixtures walks every directory under testdata/, reads
// input.json + output.json, runs the analyzer on the input, and asserts the
// result matches the output exactly.
//
// Add new scenarios by creating a new testdata/<scenario>/ with both files.
func TestDistribution_GoldenFixtures(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	a := analyze.Get("oneagent.distribution")
	if a == nil {
		t.Fatal("analyzer not registered (the underscore import should have triggered init())")
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		scenario := e.Name()
		t.Run(scenario, func(t *testing.T) {
			inputBytes := mustReadFile(t, filepath.Join("testdata", scenario, "input.json"))
			expectedBytes := mustReadFile(t, filepath.Join("testdata", scenario, "output.json"))

			gotAny, err := a.Run(inputBytes)
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}

			// Round-trip through JSON so both sides are comparable as
			// map[string]any. Direct struct vs map comparison is brittle.
			gotBytes, err := json.Marshal(gotAny)
			if err != nil {
				t.Fatalf("marshal got: %v", err)
			}
			var got, expected any
			if err := json.Unmarshal(gotBytes, &got); err != nil {
				t.Fatalf("unmarshal got: %v", err)
			}
			if err := json.Unmarshal(expectedBytes, &expected); err != nil {
				t.Fatalf("unmarshal expected: %v", err)
			}
			if !reflect.DeepEqual(got, expected) {
				// Emit the diff in a way that's actually readable.
				gotPretty, _ := json.MarshalIndent(got, "", "  ")
				expectedPretty, _ := json.MarshalIndent(expected, "", "  ")
				t.Fatalf("mismatch for scenario %q:\n--- expected ---\n%s\n\n--- got ---\n%s",
					scenario, string(expectedPretty), string(gotPretty))
			}
		})
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
