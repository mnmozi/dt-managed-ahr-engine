package tags_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/local/dt-managed-engine/internal/analyze"
	_ "github.com/local/dt-managed-engine/internal/analyze/tags"
)

// Table-driven: one entry per analyzer in this package. Each entry points
// at the analyzer kind + its testdata subdir. Add new analyzers' fixtures
// to the table; the test loop discovers scenarios automatically.
func TestTagsAnalyzers_GoldenFixtures(t *testing.T) {
	analyzers := []struct {
		kind    string
		dataDir string
	}{
		{"tags.snapshot", "testdata/snapshot"},
		{"tags.signal_extraction", "testdata/signal_extraction"},
		{"tags.strategy_coverage", "testdata/strategy_coverage"},
	}
	for _, a := range analyzers {
		t.Run(a.kind, func(t *testing.T) {
			runFixturesIn(t, a.kind, a.dataDir)
		})
	}
}

func runFixturesIn(t *testing.T, kind, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		// dir may not exist yet for analyzers not built — skip gracefully.
		t.Skipf("testdata dir %s missing: %v", dir, err)
		return
	}
	a := analyze.Get(kind)
	if a == nil {
		t.Skipf("analyzer %s not registered (probably not implemented yet)", kind)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		scenario := e.Name()
		t.Run(scenario, func(t *testing.T) {
			inputBytes := mustReadFile(t, filepath.Join(dir, scenario, "input.json"))
			expectedBytes := mustReadFile(t, filepath.Join(dir, scenario, "output.json"))
			gotAny, err := a.Run(inputBytes)
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}
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
				gotPretty, _ := json.MarshalIndent(got, "", "  ")
				expectedPretty, _ := json.MarshalIndent(expected, "", "  ")
				t.Fatalf("mismatch for %s/%s:\n--- expected ---\n%s\n\n--- got ---\n%s",
					kind, scenario, string(expectedPretty), string(gotPretty))
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
