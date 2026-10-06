package naming_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/local/dt-managed-engine/internal/analyze"
	_ "github.com/local/dt-managed-engine/internal/analyze/naming"
)

// Golden-fixture test for naming analyzers. Same structure as tags_test —
// one entry per analyzer kind, fixtures discovered by directory walk so
// adding a new scenario is just `mkdir testdata/.../scenario && place
// input.json + output.json`.
func TestNamingAnalyzers_GoldenFixtures(t *testing.T) {
	analyzers := []struct {
		kind    string
		dataDir string
	}{
		{"processgroups.naming_audit", "testdata/processgroups_naming_audit"},
		{"hosts.naming_audit", "testdata/hosts_naming_audit"},
		{"hostgroups.coverage_audit", "testdata/hostgroups_coverage_audit"},
		{"services.naming_audit", "testdata/services_naming_audit"},
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
		t.Skipf("testdata dir %s missing: %v", dir, err)
		return
	}
	a := analyze.Get(kind)
	if a == nil {
		t.Skipf("analyzer %s not registered", kind)
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
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
