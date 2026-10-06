package token_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/local/dt-managed-engine/internal/analyze"
	_ "github.com/local/dt-managed-engine/internal/analyze/token"
)

func TestSecurityAudit_GoldenFixtures(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	a := analyze.Get("token.security_audit")
	if a == nil {
		t.Fatal("analyzer not registered")
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
