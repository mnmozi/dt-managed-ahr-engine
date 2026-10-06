// Tools exposed by the engine MCP server.
//
// We expose two: engine_list_checks (discovery) and engine_run (run one or
// many checks against a bundle). One general-purpose run tool beats a tool
// per check — the client picks via the `checks` array.
package mcpserver

import (
	"encoding/json"
	"fmt"

	"github.com/local/dt-managed-engine/internal/analyze"
	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/checks"
	"github.com/local/dt-managed-engine/internal/finding"
	"github.com/local/dt-managed-engine/internal/runner"

	// Blank imports register each analyzer with the analyze registry.
	// Add a line here when you ship a new analyzer subpackage.
	_ "github.com/local/dt-managed-engine/internal/analyze/activegate"
	_ "github.com/local/dt-managed-engine/internal/analyze/naming"
	_ "github.com/local/dt-managed-engine/internal/analyze/oneagent"
	_ "github.com/local/dt-managed-engine/internal/analyze/tags"
	_ "github.com/local/dt-managed-engine/internal/analyze/token"
)

// RegisterEngineTools wires the engine's checks + analyzers into an MCP server.
func RegisterEngineTools(s *Server, engineVersion string) {
	s.RegisterTool(
		ToolDef{
			Name: "engine_list_checks",
			Description: "List every check the engine can run. Returns id and phase per check. No bundle required.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		handleListChecks,
	)

	s.RegisterTool(
		ToolDef{
			Name: "engine_list_analyzers",
			Description: "List every analyzer the engine can run. Returns kind and description per analyzer. Analyzers are pure JSON-in/JSON-out helpers, distinct from checks (which produce Findings against a bundle).",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		handleListAnalyzers,
	)

	s.RegisterTool(
		ToolDef{
			Name: "engine_run",
			Description: "Run engine checks against a bundle directory. Provide bundlePath (required) and optionally checks[] / phases[] filters. Returns Result with counts + findings (unsorted — consumer sorts for display).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundlePath": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to a bundle directory containing a raw/ subdirectory with the expected JSON files.",
					},
					"checks": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional. Filter to specific check IDs. Empty/omitted = run all.",
					},
					"phases": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional. Filter to specific phases. Applied AFTER checks[] if both provided.",
					},
				},
				"required": []string{"bundlePath"},
			},
		},
		runHandler(engineVersion),
	)

	s.RegisterTool(
		ToolDef{
			Name: "engine_analyze",
			Description: "Run an analyzer by kind. Pure JSON-in/JSON-out. The consumer (typically dt-managed-mcp) already fetched the data and just wants the engine's computation. Call engine_list_analyzers to discover kinds.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"kind": map[string]interface{}{
						"type":        "string",
						"description": "Analyzer kind, e.g. 'oneagent.distribution'. See engine_list_analyzers for available kinds.",
					},
					"input": map[string]interface{}{
						"description": "JSON value matching the analyzer's expected input shape.",
					},
				},
				"required": []string{"kind"},
			},
		},
		handleAnalyze,
	)
}

func handleListAnalyzers(_ json.RawMessage) (CallResult, error) {
	all := analyze.All()
	type row struct {
		Kind        string `json:"kind"`
		Description string `json:"description"`
	}
	rows := make([]row, 0, len(all))
	for _, a := range all {
		rows = append(rows, row{Kind: a.Kind(), Description: a.Description()})
	}
	return jsonTextResult(map[string]interface{}{
		"analyzers":         rows,
		"analyzersAvailable": len(rows),
	})
}

type analyzeArgs struct {
	Kind  string          `json:"kind"`
	Input json.RawMessage `json:"input"`
}

func handleAnalyze(raw json.RawMessage) (CallResult, error) {
	var args analyzeArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return CallResult{}, fmt.Errorf("decode args: %w", err)
		}
	}
	if args.Kind == "" {
		return CallResult{}, fmt.Errorf("kind is required")
	}
	result, err := analyze.Run(args.Kind, args.Input)
	if err != nil {
		return CallResult{}, err
	}
	return jsonTextResult(result)
}

func handleListChecks(_ json.RawMessage) (CallResult, error) {
	all := checks.All()
	type row struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
	}
	rows := make([]row, 0, len(all))
	for _, c := range all {
		rows = append(rows, row{ID: c.ID(), Phase: c.Phase()})
	}
	body := map[string]interface{}{
		"checks":        rows,
		"checksApplied": len(rows),
	}
	return jsonTextResult(body)
}

type runArgs struct {
	BundlePath string   `json:"bundlePath"`
	Checks     []string `json:"checks"`
	Phases     []string `json:"phases"`
}

func runHandler(engineVersion string) ToolHandler {
	return func(raw json.RawMessage) (CallResult, error) {
		var args runArgs
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &args); err != nil {
				return CallResult{}, fmt.Errorf("decode args: %w", err)
			}
		}
		if args.BundlePath == "" {
			return CallResult{}, fmt.Errorf("bundlePath is required")
		}

		b, err := bundle.Load(args.BundlePath)
		if err != nil {
			return CallResult{}, fmt.Errorf("load bundle %s: %w", args.BundlePath, err)
		}

		all := checks.All()
		var selected []checks.Check
		switch {
		case len(args.Checks) > 0 || len(args.Phases) > 0:
			wantIDs := stringSet(args.Checks)
			wantPhases := stringSet(args.Phases)
			for _, c := range all {
				if len(wantIDs) > 0 && !wantIDs[c.ID()] {
					continue
				}
				if len(wantPhases) > 0 && !wantPhases[c.Phase()] {
					continue
				}
				selected = append(selected, c)
			}
		default:
			selected = all
		}

		if len(selected) == 0 {
			body := map[string]interface{}{
				"bundleRoot": b.Root,
				"engine": map[string]interface{}{
					"version":       engineVersion,
					"checksApplied": 0,
				},
				"counts": runner.Counts{},
				"findings": []finding.Finding{},
				"note": "no checks matched the supplied filters",
			}
			return jsonTextResult(body)
		}

		// MCP consumer sorts for LLM consumption. The runner doesn't sort —
		// presentation is the consumer's job.
		var findings []finding.Finding
		for _, c := range selected {
			findings = append(findings, c.Run(b)...)
		}
		result := runner.Finalize(b.Root, engineVersion, len(selected), findings)
		runner.SortBySeverity(result.Findings)
		return jsonTextResult(result)
	}
}

func jsonTextResult(v interface{}) (CallResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return CallResult{}, err
	}
	return CallResult{
		Content: []ContentBlock{{Type: "text", Text: string(data)}},
	}, nil
}

func stringSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
