// Package analyze defines the contract for engine analyzers.
//
// An Analyzer is a pure function from input JSON to output value. Unlike a
// Check, an Analyzer produces structured data (not Findings) — it's a
// computation building block consumers stitch into their own outputs.
//
// Distinction:
//   - Checks  → Finding{severity, evidence, recommendation, fix_template}
//   - Analyzers → typed structured data (counts, distributions, diffs, etc.)
//
// Analyzers live in subpackages under internal/analyze/<namespace>/ and
// register themselves in this package's registry via the Register function
// called from each subpackage's init().
package analyze

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Analyzer is the contract every analyzer must satisfy.
type Analyzer interface {
	// Kind is the stable identifier used to dispatch calls.
	// Format: "<namespace>.<name>", e.g. "oneagent.distribution".
	Kind() string

	// Description is a one-line human description for discovery via engine_list.
	Description() string

	// Run takes raw JSON input and returns the result value (any JSON-serializable
	// type). Pure function: same input bytes → same output bytes. No I/O, no
	// time-of-day reads, no randomness.
	Run(input json.RawMessage) (any, error)
}

// registry is the global analyzer registry. Populated via Register() called
// from each analyzer subpackage's init().
var (
	registryMu sync.RWMutex
	registry   = map[string]Analyzer{}
)

// Register adds an analyzer to the global registry. Typically called from a
// subpackage's init() function.
//
// Panics if two analyzers register the same Kind — fail loud at startup so
// drift can't be missed.
func Register(a Analyzer) {
	registryMu.Lock()
	defer registryMu.Unlock()
	kind := a.Kind()
	if _, exists := registry[kind]; exists {
		panic(fmt.Sprintf("analyze: duplicate analyzer kind %q", kind))
	}
	registry[kind] = a
}

// All returns every registered analyzer, sorted by Kind for stable output.
func All() []Analyzer {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Analyzer, 0, len(registry))
	for _, a := range registry {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind() < out[j].Kind() })
	return out
}

// Get looks up an analyzer by kind. Returns nil if not found.
func Get(kind string) Analyzer {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[kind]
}

// Run is the dispatcher: look up by kind, run, return.
// Convenience helper for callers that don't want to call Get + Run themselves.
func Run(kind string, input json.RawMessage) (any, error) {
	a := Get(kind)
	if a == nil {
		return nil, fmt.Errorf("analyze: unknown kind %q", kind)
	}
	return a.Run(input)
}
