# dt-managed-ahr-engine

Deterministic check engine for Dynatrace Managed Account Health Reviews.

Reads a bundle produced by [`dt-managed-ahr-collector`](../dt-managed-ahr-collector) and emits a structured `findings.json`. No network, no LLM, no surprises — same bundle in, same findings out.

## Architecture

```
Collector (Go, network-attached)  →  Bundle (filesystem)  →  Engine (Go, pure function)
                                                             ↓
                                                       findings.json
                                                             ↓
                              (consumers: markdown / xlsx / pptx / diff / write payloads / LLM narrator)
```

The engine is the canonical step. Every downstream tool operates on `findings.json`, not the raw bundle. That's what makes this auditable and reproducible.

## Build

```bash
go build -o dt-ahr-engine ./cmd/dt-ahr-engine
```

## Run

```bash
dt-ahr-engine assess --bundle ./reports/<account>/<date> --out findings.json
```

Stderr prints a one-line summary; stdout (or `--out`) gets the JSON.

## Test

```bash
go test ./...
```

Each check has a golden fixture under `testdata/golden/<scenario>/bundle/` that exercises both the firing and non-firing cases.

## Adding a new check

1. Create `internal/checks/check_<name>.go` implementing the `Check` interface (see `registry.go`).
2. Add a sibling `check_<name>_test.go` with golden fixtures under `testdata/golden/`.
3. Register it in `checks.All()` in `internal/checks/registry.go`.

That's it. The runner picks it up automatically.

## Currently implemented

| ID | Phase | Description |
|---|---|---|
| `CHECK_AUTO_TAG_DEAD` | Phase 1 | Auto-tag rule producing a tag key that no entity carries |

This is intentionally minimal — the architecture is designed to scale to ~80 checks without changing shape.
