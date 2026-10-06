# dt-managed-engine

Deterministic check engine for Dynatrace Managed. Pure, offline, reproducible — same inputs in, same findings out.

Has two modes of operation:

1. **CLI (offline)** — `dt-engine assess --bundle <dir>` reads a pre-collected bundle directory, runs every check, emits findings JSON. The bundle is produced by [`dt-managed-ahr-collector`](../dt-managed-ahr-collector) when you can't run the live MCP.

2. **MCP server (live)** — `dt-engine mcp` exposes each check as an MCP tool over stdio. The companion [`dt-managed-mcp`](../dt-managed-ahr-mcp) (TS) acts as an MCP client to it: it materializes a bundle on-the-fly from live Dynatrace reads and calls back into this engine for evaluation.

The engine never touches Dynatrace directly in either mode. It is a pure function from bundle to findings.

## Architecture

```
Live path (driven by an LLM session):
  Dynatrace ──[HTTP]──▶ dt-managed-mcp  ──[MCP stdio]──▶ dt-engine mcp
                            │                                  │
                            ▼ writes                           ▼ reads
                       <bundle dir>  ◀───────────────  finds + emits findings

Offline path (no MCP, no network at evaluation time):
  Dynatrace ──[HTTP]──▶ dt-managed-ahr-collector ──▶ <bundle dir> ──▶ dt-engine assess
```

The bundle directory format is identical in both paths. That's what makes the engine the canonical evaluation step.

Time is part of the input: `manifest.json` at the bundle root carries `generatedAt`, and every age/recency computation uses it as "now" (`Bundle.Now()`). A bundle therefore evaluates identically whenever it is assessed. Without a manifest the wall clock is read once at load and reported as the reference-time source.

## Build

```bash
go build -o dt-engine ./cmd/dt-engine
```

## Run — offline CLI mode

```bash
dt-engine assess --bundle ./reports/<account>/<date> --out findings.json
```

Stderr prints a one-line summary; stdout (or `--out`) gets the JSON.

## Run — MCP server mode

```bash
dt-engine mcp
```

Speaks MCP stdio protocol; typically spawned by the data MCP (`dt-managed-mcp`), not run by hand. Exposes:

- `engine_list_checks` — list available check IDs + phases
- `engine_run` — run one or more checks against a bundle path

## Test

```bash
go test ./...
```

Each check has a golden fixture under `testdata/golden/<scenario>/raw/` that exercises both the firing and non-firing cases.

## Adding a new check

1. Create `internal/checks/check_<name>.go` implementing the `Check` interface (see `registry.go`).
2. Add a sibling `check_<name>_test.go` with golden fixtures under `testdata/golden/`.
3. Register it in `checks.All()` in `internal/checks/registry.go`.

The CLI and the MCP server both pick it up automatically.

## Currently implemented

| ID | Phase |
|---|---|
| `CHECK_AUTO_TAG_DEAD` | Phase 1 |
| `CHECK_AUTO_TAG_OVERBROAD` | Phase 1 |
| `CHECK_HOST_NO_HOSTGROUP` | Phase 1 |
| `CHECK_HOSTGROUP_SINGLETON` | Phase 1 |
| `CHECK_FULLSTACK_NO_LOGS` | Phase 1 |
| `CHECK_TAG_INCONSISTENT_ROLLOUT` | Phase 1 |
| `CHECK_PG_PGIS_SPAN_ENVS` | Phase 2 |
| `CHECK_MZ_DEAD` | Phase 3 |
| `CHECK_MZ_OVERLAP` | Phase 3 |
| `CHECK_TOKEN_NEVER_USED` | Phase 4.6 |
