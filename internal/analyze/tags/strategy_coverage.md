# Analyzer: `tags.strategy_coverage`

Round 2b of the tag-strategy loop. Given a proposed strategy (per key: an ordered list of extraction sources), simulate against the entity graph and report what coverage it would achieve. The AI uses this to decide whether a strategy is workable before any rule is written.

**Scope rule:** no I/O. Pure function.

---

## When to use it

After the AI has proposed a strategy from `tags.signal_extraction` output. Use to answer:

- "If we implement this strategy, will every entity get a value?"
- "Which entities would still be uncovered, and why?"
- "Should we tighten the strategy or accept partial coverage?"

---

## Input

```json
{
  "hosts": [...], "processGroups": [...], "processGroupInstances": [...], "services": [...],
  "strategy": {
    "team": {
      "extractFrom": ["awsTag:Team", "envVar:OWNING_TEAM", "containmentParent:tag:team"]
    },
    "env": {
      "extractFrom": ["hostGroup.name", "envVar:ENV"],
      "fallback": "default-env"
    }
  },
  "scopeEntityTypes": ["HOST", "SERVICE"]
}
```

| Field | Default | Purpose |
|---|---|---|
| `strategy` | (required) | Per-key extraction recipe |
| `scopeEntityTypes` | all four | Restrict simulation to specific types |

### Source DSL

`extractFrom` is an ordered list of source specs. First match wins. Supported:

| Spec | Resolves to |
|---|---|
| `property:<field>` | Top-level property field (must be a string) |
| `property:<field>:<subkey>` | Nested map field's subkey |
| `awsTag:<Key>` | Value of AWS tag matching `Key` (case-insensitive) |
| `azureTag:<Key>` | Same for Azure |
| `gcpTag:<Key>` | Same for GCP |
| `k8sLabel:<key>` | k8s label value |
| `envVar:<NAME>` | env var value |
| `hostGroup.name` | `properties.hostGroupName` value |
| `hostName.token[N]` | N-th token of hostname split on `-_./ ` |
| `containmentParent:tag:<key>` | First non-empty value of tag `key` on a containment parent |
| `containmentDescendantMajority:tag:<key>` | Majority value (≥66%) across descendants |
| `callGraphMajority:tag:<key>` | Majority value (≥66%) across call neighbors |
| `siblingTag:<key>` | First non-empty value of tag `key` on a sibling |
| `fallback:<literal>` | Literal value (use as a terminal) |

Plus `fallback` as a sibling field on the KeyStrategy — applied if all `extractFrom` entries return empty.

---

## Output

```json
{
  "coveragePerKey": {
    "team": {
      "perType": {
        "HOST":    { "covered": 3, "uncovered": 1, "coverage": 0.75 },
        "SERVICE": { "covered": 8, "uncovered": 0, "coverage": 1.00 }
      },
      "overall":  { "covered": 11, "uncovered": 1, "coverage": 0.92 }
    }
  },
  "uncoveredEntities": [
    {
      "entityId": "HOST-X",
      "type": "HOST",
      "displayName": "...",
      "missingKeys": [
        { "key": "team", "sourcesTried": ["awsTag:Team", "envVar:OWNING_TEAM"] }
      ]
    }
  ],
  "achievableCoverage": 0.85,
  "appliedDefaults": { "scopeEntityTypes": ["HOST", "SERVICE"] }
}
```

| Field | Semantics |
|---|---|
| `coveragePerKey[key].perType` | Per entity type → `{ covered, uncovered, coverage }` |
| `coveragePerKey[key].overall` | Across the scope (sum across types) |
| `uncoveredEntities` | Entities where ≥1 key couldn't be extracted, with reasons |
| `achievableCoverage` | Fraction of scoped entities where ALL strategy keys produced a value (per-entity-perfect) |

---

## Algorithm

```
1. Build the graph.
2. Resolve scope (default = all 4 entity types).
3. For each (entity, key in strategy):
   - Try ExtractFrom in order
   - First non-empty result wins
   - Else use KeyStrategy.Fallback if set
4. Per (entity-type, key): tally covered + uncovered
5. Per key: roll up overall coverage
6. Per entity: if ANY key didn't resolve, add to uncoveredEntities with reasons
7. Compute achievableCoverage = entities where ALL keys resolved / scope size
```

The DSL evaluator is intentionally simple — no nested expressions, no conditional logic. Each source is a single deterministic lookup.

---

## Edge cases

| Scenario | Result |
|---|---|
| Empty strategy | Returns error: "strategy is required". |
| Strategy with key that no source can produce | All entities uncovered for that key; `coverage: 0`. |
| Source spec misspelled (e.g. `awsTagz`) | Treated as "no match" — no error. Caller verifies via the uncoveredEntities list. |
| Fallback set but ExtractFrom resolves on first try | Fallback never used — first match wins. |
| Empty scope (e.g. `scopeEntityTypes: ["HOST_GROUP"]`, no such type) | `achievableCoverage: 0`; empty uncovered list. |
| Containment parent lookup with multiple parents | First non-empty match wins (parents iterated in containment order). |
| `containmentDescendantMajority:tag:team` when descendants disagree below threshold | Returns empty — no majority means no signal. |

---

## What this analyzer doesn't do

- Doesn't apply the strategy to Dynatrace — simulation only.
- Doesn't generate auto-tag rule payloads — that's downstream of strategy approval.
- Doesn't compare against existing tags — if an entity already has a value for the key, that's irrelevant to the simulation (we ask "would the strategy produce a value", not "would the strategy override existing").

---

## Test fixtures

| Scenario | Coverage |
|---|---|
| `empty` | error path — strategy provided but no entities |
| `perfect-coverage` | 100% across both keys |
| `partial-coverage` | 75% — one host with neither awsTag nor env var → uncovered |
| `with-fallback` | 100% achievable thanks to literal fallback |
