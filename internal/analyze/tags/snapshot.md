# Analyzer: `tags.snapshot`

Foundation analyzer for tag analysis. Builds the entity graph (containment + call edges) from flat input, then computes everything the AI needs to judge the tenant's tag state in one structured blob.

**Scope rule:** no I/O. Pure function over flat entity input + auto-tag rules.

---

## When to use it

Round 1 of the tag-strategy loop. Use to answer:

- "Is there a coherent tagging strategy on this tenant?"
- "Which entities are untagged or undertagged?"
- "Which tag keys look like typos / variants of each other?"
- "Are tag values inconsistent (case drift, separator drift)?"
- "Which entity types lack ownership tags?"
- "Where could a tag flow from a tagged neighbor?"

---

## Input

```json
{
  "hosts": [...], "processGroups": [...], "processGroupInstances": [...], "services": [...],
  "autoTagRules": [...],
  "lowTagThreshold": 1,
  "graphMode": "low_tag_only"
}
```

Each entity has `{ id, displayName, tags, properties, relationshipFields }` per the graph package's Input shape. Tags carry `{ context, key, value, stringRepresentation }`.

| Field | Default | Purpose |
|---|---|---|
| `autoTagRules` | `[]` | Used to map keys → producing rule ids. Each rule is `{ objectId, value.name }`. |
| `lowTagThreshold` | 1 | Entities with ≤ this many tags flagged in `lowTagEntities`. `lowTagThreshold: 0` is treated as "use default 1" — an entity with one infra-only auto-tag isn't meaningfully "tagged". |
| `graphMode` | `"low_tag_only"` | `"full"` emits every node in `lowTagSubgraph.nodes`; `"none"` skips graph entirely; `"low_tag_only"` emits seeds + 1-hop neighborhood (parents/children/call-neighbors). |

---

## Output

Top-level fields:

| Field | Semantics |
|---|---|
| `entitiesByType` | per type → `{ total, withZeroTags, withLowTags }` |
| `keys` | per tag key → coverage + values + format judgment + sourcing rules |
| `keySimilarityClusters` | clusters of keys that look like the same intent (typo / substring / case drift) |
| `lowTagEntities` | per type → list of `{ entityId, displayName, tagCount }` |
| `lowTagSubgraph` | (when graphMode ≠ none) — subgraph nodes with pre-computed parent/sibling/neighbor tag distributions |
| `propagationHints` | per key → coverage classification + call-graph hint |
| `appliedDefaults` | echoes the thresholds + graphMode used |

### `KeyStats`

```json
{
  "key": "team",
  "totalOccurrences": 156,
  "coverage": { "HOST": 0.71, "SERVICE": 0.10 },
  "distinctValues": ["foo","bar","Foo","FOO_TEAM"],
  "topValues": [{ "value": "foo", "count": 87 }],
  "valueFormatJudgment": "messy",
  "valueFormatIssues": [
    { "type": "case_drift", "groups": [["foo","Foo","FOO"]] },
    { "type": "separator_drift", "groups": [["FOO_TEAM","foo-team"]] }
  ],
  "contextDistribution": { "AUTO_TAG": 117, "CONTEXTLESS": 32 },
  "sourcingRuleIds": ["rule-id-123"]
}
```

| Field | Notes |
|---|---|
| `valueFormatJudgment` | `"single"` (one distinct value), `"uniform"` (multiple distinct, no shape drift), `"messy"` (at least one pair of values normalizes to the same string but has different shapes) |
| `valueFormatIssues[].type` | `"case_drift"` / `"separator_drift"` / `"mixed_drift"` |
| `sourcingRuleIds` | auto-tag rules whose `value.name == this.key` |

### `SimilarityCluster`

```json
{
  "canonical": "env",
  "variants": ["env","envv","environment"],
  "evidence": [
    { "pair": ["env","envv"], "metric": "levenshtein", "score": 1 },
    { "pair": ["env","environment"], "metric": "substring", "ratio": 0.27 },
    { "pair": ["Team","team"], "metric": "case_only" }
  ],
  "totalOccurrences": 234
}
```

Clusters merge via union-find — if A is similar to B AND B is similar to C, all three end up in one cluster. `canonical` is the variant with the most occurrences (alpha tiebreak).

Similarity edges fire on:
- `case_only` — `NormalizedEqual(a, b)` (case/separator-stripped match)
- `levenshtein` — `LikelyTypo(a, b)` (edit distance ≤ 2, length within 30%)
- `substring` — `SubstringContainment(a, b) ≥ 0.20`

### `SubgraphNode`

For each low-tag entity, the subgraph emits one node with:

- `containmentParentIds` / `containmentChildrenIds` / `callsFromIds` / `callsToIds` — adjacency
- `parentTagDistribution` / `siblingTagDistribution` / `neighborTagDistribution` — pre-computed `key → value → count` maps

The AI reads these directly. No tree traversal required on the AI side.

### `PropagationHint`

Per key, the engine bucket-classifies coverage:
- `fullyCoveredOn` — types with coverage ≥ 95%
- `partiallyCoveredOn` — 10–95%
- `uncoveredOn` — < 10%

Plus `callGraphHint`: when untagged services have tagged callers/callees for this key, a short narrative is emitted ("8 untagged services have at least one call-graph neighbor tagged with 'team' — likely inheritable via auto-tag rule").

---

## Algorithm

```
1. Build the graph (containment + call edges) from flat input.

2. Walk every entity. Per type:
   - total
   - withZeroTags
   - withLowTags (tagCount ≤ threshold)
   Collect low-tag nodes for the subgraph.

3. Compute per-key taxonomy:
   - For each tag occurrence, increment per-type entity-set + value count
     + context count + total occurrence count
   - Per key: coverage = withKey / typeTotal
   - Distinct values, top 10 by count
   - Value-format classification (single / uniform / messy with sub-issues)
   - Map key → sourcing auto-tag rule ids

4. Compute key similarity clusters via union-find over similarity edges.

5. Compute propagation hints per key.

6. Compute call-graph hints per key (for untagged services with tagged
   neighbors).

7. Build the low-tag subgraph (or full / none depending on graphMode):
   - seeds = low-tag nodes
   - include each seed's immediate parents, children, call neighbors
   - per node, emit pre-computed parent/sibling/neighbor tag distributions
```

---

## Constants

| Name | Value | Why |
|---|---|---|
| Full-coverage threshold | 0.95 | for `fullyCoveredOn` bucketing |
| Partial-coverage threshold | 0.10 | for `partiallyCoveredOn` lower bound |
| Substring containment threshold | 0.20 | minimum ratio to qualify as substring evidence |
| Top values cap | 10 | per-key sample size |

These are intentionally hardcoded for v1. Promote to input fields when we observe a real need.

---

## Edge cases

| Scenario | Result |
|---|---|
| Empty input | All counts 0, all lists `[]` or `null`. `lowTagSubgraph.nodes` is an empty array. |
| Entity with multiple values for the same key | Each value counts in `topValues`, but the entity itself is counted once in coverage. |
| Tag with empty key | Skipped entirely. |
| Tag with empty value | Counted in coverage + context distribution, but excluded from `distinctValues` / `topValues`. |
| Auto-tag rule with empty `value.name` | Skipped — not mapped to any key. |
| Similarity edge between case-equivalent and typo-detected keys | All connected variants land in one cluster (union-find). |
| `graphMode: "full"` on a 5000-node tenant | Output can be 5–10 MB. Use `"low_tag_only"` or `"none"` if response size matters. |

---

## What this analyzer doesn't do

- Doesn't propose a strategy — that's the AI's job.
- Doesn't extract candidate values from properties — that's `tags.signal_extraction`.
- Doesn't simulate coverage of a proposed strategy — that's `tags.strategy_coverage`.
- Doesn't fetch from Dynatrace — the MCP / consumer fetches.

---

## Test fixtures

| Scenario | Coverage |
|---|---|
| `empty` | zero state — all counts 0, empty lists/maps |
| `multi-key-multi-type` | mixed: HOST has team+env, PG has manual team, SERVICE has team — exercises per-type coverage, sourcing rules, low-tag entities |
| `with-typo-keys` | env / envv / environment — cluster detection (substring + Levenshtein + case_only) |
| `with-value-drift` | team values include `foo`/`Foo`/`FOO` + `foo-team`/`foo_team` — case_drift AND separator_drift detected |

Walk testdata/snapshot/ to add new scenarios; the test loop picks them up automatically.
