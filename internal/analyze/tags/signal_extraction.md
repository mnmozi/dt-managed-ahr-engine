# Analyzer: `tags.signal_extraction`

Round 2a of the tag-strategy loop. For specific entities + target tag keys, extract candidate values from BOTH the entity's properties AND its graph neighbors (containment parents, descendants, siblings, call-graph neighbors). Returns ranked candidates with deterministic confidence + consensus picks when multiple sources agree.

**The AI doesn't walk the tree** — this analyzer does it on the AI's behalf and hands back structured per-entity candidates.

**Scope rule:** no I/O. Pure function.

---

## When to use it

After `tags.snapshot`, when the AI has decided on target keys (e.g. `["team","env","project"]`) and wants to know which entities can be tagged + what value to use.

---

## Input

```json
{
  "hosts": [...], "processGroups": [...], "processGroupInstances": [...], "services": [...],
  "entitiesToProcess": [{ "id": "HOST-A" }],
  "targetKeys": ["team", "project"],
  "existingTagValues": { "team": ["foo","bar"] },
  "ownershipTeams": ["foo","bar","baz"],
  "callGraphMajorityThreshold": 0.66,
  "consensusMinConfidence": 0.70,
  "consensusMinSources": 2
}
```

| Field | Default | Purpose |
|---|---|---|
| `targetKeys` | (required) | Tag keys to find candidate values for. |
| `entitiesToProcess` | (all) | Limit which entities to process. Pass `[{id:"X"}]` for one; omit for all. |
| `existingTagValues` | `{}` | Values already present on other entities. Used for confidence boost when a candidate value matches. |
| `ownershipTeams` | `[]` | Team names from `builtin:ownership.teams`. Big confidence boost when a candidate matches. |
| `callGraphMajorityThreshold` | 0.66 | Fraction of neighbors needed for "majority" signal. |
| `consensusMinConfidence` | 0.70 | Minimum confidence for a value to be picked as consensus. |
| `consensusMinSources` | 2 | Minimum distinct sources required for consensus. |

---

## Output

```json
{
  "entities": [
    {
      "entityId": "SVC-UNTAGGED",
      "type": "SERVICE",
      "candidates": {
        "team": [
          { "source": "graph:siblingMajority", "value": "payments", "confidence": 0.90,
            "factors": ["sibling-majority","existing-tag-value-match","ownership-directory-match","multi-source-corroboration:2"] },
          { "source": "graph:callGraphMajority", "value": "payments", "confidence": 0.85,
            "factors": ["call-graph-majority","existing-tag-value-match","ownership-directory-match","multi-source-corroboration:2"] }
        ]
      },
      "consensus": {
        "team": {
          "value": "payments",
          "confidence": 0.90,
          "sourceCount": 2,
          "contributingSources": ["graph:callGraphMajority","graph:siblingMajority"]
        }
      }
    }
  ],
  "summary": {
    "processedEntities": 1,
    "entitiesWithCandidates": 1,
    "entitiesWithConsensus": 1,
    "entitiesWithNoCandidates": 0,
    "consensusCountByKey": { "team": 1 }
  },
  "appliedDefaults": { ... }
}
```

---

## Signal sources

Each candidate's `source` field uses one of these prefixes:

| Source | Where it comes from |
|---|---|
| `property:<field>` | Top-level property field whose normalized name matches the target key (e.g. `envVars` → walks the map) |
| `property:<field>:<subkey>` | Nested map field — value of subkey when its normalized form matches the target key |
| `graph:parentTag:<type>:<id>` | Tag with target key on a containment parent (HOST → PG, PG → PGI, PGI → SERVICE direction) |
| `graph:descendantMajority` | Majority value across containment descendants (above majority threshold) |
| `graph:siblingMajority` | Majority value across siblings (entities sharing a containment parent) |
| `graph:callGraphMajority` | Majority value across call-graph neighbors |

The properties-extraction walker handles:
- Plain string fields whose name contains the target key
- Map fields (envVars, k8sLabels, metadata) — sub-keys checked the same way
- `{key, value}` arrays (awsTags, azureTags) — `value` returned when `key` matches

---

## Confidence scoring

Base scores by source type:

| Source | Base |
|---|---|
| `property` with direct field-name match (e.g. env var named exactly `team`) | 0.60 |
| `property` with contains-match (env var `OWNING_TEAM` for key `team`) | 0.50 |
| `graph:parentTag` | 0.55 |
| `graph:descendantMajority` | 0.45 |
| `graph:siblingMajority` | 0.40 |
| `graph:callGraphMajority` | 0.35 |

Bonuses (additive):

| Bonus | Amount |
|---|---|
| Value exists exactly in `existingTagValues[key]` | +0.20 |
| Value normalize-matches an existing value (case/sep drift) | +0.10 |
| Value exists in `ownershipTeams` directory | +0.20 |
| Value normalize-matches the directory | +0.10 |
| Multi-source corroboration (per additional source) | +0.10, capped at +0.30 |

Confidence is capped at 1.00.

---

## Consensus rule

For each entity + target key, pick the consensus pick when ALL hold:

1. The top-ranked candidate (highest confidence) is at or above `consensusMinConfidence`.
2. That value appears in ≥ `consensusMinSources` distinct sources.

If neither holds, no consensus is emitted (the AI sees the ranked candidates and decides).

---

## Algorithm

```
For each entity in entitiesToProcess (or all):
  Skip if entity already has the target key — no extraction needed.
  For each target key:
    1. Collect from properties (own + nested + tag arrays).
    2. Collect from containment parents (direct tag values for the key).
    3. Collect descendant majority value (if ≥ threshold).
    4. Collect sibling majority value (if ≥ threshold).
    5. Collect call-graph neighbor majority value (if ≥ threshold).
    6. Apply bonuses (existing value, ownership directory, multi-source).
    7. Sort by confidence desc; cap at 1.00.
  Compute consensus per key.

Stable sort entities by entityId.
```

---

## Edge cases

| Scenario | Result |
|---|---|
| Entity already has target key | Skipped — no candidates returned for that key. |
| No properties + no tagged neighbors | Empty `candidates[key]`; entity counted in `entitiesWithNoCandidates`. |
| Property field name contains the target key as substring (e.g. `metadata.team-pref`) | Match emits `property-contains-match` factor with base 0.50. |
| Multiple property fields point to different values | Each is its own candidate; no automatic merge. Multi-source corroboration only fires when the VALUE matches, not the field. |
| Sibling/descendant majority threshold not met | No candidate from that source. |
| Value in directory but with case drift | Normalize-match → +0.10 (not +0.20). |
| `nowMillis`-like time inputs | Not used here. Analyzer is fully pure without external state. |

---

## What this analyzer doesn't do

- Doesn't decide which candidate to apply — AI does.
- Doesn't generate auto-tag rule payloads — that comes after.
- Doesn't simulate coverage of a proposed strategy — that's `tags.strategy_coverage`.
- Doesn't fetch — consumer provides flat input.

---

## Test fixtures

| Scenario | Coverage |
|---|---|
| `empty` | zero state |
| `host-with-aws-tags` | property extraction from awsTags array; multi-key |
| `pgi-with-envvars` | env-var extraction with direct + contains matching |
| `service-call-graph-inheritance` | sibling-majority + call-graph-majority combining to produce consensus at 0.90 |
| `team-directory-boost` | ownership-directory match boosts confidence from 0.60 → 1.00 |
