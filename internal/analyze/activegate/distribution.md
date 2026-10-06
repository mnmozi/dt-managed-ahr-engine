# Analyzer: `activegate.distribution`

Pure-logic analyzer that takes a list of ActiveGate records plus a per-OS "latest available" version lookup, and produces a comprehensive AG fleet analysis covering versions, capabilities, network zones, and outdatedness.

**Scope rule (from project doctrine):** no I/O. The consumer (MCP, collector) is responsible for fetching `/api/v2/activeGates` AND the per-OS latest version map; this analyzer just computes.

---

## When to use it

When you need to answer any of:

- "Which AGs collect K8s telemetry?" → `activeGatesByCapability.KUBERNETES`
- "Which network zone has no extension collector?" → `networkZones` minus `byCapability.EXTENSION_CONTROLLER` zones
- "Which AGs are outdated AND in prod?" → filter `outdatedActiveGatesSample` by `networkZone`
- "Are there single-points-of-failure in any capability?" → `byCapability` values equal to 1
- "Misconfigured beacon forwarders?" → `misconfiguredByCapability.BEACON_FORWARDER`
- "What's the version spread on Linux AGs?" → `versions` filtered by `osTypes`

---

## Input

```json
{
  "activeGates": [ /* /api/v2/activeGates entries */ ],
  "latestVersionsByOs": { "LINUX": "1.295.0", "WINDOWS": "1.295.0" }
}
```

### `activeGates[]` — relevant fields

| Field | Type | Used for |
|---|---|---|
| `id` | string | `AGRow.id`; primary sort key within group lists |
| `hostname` | string | display + secondary sort |
| `networkAddresses` | string[] | passed through to AGRow |
| `osType` | string | `osTypes` count; matches against `latestVersionsByOs` |
| `version` | string | `versions` count; input to `minorBehind` |
| `type` | string | `types` count + `activeGatesByType` grouping (ENVIRONMENT / CLUSTER / ENVIRONMENT_MULTI / UNKNOWN) |
| `autoUpdateSettings.effectiveSetting` | string | preferred for `autoUpdateSettings` count |
| `autoUpdateStatus` | string | fallback when `autoUpdateSettings` missing |
| `connectionStatus` | string | `connectionStatuses` count; drives `notConnectedCount` for anything other than ONLINE or UNKNOWN |
| `lastConnectedTime` | string | passed through to AGRow |
| `modules[]` | array | each `{type, enabled, misconfigured}` — drives capability map AND misconfigured detection |
| `enabledModules[]` | string[] | fallback for capability list when `modules[]` is missing/empty |
| `networkZone` | string | network zone grouping. **Checked at top level first**, then `properties.networkZone` |
| `properties.networkZone` | string | alternate location some Managed versions use |

Missing-field defaults: same convention as OneAgent — missing values bucket as `"UNKNOWN"`, missing version as `"unknown"`, missing networkZone routes the AG into `activeGatesWithoutNetworkZone`.

### `latestVersionsByOs`

Map keyed by OS type (case-tolerant — analyzer also matches case-insensitively as a fallback). Consumer fetches this from `/api/v1/deployment/installer/gateway/{os}/default/latest/metainfo` (v1) with `/api/v1/deployment/installer/gateway/versions/{os}` as fallback.

---

## Output

Top-level fields:

| Field | Type | Semantics |
|---|---|---|
| `totalActiveGates` | int | length of input |
| `latestVersionsByOs` | map | echoed from input — auditable |
| `versions` | map | counts per `version` value |
| `types` | map | counts per `type` value |
| `autoUpdateSettings` | map | counts per effective autoUpdate setting |
| `connectionStatuses` | map | counts per `connectionStatus` |
| `osTypes` | map | counts per `osType` |
| `notConnectedCount` | int | AGs with `connectionStatus` ≠ ONLINE AND ≠ UNKNOWN |
| `misconfiguredModuleCount` | int | AGs with at least one module flagged `misconfigured: true` |
| `byCapability` | map | counts per module type (capability name → AG count). E.g. `{"METRIC_API": 4, "KUBERNETES": 1}` |
| `activeGatesByCapability` | map | full list of AGs per capability (uncapped). Each AG appears under every capability it provides. |
| `misconfiguredByCapability` | map | AGs that have a capability AND that capability is misconfigured on them |
| `networkZones` | map | counts per zone |
| `activeGatesByNetworkZone` | map | full list of AGs per zone |
| `activeGatesWithoutNetworkZone` | array | AGs missing the zone field entirely |
| `activeGatesByType` | map | full list of AGs per type |
| `outdatedActiveGatesCount` | int | AGs ≥ 5 minor versions behind their OS's latest |
| `outdatedActiveGatesSample` | array | first 20 outdated AGs |
| `activeGatesWithoutOsLatestReference` | array | AGs with a version but no entry for their OS in `latestVersionsByOs` |

### `AGRow` shape

Used identically in all list fields:

| Field | omitempty | Notes |
|---|---|---|
| `id` | yes | |
| `hostname` | yes | |
| `networkAddresses` | yes | |
| `osType` | yes | defaulted to `"UNKNOWN"` if missing on input |
| `version` | yes | `"unknown"` if missing on input |
| `latestForOs` | yes | empty when no latest known for this OS |
| `minorBehind` | **NO** | 0 means "on latest" or "no latest known"; always emitted |
| `type` | yes | defaulted to `"UNKNOWN"` |
| `autoUpdateSetting` | yes | resolved from settings → status fallback |
| `connectionStatus` | yes | defaulted to `"UNKNOWN"` |
| `networkZone` | yes | empty when not resolved |
| `enabledModules` | yes | module names that are enabled (from `modules[]` where `enabled: true`, OR `enabledModules[]` fallback) |
| `misconfiguredModules` | yes | module names flagged misconfigured |
| `lastConnectedTime` | yes | |

---

## Algorithm

```
Per AG:
1. Increment totalActiveGates.
2. Bucket version / type / autoUpdate / connection / OS counts.
3. Determine connection: if non-ONLINE and non-UNKNOWN → notConnectedCount++.
4. Resolve networkZone: top-level → properties.networkZone → "".
5. Resolve capabilities:
     - Prefer modules[] with enabled:true
     - Misconfigured modules → misconfiguredCaps[]
     - If modules[] empty/missing → fall back to enabledModules[]
6. If any misconfigured cap → misconfiguredModuleCount++.
7. Build AGRow.
8. If version known AND OS has latest reference:
     - row.latestForOs + row.minorBehind set
     - if minorBehind >= 5 → outdatedCount++; append to sample (cap 20)
   Else if version known AND OS has no latest reference:
     - append to activeGatesWithoutOsLatestReference
9. Group by type → activeGatesByType.
10. Group by zone (or activeGatesWithoutNetworkZone).
11. Group by each capability → activeGatesByCapability + byCapability count.
12. Group by each misconfigured cap → misconfiguredByCapability.

After loop:
- Sort all group lists by id then hostname.
- Echo latestVersionsByOs in output.
```

`minorBehind` uses the same formula as the OneAgent analyzer (`major * 1000 + minor`).

---

## Constants

| Name | Value | Why |
|---|---|---|
| `outdatedThresholdMinor` | 5 | AG ≥ 5 minor versions behind = outdated. Matches OneAgent threshold for consistency. |
| `outdatedSampleCap` | 20 | size cap for `outdatedActiveGatesSample`. Full list is in `activeGatesByCapability` / `activeGatesByType`. |

---

## Edge cases

| Scenario | Result |
|---|---|
| Empty `activeGates` | All counts 0, all maps `{}`, all arrays `null`. |
| AG with no `modules[]` AND no `enabledModules[]` | No capabilities listed; AG still counted in totals and groupings. |
| AG with `modules[]` containing `{type:"", enabled:true}` | Skipped (empty type name). |
| AG with networkZone present at BOTH top-level and `properties.networkZone` | Top-level wins. |
| AG with `properties` but no networkZone inside | Falls through to "no zone". |
| Same OS in `latestVersionsByOs` in different cases (`LINUX` vs `linux`) | Case-insensitive match — first key found wins; consumer should be consistent. |
| Module marked `enabled:true AND misconfigured:true` | Counted in BOTH `byCapability` (it's serving) AND `misconfiguredByCapability` (it's broken). |
| AG with `connectionStatus: "UNKNOWN"` | NOT counted as not-connected (treated as no signal). |

---

## What this analyzer doesn't do

- No HTTP / no I/O
- No fetching of the latest version (that's piping)
- No sorting outside of within-group lists (which is for determinism)
- No filtering by user-supplied predicate
- No retry on missing OS latest

---

## Test fixtures

Under `testdata/`:

| Scenario | AGs | Coverage |
|---|---|---|
| `empty` | 0 | zero state |
| `single-ag` | 1 | basic happy path, one capability per AG, one zone |
| `mixed-states` | 5 | covers outdated × misconfigured × no-zone × AIX-no-latest × enabledModules-fallback × multiple types × multiple capabilities |
