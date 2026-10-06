# Analyzer: `oneagent.distribution`

Pure-logic analyzer that takes a list of OneAgent host records plus a per-OS "latest available version" lookup, and produces a comprehensive rollout-health summary.

**Scope rule (from project doctrine):** this analyzer does NO I/O. It does not call Dynatrace, does not read files, does not look up anything online. It is a pure function — the consumer (MCP, collector, etc.) is responsible for fetching the inputs and handing them in.

---

## When to use it

When you need any of:

- Counts of hosts grouped by version / autoUpdate setting / monitoring type / OS
- A faulty-version count
- An inactive count
- Per-OS "behind latest" comparison: which hosts are on outdated builds, and by how many minor versions
- Host lists grouped by monitoring type with OS attached (e.g. "show me all FULL_STACK Linux hosts and their versions")
- A clear distinction between "host is on the latest" and "we couldn't compare because we have no latest for this OS"

If you just want raw `/api/v2/oneagents` output, don't use this — just pass it through.

---

## Input

```json
{
  "hosts": [ /* array of OneAgent host objects */ ],
  "latestVersionsByOs": {
    "LINUX": "1.295.0",
    "WINDOWS_DESKTOP": "1.295.0"
  }
}
```

### `hosts[]`

Each entry mirrors the shape returned by Dynatrace's `/api/v2/oneagents` endpoint. The analyzer only reads these fields; everything else is ignored:

| Field | Type | Required | Used for |
|---|---|---|---|
| `hostInfo.hostName` | string | optional | included verbatim in `HostRow.hostName` |
| `hostInfo.entityId` | string | optional | included verbatim in `HostRow.entityId`; used as primary sort key within `hostsByMonitoringType` lists |
| `hostInfo.osType` | string | recommended | drives `osTypes` count, looked up against `latestVersionsByOs` |
| `currentVersion` | string | preferred | the version reported by the OneAgent right now |
| `installerVersion` | string | fallback | used if `currentVersion` is missing |
| `autoUpdateSetting` | string | optional | drives `autoUpdateSettings` count |
| `monitoringType` | string | optional | drives `monitoringTypes` count and the `hostsByMonitoringType` grouping |
| `faultyVersion` | bool | optional, default false | drives `faultyVersionCount`; appears on each `HostRow` |
| `active` | bool pointer | optional, default true | drives `inactiveCount`; appears on each `HostRow` |

Missing-field defaults:

- `currentVersion` and `installerVersion` both missing → version recorded as the literal string `"unknown"`. The host is included in counts but excluded from "behind latest" math.
- `autoUpdateSetting` missing → bucketed under `"UNKNOWN"`.
- `monitoringType` missing → bucketed under `"UNKNOWN"`; the host goes into `hostsByMonitoringType["UNKNOWN"]`.
- `hostInfo.osType` missing → bucketed under `"UNKNOWN"`; the host can never match anything in `latestVersionsByOs` (so it lands in `hostsWithoutOsLatestReference` if it has a version).
- `active` missing → treated as `true` (the explicit-false branch only fires when the input has `"active": false`).

### `latestVersionsByOs`

Map from OS type string (the same value seen in `hostInfo.osType`) to the version string the consumer considers "latest" for that OS.

- The consumer fetches this from `/api/v1/deployment/installer/agent/{os}/default/latest/metainfo` (with v2 fallback). The analyzer doesn't care where the values came from.
- An OS in the map but absent from any host → harmless; will appear in `latestVersionsByOs` echoed in output but won't be used.
- A host with an OS that's NOT in this map → bypasses "behind latest" math, goes into `hostsWithoutOsLatestReference` (honest failure, not silent skip).
- Empty map (or `latestVersionsByOs` omitted) → every host with a version lands in `hostsWithoutOsLatestReference`; `outdatedHostsCount` is 0.

---

## Output

```json
{
  "totalHosts": 8,
  "latestVersionsByOs": { "LINUX": "1.295.0", "WINDOWS_DESKTOP": "1.295.0" },
  "versions": { "1.295.0": 2, "1.288.0": 1, ... },
  "autoUpdateSettings": { "ENABLED": 3, "DISABLED": 5 },
  "monitoringTypes": { "FULL_STACK": 4, "INFRASTRUCTURE": 4 },
  "osTypes": { "LINUX": 5, "WINDOWS_DESKTOP": 2, "AIX_PPC": 1 },
  "faultyVersionCount": 1,
  "inactiveCount": 1,
  "hostsByMonitoringType": {
    "FULL_STACK": [HostRow, HostRow, ...],
    "INFRASTRUCTURE": [HostRow, HostRow, ...]
  },
  "outdatedHostsCount": 4,
  "outdatedHostsSample": [HostRow, HostRow, ...],
  "hostsWithoutOsLatestReference": [HostRow, ...]
}
```

### Top-level fields

| Field | Type | Semantics |
|---|---|---|
| `totalHosts` | int | Length of input `hosts[]`. Always emitted (even if zero). |
| `latestVersionsByOs` | map | Echoed from input verbatim. Lets the consumer audit what we compared against. |
| `versions` | map | Counts of hosts at each `currentVersion` (or `installerVersion` fallback, or `"unknown"`). |
| `autoUpdateSettings` | map | Counts of hosts at each `autoUpdateSetting` value. |
| `monitoringTypes` | map | Counts of hosts at each `monitoringType` value. |
| `osTypes` | map | Counts of hosts at each `hostInfo.osType` value. |
| `faultyVersionCount` | int | Count of hosts with `faultyVersion: true`. |
| `inactiveCount` | int | Count of hosts with `active: false` explicitly (defaults treated as active). |
| `hostsByMonitoringType` | map | Every host grouped by `monitoringType`. **No size cap.** Sorted within each group by `entityId` then `hostName`. |
| `outdatedHostsCount` | int | Total count of hosts whose version is ≥ 5 minor versions behind their OS's latest. Hosts without an OS latest reference are NOT counted. |
| `outdatedHostsSample` | array | First 20 outdated hosts (insertion order from the input, not sorted). Same `HostRow` shape as `hostsByMonitoringType` entries. |
| `hostsWithoutOsLatestReference` | array | Hosts with a known version but no entry in `latestVersionsByOs` for their OS. Surfaces the "we couldn't compare" case honestly. |

### `HostRow` shape

Used identically in `hostsByMonitoringType`, `outdatedHostsSample`, and `hostsWithoutOsLatestReference`.

| Field | Type | omitempty | Meaning |
|---|---|---|---|
| `hostName` | string | yes | from `hostInfo.hostName` |
| `entityId` | string | yes | from `hostInfo.entityId` |
| `osType` | string | yes | from `hostInfo.osType`, defaulted to `"UNKNOWN"` |
| `version` | string | yes | `currentVersion` ?? `installerVersion` ?? `"unknown"` |
| `latestForOs` | string | yes | the latest version we compared this host against; empty when its OS isn't in `latestVersionsByOs` |
| `minorBehind` | int | **NO** (always emitted) | how many minor versions behind `latestForOs`. 0 when on latest. Negative when AHEAD of latest. Always 0 when `latestForOs` is empty. |
| `autoUpdateSetting` | string | yes | from input |
| `faultyVersion` | bool | **NO** (always emitted) | from input; default false |
| `active` | bool | **NO** (always emitted) | from input; default true |

**Why `minorBehind`, `faultyVersion`, `active` are NOT omitempty:** these are facts the consumer needs to read explicitly. A missing `active` field is ambiguous (is the host up? is the data missing?), so we always emit it. Same logic for `faultyVersion` (false is the common, meaningful case) and `minorBehind` (0 means on latest, which is different from "we don't know").

---

## Algorithm

```
1. Initialize all maps + arrays empty. Copy latestVersionsByOs into output.

2. For each host in input.hosts:

   a. Increment totalHosts.

   b. Determine version: currentVersion || installerVersion || "unknown".
      Increment versions[version].

   c. Determine autoUpdate: autoUpdateSetting || "UNKNOWN".
      Increment autoUpdateSettings[autoUpdate].

   d. Determine monitoring type: monitoringType || "UNKNOWN".
      Increment monitoringTypes[monitoring].

   e. Determine OS: hostInfo.osType || "UNKNOWN".
      Increment osTypes[os].

   f. If faultyVersion → faultyVersionCount++.

   g. If active explicitly false → inactiveCount++.

   h. Build HostRow for this host (with all fields populated).
      Append to hostsByMonitoringType[monitoring].

   i. "Behind latest" classification:
      - If latestVersionsByOs[os] exists AND version != "unknown":
          minorBehind = compareLatest(latest, version)
          If minorBehind >= 5 → outdatedHostsCount++
            and append HostRow to outdatedHostsSample
            (up to 20 entries; ignored after that).
      - If latestVersionsByOs[os] missing AND version != "unknown":
          Append HostRow to hostsWithoutOsLatestReference.
      - If version == "unknown": skip "behind latest" entirely.

3. Sort each hostsByMonitoringType[k] in place by entityId, then hostName.

4. Return Output.
```

### Version comparison: `minorBehind(latest, current)`

Returns how many "minor" version steps `current` is behind `latest`. Returns 0 when equal, negative when current is ahead.

Formula: `(latest.major - current.major) * 1000 + (latest.minor - current.minor)`

Examples (latest = 1.295.0):

| current | minorBehind | Outdated (≥5)? |
|---|---|---|
| 1.295.0 | 0 | no |
| 1.294.0 | 1 | no |
| 1.290.0 | 5 | yes |
| 1.280.0 | 15 | yes |
| 1.250.0 | 45 | yes |
| 2.001.0 | -706 | no (ahead) |
| 1.296.0 | -1 | no (ahead) |

The `*1000` magnitude on major means any major-version difference dominates, even if minor numbers happen to overlap. Matches the legacy TS behavior we inherited.

### Version parsing: `parseVersion("1.295.123-build")`

Splits on any non-digit, returns the list of integers seen.

| Input | Parsed |
|---|---|
| `"1.295.0"` | `[1, 295, 0]` |
| `"1.295"` | `[1, 295]` |
| `"1.295.123-build42"` | `[1, 295, 123, 42]` |
| `""` | `[]` |
| `"v1.295.0"` | `[1, 295, 0]` |
| `"latest"` | `[]` |

The first two elements are used for `minorBehind`; anything after is ignored. Indices that don't exist read as 0.

---

## Constants

| Name | Value | Why |
|---|---|---|
| `outdatedThresholdMinor` | 5 | A host ≥ 5 minor versions behind is flagged as outdated. Matches the legacy TS heuristic. Hardcoded for now — promote to an input field if/when we want this configurable. |
| `outdatedSampleCap` | 20 | `outdatedHostsSample` size cap. The full list is in `hostsByMonitoringType` if you need everyone; this sample is a quick UI display thing. |

---

## Edge cases (deliberate behavior)

| Scenario | Result |
|---|---|
| Empty input.hosts | Every count is 0; all map fields are empty `{}`; arrays are `null` (Go's nil-slice marshals as null). |
| Empty input.latestVersionsByOs | Every host with a version lands in `hostsWithoutOsLatestReference`; `outdatedHostsCount` is 0. |
| Host with no `currentVersion` AND no `installerVersion` | Version is `"unknown"`, not skipped from counts; excluded from "behind latest" math (neither outdated nor in hostsWithoutOsLatestReference). |
| Host with version but `osType` missing | Bucketed as `osType: "UNKNOWN"`; goes into `hostsWithoutOsLatestReference` because the map almost certainly doesn't have `"UNKNOWN"`. |
| Host with `osType` not in `latestVersionsByOs` | Goes into `hostsWithoutOsLatestReference`. Not silently ignored. |
| Host with version AHEAD of latest (negative minorBehind) | Counts/groupings still happen; not flagged as outdated. The negative `minorBehind` shows up on the HostRow so it's auditable. |
| Same host appears twice in input | Counted twice. The analyzer trusts the consumer's deduplication. |

---

## What this analyzer doesn't do (kept honest)

- **No HTTP calls.** The consumer fetches both `/api/v2/oneagents` and the per-OS latest endpoints.
- **No I/O of any kind.** Pure function.
- **No sorting beyond `hostsByMonitoringType` group-internal stable sort.** Consumers presenting findings should sort the way they want.
- **No filtering by user-supplied predicate.** Always processes every input host.
- **No retry / fallback logic on the "latest" source.** That's a consumer concern (the MCP does v1 → v2 fallback per OS).
- **No threshold configurability.** `outdatedThresholdMinor` is currently a constant.

---

## Test fixtures

Under `testdata/`:

| Scenario | Hosts | Latest map | Tests |
|---|---|---|---|
| `empty` | 0 | `{}` | All zero counts, null arrays, empty maps. |
| `single-host` | 1 (LINUX, on latest) | `{LINUX: 1.295.0}` | Basic happy path with one host. |
| `all-on-latest` | 3 (LINUX × 2, WIN × 1) | `{LINUX, WIN}` | Multi-OS, no outdated, no failures. |
| `happy-mixed-versions` | 8 (LINUX, WIN, AIX) | `{LINUX, WIN}` | Full coverage: outdated, faulty, inactive, AIX with no latest reference, mixed monitoring types, sample cap, etc. |

`distribution_test.go` walks `testdata/`, runs the analyzer on each scenario's `input.json`, compares against `output.json` via deep equality after JSON round-trip.

Add a scenario: create a directory under `testdata/` with both files; the test picks it up automatically.
