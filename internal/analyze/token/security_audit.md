# Analyzer: `token.security_audit`

Pure-logic analyzer that classifies API tokens against common security findings (no-expiration, expired, never-used, stale-usage, high-privilege, disabled) and emits scope + owner distributions.

**Scope rule:** no I/O. The consumer fetches `/api/v2/apiTokens` and passes the list in. The analyzer additionally requires a `nowMillis` reference time so its output is deterministic across calls.

---

## When to use it

To answer:

- "Which tokens have no expiration date?"
- "Are there tokens past their expiration that are still listed?"
- "Which tokens haven't been used in 90+ days?"
- "Who owns the most write-scoped tokens?"
- "Which tokens have high-privilege scopes that haven't been used recently?"
- "How are scopes distributed across our token fleet?"

---

## Input

```json
{
  "apiTokens": [ /* /api/v2/apiTokens entries */ ],
  "nowMillis": 1715000000000,
  "staleUsageThresholdDays": 90,
  "highPrivilegeScopes": ["WriteConfig", "settings.write"]
}
```

### Required

| Field | Why |
|---|---|
| `apiTokens` | the list to classify |
| `nowMillis` | reference time for "expired" and "stale" classification. **Required** — without it the analyzer can't be a pure function. The MCP passes `Date.now()` at call time. Tests pin a fixed value. |

### Optional

| Field | Default | Notes |
|---|---|---|
| `staleUsageThresholdDays` | 90 | A token last used more than this many days ago counts as stale. |
| `highPrivilegeScopes` | `["WriteConfig", "settings.write", "tenantTokenManagement.create", "tenantTokenManagement.delete", "credentialVault.write", "TenantTokenRotationServiceAPI"]` | Scopes that mark a token as high-privilege. Override to widen / narrow the definition. |

### Token entry fields read

| Field | Type | Used for |
|---|---|---|
| `id` | string | identification + sample rows |
| `name` | string | display |
| `owner` | string | `ownerDistribution` (`"?"` if missing) |
| `enabled` | bool pointer | `disabledCount` (only when explicitly false). Pointer distinguishes "absent" from `false`. |
| `creationDate` | string ISO-8601 | computes `ageDays` for sample rows |
| `expirationDate` | string pointer | drives `noExpirationCount` (pointer-null) and `expiredCount` (date in the past relative to `nowMillis`) |
| `lastUsedDate` | string pointer | drives `neverUsedCount` (pointer-null) and `staleUsageCount` (older than threshold) |
| `scopes` | string[] | drives `scopeDistribution` + `highPrivilegeCount` |

---

## Output

```json
{
  "totalTokens": 7,
  "scopeDistribution": { "entities.read": 7, "WriteConfig": 1 },
  "ownerDistribution": { "alice@example.com": 2, "?": 0 },
  "findings": {
    "noExpirationCount": 1,    "noExpirationSample": [...],
    "expiredCount": 1,         "expiredSample": [...],
    "neverUsedCount": 1,       "neverUsedSample": [...],
    "staleUsageCount": 3,      "staleUsageSample": [...],
    "highPrivilegeCount": 1,   "highPrivilegeSample": [...],
    "disabledCount": 1
  },
  "appliedDefaults": {
    "staleUsageThresholdDays": 90,
    "highPrivilegeScopes": ["WriteConfig", "settings.write", ...],
    "nowMillis": 1715000000000
  }
}
```

### Categories — what they mean

| Category | Definition |
|---|---|
| `noExpiration` | `expirationDate` field is absent (pointer-null). |
| `expired` | `expirationDate` is set AND is in the past relative to `nowMillis`. |
| `neverUsed` | `lastUsedDate` field is absent (pointer-null). |
| `staleUsage` | `lastUsedDate` is set AND is older than `staleUsageThresholdDays` ago. |
| `highPrivilege` | At least one scope in `scopes[]` appears in the high-priv list. Counted **once per token** even if multiple high-priv scopes match. |
| `disabled` | `enabled: false` explicitly. Missing field doesn't count. |

**Important: categories overlap.** An expired token that was last used > 90 days ago appears in BOTH `expired` AND `staleUsage`. A high-priv token that hasn't been used in years counts in `highPrivilege` AND `neverUsed`/`staleUsage`. The consumer can filter / intersect as needed.

### `TokenRow` shape (samples)

Each sample (`noExpirationSample`, etc.) contains up to 50 rows with:

| Field | omitempty | Notes |
|---|---|---|
| `id`, `name`, `owner` | yes | passthrough |
| `enabled` | yes | pointer — present only if the input had it |
| `expirationDate` | yes | passthrough |
| `lastUsedDate` | yes | passthrough |
| `ageDays` | yes | days since `creationDate` (positive = past). Computed from `nowMillis`. |
| `unusedDays` | yes | days since `lastUsedDate` (positive = past). |
| `scopes` | yes | passthrough |

`ageDays` and `unusedDays` are int pointers so they're omitted (not zero) when the underlying date is missing or unparseable.

### `appliedDefaults`

Echoed in the output so the caller can audit what we classified against. Useful when the consumer wants to know whether their override took effect.

---

## Algorithm

```
1. Validate nowMillis is set (error otherwise).
2. Resolve thresholds:
     staleThreshold = input.StaleUsageThresholdDays || DefaultStaleUsageDays (90)
     highPrivSet = input.HighPrivilegeScopes ?? DefaultHighPrivScopes

Per token:
3. Increment totalTokens.
4. Per scope: scopeDistribution[scope]++.
5. ownerDistribution[owner || "?"]++.
6. Build TokenRow (ageDays + unusedDays computed against nowMillis).

7. Expiration:
     - If expirationDate is null pointer → noExpirationCount++, sample.
     - Else if (nowMillis - expirationDate) > 0 → expiredCount++, sample.

8. Usage:
     - If lastUsedDate is null pointer → neverUsedCount++, sample.
     - Else if daysFromNow(lastUsedDate) > staleThreshold → staleUsageCount++, sample.

9. High-priv: if any scope ∈ highPrivSet → highPrivilegeCount++, sample (only once per token).

10. Disabled: if enabled pointer is set AND value is false → disabledCount++.
    Disabled tokens are NOT separately sampled — just counted.

After loop: return Output with appliedDefaults echoed.
```

### Date parsing

`daysFromNow(iso, nowMillis)` tries three formats in order:

1. RFC3339 (`2026-05-06T12:34:56Z`)
2. `2006-01-02T15:04:05Z` (no fractional second)
3. `2006-01-02T15:04:05.000Z` (millisecond fractional)

Returns nil if all parses fail. The token then doesn't get classified under date-based categories (but still counts in distributions).

---

## Constants

| Name | Value | Why |
|---|---|---|
| `DefaultStaleUsageDays` | 90 | Industry-standard token-rotation cadence. |
| `DefaultHighPrivScopes` | 6 scope strings | Conservative list of write/admin scopes Dynatrace exposes. Can be widened by consumer. |
| `sampleCap` | 50 | Max samples per category. Counts are unbounded. |

---

## Edge cases

| Scenario | Result |
|---|---|
| Empty input | All counts 0, distributions `{}`, all samples `null`. `appliedDefaults` still echoed. |
| `nowMillis` missing or zero | Analyzer returns an ERROR — refuses to classify with no reference time. |
| Token with `expirationDate: ""` (empty string, not null) | Parses as invalid date → treated as if absent (no `noExpiration`, no `expired` classification). |
| Token with `lastUsedDate: "garbage"` | Date parse fails → token isn't classified under usage categories but still counts in distributions. |
| Same scope name twice in a token's `scopes[]` | Counted twice in `scopeDistribution`. (Dynatrace shouldn't emit duplicates; if it does, we trust the input.) |
| Token with multiple high-priv scopes (e.g. both `WriteConfig` AND `settings.write`) | Counted once in `highPrivilegeCount`; sample has all scopes visible. |
| Expired token that's also unused for years | Appears in BOTH `expired` AND `staleUsage` samples. |

---

## What this analyzer doesn't do

- No HTTP / no I/O — including no `time.Now()`. All time math uses `nowMillis` from input.
- No severity scoring — that's a check's job (see future `CHECK_TOKEN_NO_EXPIRATION` / `CHECK_TOKEN_EXPIRED` etc. that could consume this analyzer's output).
- No recommendations — those are check outputs.
- No deduplication of tokens — input is trusted.

---

## Relationship to existing checks

`CHECK_TOKEN_NEVER_USED` (already in the engine) produces Findings with severity for never-used tokens. This analyzer is its companion that produces the inventory + counts.

**Future extension**: add checks `CHECK_TOKEN_NO_EXPIRATION`, `CHECK_TOKEN_EXPIRED`, `CHECK_TOKEN_HIGH_PRIVILEGE` that consume this analyzer's output. They produce Findings; the analyzer produces facts.

---

## Test fixtures

| Scenario | Tokens | Coverage |
|---|---|---|
| `empty` | 0 | zero state — distributions empty, samples null, but `appliedDefaults` present |
| `mixed-states` | 7 | 1 healthy + 1 noExpiration + 1 expired + 1 neverUsed + 1 stale + 1 highPriv + 1 disabled (with overlap — expired and disabled both also count as stale) |
