// Package stats provides shared statistical / string helpers used by
// analyzers. Zero external dependencies — keep it that way.
//
// similarity.go: string comparison helpers for tag key/value analysis.
//
// We provide a small, focused set:
//   - Levenshtein distance (edit distance)
//   - NormalizedEqual (lowercase + strip non-alnum)
//   - TokenSplit (split on common separators)
//
// We deliberately do NOT include Jaro-Winkler / Soundex / Hamming etc. —
// the analyzers we have don't need them, and adding them would invite scope
// creep. If a future analyzer needs them, add then.
package stats

import "strings"

// Levenshtein returns the minimum number of single-character edits
// (insertions, deletions, or substitutions) needed to transform a into b.
//
// O(len(a) * len(b)) time, O(min(len(a), len(b))) space.
//
// Used by analyzers to detect typo-like key variants (env / envv).
func Levenshtein(a, b string) int {
	// Ensure b is the shorter — minimizes the work-row allocation.
	if len(a) < len(b) {
		a, b = b, a
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,        // deletion
				curr[j-1]+1,      // insertion
				prev[j-1]+cost,   // substitution
			)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// NormalizedEqual reports whether two strings are equal after normalization:
// lowercase + strip all non-alphanumeric characters.
//
// Used to detect "same value, different shape": env vs Env vs ENV;
// app-name vs app_name vs app.name.
func NormalizedEqual(a, b string) bool {
	return Normalize(a) == Normalize(b)
}

// Normalize lowercases s and strips non-alphanumeric characters.
// Returns the normalized form.
func Normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			// drop
		}
	}
	return b.String()
}

// TokenSplit splits s on common separators (`-`, `_`, `.`, ` `, `/`) and
// returns lowercased non-empty tokens. Used to compare structural variants
// of the same name (e.g. `prod-web-01` → ["prod","web","01"]).
func TokenSplit(s string) []string {
	out := make([]string, 0, 4)
	cur := make([]byte, 0, len(s))
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == '_' || c == '.' || c == ' ' || c == '/':
			flush()
		case c >= 'A' && c <= 'Z':
			cur = append(cur, c+32)
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return out
}

// LikelyTypo reports whether two keys look like typo variants of each other.
//
// Rule: Levenshtein distance ≤ 2 AND the lengths differ by no more than 30%
// of the longer length. The length check filters out tiny strings whose
// edit-distance can legitimately be 1–2 without being typos
// (e.g. `id` vs `xy`).
//
// Inputs are compared after normalization (so case + separators don't
// inflate the distance).
func LikelyTypo(a, b string) bool {
	na, nb := Normalize(a), Normalize(b)
	if na == nb {
		// Same after normalization — that's case/separator drift, not typo
		// (handled by a different rule).
		return false
	}
	if len(na) < 2 || len(nb) < 2 {
		return false
	}
	d := Levenshtein(na, nb)
	if d > 2 {
		return false
	}
	longer := len(na)
	if len(nb) > longer {
		longer = len(nb)
	}
	shorter := len(na)
	if len(nb) < shorter {
		shorter = len(nb)
	}
	if float64(longer-shorter)/float64(longer) > 0.30 {
		return false
	}
	return true
}

// SubstringContainment reports whether one normalized key is a clean
// substring of another (e.g. `env` ⊂ `environment`). Returns the containment
// ratio (len(short) / len(long)) if true, else 0.
//
// Useful for spotting "expansion variants" — `env` and `environment` are
// likely the same intent at different abbreviation levels.
func SubstringContainment(a, b string) float64 {
	na, nb := Normalize(a), Normalize(b)
	if na == nb {
		return 0
	}
	short, long := na, nb
	if len(nb) < len(na) {
		short, long = nb, na
	}
	if len(short) < 2 {
		return 0
	}
	if !strings.Contains(long, short) {
		return 0
	}
	return float64(len(short)) / float64(len(long))
}
