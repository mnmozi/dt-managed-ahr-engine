package graph

// walk.go — traversal helpers for the entity graph.
//
// All helpers return slices of *Node in deterministic order (insertion
// order, which is itself stable because Build creates nodes in input
// order and we never sort containment lists after they're built).

// Ancestors returns all containment ancestors of n, walking parent pointers
// transitively. The returned slice does not include n itself.
//
// For a PROCESS_GROUP_INSTANCE: returns [PROCESS_GROUP, HOST].
// For a SERVICE: returns [PROCESS_GROUP_INSTANCE..., PROCESS_GROUP..., HOST...].
//
// A node can have multiple ancestor paths (e.g. SERVICE backed by 3 PGIs
// has 3 PGI parents, each with its own host). All distinct ancestors are
// returned. The slice is deduplicated by *Node pointer.
func Ancestors(n *Node) []*Node {
	if n == nil {
		return nil
	}
	seen := make(map[*Node]bool)
	var out []*Node
	var walk func(x *Node)
	walk = func(x *Node) {
		for _, p := range x.ContainmentParents {
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
			walk(p)
		}
	}
	walk(n)
	return out
}

// Descendants returns all containment descendants of n. Same shape as
// Ancestors but going down.
//
// For a HOST: returns [PROCESS_GROUP..., PROCESS_GROUP_INSTANCE...,
// SERVICE backed by those PGIs].
func Descendants(n *Node) []*Node {
	if n == nil {
		return nil
	}
	seen := make(map[*Node]bool)
	var out []*Node
	var walk func(x *Node)
	walk = func(x *Node) {
		for _, c := range x.ContainmentChildren {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
			walk(c)
		}
	}
	walk(n)
	return out
}

// Siblings returns nodes that share at least one containment parent with n
// (and are not n itself). A node with multiple parents has the union of
// each parent's children as siblings.
//
// For a PROCESS_GROUP_INSTANCE under a given PROCESS_GROUP: siblings are
// other PGIs of the same PROCESS_GROUP (i.e. other instances of the same
// process).
func Siblings(n *Node) []*Node {
	if n == nil {
		return nil
	}
	seen := make(map[*Node]bool)
	seen[n] = true
	var out []*Node
	for _, p := range n.ContainmentParents {
		for _, c := range p.ContainmentChildren {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// CallNeighbors returns the union of {CallsFrom} ∪ {CallsTo} for n,
// deduplicated. Order: callers first (CallsFrom), then callees (CallsTo).
func CallNeighbors(n *Node) []*Node {
	if n == nil {
		return nil
	}
	seen := make(map[*Node]bool)
	out := make([]*Node, 0, len(n.CallsFrom)+len(n.CallsTo))
	for _, x := range n.CallsFrom {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	for _, x := range n.CallsTo {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// FilterByType returns the subset of nodes whose Type matches t.
func FilterByType(nodes []*Node, t EntityType) []*Node {
	out := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Type == t {
			out = append(out, n)
		}
	}
	return out
}

// TagValueDistribution counts the distinct values for `key` across `nodes`.
// Returns a map value → count. Empty value strings are skipped.
//
// Useful for the "what does the majority of my neighbors / siblings /
// descendants say for this key?" question.
func TagValueDistribution(nodes []*Node, key string) map[string]int {
	out := make(map[string]int)
	for _, n := range nodes {
		for _, t := range n.Tags {
			if t.Key == key && t.Value != "" {
				out[t.Value]++
			}
		}
	}
	return out
}

// MajorityValue returns (value, count, total, ok) where:
//   value is the most-frequent tag value for `key` across `nodes`,
//   count is its occurrence count,
//   total is the number of nodes that had ANY value for the key,
//   ok is true when count/total >= threshold.
//
// Threshold of 0.66 ≈ "two-thirds majority" is what tag analyzers default to.
// nodes with no value for the key don't count in total.
func MajorityValue(nodes []*Node, key string, threshold float64) (value string, count, total int, ok bool) {
	dist := TagValueDistribution(nodes, key)
	for _, c := range dist {
		total += c
	}
	if total == 0 {
		return "", 0, 0, false
	}
	for v, c := range dist {
		if c > count {
			value = v
			count = c
		}
	}
	ok = float64(count)/float64(total) >= threshold
	return
}

// LowTagFilter returns nodes whose tag count is at or below threshold.
// Useful for identifying entities that need a tagging proposal.
func LowTagFilter(nodes []*Node, threshold int) []*Node {
	out := make([]*Node, 0)
	for _, n := range nodes {
		if len(n.Tags) <= threshold {
			out = append(out, n)
		}
	}
	return out
}
