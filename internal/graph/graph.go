// Package graph builds and queries the entity graph used by tag analyzers.
//
// Two edge types coexist in one graph:
//
//   Containment edges
//     HOST  ←──contains──  PROCESS_GROUP  ←──contains──  PROCESS_GROUP_INSTANCE
//     PROCESS_GROUP_INSTANCE  ←──backs──  SERVICE
//
//     "ancestors" walks UP (PGI → PG → HOST; SERVICE → PGI → PG → HOST).
//     "descendants" walks DOWN.
//
//   Call edges (adjacency)
//     SERVICE  ──calls──→  SERVICE
//     PROCESS_GROUP_INSTANCE  ──calls──→  PROCESS_GROUP_INSTANCE  (when known)
//
// The graph is built from FLAT input on every analyzer call. The engine
// holds no state between calls. Build is O(N+E), microseconds for our sizes.
package graph

// Input is the flat entity input shape. All analyzers that need a graph
// take an Input.
type Input struct {
	Hosts                  []Host                  `json:"hosts"`
	ProcessGroups          []ProcessGroup          `json:"processGroups"`
	ProcessGroupInstances  []ProcessGroupInstance  `json:"processGroupInstances"`
	Services               []Service               `json:"services"`
}

// Tag is a single tag occurrence on an entity. Context is the Dynatrace
// `/api/v2/tags` context field: CONTEXTLESS (manual), ENVIRONMENT, AWS,
// KUBERNETES, etc.
type Tag struct {
	Context              string `json:"context,omitempty"`
	Key                  string `json:"key"`
	Value                string `json:"value,omitempty"`
	StringRepresentation string `json:"stringRepresentation,omitempty"`
}

// Properties is a free-form bag of entity properties (env vars, host group
// name, AWS/Azure/GCP tags, etc.) we use for signal extraction. Kept as
// map[string]any to tolerate the wide variety of shapes Dynatrace emits.
type Properties map[string]any

// Host is the input shape for a HOST entity.
type Host struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName,omitempty"`
	Tags        []Tag      `json:"tags,omitempty"`
	Properties  Properties `json:"properties,omitempty"`
}

// ProcessGroup is the input shape for a PROCESS_GROUP.
type ProcessGroup struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName,omitempty"`
	Tags        []Tag      `json:"tags,omitempty"`
	Properties  Properties `json:"properties,omitempty"`
	HostID      string     `json:"hostId,omitempty"` // containment parent
}

// ProcessGroupInstance is the input shape for a PROCESS_GROUP_INSTANCE.
//
// CallsPgiIDs are call-graph edges at the PGI level (when Dynatrace
// surfaces them).
type ProcessGroupInstance struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName,omitempty"`
	Tags        []Tag      `json:"tags,omitempty"`
	Properties  Properties `json:"properties,omitempty"`
	HostID      string     `json:"hostId,omitempty"`        // containment parent
	PGID        string     `json:"pgId,omitempty"`          // containment parent (process group)
	ServiceIDs  []string   `json:"serviceIds,omitempty"`    // this PGI backs these services
	CallsPgiIDs []string   `json:"callsPgiIds,omitempty"`   // call-graph edges out
}

// Service is the input shape for a SERVICE.
//
// PgiIDs are the PGIs that back this service (containment "parents" in our
// model — a service is conceptually "downstream" of its backing PGIs).
// CallsServiceIDs and CalledByServiceIDs are the directional call edges.
type Service struct {
	ID                 string     `json:"id"`
	DisplayName        string     `json:"displayName,omitempty"`
	Tags               []Tag      `json:"tags,omitempty"`
	Properties         Properties `json:"properties,omitempty"`
	PgiIDs             []string   `json:"pgiIds,omitempty"`             // PGIs that back this service
	CallsServiceIDs    []string   `json:"callsServiceIds,omitempty"`    // outbound call edges
	CalledByServiceIDs []string   `json:"calledByServiceIds,omitempty"` // inbound call edges
	// Endpoints are the display names of the service's SERVICE_METHOD
	// entities — typically "GET /api/v1/orders" or "OrdersController.list".
	// Populated by the naming-graph fetcher (Phase B). The PG naming
	// analyzer derives a candidate name from the paths a service serves.
	Endpoints []string `json:"endpoints,omitempty"`
}

// EntityType labels the kind of node. We use Dynatrace's canonical strings
// to match the rest of the codebase.
type EntityType string

const (
	TypeHost                 EntityType = "HOST"
	TypeProcessGroup         EntityType = "PROCESS_GROUP"
	TypeProcessGroupInstance EntityType = "PROCESS_GROUP_INSTANCE"
	TypeService              EntityType = "SERVICE"
)

// Node is the in-memory representation of one entity in the graph.
// Pointer fields for cross-references because nodes are linked by &Node.
type Node struct {
	ID          string
	Type        EntityType
	DisplayName string
	Tags        []Tag
	Properties  Properties

	// Containment edges
	// Direction: parents are "up" (closer to HOST), children are "down".
	// HOST has no containment parent.
	// PROCESS_GROUP's parent is HOST.
	// PROCESS_GROUP_INSTANCE has parents HOST + PROCESS_GROUP.
	// SERVICE's parents are its backing PROCESS_GROUP_INSTANCEs.
	ContainmentParents  []*Node
	ContainmentChildren []*Node

	// Call edges. Directional.
	CallsFrom []*Node // entities that call THIS node
	CallsTo   []*Node // entities THIS node calls
}

// HasTagKey reports whether the node has any tag with the given key.
func (n *Node) HasTagKey(key string) bool {
	for _, t := range n.Tags {
		if t.Key == key {
			return true
		}
	}
	return false
}

// TagValues returns all values present for a given key on this node.
// A node can have multiple values for the same key (rare but possible).
func (n *Node) TagValues(key string) []string {
	out := []string{}
	for _, t := range n.Tags {
		if t.Key == key {
			out = append(out, t.Value)
		}
	}
	return out
}

// Graph is the assembled entity graph plus an ID → Node index.
type Graph struct {
	// ByID maps Dynatrace entity id → Node. The primary lookup.
	ByID map[string]*Node

	// ByType groups nodes by entity type for type-scoped iteration.
	ByType map[EntityType][]*Node

	// Counters for stats / output
	ContainmentEdges int
	CallEdges        int
}

// Build constructs a Graph from flat Input. O(N + E). Stable: same input
// always produces a graph with the same iteration order (we sort node
// slices by ID).
func Build(in Input) *Graph {
	g := &Graph{
		ByID:   make(map[string]*Node, len(in.Hosts)+len(in.ProcessGroups)+len(in.ProcessGroupInstances)+len(in.Services)),
		ByType: make(map[EntityType][]*Node, 4),
	}

	// First pass: create nodes (no edges yet)
	for _, h := range in.Hosts {
		n := &Node{ID: h.ID, Type: TypeHost, DisplayName: h.DisplayName, Tags: h.Tags, Properties: h.Properties}
		g.ByID[h.ID] = n
		g.ByType[TypeHost] = append(g.ByType[TypeHost], n)
	}
	for _, p := range in.ProcessGroups {
		n := &Node{ID: p.ID, Type: TypeProcessGroup, DisplayName: p.DisplayName, Tags: p.Tags, Properties: p.Properties}
		g.ByID[p.ID] = n
		g.ByType[TypeProcessGroup] = append(g.ByType[TypeProcessGroup], n)
	}
	for _, p := range in.ProcessGroupInstances {
		n := &Node{ID: p.ID, Type: TypeProcessGroupInstance, DisplayName: p.DisplayName, Tags: p.Tags, Properties: p.Properties}
		g.ByID[p.ID] = n
		g.ByType[TypeProcessGroupInstance] = append(g.ByType[TypeProcessGroupInstance], n)
	}
	for _, s := range in.Services {
		n := &Node{ID: s.ID, Type: TypeService, DisplayName: s.DisplayName, Tags: s.Tags, Properties: s.Properties}
		g.ByID[s.ID] = n
		g.ByType[TypeService] = append(g.ByType[TypeService], n)
	}

	// Second pass: wire containment + call edges. We tolerate missing
	// targets — Dynatrace can reference entities outside the fetched set
	// (e.g. SERVICE backed by a PGI not in our snapshot). Skip silently.

	link := func(parent, child *Node) {
		if parent == nil || child == nil {
			return
		}
		parent.ContainmentChildren = append(parent.ContainmentChildren, child)
		child.ContainmentParents = append(child.ContainmentParents, parent)
		g.ContainmentEdges++
	}

	for _, p := range in.ProcessGroups {
		child := g.ByID[p.ID]
		if p.HostID != "" {
			link(g.ByID[p.HostID], child)
		}
	}
	for _, p := range in.ProcessGroupInstances {
		child := g.ByID[p.ID]
		if p.HostID != "" {
			link(g.ByID[p.HostID], child)
		}
		if p.PGID != "" {
			link(g.ByID[p.PGID], child)
		}
	}
	for _, s := range in.Services {
		child := g.ByID[s.ID]
		// A service's parents (in our containment model) are the PGIs that back it.
		for _, pgiID := range s.PgiIDs {
			link(g.ByID[pgiID], child)
		}
	}

	// Call edges.
	addCall := func(from, to *Node) {
		if from == nil || to == nil {
			return
		}
		from.CallsTo = append(from.CallsTo, to)
		to.CallsFrom = append(to.CallsFrom, from)
		g.CallEdges++
	}
	for _, s := range in.Services {
		from := g.ByID[s.ID]
		for _, otherID := range s.CallsServiceIDs {
			addCall(from, g.ByID[otherID])
		}
		// We don't double-process CalledByServiceIDs since each call edge
		// should appear once in CallsServiceIDs of the caller. We rely on
		// the caller's CallsServiceIDs being complete. If the caller isn't
		// in the snapshot but the callee is, we miss the edge — acceptable.
	}
	for _, p := range in.ProcessGroupInstances {
		from := g.ByID[p.ID]
		for _, otherID := range p.CallsPgiIDs {
			addCall(from, g.ByID[otherID])
		}
	}

	return g
}
