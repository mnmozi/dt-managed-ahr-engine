// Package activegate contains analyzers operating on /api/v2/activeGates data.
//
// distribution.go — comprehensive ActiveGate inventory analysis:
//   - per-version / per-type / per-autoUpdate / per-connection / per-OS counts
//   - capability (module) map: which AGs serve which capabilities
//   - network zone distribution
//   - per-OS "behind latest" comparison (consumer-provided latestVersionsByOs)
//   - misconfigured-module detection
//   - not-connected detection
//
// Pure logic. No I/O. The MCP consumer fetches /api/v2/activeGates and the
// per-OS latest deployment endpoint; this analyzer just computes.
package activegate

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/local/dt-managed-engine/internal/analyze"
)

func init() {
	analyze.Register(Distribution{})
}

// Distribution is the analyzer.
type Distribution struct{}

func (Distribution) Kind() string { return "activegate.distribution" }

func (Distribution) Description() string {
	return "ActiveGate inventory analysis: version / type / autoUpdate / connection / OS counts, capability map (which AGs serve which modules: KUBERNETES, EXTENSION_CONTROLLER, BEACON_FORWARDER, etc.), network zone distribution, per-OS 'behind latest' comparison, misconfigured-module detection. Pure function; consumer provides /api/v2/activeGates + per-OS latest version map."
}

// Input is the analyzer input shape.
type Input struct {
	ActiveGates        []AG              `json:"activeGates"`
	LatestVersionsByOs map[string]string `json:"latestVersionsByOs"`
}

// AG mirrors the relevant subset of /api/v2/activeGates entries.
//
// `properties` is a passthrough — some Managed versions emit `networkZone`
// at the top level, others under properties.networkZone. We read both.
type AG struct {
	ID                  string             `json:"id,omitempty"`
	Hostname            string             `json:"hostname,omitempty"`
	NetworkAddresses    []string           `json:"networkAddresses,omitempty"`
	LoadBalancerAddrs   []string           `json:"loadBalancerAddresses,omitempty"`
	OsType              string             `json:"osType,omitempty"`
	Version             string             `json:"version,omitempty"`
	Type                string             `json:"type,omitempty"`
	AutoUpdateSettings  *AutoUpdateBlock   `json:"autoUpdateSettings,omitempty"`
	AutoUpdateStatus    string             `json:"autoUpdateStatus,omitempty"`
	ConnectionStatus    string             `json:"connectionStatus,omitempty"`
	LastConnectedTime   string             `json:"lastConnectedTime,omitempty"`
	Modules             []Module           `json:"modules,omitempty"`
	EnabledModules      []string           `json:"enabledModules,omitempty"`
	NetworkZone         string             `json:"networkZone,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

// AutoUpdateBlock is the nested autoUpdateSettings block.
type AutoUpdateBlock struct {
	EffectiveSetting string `json:"effectiveSetting,omitempty"`
}

// Module is one entry in modules[].
type Module struct {
	Type          string `json:"type,omitempty"`
	Enabled       bool   `json:"enabled,omitempty"`
	Misconfigured bool   `json:"misconfigured,omitempty"`
	Version       string `json:"version,omitempty"`
}

// Output is the analyzer result.
type Output struct {
	TotalActiveGates                  int                  `json:"totalActiveGates"`
	LatestVersionsByOs                map[string]string    `json:"latestVersionsByOs"`
	Versions                          map[string]int       `json:"versions"`
	Types                             map[string]int       `json:"types"`
	AutoUpdateSettings                map[string]int       `json:"autoUpdateSettings"`
	ConnectionStatuses                map[string]int       `json:"connectionStatuses"`
	OsTypes                           map[string]int       `json:"osTypes"`
	NotConnectedCount                 int                  `json:"notConnectedCount"`
	MisconfiguredModuleCount          int                  `json:"misconfiguredModuleCount"`
	ByCapability                      map[string]int       `json:"byCapability"`
	ActiveGatesByCapability           map[string][]AGRow   `json:"activeGatesByCapability"`
	MisconfiguredByCapability         map[string][]AGRow   `json:"misconfiguredByCapability"`
	NetworkZones                      map[string]int       `json:"networkZones"`
	ActiveGatesByNetworkZone          map[string][]AGRow   `json:"activeGatesByNetworkZone"`
	ActiveGatesWithoutNetworkZone     []AGRow              `json:"activeGatesWithoutNetworkZone"`
	ActiveGatesByType                 map[string][]AGRow   `json:"activeGatesByType"`
	OutdatedActiveGatesCount          int                  `json:"outdatedActiveGatesCount"`
	OutdatedActiveGatesSample         []AGRow              `json:"outdatedActiveGatesSample"`
	ActiveGatesWithoutOsLatestRef     []AGRow              `json:"activeGatesWithoutOsLatestReference"`
}

// AGRow is the per-AG shape we emit in lists.
//
// As with HostRow on the OneAgent side, fields whose absence is meaningful
// (connectionStatus, type) use omitempty; bool fields and minorBehind are
// always emitted so consumers don't have to disambiguate "missing" from
// the zero value.
type AGRow struct {
	ID                    string   `json:"id,omitempty"`
	Hostname              string   `json:"hostname,omitempty"`
	NetworkAddresses      []string `json:"networkAddresses,omitempty"`
	OsType                string   `json:"osType,omitempty"`
	Version               string   `json:"version,omitempty"`
	LatestForOs           string   `json:"latestForOs,omitempty"`
	MinorBehind           int      `json:"minorBehind"`
	Type                  string   `json:"type,omitempty"`
	AutoUpdateSetting     string   `json:"autoUpdateSetting,omitempty"`
	ConnectionStatus      string   `json:"connectionStatus,omitempty"`
	NetworkZone           string   `json:"networkZone,omitempty"`
	EnabledModules        []string `json:"enabledModules,omitempty"`
	MisconfiguredModules  []string `json:"misconfiguredModules,omitempty"`
	LastConnectedTime     string   `json:"lastConnectedTime,omitempty"`
}

const (
	outdatedThresholdMinor = 5
	outdatedSampleCap      = 20
)

// Run is the analyzer entrypoint.
func (Distribution) Run(raw json.RawMessage) (any, error) {
	var in Input
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}

	out := Output{
		LatestVersionsByOs:        in.LatestVersionsByOs,
		Versions:                  map[string]int{},
		Types:                     map[string]int{},
		AutoUpdateSettings:        map[string]int{},
		ConnectionStatuses:        map[string]int{},
		OsTypes:                   map[string]int{},
		ByCapability:              map[string]int{},
		ActiveGatesByCapability:   map[string][]AGRow{},
		MisconfiguredByCapability: map[string][]AGRow{},
		NetworkZones:              map[string]int{},
		ActiveGatesByNetworkZone:  map[string][]AGRow{},
		ActiveGatesByType:         map[string][]AGRow{},
	}
	if out.LatestVersionsByOs == nil {
		out.LatestVersionsByOs = map[string]string{}
	}

	for _, ag := range in.ActiveGates {
		out.TotalActiveGates++

		version := ag.Version
		if version == "" {
			version = "unknown"
		}
		out.Versions[version]++

		agType := ag.Type
		if agType == "" {
			agType = "UNKNOWN"
		}
		out.Types[agType]++

		au := ""
		if ag.AutoUpdateSettings != nil {
			au = ag.AutoUpdateSettings.EffectiveSetting
		}
		if au == "" {
			au = ag.AutoUpdateStatus
		}
		if au == "" {
			au = "UNKNOWN"
		}
		out.AutoUpdateSettings[au]++

		cs := ag.ConnectionStatus
		if cs == "" {
			cs = "UNKNOWN"
		}
		out.ConnectionStatuses[cs]++
		if cs != "ONLINE" && cs != "UNKNOWN" {
			out.NotConnectedCount++
		}

		os := ag.OsType
		if os == "" {
			os = "UNKNOWN"
		}
		out.OsTypes[os]++

		// Resolve network zone from top-level OR properties.networkZone
		zone := ag.NetworkZone
		if zone == "" && ag.Properties != nil {
			if v, ok := ag.Properties["networkZone"].(string); ok {
				zone = v
			}
		}

		// Build capability list:
		//   - prefer modules[].type where enabled=true
		//   - fall back to enabledModules[] if modules[] is empty
		enabledCaps := []string{}
		misconfigCaps := []string{}
		if len(ag.Modules) > 0 {
			for _, m := range ag.Modules {
				if m.Type == "" {
					continue
				}
				if m.Enabled {
					enabledCaps = append(enabledCaps, m.Type)
				}
				if m.Misconfigured {
					misconfigCaps = append(misconfigCaps, m.Type)
				}
			}
		} else {
			enabledCaps = append(enabledCaps, ag.EnabledModules...)
		}
		if len(misconfigCaps) > 0 {
			out.MisconfiguredModuleCount++
		}

		row := AGRow{
			ID:                   ag.ID,
			Hostname:             ag.Hostname,
			NetworkAddresses:     ag.NetworkAddresses,
			OsType:               os,
			Version:              version,
			Type:                 agType,
			AutoUpdateSetting:    au,
			ConnectionStatus:     cs,
			NetworkZone:          zone,
			EnabledModules:       enabledCaps,
			MisconfiguredModules: misconfigCaps,
			LastConnectedTime:    ag.LastConnectedTime,
		}

		// Per-OS "behind latest" classification
		if version != "unknown" {
			if latest, ok := lookupLatest(in.LatestVersionsByOs, os); ok {
				row.LatestForOs = latest
				row.MinorBehind = minorBehind(latest, version)
				if row.MinorBehind >= outdatedThresholdMinor {
					out.OutdatedActiveGatesCount++
					if len(out.OutdatedActiveGatesSample) < outdatedSampleCap {
						out.OutdatedActiveGatesSample = append(out.OutdatedActiveGatesSample, row)
					}
				}
			} else {
				out.ActiveGatesWithoutOsLatestRef = append(out.ActiveGatesWithoutOsLatestRef, row)
			}
		}

		// Type grouping
		out.ActiveGatesByType[agType] = append(out.ActiveGatesByType[agType], row)

		// Network zone grouping
		if zone == "" {
			out.ActiveGatesWithoutNetworkZone = append(out.ActiveGatesWithoutNetworkZone, row)
		} else {
			out.NetworkZones[zone]++
			out.ActiveGatesByNetworkZone[zone] = append(out.ActiveGatesByNetworkZone[zone], row)
		}

		// Capability grouping
		for _, cap := range enabledCaps {
			out.ByCapability[cap]++
			out.ActiveGatesByCapability[cap] = append(out.ActiveGatesByCapability[cap], row)
		}
		for _, cap := range misconfigCaps {
			out.MisconfiguredByCapability[cap] = append(out.MisconfiguredByCapability[cap], row)
		}
	}

	// Stable sort within every group for determinism.
	sortRowsInMap(out.ActiveGatesByCapability)
	sortRowsInMap(out.MisconfiguredByCapability)
	sortRowsInMap(out.ActiveGatesByNetworkZone)
	sortRowsInMap(out.ActiveGatesByType)

	return out, nil
}

// lookupLatest tries the OS key in both its original case AND lowercased,
// since the deployment-installer endpoints use lowercase but the host
// inventory typically returns uppercase. The consumer should be sending
// uppercase keys (matching ag.osType), but be tolerant.
func lookupLatest(m map[string]string, osType string) (string, bool) {
	if v, ok := m[osType]; ok {
		return v, true
	}
	// Also try the original (unaltered) form — in case caller already
	// stored lowercase.
	for k, v := range m {
		if equalsCaseInsensitive(k, osType) {
			return v, true
		}
	}
	return "", false
}

func equalsCaseInsensitive(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func sortRowsInMap(m map[string][]AGRow) {
	for k := range m {
		rows := m[k]
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].ID != rows[j].ID {
				return rows[i].ID < rows[j].ID
			}
			return rows[i].Hostname < rows[j].Hostname
		})
	}
}

// minorBehind — same formula as the OneAgent analyzer.
func minorBehind(latest, current string) int {
	lv := parseVersion(latest)
	cv := parseVersion(current)
	major := safeAt(lv, 0) - safeAt(cv, 0)
	minor := safeAt(lv, 1) - safeAt(cv, 1)
	return major*1000 + minor
}

func parseVersion(s string) []int {
	parts := []int{}
	cur := 0
	hasDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			cur = cur*10 + int(c-'0')
			hasDigit = true
			continue
		}
		if hasDigit {
			parts = append(parts, cur)
			cur = 0
			hasDigit = false
		}
	}
	if hasDigit {
		parts = append(parts, cur)
	}
	return parts
}

func safeAt(xs []int, i int) int {
	if i < len(xs) {
		return xs[i]
	}
	return 0
}
