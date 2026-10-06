// Package oneagent contains analyzers operating on /api/v2/oneagents data.
//
// distribution.go — computes the OneAgent rollout health summary:
//
//   - per-version / per-autoUpdate / per-monitoring-type / per-OS counts
//   - faulty / inactive counts
//   - "behind latest" comparison against per-OS latest versions provided by
//     the consumer (the engine does NOT fetch latest itself — that's piping)
//   - host lists grouped by monitoringType (so consumers can see WHO is full-
//     stack vs infra, with OS type)
//
// Input expects the same shape `/api/v2/oneagents` returns (with all pages
// already merged into `hosts`) PLUS a `latestVersionsByOs` map the consumer
// has separately fetched from /api/v1/deployment/installer/... .
package oneagent

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/local/dt-managed-engine/internal/analyze"
)

func init() {
	analyze.Register(Distribution{})
}

// Distribution is the analyzer. Empty struct — pure function via methods.
type Distribution struct{}

// Kind returns the registry key.
func (Distribution) Kind() string { return "oneagent.distribution" }

// Description is shown via engine_list.
func (Distribution) Description() string {
	return "OneAgent rollout health: version + autoUpdate + monitoring + OS distributions, faulty/inactive counts, and per-OS 'behind latest' comparison. Input includes the /api/v2/oneagents response plus a latestVersionsByOs lookup the consumer fetched separately."
}

// Input is the analyzer input shape.
type Input struct {
	// Hosts mirrors /api/v2/oneagents `hosts[]` exactly. We only read the
	// fields we care about; everything else is ignored.
	Hosts []Host `json:"hosts"`

	// LatestVersionsByOs is the cluster's view of the latest available
	// OneAgent version per OS type (e.g. {"LINUX":"1.295.0","WINDOWS_DESKTOP":"1.295.0"}).
	// Consumer fetches this from /api/v1/deployment/installer/agent/... per OS.
	// Hosts whose osType is missing from this map go into HostsWithoutOsLatestReference.
	LatestVersionsByOs map[string]string `json:"latestVersionsByOs"`
}

// Host is the subset of fields we read from /api/v2/oneagents host entries.
type Host struct {
	HostInfo          *HostInfo `json:"hostInfo,omitempty"`
	CurrentVersion    string    `json:"currentVersion,omitempty"`
	InstallerVersion  string    `json:"installerVersion,omitempty"`
	AutoUpdateSetting string    `json:"autoUpdateSetting,omitempty"`
	MonitoringType    string    `json:"monitoringType,omitempty"`
	FaultyVersion     bool      `json:"faultyVersion,omitempty"`
	Active            *bool     `json:"active,omitempty"` // pointer so we can distinguish "not present" from "false"
}

// HostInfo is the nested hostInfo block.
type HostInfo struct {
	HostName string `json:"hostName,omitempty"`
	EntityID string `json:"entityId,omitempty"`
	OsType   string `json:"osType,omitempty"`
}

// Output is the analyzer result shape.
type Output struct {
	TotalHosts                    int                  `json:"totalHosts"`
	LatestVersionsByOs            map[string]string    `json:"latestVersionsByOs"`
	Versions                      map[string]int       `json:"versions"`
	AutoUpdateSettings            map[string]int       `json:"autoUpdateSettings"`
	MonitoringTypes               map[string]int       `json:"monitoringTypes"`
	OsTypes                       map[string]int       `json:"osTypes"`
	FaultyVersionCount            int                  `json:"faultyVersionCount"`
	InactiveCount                 int                  `json:"inactiveCount"`
	HostsByMonitoringType         map[string][]HostRow `json:"hostsByMonitoringType"`
	OutdatedHostsCount            int                  `json:"outdatedHostsCount"`
	OutdatedHostsSample           []HostRow            `json:"outdatedHostsSample"`
	HostsWithoutOsLatestReference []HostRow            `json:"hostsWithoutOsLatestReference"`
}

// HostRow is the per-host shape we emit in lists. Each field is either a
// fact from the input host, or a comparison result against LatestVersionsByOs.
//
// active + faultyVersion are deliberately NOT omitempty — false is a
// meaningful, common value that consumers need to read explicitly.
// minorBehind is also always present — 0 means "on latest", which is
// different from "we couldn't compare" (that's signaled by missing latestForOs).
type HostRow struct {
	HostName          string `json:"hostName,omitempty"`
	EntityID          string `json:"entityId,omitempty"`
	OsType            string `json:"osType,omitempty"`
	Version           string `json:"version,omitempty"`
	LatestForOs       string `json:"latestForOs,omitempty"`
	MinorBehind       int    `json:"minorBehind"`
	AutoUpdateSetting string `json:"autoUpdateSetting,omitempty"`
	FaultyVersion     bool   `json:"faultyVersion"`
	Active            bool   `json:"active"`
}

// outdatedThresholdMinor — a host is "outdated" when it's at least this many
// minor versions behind the latest for its OS. Hardcoded to match current TS
// behavior; promote to an input field if we ever want to vary it.
const outdatedThresholdMinor = 5

// outdatedSampleCap — how many hosts to include in OutdatedHostsSample.
// HostsByMonitoringType is uncapped intentionally; this small sample is for
// quick UI display.
const outdatedSampleCap = 20

// Run is the analyzer entrypoint. Pure function.
func (Distribution) Run(raw json.RawMessage) (any, error) {
	var in Input
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
	}

	out := Output{
		LatestVersionsByOs:    in.LatestVersionsByOs,
		Versions:              map[string]int{},
		AutoUpdateSettings:    map[string]int{},
		MonitoringTypes:       map[string]int{},
		OsTypes:               map[string]int{},
		HostsByMonitoringType: map[string][]HostRow{},
	}
	// Ensure deterministic-ordered emission even when the map is empty.
	if out.LatestVersionsByOs == nil {
		out.LatestVersionsByOs = map[string]string{}
	}

	for _, h := range in.Hosts {
		out.TotalHosts++

		version := h.CurrentVersion
		if version == "" {
			version = h.InstallerVersion
		}
		if version == "" {
			version = "unknown"
		}
		out.Versions[version]++

		au := h.AutoUpdateSetting
		if au == "" {
			au = "UNKNOWN"
		}
		out.AutoUpdateSettings[au]++

		mt := h.MonitoringType
		if mt == "" {
			mt = "UNKNOWN"
		}
		out.MonitoringTypes[mt]++

		var os string
		if h.HostInfo != nil {
			os = h.HostInfo.OsType
		}
		if os == "" {
			os = "UNKNOWN"
		}
		out.OsTypes[os]++

		if h.FaultyVersion {
			out.FaultyVersionCount++
		}
		if h.Active != nil && !*h.Active {
			out.InactiveCount++
		}

		row := buildHostRow(h, version, os, in.LatestVersionsByOs)
		out.HostsByMonitoringType[mt] = append(out.HostsByMonitoringType[mt], row)

		// Per-OS "behind latest" classification
		latest, hasLatest := in.LatestVersionsByOs[os]
		switch {
		case !hasLatest && version != "unknown":
			// We have a version but no latest reference — surface honestly.
			out.HostsWithoutOsLatestReference = append(out.HostsWithoutOsLatestReference, row)
		case hasLatest && version != "unknown":
			if mb := minorBehind(latest, version); mb >= outdatedThresholdMinor {
				out.OutdatedHostsCount++
				if len(out.OutdatedHostsSample) < outdatedSampleCap {
					out.OutdatedHostsSample = append(out.OutdatedHostsSample, row)
				}
			}
		}
	}

	// Stable iteration order for the by-MT lists — sort rows within each type
	// by entityId then hostName for determinism.
	for k := range out.HostsByMonitoringType {
		rows := out.HostsByMonitoringType[k]
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].EntityID != rows[j].EntityID {
				return rows[i].EntityID < rows[j].EntityID
			}
			return rows[i].HostName < rows[j].HostName
		})
	}

	return out, nil
}

// buildHostRow assembles a HostRow from a Host, including the per-OS
// "behind latest" math if a latest is known for the host's OS.
func buildHostRow(h Host, version, os string, latestByOs map[string]string) HostRow {
	row := HostRow{
		Version:           version,
		OsType:            os,
		AutoUpdateSetting: h.AutoUpdateSetting,
		FaultyVersion:     h.FaultyVersion,
		Active:            h.Active == nil || *h.Active, // default true when not present
	}
	if h.HostInfo != nil {
		row.HostName = h.HostInfo.HostName
		row.EntityID = h.HostInfo.EntityID
	}
	if latest, ok := latestByOs[os]; ok && version != "unknown" {
		row.LatestForOs = latest
		row.MinorBehind = minorBehind(latest, version)
	}
	return row
}

// minorBehind returns how many minor versions `current` is behind `latest`.
// Computed as (major_diff)*1000 + (minor_diff), matching the existing TS
// behavior. Negative values are possible (current is ahead) and are returned
// as-is; the caller decides whether to treat them as outdated.
func minorBehind(latest, current string) int {
	lv := parseVersion(latest)
	cv := parseVersion(current)
	major := safeAt(lv, 0) - safeAt(cv, 0)
	minor := safeAt(lv, 1) - safeAt(cv, 1)
	return major*1000 + minor
}

// parseVersion splits "1.291.123-build" → [1, 291, 123, ...] ignoring non-numeric.
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
		// boundary character — flush current accumulator if we saw digits
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
