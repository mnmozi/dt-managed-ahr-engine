package bundle

import "encoding/json"

// OneAgent is the relevant subset of an /api/v2/oneagents host entry.
// We don't model every field — only what current and near-future checks need.
type OneAgent struct {
	HostInfo         OneAgentHostInfo  `json:"hostInfo"`
	MonitoringType   string            `json:"monitoringType"` // FULL_STACK | INFRASTRUCTURE | DISCOVERY | ...
	Active           *bool             `json:"active,omitempty"`
	FaultyVersion    bool              `json:"faultyVersion"`
	Modules          []OneAgentModule  `json:"modules"`
	CurrentVersion   string            `json:"currentVersion"`
	InstallerVersion string            `json:"installerVersion"`
	AutoUpdateSet    string            `json:"autoUpdateSetting"`
	UpdateStatus     string            `json:"updateStatus"`
	AvailabilitySt   string            `json:"availabilityState"`
	DetectedTechs    []DetectedTech    `json:"detectedTechnologies"`
}

// OneAgentHostInfo identifies the host the OneAgent is installed on.
type OneAgentHostInfo struct {
	HostName string `json:"hostName"`
	EntityID string `json:"entityId"`
	OsType   string `json:"osType"`
}

// UnmarshalJSON accepts the /api/v1/oneagents shape too, which has no
// hostName — only displayName / discoveredName / localHostName.
func (h *OneAgentHostInfo) UnmarshalJSON(data []byte) error {
	var raw struct {
		HostName       string `json:"hostName"`
		DisplayName    string `json:"displayName"`
		DiscoveredName string `json:"discoveredName"`
		LocalHostName  string `json:"localHostName"`
		EntityID       string `json:"entityId"`
		OsType         string `json:"osType"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	h.HostName = firstNonEmpty(raw.HostName, raw.DisplayName, raw.DiscoveredName, raw.LocalHostName)
	h.EntityID = raw.EntityID
	h.OsType = raw.OsType
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// OneAgentModule describes one OneAgent module — typically one of:
// LOG_ANALYTICS, OS, JAVA, DOTNET, NODE_JS, etc.
//
// Two source shapes: v2 carries enabled/version directly; /api/v1/oneagents
// (Managed 1.350+ with includeDetails=true) carries instances[] with a
// per-instance active flag and no enabled field. UnmarshalJSON folds the v1
// shape into Enabled (any instance active) so checks see one contract.
type OneAgentModule struct {
	ModuleType    string                   `json:"moduleType"`
	Enabled       bool                     `json:"enabled"`
	Version       string                   `json:"version"`
	Misconfigured bool                     `json:"misconfigured"`
	Instances     []OneAgentModuleInstance `json:"instances,omitempty"`
}

// OneAgentModuleInstance is one injected instance of a v1 module.
type OneAgentModuleInstance struct {
	InstanceName  string `json:"instanceName"`
	ModuleVersion string `json:"moduleVersion"`
	FaultyVersion bool   `json:"faultyVersion"`
	Active        bool   `json:"active"`
}

func (m *OneAgentModule) UnmarshalJSON(data []byte) error {
	type plain OneAgentModule
	var raw struct {
		plain
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = OneAgentModule(raw.plain)
	if raw.Enabled != nil {
		m.Enabled = *raw.Enabled
		return nil
	}
	for _, in := range m.Instances {
		if in.Active {
			m.Enabled = true
		}
		if m.Version == "" {
			m.Version = in.ModuleVersion
		}
	}
	return nil
}

// DetectedTech reports a technology OneAgent observed on the host.
type DetectedTech struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// HasEnabledLogModule returns true if any OneAgent module that looks like a
// log-monitoring module is enabled. DT changes the canonical name across
// versions ("LOG_ANALYTICS", "LOGS", "LOG_AGENT"), so we match loosely.
func (oa OneAgent) HasEnabledLogModule() bool {
	for _, m := range oa.Modules {
		if !m.Enabled {
			continue
		}
		t := m.ModuleType
		// Loose match — works across DT versions.
		switch t {
		case "LOG_ANALYTICS", "LOG_AGENT", "LOGS", "LOG":
			return true
		}
		// Some versions name it like "LogAnalytics" or "logmonitoring".
		// Use a contains check as a final fallback (case-insensitive).
		if containsFoldLog(t) {
			return true
		}
	}
	return false
}

func containsFoldLog(s string) bool {
	// Manually do case-insensitive substring match (no string.ToLower allocation).
	const target = "log"
	for i := 0; i+len(target) <= len(s); i++ {
		if foldEq(s[i:i+len(target)], target) {
			return true
		}
	}
	return false
}

func foldEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
