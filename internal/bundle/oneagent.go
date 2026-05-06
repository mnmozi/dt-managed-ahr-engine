package bundle

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

// OneAgentModule describes one OneAgent module — typically one of:
// LOG_ANALYTICS, OS, JAVA, DOTNET, NODE_JS, etc.
type OneAgentModule struct {
	ModuleType    string `json:"moduleType"`
	Enabled       bool   `json:"enabled"`
	Version       string `json:"version"`
	Misconfigured bool   `json:"misconfigured"`
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
