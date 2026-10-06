package bundle

import (
	"encoding/json"
	"testing"
)

// Shape served by /api/v1/oneagents?includeDetails=true on Managed 1.350.7
// (trimmed): no hostName, no per-module enabled flag — instances[] instead.
const v1OneAgentsJSON = `{"hosts":[{
  "hostInfo":{"displayName":"ip-10-0-0-3.ec2.internal","entityId":"HOST-1","osType":"LINUX"},
  "monitoringType":"FULL_STACK",
  "modules":[
    {"moduleType":"LOG_ANALYTICS","instances":[{"instanceName":"oneagentloganalytics","moduleVersion":"1.345.68.20260903-162827","faultyVersion":false,"active":true}]},
    {"moduleType":"JAVA","instances":[{"instanceName":"a","moduleVersion":"1.345.68","active":false},{"instanceName":"b","moduleVersion":"1.345.68","active":false}]}
  ]}]}`

func TestOneAgent_V1ModuleShapeFoldsIntoEnabled(t *testing.T) {
	var resp oneagentsResponse
	if err := json.Unmarshal([]byte(v1OneAgentsJSON), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	oa := resp.Hosts[0]
	if oa.HostInfo.HostName != "ip-10-0-0-3.ec2.internal" {
		t.Errorf("hostName should fall back to displayName, got %q", oa.HostInfo.HostName)
	}
	if !oa.HasEnabledLogModule() {
		t.Error("LOG_ANALYTICS with an active instance must count as enabled")
	}
	if oa.Modules[0].Version != "1.345.68.20260903-162827" {
		t.Errorf("version should come from the first instance, got %q", oa.Modules[0].Version)
	}
	if oa.Modules[1].Enabled {
		t.Error("module whose instances are all inactive must not count as enabled")
	}
}

func TestOneAgent_V2ExplicitEnabledWins(t *testing.T) {
	var m OneAgentModule
	if err := json.Unmarshal([]byte(`{"moduleType":"LOG_ANALYTICS","enabled":false,"instances":[{"active":true}]}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Enabled {
		t.Error("an explicit enabled:false must not be overridden by instances")
	}
}
