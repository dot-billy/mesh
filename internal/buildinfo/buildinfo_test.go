package buildinfo

import (
	"encoding/base64"
	"strings"
	"testing"

	"mesh/internal/agentstate"
)

func TestCurrentReportsCanonicalDevelopmentIdentity(t *testing.T) {
	info, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "dev" || info.Commit != "unknown" || info.BuildTime != "unknown" || info.SecurityFloor != 1 ||
		info.AgentStateReadMin != agentstate.CurrentSchemaVersion || info.AgentStateReadMax != agentstate.CurrentSchemaVersion ||
		info.AgentStateWriteVersion != agentstate.CurrentWriteVersion ||
		info.GoVersion == "" || info.OS == "" || info.Arch == "" {
		t.Fatalf("unexpected development build info: %+v", info)
	}
	if _, err := CurrentProduction(); err == nil {
		t.Fatal("development sentinel accepted by production identity accessor")
	}
}

func TestIdentityCanonicalRoundTrip(t *testing.T) {
	want := IdentityInfo{
		Schema: Schema, Version: "1.2.3-rc.1+release", Commit: strings.Repeat("a", 40),
		BuildTime: "2026-07-19T12:34:56Z", SecurityFloor: 7,
		AgentStateReadMin: 1, AgentStateReadMax: 3, AgentStateWriteVersion: 2,
	}
	frame, err := EncodeIdentity(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIdentity(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("identity round trip = %+v, want %+v", got, want)
	}
}

func TestCurrentProductionAcceptsCanonicalReleaseFrame(t *testing.T) {
	original := Identity
	t.Cleanup(func() { Identity = original })
	frame, err := EncodeIdentity(IdentityInfo{
		Schema: Schema, Version: "1.2.3", Commit: strings.Repeat("c", 40),
		BuildTime: "2026-07-19T12:34:56Z", SecurityFloor: 4,
		AgentStateReadMin: 1, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	Identity = frame
	info, err := CurrentProduction()
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "1.2.3" || info.SecurityFloor != 4 || info.AgentStateReadMin != 1 || info.AgentStateReadMax != 2 || info.AgentStateWriteVersion != 2 {
		t.Fatalf("unexpected production info: %+v", info)
	}
}

func TestFramedDevelopmentIdentityUsesCurrentAgentStateSchema(t *testing.T) {
	if _, err := EncodeIdentity(IdentityInfo{
		Schema: Schema, Version: "dev", Commit: "unknown", BuildTime: "unknown", SecurityFloor: 1,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion,
	}); err != nil {
		t.Fatalf("current development compatibility identity rejected: %v", err)
	}
	if _, err := EncodeIdentity(IdentityInfo{
		Schema: Schema, Version: "dev", Commit: "unknown", BuildTime: "unknown", SecurityFloor: 1,
		AgentStateReadMin: agentstate.CurrentSchemaVersion + 1, AgentStateReadMax: agentstate.CurrentSchemaVersion + 1,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion + 1,
	}); err == nil {
		t.Fatal("development identity with a stale agent-state schema accepted")
	}
}

func TestCurrentRejectsMalformedLinkedIdentity(t *testing.T) {
	original := Identity
	t.Cleanup(func() { Identity = original })
	for _, value := range []string{"", "not-framed", FramePrefix + "!" + FrameSuffix} {
		Identity = value
		if _, err := Current(); err == nil {
			t.Fatalf("Current accepted malformed identity %q", value)
		}
	}
}

func TestParseIdentityRejectsNoncanonicalAndUnsafeValues(t *testing.T) {
	valid, err := EncodeIdentity(IdentityInfo{
		Schema: Schema, Version: "1.2.3", Commit: strings.Repeat("b", 40),
		BuildTime: "2026-07-19T00:00:00Z", SecurityFloor: 1,
		AgentStateReadMin: 1, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(valid, FramePrefix), FrameSuffix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		valid + "tail",
		FramePrefix + encoded + "=" + FrameSuffix,
		frameRaw(strings.Replace(string(raw), `"schema":`, `"schema":"other","schema":`, 1)),
		frameRaw(strings.Replace(string(raw), `"schema":`, `"unknown":true,"schema":`, 1)),
		frameRaw(strings.Replace(string(raw), `"version":"1.2.3"`, `"version":"01.2.3"`, 1)),
		frameRaw(strings.Replace(string(raw), `"security_floor":1`, `"security_floor":0`, 1)),
		frameRaw(strings.Replace(string(raw), `"agent_state_read_min":1`, `"agent_state_read_min":0`, 1)),
		frameRaw(strings.Replace(string(raw), `"agent_state_read_max":2`, `"agent_state_read_max":0`, 1)),
		frameRaw(strings.Replace(string(raw), `"agent_state_read_min":1`, `"agent_state_read_min":3`, 1)),
		frameRaw(strings.Replace(string(raw), `"agent_state_write_version":2`, `"agent_state_write_version":0`, 1)),
		frameRaw(strings.Replace(string(raw), `"agent_state_write_version":2`, `"agent_state_write_version":3`, 1)),
		frameRaw(strings.Replace(string(raw), `"build_time":"2026-07-19T00:00:00Z"`, `"build_time":"2026-07-19T00:00:00.000Z"`, 1)),
	}
	for _, candidate := range cases {
		if _, err := ParseIdentity(candidate); err == nil {
			t.Fatalf("accepted invalid identity frame %q", candidate)
		}
	}
}

func frameRaw(raw string) string {
	return FramePrefix + base64.RawURLEncoding.EncodeToString([]byte(raw)) + FrameSuffix
}
