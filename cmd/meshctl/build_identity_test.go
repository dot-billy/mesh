package main

import (
	"testing"

	"mesh/internal/buildinfo"
)

func TestCurrentMeshAgentVersionUsesBuildIdentity(t *testing.T) {
	originalIdentity := buildinfo.Identity
	t.Cleanup(func() { buildinfo.Identity = originalIdentity })
	identity, err := buildinfo.EncodeIdentity(buildinfo.IdentityInfo{
		Schema: buildinfo.Schema, Version: "1.2.3", Commit: "0123456789012345678901234567890123456789",
		BuildTime: "2026-07-19T00:00:00Z", SecurityFloor: 7,
		AgentStateReadMin: 2, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	buildinfo.Identity = identity
	got, err := currentMeshAgentVersion()
	if err != nil {
		t.Fatal(err)
	}
	if got != "meshctl/1.2.3" {
		t.Fatalf("reported agent version = %q", got)
	}
}

func TestCurrentMeshAgentVersionRejectsUnsafeMetadata(t *testing.T) {
	originalIdentity := buildinfo.Identity
	t.Cleanup(func() { buildinfo.Identity = originalIdentity })
	for _, candidate := range []string{"", "not-framed", buildinfo.FramePrefix + "!" + buildinfo.FrameSuffix} {
		buildinfo.Identity = candidate
		if _, err := currentMeshAgentVersion(); err == nil {
			t.Fatalf("unsafe build identity %q accepted", candidate)
		}
	}
}
