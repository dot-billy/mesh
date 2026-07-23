package bootstrapanchor_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mesh/internal/bootstrapanchor"
	"mesh/internal/bootstrapanchorauthor"
	"mesh/internal/bootstraphandoff"
	"mesh/internal/buildinfo"
)

var anchorTestNow = time.Date(2026, 7, 21, 12, 30, 0, 0, time.UTC)

func TestAnchorCanonicalRoundTripAndExactHandoffResolution(t *testing.T) {
	handoffRaw := testHandoffRaw(t)
	document, raw, err := bootstrapanchorauthor.Create(handoffRaw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bootstrapanchor.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Channel != "stable" || parsed.Handoff.Size != int64(len(handoffRaw)) || len(parsed.Verifiers) != 4 {
		t.Fatalf("unexpected anchor: %#v", parsed)
	}
	parsed.Verifiers[0].SHA256 = strings.Repeat("9", 64)
	if document.Verifiers[0].SHA256 == parsed.Verifiers[0].SHA256 {
		t.Fatal("parsed anchor aliases author output")
	}
	resolution, err := bootstrapanchor.Resolve(raw, handoffRaw, anchorTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolution.AnchorSHA256) != 64 || resolution.HandoffSHA256 != document.Handoff.SHA256 {
		t.Fatalf("unexpected resolution: %#v", resolution)
	}
	if _, err := bootstrapanchor.Parse(bytes.TrimSuffix(raw, []byte("\n"))); err == nil {
		t.Fatal("noncanonical anchor accepted")
	}
	duplicate := bytes.Replace(raw, []byte(`"schema":"mesh-bootstrap-anchor-v2"`), []byte(`"schema":"mesh-bootstrap-anchor-v2","schema":"mesh-bootstrap-anchor-v2"`), 1)
	if _, err := bootstrapanchor.Parse(duplicate); err == nil {
		t.Fatal("duplicate anchor field accepted")
	}
	unknown := bytes.Replace(raw, []byte(`"schema":"mesh-bootstrap-anchor-v2"`), []byte(`"schema":"mesh-bootstrap-anchor-v2","unexpected":true`), 1)
	if _, err := bootstrapanchor.Parse(unknown); err == nil {
		t.Fatal("unknown anchor field accepted")
	}
}

func TestAnchorRejectsCourierAndReviewDrift(t *testing.T) {
	handoffRaw := testHandoffRaw(t)
	document, _, err := bootstrapanchorauthor.Create(handoffRaw)
	if err != nil {
		t.Fatal(err)
	}

	changedHandoff := append(append([]byte(nil), handoffRaw...), '\n')
	raw, _ := bootstrapanchor.Encode(document)
	if _, err := bootstrapanchor.Resolve(raw, changedHandoff, anchorTestNow); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("changed courier returned %v", err)
	}
	changedHandoff = append([]byte(nil), handoffRaw...)
	changedHandoff[len(changedHandoff)-2] ^= 1
	if _, err := bootstrapanchor.Resolve(raw, changedHandoff, anchorTestNow); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("same-size changed courier returned %v", err)
	}

	document.Build.Version = "1.2.4"
	drifted, err := bootstrapanchor.Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapanchor.Resolve(drifted, handoffRaw, anchorTestNow); err == nil || !strings.Contains(err.Error(), "review fields") {
		t.Fatalf("review drift returned %v", err)
	}

	document, _, _ = bootstrapanchorauthor.Create(handoffRaw)
	document.Verifiers[0], document.Verifiers[1] = document.Verifiers[1], document.Verifiers[0]
	if _, err := bootstrapanchor.Encode(document); err == nil {
		t.Fatal("reordered verifier references accepted")
	}

	document, _, _ = bootstrapanchorauthor.Create(handoffRaw)
	document.Handoff.SHA256 = strings.Repeat("A", 64)
	if _, err := bootstrapanchor.Encode(document); err == nil {
		t.Fatal("noncanonical digest accepted")
	}

	document, raw, _ = bootstrapanchorauthor.Create(handoffRaw)
	if _, err := bootstrapanchor.Resolve(raw, handoffRaw, time.Date(2026, 7, 22, 13, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired anchor returned %v", err)
	}
}

func testHandoffRaw(t *testing.T) []byte {
	t.Helper()
	document := bootstraphandoff.Document{
		Schema: bootstraphandoff.Schema, Channel: "stable",
		IssuedAt: "2026-07-21T12:00:00Z", ExpiresAt: "2026-07-22T12:00:00Z",
		Root: bootstraphandoff.RootReference{
			Name: bootstraphandoff.RootName, Version: 1, ReleaseEpoch: 1, MinimumSecurityFloor: 1,
			IssuedAt: "2026-07-21T11:00:00Z", ExpiresAt: "2026-08-20T12:00:00Z",
			Size: 1024, SHA256: strings.Repeat("a", 64),
		},
		Build: buildinfo.IdentityInfo{
			Schema: buildinfo.Schema, Version: "1.2.3", Commit: strings.Repeat("b", 40),
			BuildTime: "2026-07-21T11:30:00Z", SecurityFloor: 1,
			AgentStateReadMin: 2, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
		},
		GoVersion: "go1.26.0",
		Verifiers: []bootstraphandoff.VerifierReference{
			{Name: bootstraphandoff.VerifierName("linux", "amd64"), OS: "linux", Arch: "amd64", Size: 4096, SHA256: strings.Repeat("c", 64), PackageJSONSHA256: strings.Repeat("d", 64), VerifierSHA256: strings.Repeat("e", 64)},
			{Name: bootstraphandoff.VerifierName("linux", "arm64"), OS: "linux", Arch: "arm64", Size: 4096, SHA256: strings.Repeat("f", 64), PackageJSONSHA256: strings.Repeat("0", 64), VerifierSHA256: strings.Repeat("1", 64)},
			{Name: bootstraphandoff.VerifierName("windows", "amd64"), OS: "windows", Arch: "amd64", Size: 4096, SHA256: strings.Repeat("2", 64), PackageJSONSHA256: strings.Repeat("3", 64), VerifierSHA256: strings.Repeat("4", 64)},
			{Name: bootstraphandoff.VerifierName("windows", "arm64"), OS: "windows", Arch: "arm64", Size: 4096, SHA256: strings.Repeat("5", 64), PackageJSONSHA256: strings.Repeat("6", 64), VerifierSHA256: strings.Repeat("7", 64)},
		},
	}
	raw, err := bootstraphandoff.Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
