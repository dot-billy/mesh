package darwincodesign

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReceiptCanonicalRoundTripAndMatch(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	policy := receiptPolicy(t)
	receipt := testReceipt(now)
	receipt.PolicySHA256 = policy.SHA256
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(raw)
	if err != nil || parsed.VerifiedAt != receipt.VerifiedAt {
		t.Fatalf("parsed=%+v error=%v", parsed, err)
	}
	artifacts := []ArtifactIdentity{
		{Path: "bin/nebula-cert", SHA256: strings.Repeat("c", 64), Size: 3000},
		{Path: "bin/meshctl", SHA256: strings.Repeat("a", 64), Size: 1000},
		{Path: "bin/nebula", SHA256: strings.Repeat("b", 64), Size: 2000},
	}
	if err := parsed.Match(now, policy, "arm64", artifacts); err != nil {
		t.Fatal(err)
	}
	bootstrap := ArtifactIdentity{
		Path: "mesh-install", SHA256: strings.Repeat("0", 64), Size: 900,
	}
	if err := parsed.MatchBootstrap(now, policy, "arm64", bootstrap); err != nil {
		t.Fatal(err)
	}
	bootstrap.SHA256 = strings.Repeat("f", 64)
	if err := parsed.MatchBootstrap(now, policy, "arm64", bootstrap); err == nil {
		t.Fatal("drifted Darwin package bootstrap matched receipt")
	}
	artifacts[0].Size++
	if err := parsed.Match(now, policy, "arm64", artifacts); err == nil {
		t.Fatal("drifted Darwin signed artifact matched receipt")
	}
}

func TestReceiptRejectsStaleNoncanonicalOrAmbiguousEvidence(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	policy := receiptPolicy(t)
	receipt := testReceipt(now.Add(-25 * time.Hour))
	receipt.PolicySHA256 = policy.SHA256
	if err := receipt.Match(now, policy, receipt.Architecture, runtimeIdentitiesForReceipt(receipt)); err == nil {
		t.Fatal("stale Darwin code-signing receipt accepted")
	}
	valid := testReceipt(now)
	valid.PolicySHA256 = policy.SHA256
	valid.Files[1].Identifier = valid.Files[0].Identifier
	if _, err := EncodeReceipt(valid); err == nil {
		t.Fatal("duplicate Darwin code identifier accepted")
	}
	raw, err := EncodeReceipt(testReceipt(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReceipt(bytes.Replace(raw, []byte(`"schema"`), []byte(`"unknown"`), 1)); err == nil {
		t.Fatal("unknown Darwin receipt field accepted")
	}
}

func testReceipt(now time.Time) Receipt {
	return Receipt{
		Schema: ReceiptSchema, Architecture: "arm64",
		PolicySHA256: strings.Repeat("d", 64), TeamID: "AB12CD34EF",
		VerifiedAt: now.Format(time.RFC3339),
		Files: []FileEvidence{
			{Path: "mesh-install", Role: MeshInstallRole, Identifier: "io.mesh.node.mesh-install", SHA256: strings.Repeat("0", 64), Size: 900},
			{Path: "bin/meshctl", Role: MeshctlRole, Identifier: "io.mesh.node.meshctl", SHA256: strings.Repeat("a", 64), Size: 1000},
			{Path: "bin/nebula", Role: NebulaRole, Identifier: "io.mesh.node.nebula", SHA256: strings.Repeat("b", 64), Size: 2000},
			{Path: "bin/nebula-cert", Role: NebulaCertRole, Identifier: "io.mesh.node.nebula-cert", SHA256: strings.Repeat("c", 64), Size: 3000},
		},
	}
}

func receiptPolicy(t *testing.T) Policy {
	t.Helper()
	_, policy, err := EncodePolicy(PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl",
		NebulaIdentifier:  "io.mesh.node.nebula", NebulaCertIdentifier: "io.mesh.node.nebula-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func runtimeIdentitiesForReceipt(receipt Receipt) []ArtifactIdentity {
	result := make([]ArtifactIdentity, 0, 3)
	for _, file := range receipt.Files {
		if file.Path != "mesh-install" {
			result = append(result, ArtifactIdentity{Path: file.Path, SHA256: file.SHA256, Size: file.Size})
		}
	}
	return result
}
