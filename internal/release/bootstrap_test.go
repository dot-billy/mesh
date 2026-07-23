package release

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mesh/internal/buildinfo"
)

func TestBootstrapManifestRootThresholdAndExactCanonicalBytes(t *testing.T) {
	document, rootPrivate, releasePrivate := testRootAuthority(t)
	rootRaw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseRoot(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrapManifestForRoot(root)
	raw, err := EncodeBootstrapManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(raw, []byte{'\n'}) != 1 || raw[len(raw)-1] != '\n' {
		t.Fatalf("bootstrap manifest is not compact JSON plus LF: %q", raw)
	}
	parsed, err := ParseBootstrapManifest(raw, bootstrapTestNow(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Document != manifest || len(parsed.SHA256) != 64 {
		t.Fatalf("unexpected parsed bootstrap: %+v", parsed)
	}
	signatures := signWithKeys(t, BootstrapManifestKind, raw, rootPrivate)
	verified, err := VerifyBootstrapManifest(raw, signatures, root, bootstrapTestNow(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Document.Artifact.SHA256 != strings.Repeat("c", 64) || len(verified.SignerKeyIDs) != 2 {
		t.Fatalf("unexpected verified bootstrap: %+v", verified)
	}
	if _, err := VerifyBootstrapManifest(raw, signatures[:1], root, bootstrapTestNow(), 0); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("one root signature returned %v", err)
	}
	wrongRole := signWithKeys(t, BootstrapManifestKind, raw, releasePrivate)
	if _, err := VerifyBootstrapManifest(raw, wrongRole, root, bootstrapTestNow(), 0); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("release-role bootstrap signatures returned %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyBootstrapManifest(tampered, signatures, root, bootstrapTestNow(), 0); err == nil {
		t.Fatal("bootstrap signatures accepted changed exact bytes")
	}
	if _, err := SignManifest(ReleaseManifestKind, raw, rootPrivate[0]); err == nil || !strings.Contains(err.Error(), "declares") {
		t.Fatalf("bootstrap signed in release domain returned %v", err)
	}
	if _, err := VerifyManifest(raw, signatures, root.RootKeys, policyWithThreshold(2)); err == nil || !strings.Contains(err.Error(), "no manifest type") {
		t.Fatalf("ordinary release verification accepted bootstrap authority: %v", err)
	}
}

func TestBootstrapManifestRejectsRootDriftExpiryAndAmbiguity(t *testing.T) {
	document, rootPrivate, _ := testRootAuthority(t)
	rootRaw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseRoot(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrapManifestForRoot(root)
	manifest.RootSHA256 = strings.Repeat("0", 64)
	raw, err := EncodeBootstrapManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signatures := signWithKeys(t, BootstrapManifestKind, raw, rootPrivate)
	if _, err := VerifyBootstrapManifest(raw, signatures, root, bootstrapTestNow(), 0); err == nil || !strings.Contains(err.Error(), "independently authenticated") {
		t.Fatalf("root drift returned %v", err)
	}

	manifest = bootstrapManifestForRoot(root)
	manifest.ExpiresAt = "2026-09-01T12:00:00Z"
	if _, err := EncodeBootstrapManifest(manifest); err == nil || !strings.Contains(err.Error(), "validity") {
		t.Fatalf("overlong bootstrap validity returned %v", err)
	}
	raw, err = EncodeBootstrapManifest(bootstrapManifestForRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBootstrapManifest(raw, time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC), 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired bootstrap returned %v", err)
	}
	duplicate := bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1)
	if _, err := ParseBootstrapManifest(duplicate, bootstrapTestNow(), 0); err == nil {
		t.Fatal("duplicate bootstrap field accepted")
	}
}

func TestBootstrapManifestAcceptsExactWindowsInstallerArtifact(t *testing.T) {
	document, _, _ := testRootAuthority(t)
	rootRaw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseRoot(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrapManifestForRoot(root)
	manifest.Artifact = BootstrapArtifact{
		Name: "mesh-install-windows.exe", OS: "windows", Arch: "arm64", Size: 1234, SHA256: strings.Repeat("c", 64),
	}
	raw, err := EncodeBootstrapManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBootstrapManifest(raw, bootstrapTestNow(), 0)
	if err != nil || parsed.Document.Artifact != manifest.Artifact {
		t.Fatalf("parsed Windows bootstrap = %+v, error=%v", parsed, err)
	}
	manifest.Artifact.Name = "mesh-install.exe"
	if _, err := EncodeBootstrapManifest(manifest); err == nil {
		t.Fatal("Windows bootstrap with a noncanonical installer name was accepted")
	}
}

func bootstrapManifestForRoot(root ParsedRoot) BootstrapManifest {
	return BootstrapManifest{
		Schema: BootstrapManifestSchema, Channel: root.Document.Channel,
		RootVersion: 1, ReleaseEpoch: 1, RootSHA256: root.SHA256,
		InstallerBootstrapSHA256: strings.Repeat("b", 64),
		IssuedAt:                 "2026-07-21T12:00:00Z", ExpiresAt: "2026-07-25T12:00:00Z",
		Build: buildinfo.IdentityInfo{
			Schema: buildinfo.Schema, Version: "1.2.3", Commit: strings.Repeat("a", 40),
			BuildTime: "2026-07-21T11:00:00Z", SecurityFloor: 1,
			AgentStateReadMin: 1, AgentStateReadMax: 1, AgentStateWriteVersion: 1,
		},
		GoVersion: "go1.24.5",
		Artifact: BootstrapArtifact{
			Name: "mesh-install", OS: "linux", Arch: "amd64", Size: 1234, SHA256: strings.Repeat("c", 64),
		},
	}
}

func bootstrapTestNow() time.Time {
	return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
}
