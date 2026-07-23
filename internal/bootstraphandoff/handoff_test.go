package bootstraphandoff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
	"time"

	"mesh/internal/buildinfo"
	releasetrust "mesh/internal/release"
)

func TestDocumentCanonicalRoundTripAndStrictValidation(t *testing.T) {
	document := testDocument()
	raw, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Channel != "stable" || len(parsed.Verifiers) != 4 || parsed.Verifiers[3].OS != "windows" || parsed.Verifiers[3].Arch != "arm64" {
		t.Fatalf("unexpected parsed handoff: %+v", parsed)
	}
	parsed.Verifiers[0].SHA256 = strings.Repeat("2", 64)
	if document.Verifiers[0].SHA256 == parsed.Verifiers[0].SHA256 {
		t.Fatal("parsed handoff aliases caller verifier references")
	}
	if _, err := Parse(append(bytes.TrimSuffix(raw, []byte("\n")), ' ')); err == nil {
		t.Fatal("noncanonical handoff bytes accepted")
	}
	duplicate := bytes.Replace(raw, []byte(`"schema":"mesh-bootstrap-handoff-v2"`), []byte(`"schema":"mesh-bootstrap-handoff-v2","schema":"mesh-bootstrap-handoff-v2"`), 1)
	if _, err := Parse(duplicate); err == nil {
		t.Fatal("duplicate handoff field accepted")
	}
}

func TestResolveAuthenticatesHandoffBeforeRootAndSelectsExactPlatform(t *testing.T) {
	rootRaw := testRoot(t)
	root, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	document := testDocument()
	document.IssuedAt = "2026-07-21T11:30:00Z"
	document.ExpiresAt = "2026-07-21T13:00:00Z"
	document.Build.BuildTime = "2026-07-21T11:00:00Z"
	document.Root = RootReference{
		Name: RootName, Version: 1, ReleaseEpoch: 1, MinimumSecurityFloor: 1,
		IssuedAt: root.Document.IssuedAt, ExpiresAt: root.Document.ExpiresAt,
		Size: int64(len(rootRaw)), SHA256: root.SHA256,
	}
	raw, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	expected := hex.EncodeToString(digest[:])
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	resolved, err := Resolve(raw, expected, rootRaw, "linux", "amd64", now)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.HandoffSHA256 != expected || resolved.RootSHA256 != root.SHA256 || resolved.Verifier.Arch != "amd64" || resolved.Verifier.SHA256 != document.Verifiers[0].SHA256 {
		t.Fatalf("unexpected resolution: %+v", resolved)
	}
	windowsResolved, err := Resolve(raw, expected, rootRaw, "windows", "arm64", now)
	if err != nil || windowsResolved.Verifier != document.Verifiers[3] {
		t.Fatalf("unexpected Windows resolution: %+v, %v", windowsResolved, err)
	}
	if _, err := Resolve(raw, strings.Repeat("0", 64), nil, "linux", "amd64", now); err == nil || !strings.Contains(err.Error(), "independently authenticated") {
		t.Fatalf("wrong handoff digest returned %v", err)
	}
	if _, err := Resolve(raw, expected, append(append([]byte(nil), rootRaw...), '\n'), "linux", "amd64", now); err == nil || !strings.Contains(err.Error(), "root size") {
		t.Fatalf("changed root returned %v", err)
	}
	if _, err := Resolve(raw, expected, rootRaw, "darwin", "amd64", now); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("wrong platform returned %v", err)
	}
	if _, err := Resolve(raw, expected, rootRaw, "linux", "arm64", time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired handoff returned %v", err)
	}
}

func TestDocumentRejectsTrustAmbiguity(t *testing.T) {
	for name, mutate := range map[string]func(*Document){
		"schema":       func(value *Document) { value.Schema = "other" },
		"validity":     func(value *Document) { value.ExpiresAt = "2026-08-22T12:00:00Z" },
		"root digest":  func(value *Document) { value.Root.SHA256 = strings.Repeat("A", 64) },
		"root window":  func(value *Document) { value.Root.ExpiresAt = "2026-07-21T12:30:00Z" },
		"development":  func(value *Document) { value.Build.Version = "dev" },
		"future build": func(value *Document) { value.Build.BuildTime = "2026-07-21T12:00:01Z" },
		"one package":  func(value *Document) { value.Verifiers = value.Verifiers[:1] },
		"wrong order": func(value *Document) {
			value.Verifiers[0], value.Verifiers[1] = value.Verifiers[1], value.Verifiers[0]
		},
		"wrong target": func(value *Document) { value.Verifiers[1].OS = "windows" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clone(testDocument())
			mutate(&candidate)
			if _, err := Encode(candidate); err == nil {
				t.Fatal("ambiguous handoff accepted")
			}
		})
	}
}

func TestLegacyLinuxHandoffRemainsReadableButCannotSelectWindows(t *testing.T) {
	rootRaw := testRoot(t)
	root, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	document := testDocument()
	document.Schema = LegacySchema
	document.IssuedAt = "2026-07-21T11:30:00Z"
	document.ExpiresAt = "2026-07-21T13:00:00Z"
	document.Build.BuildTime = "2026-07-21T11:00:00Z"
	document.Root = RootReference{
		Name: RootName, Version: 1, ReleaseEpoch: 1, MinimumSecurityFloor: 1,
		IssuedAt: root.Document.IssuedAt, ExpiresAt: root.Document.ExpiresAt,
		Size: int64(len(rootRaw)), SHA256: root.SHA256,
	}
	document.Verifiers = document.Verifiers[:2]
	raw, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	expected := hex.EncodeToString(digest[:])
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	if _, err := Resolve(raw, expected, rootRaw, "linux", "arm64", now); err != nil {
		t.Fatalf("legacy Linux selection failed: %v", err)
	}
	if _, err := Resolve(raw, expected, rootRaw, "windows", "arm64", now); err == nil || !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("legacy handoff Windows selection returned %v", err)
	}
}

func testDocument() Document {
	return Document{
		Schema: Schema, Channel: "stable",
		IssuedAt: "2026-07-21T12:00:00Z", ExpiresAt: "2026-07-22T12:00:00Z",
		Root: RootReference{
			Name: RootName, Version: 1, ReleaseEpoch: 1, MinimumSecurityFloor: 1,
			IssuedAt: "2026-07-21T11:00:00Z", ExpiresAt: "2026-08-20T12:00:00Z",
			Size: 1024, SHA256: strings.Repeat("a", 64),
		},
		Build: buildinfo.IdentityInfo{
			Schema: buildinfo.Schema, Version: "1.2.3", Commit: strings.Repeat("b", 40),
			BuildTime: "2026-07-21T11:30:00Z", SecurityFloor: 1,
			AgentStateReadMin: 2, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
		},
		GoVersion: "go1.26.0",
		Verifiers: []VerifierReference{
			{Name: VerifierName("linux", "amd64"), OS: "linux", Arch: "amd64", Size: 4096, SHA256: strings.Repeat("c", 64), PackageJSONSHA256: strings.Repeat("d", 64), VerifierSHA256: strings.Repeat("e", 64)},
			{Name: VerifierName("linux", "arm64"), OS: "linux", Arch: "arm64", Size: 4096, SHA256: strings.Repeat("f", 64), PackageJSONSHA256: strings.Repeat("0", 64), VerifierSHA256: strings.Repeat("1", 64)},
			{Name: VerifierName("windows", "amd64"), OS: "windows", Arch: "amd64", Size: 4096, SHA256: strings.Repeat("2", 64), PackageJSONSHA256: strings.Repeat("3", 64), VerifierSHA256: strings.Repeat("4", 64)},
			{Name: VerifierName("windows", "arm64"), OS: "windows", Arch: "arm64", Size: 4096, SHA256: strings.Repeat("5", 64), PackageJSONSHA256: strings.Repeat("6", 64), VerifierSHA256: strings.Repeat("7", 64)},
		},
	}
}

func testRoot(t *testing.T) []byte {
	t.Helper()
	keys := make([]releasetrust.PublicKeyFile, 0, 4)
	for range 4 {
		_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		clear(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, publicKey)
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	raw, err := releasetrust.EncodeRoot(releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-21T11:00:00Z", ExpiresAt: "2026-08-20T13:00:00Z", Keys: keys,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{keys[0].KeyID, keys[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{keys[2].KeyID, keys[3].KeyID}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
