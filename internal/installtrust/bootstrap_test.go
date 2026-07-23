package installtrust

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	releasetrust "mesh/internal/release"
)

func TestBootstrapFrameLoadsInitialRootAndDerivedLegacyPolicy(t *testing.T) {
	rootRaw, releaseFiles := validBootstrapRoot(t)
	frame, encoded, err := EncodeBootstrap(BootstrapSpec{InitialRoot: rootRaw})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(frame, BootstrapFramePrefix) || !strings.HasSuffix(frame, BootstrapFrameSuffix) {
		t.Fatalf("invalid bootstrap frame %q", frame)
	}
	legacyFrame, legacyPolicy, err := Encode(PolicySpec{
		Channel: "stable", SignatureThreshold: 2, MinimumSequence: 1,
		MinimumSecurityFloor: 1, TrustedKeys: releaseFiles,
	})
	if err != nil || legacyFrame == "" {
		t.Fatal(err)
	}
	if encoded.InitialRoot.Document.Version != 1 || encoded.InitialRoot.Document.ReleaseEpoch != 1 ||
		encoded.InitialRootSHA256 != encoded.InitialRoot.SHA256 || encoded.LegacyPolicySHA256 != legacyPolicy.SHA256 || len(encoded.SHA256) != 64 {
		t.Fatalf("unexpected bootstrap: %+v", encoded)
	}

	withEncodedPolicy(t, frame)
	loaded, err := LoadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SHA256 != encoded.SHA256 || loaded.LegacyPolicySHA256 != legacyPolicy.SHA256 || !bytes.Equal(loaded.InitialRootRaw, rootRaw) {
		t.Fatalf("loaded bootstrap differs: %+v", loaded)
	}
	loaded.InitialRootRaw[0] ^= 1
	loaded.InitialRoot.Document.Roles.Root.KeyIDs[0] = "poisoned"
	loaded.InitialRoot.RootKeys[0].PublicKey[0] ^= 1
	again, err := LoadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.InitialRootRaw, rootRaw) || again.InitialRoot.Document.Roles.Root.KeyIDs[0] == "poisoned" {
		t.Fatal("caller mutation poisoned compiled bootstrap")
	}
}

func TestBootstrapRequiresVersionOneEpochOneCanonicalRoot(t *testing.T) {
	rootRaw, _ := validBootstrapRoot(t)
	parsed, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*releasetrust.Root){
		"version": func(root *releasetrust.Root) { root.Version = 2 },
		"epoch":   func(root *releasetrust.Root) { root.ReleaseEpoch = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			document := parsed.Document
			document.Keys = append([]releasetrust.PublicKeyFile(nil), parsed.Document.Keys...)
			document.Roles.Root.KeyIDs = append([]string(nil), parsed.Document.Roles.Root.KeyIDs...)
			document.Roles.Release.KeyIDs = append([]string(nil), parsed.Document.Roles.Release.KeyIDs...)
			mutate(&document)
			raw, err := releasetrust.EncodeRoot(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := EncodeBootstrap(BootstrapSpec{InitialRoot: raw}); err == nil {
				t.Fatal("invalid initial root encoded")
			}
		})
	}
	noncanonical := append([]byte{' '}, rootRaw...)
	if _, _, err := EncodeBootstrap(BootstrapSpec{InitialRoot: noncanonical}); err == nil {
		t.Fatal("noncanonical initial root encoded")
	}
}

func TestBootstrapParserRejectsMalformedOrInconsistentFrames(t *testing.T) {
	rootRaw, _ := validBootstrapRoot(t)
	frame, _, err := EncodeBootstrap(BootstrapSpec{InitialRoot: rootRaw})
	if err != nil {
		t.Fatal(err)
	}
	document := decodedBootstrapDocument(t, frame)
	mutations := map[string]func(map[string]any){
		"wrong initial digest": func(value map[string]any) { value["initial_root_sha256"] = strings.Repeat("0", 64) },
		"wrong legacy digest":  func(value map[string]any) { value["legacy_policy_sha256"] = strings.Repeat("0", 64) },
		"unknown field":        func(value map[string]any) { value["unknown"] = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			clone := make(map[string]any, len(document)+1)
			for key, value := range document {
				clone[key] = value
			}
			mutate(clone)
			raw, err := json.Marshal(clone)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseBootstrapIdentity(encodeBootstrapBytes(raw)); err == nil {
				t.Fatal("malformed bootstrap parsed")
			}
		})
	}
	raw := decodedBootstrapBytes(t, frame)
	for name, candidate := range map[string]string{
		"bad base64": BootstrapFramePrefix + "!" + BootstrapFrameSuffix,
		"padded":     frame + "=",
		"duplicate":  encodeBootstrapBytes([]byte(strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1))),
		"trailing":   encodeBootstrapBytes(append(append([]byte(nil), raw...), []byte(`{}`)...)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBootstrapIdentity(candidate); err == nil {
				t.Fatal("invalid bootstrap frame parsed")
			}
		})
	}
}

func TestLoadBootstrapFailsClosedWithoutCompiledRoot(t *testing.T) {
	withEncodedPolicy(t, DevelopmentPolicy)
	if _, err := LoadBootstrap(); err == nil {
		t.Fatal("development bootstrap loaded")
	}
	withEncodedPolicy(t, "")
	if _, err := LoadBootstrap(); err == nil {
		t.Fatal("empty bootstrap loaded")
	}
}

func validBootstrapRoot(t *testing.T) ([]byte, []releasetrust.PublicKeyFile) {
	t.Helper()
	files := []releasetrust.PublicKeyFile{newPublicKeyFile(t), newPublicKeyFile(t), newPublicKeyFile(t), newPublicKeyFile(t)}
	sort.Slice(files, func(left, right int) bool { return files[left].KeyID < files[right].KeyID })
	rootFiles := append([]releasetrust.PublicKeyFile(nil), files[:2]...)
	releaseFiles := append([]releasetrust.PublicKeyFile(nil), files[2:]...)
	document := releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z",
		Keys: files,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{rootFiles[0].KeyID, rootFiles[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{releaseFiles[0].KeyID, releaseFiles[1].KeyID}},
		},
	}
	raw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw, releaseFiles
}

func decodedBootstrapDocument(t *testing.T, frame string) map[string]any {
	t.Helper()
	raw := decodedBootstrapBytes(t, frame)
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func decodedBootstrapBytes(t *testing.T, frame string) []byte {
	t.Helper()
	payload := strings.TrimSuffix(strings.TrimPrefix(frame, BootstrapFramePrefix), BootstrapFrameSuffix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func encodeBootstrapBytes(raw []byte) string {
	return BootstrapFramePrefix + base64.RawURLEncoding.EncodeToString(raw) + BootstrapFrameSuffix
}
