package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/buildinfo"
	releasetrust "mesh/internal/release"
)

func TestVersionJSON(t *testing.T) {
	var output bytes.Buffer
	if err := versionTo([]string{"--json"}, &output); err != nil {
		t.Fatal(err)
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Version == "" || info.GoVersion == "" || info.OS == "" || info.Arch == "" || info.SecurityFloor != 1 ||
		info.AgentStateReadMin == 0 || info.AgentStateReadMax < info.AgentStateReadMin ||
		info.AgentStateWriteVersion < info.AgentStateReadMin || info.AgentStateWriteVersion > info.AgentStateReadMax {
		t.Fatalf("incomplete version JSON: %+v", info)
	}
}

func TestVerifyReleaseCommandAuthenticatesBeforeStreamingArtifact(t *testing.T) {
	directory := t.TempDir()
	artifact := []byte("locally downloaded artifact")
	digest := sha256.Sum256(artifact)
	manifest := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchema, Channel: "stable", Version: "2.0.0", Sequence: 42, MinimumSecurityFloor: 1,
		IssuedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Artifacts: []releasetrust.Artifact{{OS: "testos", Arch: "testarch", URL: "https://releases.example/meshctl", Size: int64(len(artifact)), SHA256: hex.EncodeToString(digest[:])}},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "release.json")
	artifactPath := filepath.Join(directory, "artifact")
	if err := os.WriteFile(manifestPath, manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--manifest", manifestPath, "--artifact", artifactPath, "--os", "testos", "--arch", "testarch", "--channel", "stable", "--minimum-sequence", "42"}
	for index := 0; index < 2; index++ {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := releasetrust.KeyID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		publicRaw, err := releasetrust.MarshalPublicKeyFile(releasetrust.PublicKeyFile{Schema: releasetrust.PublicKeySchema, KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)})
		if err != nil {
			t.Fatal(err)
		}
		signatureRaw, err := releasetrust.SignManifest(releasetrust.ReleaseManifestKind, manifestRaw, privateKey)
		clear(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicPath := filepath.Join(directory, "key-"+string(rune('a'+index))+".json")
		signaturePath := filepath.Join(directory, "signature-"+string(rune('a'+index))+".json")
		if err := os.WriteFile(publicPath, publicRaw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(signaturePath, signatureRaw, 0o644); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--trusted-public-key", publicPath, "--signature", signaturePath)
	}
	var output bytes.Buffer
	if err := verifyReleaseTo(args, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Verified release 2.0.0") || !strings.Contains(output.String(), "Verified artifact") {
		t.Fatalf("unexpected output: %q", output.String())
	}
	if err := os.WriteFile(artifactPath, append(artifact, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	var failureOutput bytes.Buffer
	if err := verifyReleaseTo(args, &failureOutput); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("appended artifact returned %v", err)
	}
	if failureOutput.Len() != 0 {
		t.Fatalf("failed artifact verification emitted partial success: %q", failureOutput.String())
	}
}
