package installerinspect

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/agentstate"
	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsinstallercompat"
)

func TestInspectWindowsInstallerPE(t *testing.T) {
	identity := meshbuildinfo.IdentityInfo{
		Schema: meshbuildinfo.Schema, Version: "1.2.3", Commit: "0123456789012345678901234567890123456789",
		BuildTime: "2026-07-21T00:00:00Z", SecurityFloor: 1,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion,
	}
	identityFrame, err := meshbuildinfo.EncodeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	trustFrame, bootstrap := windowsInspectorTrust(t)
	authenticodeFrame, authenticodePolicy := windowsInspectorAuthenticode(t)
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "mesh-install-windows.exe")
			ldflags := "-s -w -buildid= -X mesh/internal/buildinfo.Identity=" + identityFrame + " -X mesh/internal/installtrust.Identity=" + trustFrame + " -X mesh/internal/windowsauthenticode.Identity=" + authenticodeFrame
			command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", output, "./cmd/mesh-install-windows")
			command.Dir = repositoryRoot
			command.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
			if combined, err := command.CombinedOutput(); err != nil {
				t.Fatalf("build Windows installer: %v\n%s", err, combined)
			}
			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			inspection, err := InspectWindows(raw, arch)
			if err != nil {
				t.Fatal(err)
			}
			if inspection.Identity != identity || inspection.Bootstrap.SHA256 != bootstrap.SHA256 || inspection.Compatibility != windowsinstallercompat.Supported() || inspection.Authenticode.SHA256 != authenticodePolicy.SHA256 {
				t.Fatalf("Windows inspection = %+v", inspection)
			}
			tampered := append([]byte(nil), raw...)
			offset := bytes.Index(tampered, []byte(windowsinstallercompat.Identity))
			if offset < 0 || bytes.Count(tampered, []byte(windowsinstallercompat.Identity)) != 1 {
				t.Fatal("Windows installer does not contain exactly one compatibility frame")
			}
			tampered[offset] ^= 1
			if _, err := InspectWindows(tampered, arch); err == nil {
				t.Fatal("Windows installer with a malformed compatibility frame was accepted")
			}
		})
	}
}

func TestInspectWindowsStandaloneVerifierPE(t *testing.T) {
	identity := meshbuildinfo.IdentityInfo{
		Schema: meshbuildinfo.Schema, Version: "1.2.3", Commit: "0123456789012345678901234567890123456789",
		BuildTime: "2026-07-21T00:00:00Z", SecurityFloor: 1,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion,
	}
	identityFrame, err := meshbuildinfo.EncodeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	authenticodeFrame, authenticodePolicy := windowsInspectorAuthenticode(t)
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "mesh-bootstrap-verify.exe")
			command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", "-buildid= -X mesh/internal/buildinfo.Identity="+identityFrame+" -X mesh/internal/windowsauthenticode.Identity="+authenticodeFrame, "-o", output, "./cmd/mesh-bootstrap-verify")
			command.Dir = repositoryRoot
			command.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
			if combined, err := command.CombinedOutput(); err != nil {
				t.Fatalf("build Windows standalone verifier: %v\n%s", err, combined)
			}
			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			inspection, err := InspectVerifier(raw, "windows", arch)
			if err != nil {
				t.Fatal(err)
			}
			if inspection.Identity != identity || inspection.GoVersion == "" || inspection.Authenticode.SHA256 != authenticodePolicy.SHA256 {
				t.Fatalf("Windows verifier inspection = %+v", inspection)
			}
			if _, err := InspectVerifier(raw, "linux", arch); err == nil {
				t.Fatal("Windows verifier accepted as Linux ELF")
			}
		})
	}
}

func windowsInspectorAuthenticode(t *testing.T) (string, windowsauthenticode.Policy) {
	t.Helper()
	frame, policy, err := windowsauthenticode.EncodePolicy(windowsauthenticode.PolicySpec{
		MeshSignerSPKISHA256:   []string{strings.Repeat("a", 64)},
		WintunSignerSPKISHA256: []string{strings.Repeat("b", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return frame, policy
}

func windowsInspectorTrust(t *testing.T) (string, installtrust.Bootstrap) {
	t.Helper()
	keys := make([]releasetrust.PublicKeyFile, 0, 4)
	for value := byte(1); value <= 4; value++ {
		privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
		publicFile, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, publicFile)
	}
	rootRaw, err := releasetrust.EncodeRoot(releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T00:00:00Z", ExpiresAt: "2027-07-20T00:00:00Z", Keys: keys,
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{keys[0].KeyID, keys[1].KeyID}},
			Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{keys[2].KeyID, keys[3].KeyID}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, bootstrap, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: rootRaw})
	if err != nil {
		t.Fatal(err)
	}
	return frame, bootstrap
}
