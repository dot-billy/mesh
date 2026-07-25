package linuxbundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mesh/internal/agentstate"
	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/installtrust"
	"mesh/internal/nebulaobserverartifact"
	releasetrust "mesh/internal/release"
	systemdassets "mesh/packaging/systemd"
)

const (
	testVersion = "1.2.3"
	testCommit  = "0123456789abcdef0123456789abcdef01234567"
	testEpoch   = int64(1752883200)
	testFloor   = uint64(2)
)

func TestProductionPolicyContainsExactTimeoutAbortCompatibilityMasks(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	policy, err := productionPolicy(arch)
	if err != nil {
		t.Fatal(err)
	}
	observerPolicy, observerPolicyDigest, err := nebulaobserverartifact.EmbeddedPolicy()
	if err != nil {
		t.Fatal(err)
	}
	wantNebula := NebulaIdentity{
		Version: observerPolicy.Version, UpstreamCommit: observerPolicy.Commit,
		UpstreamLockSHA256: observerPolicy.UpstreamLockSHA256, ObserverLockSHA256: observerPolicyDigest,
		SourceTreeSHA256: observerPolicy.SourceTreeSHA256, PatchedTreeSHA256: observerPolicy.PatchedTreeSHA256,
		PatchSetSHA256: observerPolicy.PatchSetSHA256, GoVersion: observerPolicy.Toolchain,
	}
	if policy.nebula != wantNebula {
		t.Fatalf("compiled Linux bundle observer provenance=%+v, want %+v", policy.nebula, wantNebula)
	}
	wantContent := systemdassets.TimeoutAbortCompatibilityMask()
	wantPaths := []string{
		"lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf",
		"lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf",
	}
	for _, path := range wantPaths {
		expectation, ok := policy.expectation[path]
		if !ok || expectation.kind != kindEmbedded || expectation.mode != 0o444 || !bytes.Equal(expectation.bytes, wantContent) {
			t.Fatalf("compiled policy does not bind exact compatibility mask %q: %+v", path, expectation)
		}
		foundPayload := false
		for _, spec := range payloadSpecs {
			if spec.path == path && spec.mode == 0o444 {
				foundPayload = true
				break
			}
		}
		if !foundPayload {
			t.Fatalf("deterministic payload omits compatibility mask %q", path)
		}
	}
	for _, directory := range []string{
		"lib/systemd/system/mesh-agent.service.d",
		"lib/systemd/system/mesh-nebula.service.d",
	} {
		found := false
		for _, path := range directoryPaths {
			if path == directory {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("deterministic directory policy omits %q", directory)
		}
	}
}

func TestProductionBuildAcceptsLockedObserverStage(t *testing.T) {
	stage := os.Getenv("MESH_NEBULA_OBSERVER_STAGE")
	if stage == "" {
		t.Skip("set MESH_NEBULA_OBSERVER_STAGE to an exact mesh-deps observer stage")
	}
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	contents := fixtureContents(t, arch)
	inputs := t.TempDir()
	meshInstall := filepath.Join(inputs, "mesh-install")
	meshctl := filepath.Join(inputs, "meshctl")
	if err := os.WriteFile(meshInstall, contents["bin/mesh-install"], 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meshctl, contents["bin/meshctl"], 0o500); err != nil {
		t.Fatal(err)
	}
	options := fixtureBuildOptions(arch, filepath.Join(t.TempDir(), "bundle.tar"))
	options.MeshInstallPath = meshInstall
	options.MeshctlPath = meshctl
	options.NebulaDirectory = stage
	result, err := Build(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Package.Schema != Schema || result.Package.Nebula.ObserverLockSHA256 == "" || result.Package.Nebula.PatchSetSHA256 == "" {
		t.Fatalf("production package omitted observer provenance: %+v", result.Package.Nebula)
	}
}

func TestDeterministicBuildStageAndDirectoryProof(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("test fixture is supported only on amd64 and arm64")
	}
	contents := fixtureContents(t, arch)
	policy := fixturePolicy(t, arch, contents)
	parent := t.TempDir()
	firstPath := filepath.Join(parent, "first.tar")
	secondPath := filepath.Join(parent, "second.tar")
	options := fixtureBuildOptions(arch, firstPath)
	first, err := buildWithPolicy(options, policy, contents)
	if err != nil {
		t.Fatal(err)
	}
	trustFrame, wantRootSHA := fixtureInstallerTrust(t)
	bootstrap, err := installtrust.ParseBootstrapIdentity(trustFrame)
	if err != nil {
		t.Fatal(err)
	}
	if first.Package.InstallerBootstrapRootSHA256 != wantRootSHA || first.Package.InstallerBootstrapRootSHA256 == bootstrap.LegacyPolicySHA256 {
		t.Fatalf("package trust identity = %q, root=%q legacy=%q", first.Package.InstallerBootstrapRootSHA256, wantRootSHA, bootstrap.LegacyPolicySHA256)
	}
	options.OutputPath = secondPath
	second, err := buildWithPolicy(options, policy, contents)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || first.SHA256 != second.SHA256 || first.PackageJSONSHA256 != second.PackageJSONSHA256 {
		t.Fatal("two builds from the same snapshots were not byte-reproducible")
	}
	if info, err := os.Stat(firstPath); err != nil || info.Mode().Perm() != 0o644 || info.Size() != int64(len(firstBytes)) || !singleLink(info) {
		t.Fatalf("published archive metadata is invalid: info=%v err=%v", info, err)
	}
	archive, err := os.Open(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(parent, "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyTree(t, stagePath)
	root, err := os.OpenRoot(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	expected := fixtureExpected(t, arch)
	staged, stageErr := stageWithPolicy(archive, root, expected, ArtifactIdentity{Size: first.Size, SHA256: first.SHA256}, policy)
	closeRootErr := root.Close()
	closeArchiveErr := archive.Close()
	if stageErr != nil || closeRootErr != nil || closeArchiveErr != nil {
		t.Fatalf("stage=%v close-root=%v close-archive=%v", stageErr, closeRootErr, closeArchiveErr)
	}
	if staged.PackageJSONSHA256 != first.PackageJSONSHA256 || staged.FileCount != len(payloadSpecs)+1 || staged.Package.Version != testVersion ||
		staged.Package.AgentStateReadMin != agentstate.CurrentSchemaVersion || staged.Package.AgentStateReadMax != agentstate.CurrentSchemaVersion ||
		staged.Package.AgentStateWriteVersion != agentstate.CurrentWriteVersion || staged.Package.Schema != Schema ||
		staged.Package.InstallerStateReadMin != installercompat.CurrentReadMinimum ||
		staged.Package.InstallerStateReadMax != installercompat.CurrentReadMaximum ||
		staged.Package.InstallerStateWriteVersion != installercompat.CurrentWriteVersion {
		t.Fatalf("unexpected stage result: %+v", staged)
	}
	if info, err := os.Stat(stagePath); err != nil || info.Mode().Perm() != directoryMode {
		t.Fatalf("stage root mode = %v, err=%v", info, err)
	}
	verified := verifyFixtureDirectory(t, stagePath, expected, policy)
	if verified.PackageJSONSHA256 != staged.PackageJSONSHA256 || verified.TotalBytes != staged.TotalBytes {
		t.Fatalf("directory proof = %+v, stage = %+v", verified, staged)
	}
}

func TestBuildDoesNotReplaceOutput(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	contents := fixtureContents(t, arch)
	policy := fixturePolicy(t, arch, contents)
	output := filepath.Join(t.TempDir(), "bundle.tar")
	options := fixtureBuildOptions(arch, output)
	if _, err := buildWithPolicy(options, policy, contents); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(output)
	if _, err := buildWithPolicy(options, policy, contents); err == nil {
		t.Fatal("existing output was replaced")
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(before, after) {
		t.Fatal("failed no-replace build changed existing output")
	}
}

func TestStageRejectsAdversarialUSTAR(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	archiveBytes, policy := fixtureArchive(t, arch)
	layout := inspectArchiveLayout(t, archiveBytes)
	firstPayload := layout[1]
	secondPayload := layout[2]
	paddingMember := layoutWithPadding(t, layout)

	tests := map[string]func([]byte) []byte{
		"path traversal": func(raw []byte) []byte {
			setTarString(raw[firstPayload.start:firstPayload.start+512], 0, 100, "../escape")
			recomputeTarChecksum(raw[firstPayload.start : firstPayload.start+512])
			return raw
		},
		"symlink": func(raw []byte) []byte {
			header := raw[firstPayload.start : firstPayload.start+512]
			header[156] = tar.TypeSymlink
			setTarString(header, 157, 257, "target")
			recomputeTarChecksum(header)
			return raw
		},
		"directory member": func(raw []byte) []byte {
			header := raw[firstPayload.start : firstPayload.start+512]
			header[156] = tar.TypeDir
			recomputeTarChecksum(header)
			return raw
		},
		"PAX member": func(raw []byte) []byte {
			header := raw[firstPayload.start : firstPayload.start+512]
			header[156] = tar.TypeXHeader
			recomputeTarChecksum(header)
			return raw
		},
		"GNU header": func(raw []byte) []byte {
			header := raw[firstPayload.start : firstPayload.start+512]
			copy(header[257:263], []byte("ustar "))
			copy(header[263:265], []byte(" \x00"))
			recomputeTarChecksum(header)
			return raw
		},
		"wrong mode": func(raw []byte) []byte {
			header := raw[firstPayload.start : firstPayload.start+512]
			setTarOctal(header[100:108], 0o755)
			recomputeTarChecksum(header)
			return raw
		},
		"duplicate member": func(raw []byte) []byte {
			copy(raw[secondPayload.start:secondPayload.start+512], raw[firstPayload.start:firstPayload.start+512])
			return raw
		},
		"out of order": func(raw []byte) []byte {
			prefix := append([]byte(nil), raw[:firstPayload.start]...)
			first := append([]byte(nil), raw[firstPayload.start:firstPayload.end]...)
			second := append([]byte(nil), raw[secondPayload.start:secondPayload.end]...)
			suffix := append([]byte(nil), raw[secondPayload.end:]...)
			return append(append(append(prefix, second...), first...), suffix...)
		},
		"payload hash": func(raw []byte) []byte {
			raw[firstPayload.start+512] ^= 0xff
			return raw
		},
		"nonzero padding": func(raw []byte) []byte {
			raw[paddingMember.start+512+int(paddingMember.size)] = 1
			return raw
		},
		"trailing byte":     func(raw []byte) []byte { return append(raw, 1) },
		"third zero block":  func(raw []byte) []byte { return append(raw, make([]byte, 512)...) },
		"truncated trailer": func(raw []byte) []byte { return raw[:len(raw)-512] },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]byte(nil), archiveBytes...))
			stagePath := filepath.Join(t.TempDir(), "stage")
			if err := os.Mkdir(stagePath, 0o700); err != nil {
				t.Fatal(err)
			}
			archivePath := filepath.Join(t.TempDir(), "candidate.tar")
			if err := os.WriteFile(archivePath, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			archive, _ := os.Open(archivePath)
			root, _ := os.OpenRoot(stagePath)
			_, err := stageWithPolicy(archive, root, fixtureExpected(t, arch), artifactIdentity(candidate), policy)
			_ = root.Close()
			_ = archive.Close()
			if err == nil {
				t.Fatal("adversarial archive was accepted")
			}
			entries, readErr := os.ReadDir(stagePath)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("failed stage left files behind: entries=%v err=%v", entries, readErr)
			}
			if info, statErr := os.Stat(stagePath); statErr != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("failed stage root mode = %v, err=%v", info, statErr)
			}
		})
	}
}

func TestStageUsesAlreadyOpenDescriptor(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	archiveBytes, policy := fixtureArchive(t, arch)
	parent := t.TempDir()
	archivePath := filepath.Join(parent, "bundle.tar")
	if err := os.WriteFile(archivePath, archiveBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(archivePath, filepath.Join(parent, "authenticated.tar")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(parent, "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyTree(t, stagePath)
	root, _ := os.OpenRoot(stagePath)
	result, stageErr := stageWithPolicy(archive, root, fixtureExpected(t, arch), artifactIdentity(archiveBytes), policy)
	_ = root.Close()
	_ = archive.Close()
	if stageErr != nil || result.Package.Version != testVersion {
		t.Fatalf("same-descriptor stage failed: result=%+v err=%v", result, stageErr)
	}
}

func TestStageRejectsMismatchedThresholdArtifactIdentity(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	archiveBytes, policy := fixtureArchive(t, arch)
	archivePath := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(archivePath, archiveBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	stagePath := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	wrong := artifactIdentity(archiveBytes)
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err := stageWithPolicy(archive, root, fixtureExpected(t, arch), wrong, policy); err == nil {
		t.Fatal("archive accepted under a different threshold-authenticated digest")
	}
	entries, err := os.ReadDir(stagePath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed digest rebind left stage residue: entries=%v err=%v", entries, err)
	}
}

func TestStrictPackageJSON(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	archiveBytes, _ := fixtureArchive(t, arch)
	layout := inspectArchiveLayout(t, archiveBytes)
	raw := append([]byte(nil), archiveBytes[layout[0].start+512:layout[0].start+512+int(layout[0].size)]...)
	cases := map[string][]byte{
		"duplicate": bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schema":"mesh-linux-node-bundle-v2","schema":`), 1),
		"unknown":   bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"unknown":true,"schema":`), 1),
		"trailing":  append(append([]byte(nil), raw...), []byte("{}")...),
		"UTF-8":     append(append([]byte(nil), raw...), 0xff),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePackage(candidate); err == nil {
				t.Fatal("non-strict package.json accepted")
			}
		})
	}
}

func TestMeshBinaryIdentityIsBound(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	contents := fixtureContents(t, arch)
	identity := fixtureIdentity(t)
	if _, err := verifyMeshBinary(contents["bin/mesh-install"], "mesh/cmd/mesh-install", arch, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMeshBinary(contents["bin/meshctl"], "mesh/cmd/meshctl", arch, identity); err != nil {
		t.Fatal(err)
	}
	wrong := identity
	wrong.Version = "1.2.4"
	if _, err := verifyMeshBinary(contents["bin/meshctl"], "mesh/cmd/meshctl", arch, wrong); err == nil {
		t.Fatal("binary accepted under a different package version")
	}
	wrong = identity
	wrong.AgentStateReadMin++
	if _, err := verifyMeshBinary(contents["bin/meshctl"], "mesh/cmd/meshctl", arch, wrong); err == nil {
		t.Fatal("binary accepted under a different agent-state compatibility range")
	}
	wrong = identity
	wrong.AgentStateWriteVersion++
	wrong.AgentStateReadMax++
	if _, err := verifyMeshBinary(contents["bin/meshctl"], "mesh/cmd/meshctl", arch, wrong); err == nil {
		t.Fatal("binary accepted under a different agent-state write version")
	}
	meshctlDigest := sha256.Sum256(contents["bin/meshctl"])
	stagedMetadata := Package{
		Version: identity.Version, Commit: identity.Commit, BuildTime: identity.BuildTime,
		SecurityFloor: identity.SecurityFloor, AgentStateReadMin: identity.AgentStateReadMin,
		AgentStateReadMax: identity.AgentStateReadMax + 1, GoVersion: runtime.Version(),
		AgentStateWriteVersion: identity.AgentStateWriteVersion,
		Entries:                []Entry{{Path: "bin/meshctl", Size: int64(len(contents["bin/meshctl"])), SHA256: hex.EncodeToString(meshctlDigest[:])}},
	}
	stagedPolicy := bundlePolicy{arch: arch, expectation: map[string]contentExpectation{"bin/meshctl": {kind: kindMeshctl}}}
	if err := stagedPolicy.validateContent("bin/meshctl", contents["bin/meshctl"], stagedMetadata); err == nil {
		t.Fatal("staged meshctl accepted package.json with a different agent-state compatibility range")
	}
	stagedMetadata.AgentStateReadMax = identity.AgentStateReadMax + 1
	stagedMetadata.AgentStateWriteVersion = identity.AgentStateWriteVersion + 1
	if err := stagedPolicy.validateContent("bin/meshctl", contents["bin/meshctl"], stagedMetadata); err == nil {
		t.Fatal("staged meshctl accepted package.json with a different agent-state write version")
	}
	if _, err := verifyMeshBinary(contents["bin/meshctl"], "mesh/cmd/mesh-install", arch, identity); err == nil {
		t.Fatal("meshctl accepted as mesh-install")
	}
	trust, err := inspectInstallerTrustBootstrapBytes(contents["bin/mesh-install"])
	if err != nil {
		t.Fatal(err)
	}
	_, expectedTrustSHA := fixtureInstallerTrust(t)
	if trust.InitialRootSHA256 != expectedTrustSHA {
		t.Fatalf("installer bootstrap-root SHA = %q, want %q", trust.InitialRootSHA256, expectedTrustSHA)
	}
	if err := rejectInstallerTrustFramesBytes(contents["bin/meshctl"]); err != nil {
		t.Fatal(err)
	}
	compatibility, err := inspectInstallerCompatibilityBytes(contents["bin/mesh-install"])
	if err != nil {
		t.Fatal(err)
	}
	if compatibility != installercompat.Supported() {
		t.Fatalf("installer compatibility = %+v, want %+v", compatibility, installercompat.Supported())
	}
	if err := rejectInstallerCompatibilityFramesBytes(contents["bin/meshctl"]); err != nil {
		t.Fatal(err)
	}
	tamperedInstaller := append([]byte(nil), contents["bin/mesh-install"]...)
	trustFrame, _ := fixtureInstallerTrust(t)
	offset := bytes.Index(tamperedInstaller, []byte(trustFrame))
	if offset < 0 {
		t.Fatal("fixture installer policy frame is absent")
	}
	tamperedInstaller[offset] ^= 1
	if _, err := inspectInstallerTrustBootstrapBytes(tamperedInstaller); err == nil {
		t.Fatal("bootstrap-less or malformed mesh-install was accepted")
	}
	tamperedCompatibility := append([]byte(nil), contents["bin/mesh-install"]...)
	offset = bytes.Index(tamperedCompatibility, []byte(installercompat.Identity))
	if offset < 0 {
		t.Fatal("fixture installer compatibility frame is absent")
	}
	tamperedCompatibility[offset] ^= 1
	if _, err := inspectInstallerCompatibilityBytes(tamperedCompatibility); err == nil {
		t.Fatal("compatibility-less or malformed mesh-install was accepted")
	}
}

func TestBuildSourcesAgentStateCompatibilityFromEquivalentMeshIdentities(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	contents := fixtureContents(t, arch)
	policy := fixturePolicy(t, arch, contents)
	original := fixtureIdentity(t)

	different := original
	different.AgentStateReadMin = 1
	contents["bin/mesh-install"] = replaceIdentityFrame(t, contents["bin/mesh-install"], original, different)
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, filepath.Join(t.TempDir(), "different.tar")), policy, contents); err == nil {
		t.Fatal("bundle accepted mesh-install and meshctl with different agent-state compatibility identities")
	}

	contents = fixtureContents(t, arch)
	policy = fixturePolicy(t, arch, contents)
	incompatible := original
	incompatible.AgentStateReadMax = agentstate.CurrentSchemaVersion + 1
	incompatible.AgentStateWriteVersion = agentstate.CurrentWriteVersion + 1
	for _, path := range []string{"bin/mesh-install", "bin/meshctl"} {
		contents[path] = replaceIdentityFrame(t, contents[path], original, incompatible)
	}
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, filepath.Join(t.TempDir(), "incompatible.tar")), policy, contents); err == nil {
		t.Fatal("bundle accepted a meshctl identity that claims a noncurrent agent-state write schema")
	}
}

func replaceIdentityFrame(t *testing.T, content []byte, from, to meshbuildinfo.IdentityInfo) []byte {
	t.Helper()
	oldFrame, err := meshbuildinfo.EncodeIdentity(from)
	if err != nil {
		t.Fatal(err)
	}
	newFrame, err := meshbuildinfo.EncodeIdentity(to)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldFrame) != len(newFrame) {
		t.Fatalf("test identities have different framed lengths: old=%d new=%d", len(oldFrame), len(newFrame))
	}
	if bytes.Count(content, []byte(oldFrame)) != 1 {
		t.Fatal("fixture binary does not contain exactly one source identity frame")
	}
	return bytes.Replace(append([]byte(nil), content...), []byte(oldFrame), []byte(newFrame), 1)
}

func TestPackageStateCompatibilityIsValidated(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	raw, _ := fixtureArchive(t, arch)
	layout := inspectArchiveLayout(t, raw)
	packageRaw := raw[layout[0].start+512 : layout[0].start+512+int(layout[0].size)]
	metadata, err := parsePackage(packageRaw)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Package){
		"zero minimum": func(value *Package) { value.AgentStateReadMin = 0 },
		"zero maximum": func(value *Package) { value.AgentStateReadMax = 0 },
		"zero writer":  func(value *Package) { value.AgentStateWriteVersion = 0 },
		"reversed range": func(value *Package) {
			value.AgentStateReadMin = 3
			value.AgentStateReadMax = 2
		},
		"writer below range": func(value *Package) {
			value.AgentStateReadMin = 2
			value.AgentStateWriteVersion = 1
		},
		"writer above range": func(value *Package) {
			value.AgentStateReadMax = 2
			value.AgentStateWriteVersion = 3
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePackage(metadata)
			mutate(&candidate)
			if _, err := validatePackage(candidate); err == nil {
				t.Fatal("invalid agent-state compatibility range accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Package){
		"zero installer minimum": func(value *Package) { value.InstallerStateReadMin = 0 },
		"zero installer maximum": func(value *Package) { value.InstallerStateReadMax = 0 },
		"zero installer writer":  func(value *Package) { value.InstallerStateWriteVersion = 0 },
		"reversed installer range": func(value *Package) {
			value.InstallerStateReadMin = 4
			value.InstallerStateReadMax = 3
		},
		"installer writer below range": func(value *Package) {
			value.InstallerStateReadMin = 3
			value.InstallerStateWriteVersion = 2
		},
		"installer writer above range": func(value *Package) {
			value.InstallerStateReadMax = 3
			value.InstallerStateWriteVersion = 4
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePackage(metadata)
			mutate(&candidate)
			if _, err := validatePackage(candidate); err == nil {
				t.Fatal("invalid installer-state compatibility range accepted")
			}
		})
	}

	expected := fixtureExpected(t, arch)
	if err := validateExpected(expected, metadata); err != nil {
		t.Fatal(err)
	}
	expected.InstallerStateSchemaVersion = 4
	if err := validateExpected(expected, metadata); err == nil {
		t.Fatal("package accepted an inherited installer-state schema outside its authenticated read range")
	}

	legacy := clonePackage(metadata)
	legacy.Schema = LegacySchema
	legacy.InstallerStateReadMin = 0
	legacy.InstallerStateReadMax = 0
	legacy.InstallerStateWriteVersion = 0
	legacyRaw, err := marshalPackage(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err = parsePackage(legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	expected.InstallerStateSchemaVersion = 3
	if err := validateExpected(expected, legacy); err != nil {
		t.Fatalf("exact legacy v2-to-v3 compatibility bridge failed: %v", err)
	}
	expected.InstallerStateSchemaVersion = 4
	if err := validateExpected(expected, legacy); err == nil {
		t.Fatal("legacy bundle without an authenticated contract crossed into installer-state v4")
	}

}

func TestDirectoryProofRejectsTamperingAndExtraLinks(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	tests := []string{"extra", "mode", "special-mode", "hash", "hardlink", "root-mode"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			stagePath, policy := stagedFixture(t, arch)
			switch name {
			case "extra":
				if err := os.Chmod(stagePath, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(stagePath, "extra"), []byte("x"), 0o444); err != nil {
					t.Fatal(err)
				}
				_ = os.Chmod(stagePath, directoryMode)
			case "mode":
				if err := os.Chmod(filepath.Join(stagePath, "bin/meshctl"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "special-mode":
				path := filepath.Join(stagePath, "bin/meshctl")
				if err := os.Chmod(path, 0o555|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
				if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSetuid == 0 {
					t.Fatalf("test setup did not set setuid bit: info=%v err=%v", info, err)
				}
			case "hash":
				path := filepath.Join(stagePath, "share/licenses/nebula/LICENSE")
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("changed"), 0o644); err != nil {
					t.Fatal(err)
				}
				_ = os.Chmod(path, 0o444)
			case "hardlink":
				if err := os.Link(filepath.Join(stagePath, "bin/meshctl"), filepath.Join(t.TempDir(), "other-link")); err != nil {
					t.Fatal(err)
				}
			case "root-mode":
				if err := os.Chmod(stagePath, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if name == "root-mode" {
				if _, err := VerifyStagedDirectory(stagePath, fixtureExpected(t, arch)); err == nil {
					t.Fatal("production directory verifier accepted wrong root mode")
				}
				return
			}
			if _, err := verifyFixtureDirectoryE(stagePath, fixtureExpected(t, arch), policy); err == nil {
				t.Fatal("directory tampering was accepted")
			}
		})
	}
}

func TestDirectoryProofRejectsInstallerBootstrapRootDrift(t *testing.T) {
	arch := runtime.GOARCH
	if !supportedArch(arch) {
		t.Skip("unsupported test host")
	}
	stagePath, policy := stagedFixture(t, arch)
	expected := fixtureExpected(t, arch)
	expected.InstallerBootstrapRootSHA256 = strings.Repeat("0", 64)
	if _, err := verifyFixtureDirectoryE(stagePath, expected, policy); err == nil {
		t.Fatal("staged installer with a different compiled bootstrap root was accepted")
	}
}

func TestSnapshotRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	link := filepath.Join(parent, "link")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotRegularFile(link, 1024); err == nil {
		t.Fatal("symlink input was snapshotted")
	}
}

type archiveMember struct {
	name       string
	start, end int
	size       int64
}

func fixtureArchive(t *testing.T, arch string) ([]byte, bundlePolicy) {
	t.Helper()
	contents := fixtureContents(t, arch)
	policy := fixturePolicy(t, arch, contents)
	output := filepath.Join(t.TempDir(), "bundle.tar")
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, output), policy, contents); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return raw, policy
}

func fixtureContents(t *testing.T, arch string) map[string][]byte {
	t.Helper()
	directory := t.TempDir()
	identityFrame, err := meshbuildinfo.EncodeIdentity(fixtureIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contents := make(map[string][]byte, len(payloadSpecs))
	for _, command := range []struct{ path, packagePath string }{
		{"bin/mesh-install", "./cmd/mesh-install"},
		{"bin/meshctl", "./cmd/meshctl"},
	} {
		output := filepath.Join(directory, filepath.Base(command.path))
		ldflags := "-s -w -X mesh/internal/buildinfo.Identity=" + identityFrame
		if command.path == "bin/mesh-install" {
			trustFrame, _ := fixtureInstallerTrust(t)
			ldflags += " -X mesh/internal/installtrust.Identity=" + trustFrame
		}
		build := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", output, command.packagePath)
		build.Dir = repositoryRoot
		build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if combined, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", command.path, err, combined)
		}
		content, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		contents[command.path] = content
	}
	for _, spec := range payloadSpecs {
		if _, exists := contents[spec.path]; !exists {
			contents[spec.path] = []byte("fixture payload for " + spec.path + "\n")
		}
	}
	return contents
}

func fixturePolicy(t *testing.T, arch string, contents map[string][]byte) bundlePolicy {
	t.Helper()
	policy := bundlePolicy{
		arch: arch,
		nebula: NebulaIdentity{
			Version: "v1.10.3", UpstreamCommit: strings.Repeat("a", 40),
			UpstreamLockSHA256: strings.Repeat("1", 64), ObserverLockSHA256: strings.Repeat("2", 64),
			SourceTreeSHA256: strings.Repeat("3", 64), PatchedTreeSHA256: strings.Repeat("4", 64),
			PatchSetSHA256: strings.Repeat("5", 64), GoVersion: runtime.Version(),
		},
		expectation: make(map[string]contentExpectation, len(payloadSpecs)),
	}
	for _, spec := range payloadSpecs {
		expectation := contentExpectation{mode: spec.mode}
		switch spec.path {
		case "bin/mesh-install":
			expectation.kind = kindMeshInstall
		case "bin/meshctl":
			expectation.kind = kindMeshctl
		default:
			expectation.kind = kindEmbedded
			expectation.bytes = append([]byte(nil), contents[spec.path]...)
			expectation.size = int64(len(contents[spec.path]))
			digest := sha256.Sum256(contents[spec.path])
			expectation.sha256 = hex.EncodeToString(digest[:])
		}
		policy.expectation[spec.path] = expectation
	}
	return policy
}

func fixtureIdentity(t *testing.T) meshbuildinfo.IdentityInfo {
	t.Helper()
	return meshbuildinfo.IdentityInfo{
		Schema: meshbuildinfo.Schema, Version: testVersion, Commit: testCommit,
		BuildTime: "2025-07-19T00:00:00Z", SecurityFloor: testFloor,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion,
	}
}

func fixtureBuildOptions(arch, output string) BuildOptions {
	return BuildOptions{
		Version: testVersion, Commit: testCommit, SourceDateEpoch: testEpoch,
		SecurityFloor: testFloor, Arch: arch, OutputPath: output,
	}
}

func fixtureExpected(t *testing.T, arch string) Expected {
	t.Helper()
	_, rootSHA := fixtureInstallerTrust(t)
	return Expected{
		Version: testVersion, OS: "linux", Arch: arch, MinimumSecurityFloor: testFloor,
		InstallerBootstrapRootSHA256: rootSHA,
		InstallerStateSchemaVersion:  3,
	}
}

func fixtureInstallerTrust(t *testing.T) (string, string) {
	t.Helper()
	keys := make([]releasetrust.PublicKeyFile, 0, 4)
	for value := byte(1); value <= 4; value++ {
		seed := bytes.Repeat([]byte{value}, ed25519.SeedSize)
		privateKey := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		publicFile, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		clear(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, publicFile)
	}
	rootRaw, err := releasetrust.EncodeRoot(releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2025-07-18T00:00:00Z", ExpiresAt: "2026-07-18T00:00:00Z",
		Keys: keys,
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
	return frame, bootstrap.InitialRootSHA256
}

func artifactIdentity(raw []byte) ArtifactIdentity {
	digest := sha256.Sum256(raw)
	return ArtifactIdentity{Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])}
}

func stagedFixture(t *testing.T, arch string) (string, bundlePolicy) {
	t.Helper()
	raw, policy := fixtureArchive(t, arch)
	archivePath := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	archive, _ := os.Open(archivePath)
	stagePath := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyTree(t, stagePath)
	root, _ := os.OpenRoot(stagePath)
	_, err := stageWithPolicy(archive, root, fixtureExpected(t, arch), artifactIdentity(raw), policy)
	_ = root.Close()
	_ = archive.Close()
	if err != nil {
		t.Fatal(err)
	}
	return stagePath, policy
}

func verifyFixtureDirectory(t *testing.T, path string, expected Expected, policy bundlePolicy) StageResult {
	t.Helper()
	result, err := verifyFixtureDirectoryE(path, expected, policy)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func verifyFixtureDirectoryE(path string, expected Expected, policy bundlePolicy) (StageResult, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return StageResult{}, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return StageResult{}, err
	}
	defer root.Close()
	raw, err := readRootedRegular(root, packageJSONPath, packageJSONMode, maxPackageJSONSize)
	if err != nil {
		return StageResult{}, err
	}
	metadata, err := parsePackage(raw)
	if err != nil {
		return StageResult{}, err
	}
	if err := validateExpected(expected, metadata); err != nil {
		return StageResult{}, err
	}
	return verifyDirectoryWithPolicy(root, info, expected, metadata, raw, policy)
}

func inspectArchiveLayout(t *testing.T, raw []byte) []archiveMember {
	t.Helper()
	var members []archiveMember
	offset := 0
	for offset+1024 <= len(raw) {
		if allZero(raw[offset : offset+512]) {
			break
		}
		header, err := parseHeaderBlock(raw[offset : offset+512])
		if err != nil {
			t.Fatal(err)
		}
		end := offset + 512 + int(paddedSize(header.Size))
		members = append(members, archiveMember{name: header.Name, start: offset, end: end, size: header.Size})
		offset = end
	}
	if len(members) != len(payloadSpecs)+1 {
		t.Fatalf("archive has %d members", len(members))
	}
	return members
}

func layoutWithPadding(t *testing.T, layout []archiveMember) archiveMember {
	t.Helper()
	for _, member := range layout {
		if paddedSize(member.size) != member.size {
			return member
		}
	}
	t.Fatal("fixture has no padded member")
	return archiveMember{}
}

func setTarString(header []byte, start, end int, value string) {
	for index := start; index < end; index++ {
		header[index] = 0
	}
	copy(header[start:end], value)
}

func setTarOctal(field []byte, value int64) {
	text := fmt.Sprintf("%0*o", len(field)-1, value)
	for index := range field {
		field[index] = 0
	}
	copy(field, text)
}

func recomputeTarChecksum(header []byte) {
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, value := range header {
		sum += int64(value)
	}
	copy(header[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
}

func cleanupReadOnlyTree(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
}
