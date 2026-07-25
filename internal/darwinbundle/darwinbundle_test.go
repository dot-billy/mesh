package darwinbundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/agentstate"
	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/nebulaobserverartifact"
	"mesh/packaging/launchd"
	nebulasource "mesh/third_party/nebula"
)

const (
	testVersion = "1.2.3"
	testCommit  = "0123456789012345678901234567890123456789"
	testEpoch   = int64(1752883200)
	testFloor   = uint64(2)
)

var fixtureBinaries sync.Map

func TestBuildHostBoundary(t *testing.T) {
	if err := requireBuildHost("linux"); err != nil {
		t.Fatalf("Linux packaging host rejected: %v", err)
	}
	for _, goos := range []string{"darwin", "windows", "freebsd"} {
		if err := requireBuildHost(goos); err == nil || !strings.Contains(err.Error(), "Linux packaging host") {
			t.Fatalf("host %q error = %v, want explicit Linux-host boundary", goos, err)
		}
	}
}

func TestProductionPolicySelectsExactDarwinPayload(t *testing.T) {
	wantPaths := []string{
		"Library/LaunchDaemons/io.mesh.node-agent.plist",
		"bin/meshctl", "bin/nebula", "bin/nebula-cert",
		"share/doc/mesh/launchd/README.md", "share/licenses/nebula/LICENSE",
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			policy, err := productionPolicy(arch)
			if err != nil {
				t.Fatal(err)
			}
			if policy.arch != arch || len(policy.expectation) != len(wantPaths) || len(policy.inputs) != 3 {
				t.Fatalf("incomplete darwin/%s policy: %+v", arch, policy)
			}
			target, err := nebulaobserverartifact.DarwinTargetLock(arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range wantPaths {
				if _, ok := policy.expectation[path]; !ok {
					t.Fatalf("compiled policy missing %q", path)
				}
			}
			for _, entry := range target.Entries {
				got := policy.expectation["bin/"+entry.Name]
				if got.size != entry.Size || got.sha256 != entry.SHA256 || got.archiveMode != 0o555 {
					t.Fatalf("runtime entry %q does not match output lock: %+v", entry.Name, got)
				}
			}
			if !bytes.Equal(policy.expectation["Library/LaunchDaemons/io.mesh.node-agent.plist"].bytes, launchd.NodeAgentPlist()) ||
				!bytes.Equal(policy.expectation["share/doc/mesh/launchd/README.md"].bytes, launchd.README()) ||
				!bytes.Equal(policy.expectation["share/licenses/nebula/LICENSE"].bytes, nebulasource.V1103License()) {
				t.Fatal("reviewed embedded Darwin assets differ from the compiled policy")
			}
		})
	}
	if _, err := productionPolicy("386"); err == nil {
		t.Fatal("unsupported Darwin architecture accepted")
	}
}

func TestBuildIsDeterministicCanonicalUSTAR(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			contents := fixtureContents(t, arch, fixtureIdentity())
			policy := fixturePolicy(arch, contents)
			firstPath := filepath.Join(t.TempDir(), "first.tar")
			secondPath := filepath.Join(t.TempDir(), "second.tar")
			first, err := buildWithPolicy(fixtureBuildOptions(arch, firstPath), policy, contents)
			if err != nil {
				t.Fatal(err)
			}
			second, err := buildWithPolicy(fixtureBuildOptions(arch, secondPath), policy, contents)
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
			if !bytes.Equal(firstBytes, secondBytes) || first.SHA256 != second.SHA256 || first.Size != int64(len(firstBytes)) {
				t.Fatal("equivalent Darwin staging bundles were not byte-for-byte deterministic")
			}
			if info, err := os.Lstat(firstPath); err != nil || !exactRegularMode(info, 0o644) {
				t.Fatalf("published bundle mode/identity is not exact: info=%v err=%v", info, err)
			}
			verifyArchive(t, firstBytes, first.Package, contents)
		})
	}
}

func TestPackageJSONIsStrictCanonicalAndStagingOnly(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	result, err := buildWithPolicy(fixtureBuildOptions(arch, filepath.Join(t.TempDir(), "bundle.tar")), fixturePolicy(arch, contents), contents)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalPackage(result.Package)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"schema":"mesh-darwin-node-staging-bundle-v1"`)) || bytes.Contains(raw, []byte("installer")) {
		t.Fatalf("metadata implies unsupported installer behavior: %s", raw)
	}
	for name, candidate := range map[string][]byte{
		"unknown field":      bytes.Replace(raw, []byte(`"version":`), []byte(`"unknown":true,"version":`), 1),
		"duplicate field":    bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"1.2.3","version":`), 1),
		"leading whitespace": append([]byte("\n"), raw...),
		"trailing value":     append(append([]byte(nil), raw...), []byte("{}\n")...),
		"invalid UTF-8":      bytes.Replace(raw, []byte(`"version":"1.2.3"`), []byte{'"', 'v', 'e', 'r', 's', 'i', 'o', 'n', '"', ':', '"', 0xff, '"'}, 1),
		"unpaired surrogate": bytes.Replace(raw, []byte(`"version":"1.2.3"`), []byte(`"version":"\ud800"`), 1),
	} {
		if _, err := parsePackage(candidate); err == nil {
			t.Fatalf("%s package.json accepted", name)
		}
	}
	indented := new(bytes.Buffer)
	if err := json.Indent(indented, bytes.TrimSpace(raw), "", "  "); err != nil {
		t.Fatal(err)
	}
	indented.WriteByte('\n')
	if _, err := parsePackage(indented.Bytes()); err == nil {
		t.Fatal("non-canonical JSON encoding accepted")
	}
}

func TestReconstructCandidateInspectionFromCanonicalPublishedMetadata(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	output := filepath.Join(t.TempDir(), "bundle.tar")
	result, err := buildWithPolicy(fixtureBuildOptions(arch, output), fixturePolicy(arch, contents), contents)
	if err != nil {
		t.Fatal(err)
	}
	packageJSON, err := marshalPackage(result.Package)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	inspection, err := ReconstructCandidateInspection(hex.EncodeToString(digest[:]), packageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ArtifactSize != int64(len(artifact)) || inspection.PackageJSONSHA256 == "" || inspection.FileCount != len(result.Package.Entries)+1 {
		t.Fatalf("reconstructed candidate inspection = %+v", inspection)
	}
	changed := append([]byte(nil), packageJSON...)
	changed = append([]byte(" "), changed...)
	if _, err := ReconstructCandidateInspection(inspection.ArtifactSHA256, changed); err == nil {
		t.Fatal("noncanonical published package metadata was accepted")
	}
}

func TestCandidateDirectoriesAreExact(t *testing.T) {
	want := []string{
		"Library", "bin", "share", "Library/LaunchDaemons", "share/doc", "share/licenses",
		"share/doc/mesh", "share/licenses/nebula", "share/doc/mesh/launchd",
	}
	if got := candidateDirectories("amd64"); !equalStrings(got, want) {
		t.Fatalf("candidate directories = %#v, want %#v", got, want)
	}
}

func verifyArchive(t *testing.T, raw []byte, metadata Package, contents map[string][]byte) {
	t.Helper()
	packageJSON, err := marshalPackage(metadata)
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil || int64(len(raw)) != wantSize {
		t.Fatalf("archive size = %d, want %d (err=%v)", len(raw), wantSize, err)
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	wantNames := []string{packageJSONPath}
	wantModes := map[string]int64{packageJSONPath: packageJSONArchiveMode}
	for _, spec := range payloadSpecs(metadata.Target.Arch) {
		wantNames = append(wantNames, spec.path)
		wantModes[spec.path] = int64(spec.archiveMode)
	}
	for _, want := range wantNames {
		header, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != want || header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg ||
			header.Mode != wantModes[want] || header.Uid != 0 || header.Gid != 0 || header.Uname != "" ||
			header.Gname != "" || header.Linkname != "" || !header.ModTime.Equal(time.Unix(testEpoch, 0).UTC()) ||
			!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || len(header.PAXRecords) != 0 {
			t.Fatalf("non-canonical header: %+v", header)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if want == packageJSONPath {
			if parsed, err := parsePackage(content); err != nil || parsed.Target != metadata.Target {
				t.Fatalf("invalid package.json: parsed=%+v err=%v", parsed, err)
			}
		} else if !bytes.Equal(content, contents[want]) {
			t.Fatalf("payload %q changed", want)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("archive has trailing member or malformed end: %v", err)
	}
}

func fixtureContents(t *testing.T, arch string, identity meshbuildinfo.IdentityInfo) map[string][]byte {
	t.Helper()
	contents := make(map[string][]byte, len(payloadSpecs(arch)))
	contents["bin/meshctl"] = fixtureMeshctl(t, arch, identity)
	for _, spec := range payloadSpecs(arch) {
		if _, exists := contents[spec.path]; !exists {
			contents[spec.path] = []byte("fixture payload for " + spec.path + "\n")
		}
	}
	return contents
}

func fixturePolicy(arch string, contents map[string][]byte) bundlePolicy {
	policy := bundlePolicy{
		arch: arch,
		runtime: RuntimeIdentity{
			Version: "v1.10.3", Commit: "f573e8a26695278f9d71587390fbfe0d0933aa21",
			UpstreamLockSHA256: strings.Repeat("1", 64), SourceBuildLockSHA256: strings.Repeat("2", 64),
			DarwinBuildLockSHA256: strings.Repeat("3", 64), SourceTreeSHA256: strings.Repeat("4", 64),
			PatchedTreeSHA256: strings.Repeat("5", 64), PatchSetSHA256: strings.Repeat("6", 64), GoVersion: "go1.26.5",
		},
		expectation: make(map[string]contentExpectation, len(payloadSpecs(arch))),
	}
	for _, spec := range payloadSpecs(arch) {
		expectation := contentExpectation{archiveMode: spec.archiveMode}
		if spec.path == "bin/meshctl" {
			expectation.kind = kindMeshctl
		} else {
			expectation.kind = kindEmbedded
			expectation.bytes = append([]byte(nil), contents[spec.path]...)
			expectation.size = int64(len(contents[spec.path]))
			expectation.sha256 = sha256Hex(contents[spec.path])
		}
		policy.expectation[spec.path] = expectation
	}
	return policy
}

func fixtureIdentity() meshbuildinfo.IdentityInfo {
	return meshbuildinfo.IdentityInfo{
		Schema: meshbuildinfo.Schema, Version: testVersion, Commit: testCommit,
		BuildTime: "2025-07-19T00:00:00Z", SecurityFloor: testFloor,
		AgentStateReadMin: agentstate.CurrentSchemaVersion, AgentStateReadMax: agentstate.CurrentSchemaVersion,
		AgentStateWriteVersion: agentstate.CurrentWriteVersion,
	}
}

func fixtureBuildOptions(arch, output string) BuildOptions {
	return BuildOptions{Version: testVersion, Commit: testCommit, SourceDateEpoch: testEpoch, SecurityFloor: testFloor, Arch: arch, OutputPath: output}
}

func fixtureMeshctl(t *testing.T, arch string, identity meshbuildinfo.IdentityInfo) []byte {
	t.Helper()
	frame, err := meshbuildinfo.EncodeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	key := arch + "\x00" + frame
	if cached, ok := fixtureBinaries.Load(key); ok {
		return append([]byte(nil), cached.([]byte)...)
	}
	directory := t.TempDir()
	output := filepath.Join(directory, "meshctl")
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ldflags := "-s -w -buildid= -X mesh/internal/buildinfo.Identity=" + frame
	command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", output, "./cmd/meshctl")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Darwin meshctl/%s: %v\n%s", arch, err, combined)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	fixtureBinaries.Store(key, append([]byte(nil), content...))
	return content
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
