package windowsbundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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
	"mesh/internal/nebulaartifact"
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
	for _, goos := range []string{"windows", "darwin", "freebsd"} {
		if err := requireBuildHost(goos); err == nil || !strings.Contains(err.Error(), "Linux packaging host") {
			t.Fatalf("host %q error = %v, want explicit Linux-host boundary", goos, err)
		}
	}
}

func TestProductionPolicySelectsExactWindowsPayload(t *testing.T) {
	lock, err := nebulaartifact.EmbeddedLock()
	if err != nil {
		t.Fatal(err)
	}
	lockDigest := sha256.Sum256(nebulasource.V1103Lock())
	for _, arch := range []string{"amd64", "arm64"} {
		arch := arch
		t.Run(arch, func(t *testing.T) {
			policy, err := productionPolicy(arch)
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := lock.Select("windows", arch)
			if err != nil {
				t.Fatal(err)
			}
			if policy.nebula != (NebulaIdentity{
				Version: lock.Version, LockSHA256: hex.EncodeToString(lockDigest[:]),
				AssetID: artifact.AssetID, AssetName: artifact.Name,
				ArchiveSize: artifact.Size, ArchiveSHA256: artifact.SHA256,
			}) {
				t.Fatalf("unexpected dependency identity: %+v", policy.nebula)
			}
			wantDLL := "bin/dist/windows/wintun/bin/" + arch + "/wintun.dll"
			if _, ok := policy.expectation[wantDLL]; !ok {
				t.Fatalf("selected Wintun DLL %q is absent", wantDLL)
			}
			other := "arm64"
			if arch == other {
				other = "amd64"
			}
			if _, ok := policy.expectation["bin/dist/windows/wintun/bin/"+other+"/wintun.dll"]; ok {
				t.Fatal("unselected Wintun DLL entered the bundle policy")
			}
			if got := policy.inputs[wantDLL]; got != "dist/windows/wintun/bin/"+arch+"/wintun.dll" {
				t.Fatalf("Wintun source = %q", got)
			}
			for _, required := range []string{
				"bin/dist/windows/wintun/LICENSE.txt", "bin/dist/windows/wintun/README.md",
				"bin/meshctl.exe", "bin/nebula-cert.exe", "bin/nebula.exe",
				"share/licenses/nebula/LICENSE",
			} {
				if _, ok := policy.expectation[required]; !ok {
					t.Fatalf("compiled policy missing %q", required)
				}
			}
			if !bytes.Equal(policy.expectation["share/licenses/nebula/LICENSE"].bytes, nebulasource.V1103License()) {
				t.Fatal("embedded Nebula license differs")
			}
		})
	}
	if _, err := productionPolicy("386"); err == nil {
		t.Fatal("unsupported Windows architecture accepted")
	}
}

func TestBuildIsDeterministicCanonicalUSTAR(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		arch := arch
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
			firstInfo, err := os.Lstat(firstPath)
			if err != nil || !exactRegularMode(firstInfo, 0o644) {
				t.Fatalf("published bundle mode/identity is not exact: info=%v err=%v", firstInfo, err)
			}
			secondBytes, err := os.ReadFile(secondPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstBytes, secondBytes) || first.SHA256 != second.SHA256 || first.Size != int64(len(firstBytes)) {
				t.Fatal("equivalent Windows staging bundles were not byte-for-byte deterministic")
			}
			if got := sha256Hex(firstBytes); got != first.SHA256 {
				t.Fatalf("bundle digest = %s, want %s", got, first.SHA256)
			}
			verifyArchive(t, firstBytes, first.Package, contents)
		})
	}
}

func TestCandidateArchiveCoreReturnsOwnedCanonicalExpansion(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	policy := fixturePolicy(arch, contents)
	output := filepath.Join(t.TempDir(), "candidate.tar")
	built, err := buildWithPolicy(fixtureBuildOptions(arch, output), policy, contents)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	inspection, packageJSON, expandedContents, err := inspectCandidateArchiveWithPolicy(raw, func(wantArch string) (bundlePolicy, error) {
		if wantArch != arch {
			t.Fatalf("policy requested architecture %q, want %q", wantArch, arch)
		}
		return policy, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ArtifactSHA256 != built.SHA256 || inspection.ArtifactSize != built.Size ||
		inspection.PackageJSONSHA256 != built.PackageJSONSHA256 {
		t.Fatalf("candidate inspection = %+v, build = %+v", inspection, built)
	}
	expanded := expandedCandidateFromParts(inspection, packageJSON, expandedContents)
	if len(expanded.Files) != len(contents)+1 || expanded.Files[0].Path != packageJSONPath ||
		expanded.Files[0].ArchiveMode != packageJSONArchiveMode || !bytes.Equal(expanded.Files[0].Content, packageJSON) {
		t.Fatalf("unexpected expanded candidate topology: %+v", expanded.Files)
	}
	for index, entry := range inspection.Package.Entries {
		file := expanded.Files[index+1]
		if file.Path != entry.Path || file.ArchiveMode != entry.ArchiveMode || !bytes.Equal(file.Content, contents[entry.Path]) {
			t.Fatalf("expanded file %d = %+v, want %q", index+1, file, entry.Path)
		}
	}
	wantFirst := append([]byte(nil), expanded.Files[0].Content...)
	for index := range raw {
		raw[index] = 0
	}
	if !bytes.Equal(expanded.Files[0].Content, wantFirst) {
		t.Fatal("expanded candidate aliases the caller's archive buffer")
	}
	if _, _, _, err := inspectCandidateArchiveWithPolicy(nil, func(string) (bundlePolicy, error) { return policy, nil }); err == nil {
		t.Fatal("empty candidate archive was accepted")
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
	inspection, err := ReconstructCandidateInspection(result.SHA256, packageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ArtifactSize != result.Size || inspection.PackageJSONSHA256 != result.PackageJSONSHA256 || inspection.FileCount != len(result.Package.Entries)+1 {
		t.Fatalf("reconstructed inspection = %+v", inspection)
	}
	changed := append([]byte(" "), packageJSON...)
	if _, err := ReconstructCandidateInspection(result.SHA256, changed); err == nil {
		t.Fatal("noncanonical published package metadata was accepted")
	}
}

func TestBuildDoesNotClobberOutput(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	policy := fixturePolicy(arch, contents)
	output := filepath.Join(t.TempDir(), "existing.tar")
	sentinel := []byte("do not replace\n")
	if err := os.WriteFile(output, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, output), policy, contents); err == nil {
		t.Fatal("existing output was accepted")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatal("existing output changed")
	}
}

func TestBuildDoesNotClobberSymlinkOrTraverseSymlinkedParent(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	policy := fixturePolicy(arch, contents)
	root := t.TempDir()
	target := filepath.Join(root, "target")
	sentinel := []byte("symlink target must remain unchanged\n")
	if err := os.WriteFile(target, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	outputLink := filepath.Join(root, "output.tar")
	if err := os.Symlink(target, outputLink); err != nil {
		t.Fatal(err)
	}
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, outputLink), policy, contents); err == nil {
		t.Fatal("existing output symlink was accepted")
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatalf("symlink target changed: content=%q err=%v", got, err)
	}

	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	throughLink := filepath.Join(linkedParent, "bundle.tar")
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, throughLink), policy, contents); err == nil {
		t.Fatal("symlinked output parent was accepted")
	}
	if _, err := os.Lstat(filepath.Join(realParent, "bundle.tar")); !os.IsNotExist(err) {
		t.Fatalf("symlinked parent received output: %v", err)
	}
}

func TestConcurrentBuildersPublishExactlyOnce(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	policy := fixturePolicy(arch, contents)
	parent := t.TempDir()
	output := filepath.Join(parent, "single-winner.tar")
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := buildWithPolicy(fixtureBuildOptions(arch, output), policy, contents)
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent publishers produced %d successes, want exactly one", successes)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(output) {
		t.Fatalf("publication left unexpected files: %+v", entries)
	}
}

func TestBuildRejectsNebulaTreeThatIsNotTheExactLockedTree(t *testing.T) {
	output := filepath.Join(t.TempDir(), "must-not-exist.tar")
	_, err := Build(BuildOptions{
		Version: testVersion, Commit: testCommit, SourceDateEpoch: testEpoch,
		SecurityFloor: testFloor, Arch: "amd64", MeshctlPath: filepath.Join(t.TempDir(), "missing-meshctl.exe"),
		NebulaDirectory: t.TempDir(), OutputPath: output,
	})
	if err == nil || !strings.Contains(err.Error(), "exact staged Nebula dependency tree") {
		t.Fatalf("Build error = %v, want exact locked-tree rejection", err)
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		t.Fatalf("rejected dependency tree left output: %v", statErr)
	}
}

func TestBuildRejectsIdentityAndAgentStateMismatch(t *testing.T) {
	arch := "amd64"
	tests := []struct {
		name     string
		identity meshbuildinfo.IdentityInfo
		options  func(*BuildOptions)
	}{
		{name: "version", identity: fixtureIdentity(), options: func(options *BuildOptions) { options.Version = "1.2.4" }},
		{name: "commit", identity: fixtureIdentity(), options: func(options *BuildOptions) { options.Commit = strings.Repeat("a", 40) }},
		{name: "security floor", identity: fixtureIdentity(), options: func(options *BuildOptions) { options.SecurityFloor++ }},
		{name: "cannot read current", identity: func() meshbuildinfo.IdentityInfo {
			identity := fixtureIdentity()
			identity.AgentStateReadMin = agentstate.CurrentSchemaVersion + 1
			identity.AgentStateReadMax = identity.AgentStateReadMin
			identity.AgentStateWriteVersion = identity.AgentStateReadMin
			return identity
		}()},
		{name: "wrong writer", identity: func() meshbuildinfo.IdentityInfo {
			identity := fixtureIdentity()
			identity.AgentStateReadMin = 1
			identity.AgentStateReadMax = agentstate.CurrentSchemaVersion + 1
			identity.AgentStateWriteVersion = agentstate.CurrentSchemaVersion + 1
			return identity
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := fixtureContents(t, arch, test.identity)
			policy := fixturePolicy(arch, contents)
			output := filepath.Join(t.TempDir(), "rejected.tar")
			options := fixtureBuildOptions(arch, output)
			if test.options != nil {
				test.options(&options)
			}
			if _, err := buildWithPolicy(options, policy, contents); err == nil {
				t.Fatal("identity mismatch was accepted")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected build left output: %v", err)
			}
		})
	}
}

func TestMeshPEVerification(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		content := fixtureMeshctl(t, arch, fixtureIdentity())
		version, err := verifyMeshBinary(content, "mesh/cmd/meshctl", arch, fixtureIdentity())
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if version == "" {
			t.Fatal("Go version is empty")
		}
		wrongArch := "arm64"
		if arch == wrongArch {
			wrongArch = "amd64"
		}
		if _, err := verifyMeshBinary(content, "mesh/cmd/meshctl", wrongArch, fixtureIdentity()); err == nil {
			t.Fatalf("%s PE accepted as %s", arch, wrongArch)
		}
		if _, err := verifyMeshBinary(content, "mesh/cmd/other", arch, fixtureIdentity()); err == nil {
			t.Fatal("wrong Mesh main package accepted")
		}
	}
}

func TestWintunPEEnvelopeChecksMachineAndDLL(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		content := append([]byte(nil), fixtureMeshctl(t, arch, fixtureIdentity())...)
		setPEDLLCharacteristic(t, content)
		if err := verifyWintunDLL(content, arch); err != nil {
			t.Fatalf("%s synthetic DLL: %v", arch, err)
		}
		wrong := "arm64"
		if arch == wrong {
			wrong = "amd64"
		}
		if err := verifyWintunDLL(content, wrong); err == nil {
			t.Fatal("wrong Wintun PE machine accepted")
		}
	}
}

func TestPackageJSONIsStrictCanonicalAndStagingOnly(t *testing.T) {
	arch := "amd64"
	contents := fixtureContents(t, arch, fixtureIdentity())
	output := filepath.Join(t.TempDir(), "bundle.tar")
	result, err := buildWithPolicy(fixtureBuildOptions(arch, output), fixturePolicy(arch, contents), contents)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalPackage(result.Package)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"schema":"mesh-windows-node-staging-bundle-v2"`)) || bytes.Contains(raw, []byte("installer")) {
		t.Fatalf("metadata implies unsupported installer behavior: %s", raw)
	}
	if _, err := parsePackage(raw); err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(raw, []byte(`"version":`), []byte(`"unknown":true,"version":`), 1)
	if _, err := parsePackage(unknown); err == nil {
		t.Fatal("unknown JSON field accepted")
	}
	duplicate := bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"1.2.3","version":`), 1)
	if _, err := parsePackage(duplicate); err == nil {
		t.Fatal("duplicate JSON field accepted")
	}
	indented := new(bytes.Buffer)
	if err := json.Indent(indented, bytes.TrimSpace(raw), "", "  "); err != nil {
		t.Fatal(err)
	}
	indented.WriteByte('\n')
	if _, err := parsePackage(indented.Bytes()); err == nil {
		t.Fatal("non-canonical JSON encoding accepted")
	}
	for name, candidate := range map[string][]byte{
		"leading whitespace": append([]byte("\n"), raw...),
		"trailing value":     append(append([]byte(nil), raw...), []byte("{}\n")...),
		"invalid UTF-8":      bytes.Replace(raw, []byte(`"version":"1.2.3"`), []byte{'"', 'v', 'e', 'r', 's', 'i', 'o', 'n', '"', ':', '"', 0xff, '"'}, 1),
		"unpaired surrogate": bytes.Replace(raw, []byte(`"version":"1.2.3"`), []byte(`"version":"\ud800"`), 1),
		"oversized package":  bytes.Repeat([]byte(" "), int(maxPackageJSONSize)+1),
	} {
		if _, err := parsePackage(candidate); err == nil {
			t.Fatalf("%s package.json accepted", name)
		}
	}
}

func verifyArchive(t *testing.T, raw []byte, metadata Package, contents map[string][]byte) {
	t.Helper()
	packageJSON, err := marshalPackage(metadata)
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) != wantSize {
		t.Fatalf("archive size = %d, want exact canonical size %d", len(raw), wantSize)
	}
	if len(raw) < 2*int(tarBlockSize) || !bytes.Equal(raw[len(raw)-2*int(tarBlockSize):], make([]byte, 2*int(tarBlockSize))) {
		t.Fatal("archive does not end in canonical zero trailer blocks")
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	wantNames := []string{packageJSONPath}
	wantModes := map[string]int64{packageJSONPath: packageJSONArchiveMode}
	for _, spec := range payloadSpecs(metadata.Target.Arch) {
		wantNames = append(wantNames, spec.path)
		wantModes[spec.path] = int64(spec.archiveMode)
	}
	for index, want := range wantNames {
		header, err := reader.Next()
		if err != nil {
			t.Fatalf("member %d: %v", index, err)
		}
		if header.Name != want || header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg ||
			header.Mode != wantModes[want] || header.Uid != 0 || header.Gid != 0 || header.Uname != "" ||
			header.Gname != "" || header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 ||
			!header.ModTime.Equal(timeFromEpoch()) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
			len(header.PAXRecords) != 0 {
			t.Fatalf("non-canonical header: %+v", header)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if want == packageJSONPath {
			parsed, err := parsePackage(content)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Schema != Schema || parsed.Target != metadata.Target {
				t.Fatalf("unexpected parsed package: %+v", parsed)
			}
			continue
		}
		if !bytes.Equal(content, contents[want]) {
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
	contents["bin/meshctl.exe"] = fixtureMeshctl(t, arch, identity)
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
		nebula: NebulaIdentity{
			Version: "v1.10.3", LockSHA256: strings.Repeat("1", 64), AssetID: 123,
			AssetName: "nebula-windows-" + arch + ".zip", ArchiveSize: 456,
			ArchiveSHA256: strings.Repeat("2", 64),
		},
		runtime: RuntimeIdentity{
			Version: "v1.10.3", Commit: "f573e8a26695278f9d71587390fbfe0d0933aa21",
			UpstreamLockSHA256: strings.Repeat("3", 64), SourceBuildLockSHA256: strings.Repeat("4", 64),
			WindowsBuildLockSHA256: strings.Repeat("5", 64), SourceTreeSHA256: strings.Repeat("6", 64),
			PatchedTreeSHA256: strings.Repeat("7", 64), PatchSetSHA256: strings.Repeat("8", 64), GoVersion: "go1.26.5",
		},
		expectation: make(map[string]contentExpectation, len(payloadSpecs(arch))),
	}
	for _, spec := range payloadSpecs(arch) {
		expectation := contentExpectation{archiveMode: spec.archiveMode}
		if spec.path == "bin/meshctl.exe" {
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
	return BuildOptions{
		Version: testVersion, Commit: testCommit, SourceDateEpoch: testEpoch,
		SecurityFloor: testFloor, Arch: arch, OutputPath: output,
	}
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
	output := filepath.Join(directory, "meshctl.exe")
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ldflags := "-s -w -buildid= -X mesh/internal/buildinfo.Identity=" + frame
	command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", output, "./cmd/meshctl")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Windows meshctl/%s: %v\n%s", arch, err, combined)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	fixtureBinaries.Store(key, append([]byte(nil), content...))
	return content
}

func setPEDLLCharacteristic(t *testing.T, content []byte) {
	t.Helper()
	if len(content) < 0x40 {
		t.Fatal("PE fixture is too short")
	}
	peOffset := int(binary.LittleEndian.Uint32(content[0x3c:0x40]))
	characteristicsOffset := peOffset + 4 + 18
	if characteristicsOffset+2 > len(content) {
		t.Fatal("PE file header is outside fixture")
	}
	value := binary.LittleEndian.Uint16(content[characteristicsOffset : characteristicsOffset+2])
	binary.LittleEndian.PutUint16(content[characteristicsOffset:characteristicsOffset+2], value|0x2000)
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func timeFromEpoch() time.Time { return time.Unix(testEpoch, 0).UTC() }
