package linuxbundle

import (
	"archive/tar"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mesh/internal/agentstate"
	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/nebulaobserverartifact"
)

// Build creates one deterministic Linux node bundle at a new output path.
func Build(options BuildOptions) (BuildResult, error) {
	policy, err := productionPolicy(strings.TrimSpace(options.Arch))
	if err != nil {
		return BuildResult{}, err
	}
	if strings.TrimSpace(options.NebulaDirectory) == "" {
		return BuildResult{}, errors.New("Nebula staging directory is required")
	}
	if _, err := nebulaobserverartifact.VerifyStagedDirectory(options.NebulaDirectory, policy.arch); err != nil {
		return BuildResult{}, fmt.Errorf("verify exact staged observer-enabled Nebula dependency: %w", err)
	}
	contents := make(map[string][]byte, len(payloadSpecs))
	inputs := map[string]string{
		"bin/mesh-install": options.MeshInstallPath,
		"bin/meshctl":      options.MeshctlPath,
		"bin/nebula":       filepath.Join(options.NebulaDirectory, "nebula"),
		"bin/nebula-cert":  filepath.Join(options.NebulaDirectory, "nebula-cert"),
	}
	for path, input := range inputs {
		if strings.TrimSpace(input) == "" {
			return BuildResult{}, fmt.Errorf("input path for %s is required", path)
		}
		content, err := snapshotRegularFile(input, maxPayloadFileSize)
		if err != nil {
			return BuildResult{}, fmt.Errorf("snapshot %s: %w", path, err)
		}
		contents[path] = content
	}
	for path, expectation := range policy.expectation {
		if expectation.kind == kindEmbedded {
			contents[path] = append([]byte(nil), expectation.bytes...)
		}
	}
	return buildWithPolicy(options, policy, contents)
}

func buildWithPolicy(options BuildOptions, policy bundlePolicy, contents map[string][]byte) (BuildResult, error) {
	options.Version = strings.TrimSpace(options.Version)
	options.Commit = strings.TrimSpace(options.Commit)
	options.Arch = strings.TrimSpace(options.Arch)
	if err := validateVersion(options.Version); err != nil {
		return BuildResult{}, fmt.Errorf("version: %w", err)
	}
	if !commitPattern.MatchString(options.Commit) {
		return BuildResult{}, errors.New("commit must be exactly 40 lowercase hexadecimal characters")
	}
	if options.SecurityFloor == 0 {
		return BuildResult{}, errors.New("security floor must be positive")
	}
	if options.Arch != policy.arch || !supportedArch(options.Arch) {
		return BuildResult{}, errors.New("build architecture does not match the compiled bundle policy")
	}
	buildTimeText, err := canonicalEpoch(options.SourceDateEpoch)
	if err != nil {
		return BuildResult{}, err
	}
	buildTime := time.Unix(options.SourceDateEpoch, 0).UTC()
	if len(contents) != len(payloadSpecs) {
		return BuildResult{}, errors.New("bundle content set is incomplete")
	}
	expectedIdentity, err := inspectMeshIdentityBytes(contents["bin/meshctl"])
	if err != nil {
		return BuildResult{}, fmt.Errorf("inspect bin/meshctl build identity: %w", err)
	}
	if expectedIdentity.Schema != meshbuildinfo.Schema || expectedIdentity.Version != options.Version ||
		expectedIdentity.Commit != options.Commit || expectedIdentity.BuildTime != buildTimeText ||
		expectedIdentity.SecurityFloor != options.SecurityFloor {
		return BuildResult{}, errors.New("bin/meshctl compiled identity does not match requested package identity")
	}
	if expectedIdentity.AgentStateReadMin > agentstate.CurrentSchemaVersion ||
		expectedIdentity.AgentStateReadMax < agentstate.CurrentSchemaVersion {
		return BuildResult{}, fmt.Errorf("bin/meshctl cannot read current agent-state schema %d", agentstate.CurrentSchemaVersion)
	}
	if expectedIdentity.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
		return BuildResult{}, fmt.Errorf("bin/meshctl writes agent-state schema %d, want current schema %d", expectedIdentity.AgentStateWriteVersion, agentstate.CurrentWriteVersion)
	}
	installVersion, err := verifyMeshBinary(contents["bin/mesh-install"], "mesh/cmd/mesh-install", policy.arch, expectedIdentity)
	if err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/mesh-install: %w", err)
	}
	installerCompatibility, err := inspectInstallerCompatibilityBytes(contents["bin/mesh-install"])
	if err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/mesh-install compatibility: %w", err)
	}
	if installerCompatibility != installercompat.Supported() {
		return BuildResult{}, fmt.Errorf("bin/mesh-install compatibility %+v differs from the release builder implementation %+v", installerCompatibility, installercompat.Supported())
	}
	ctlVersion, err := verifyMeshBinary(contents["bin/meshctl"], "mesh/cmd/meshctl", policy.arch, expectedIdentity)
	if err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/meshctl: %w", err)
	}
	if installVersion != ctlVersion {
		return BuildResult{}, errors.New("Mesh executables were built with different Go toolchain versions")
	}
	installerTrust, err := inspectInstallerTrustBootstrapBytes(contents["bin/mesh-install"])
	if err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/mesh-install trust bootstrap: %w", err)
	}
	if err := rejectInstallerTrustFramesBytes(contents["bin/meshctl"]); err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/meshctl trust separation: %w", err)
	}
	if err := rejectInstallerCompatibilityFramesBytes(contents["bin/meshctl"]); err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/meshctl compatibility separation: %w", err)
	}
	metadata := Package{
		Schema: Schema, Version: options.Version, Commit: options.Commit,
		BuildTime: buildTimeText, SecurityFloor: options.SecurityFloor,
		AgentStateReadMin: expectedIdentity.AgentStateReadMin, AgentStateReadMax: expectedIdentity.AgentStateReadMax,
		AgentStateWriteVersion:       expectedIdentity.AgentStateWriteVersion,
		InstallerStateReadMin:        installerCompatibility.ReadMinimum,
		InstallerStateReadMax:        installerCompatibility.ReadMaximum,
		InstallerStateWriteVersion:   installerCompatibility.WriteVersion,
		InstallerBootstrapRootSHA256: installerTrust.InitialRootSHA256, GoVersion: ctlVersion,
		Target: Target{OS: "linux", Arch: policy.arch}, Nebula: policy.nebula,
		Entries: make([]Entry, 0, len(payloadSpecs)),
	}
	var total int64
	for _, spec := range payloadSpecs {
		content, ok := contents[spec.path]
		if !ok || len(content) == 0 || int64(len(content)) > maxPayloadFileSize {
			return BuildResult{}, fmt.Errorf("payload %q is missing or outside the supported size bound", spec.path)
		}
		if total > maxPayloadSize-int64(len(content)) {
			return BuildResult{}, errors.New("payload exceeds aggregate size bound")
		}
		total += int64(len(content))
		digest := sha256.Sum256(content)
		metadata.Entries = append(metadata.Entries, Entry{
			Path: spec.path, Mode: spec.mode, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if _, err := validatePackage(metadata); err != nil {
		return BuildResult{}, err
	}
	if err := policy.validateMetadata(metadata); err != nil {
		return BuildResult{}, err
	}
	for _, spec := range payloadSpecs {
		if err := policy.validateContent(spec.path, contents[spec.path], metadata); err != nil {
			return BuildResult{}, err
		}
	}
	packageJSON, err := marshalPackage(metadata)
	if err != nil {
		return BuildResult{}, err
	}
	expectedSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil {
		return BuildResult{}, err
	}
	outputPath, err := filepath.Abs(strings.TrimSpace(options.OutputPath))
	if err != nil || strings.TrimSpace(options.OutputPath) == "" {
		return BuildResult{}, errors.New("output path is required")
	}
	outputPath = filepath.Clean(outputPath)
	parentPath, outputName := filepath.Split(outputPath)
	parentPath = filepath.Clean(parentPath)
	if outputName == "" || outputName == "." || outputName == ".." {
		return BuildResult{}, errors.New("output path must name a new regular file")
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return BuildResult{}, errors.New("output parent must be an existing real directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || filepath.Clean(resolvedParent) != parentPath {
		return BuildResult{}, errors.New("output parent path cannot traverse symlinks")
	}
	parentDirectory, err := os.Open(parentPath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("open output parent: %w", err)
	}
	defer parentDirectory.Close()
	openedParentInfo, err := parentDirectory.Stat()
	if err != nil || !os.SameFile(parentInfo, openedParentInfo) {
		return BuildResult{}, errors.New("output parent changed while opening")
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("anchor output parent: %w", err)
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(openedParentInfo, rootInfo) {
		return BuildResult{}, errors.New("output parent changed while anchoring")
	}
	if _, err := root.Lstat(outputName); err == nil {
		return BuildResult{}, fmt.Errorf("output %q already exists", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return BuildResult{}, fmt.Errorf("inspect output: %w", err)
	}
	temporaryName, err := randomName(".mesh-linux-bundle-")
	if err != nil {
		return BuildResult{}, err
	}
	temporary, err := root.OpenFile(temporaryName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return BuildResult{}, fmt.Errorf("create private bundle output: %w", err)
	}
	temporaryOwned := true
	defer func() {
		_ = temporary.Close()
		if temporaryOwned {
			_ = root.Remove(temporaryName)
		}
	}()
	hasher := sha256.New()
	tarWriter := tar.NewWriter(io.MultiWriter(temporary, hasher))
	if err := writeMember(tarWriter, packageJSONPath, packageJSONMode, packageJSON, buildTime); err != nil {
		return BuildResult{}, err
	}
	for _, spec := range payloadSpecs {
		if err := writeMember(tarWriter, spec.path, spec.mode, contents[spec.path], buildTime); err != nil {
			return BuildResult{}, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return BuildResult{}, fmt.Errorf("finish canonical USTAR: %w", err)
	}
	info, err := temporary.Stat()
	if err != nil {
		return BuildResult{}, fmt.Errorf("inspect completed bundle: %w", err)
	}
	if info.Size() != expectedSize || info.Size() > MaxArchiveSize {
		return BuildResult{}, fmt.Errorf("canonical bundle size is %d, want %d", info.Size(), expectedSize)
	}
	if err := temporary.Chmod(0o644); err != nil {
		return BuildResult{}, fmt.Errorf("set published bundle mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return BuildResult{}, fmt.Errorf("sync completed bundle: %w", err)
	}
	if err := root.Link(temporaryName, outputName); err != nil {
		return BuildResult{}, fmt.Errorf("publish bundle without replacement: %w", err)
	}
	published := true
	cleanupPublished := func() {
		if published {
			_ = root.Remove(outputName)
			_ = parentDirectory.Sync()
		}
	}
	if err := parentDirectory.Sync(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("sync bundle publication: %w", err)
	}
	outputInfo, err := root.Lstat(outputName)
	currentInfo, currentErr := temporary.Stat()
	if err != nil || currentErr != nil || !exactRegularMode(outputInfo, 0o644) || !os.SameFile(outputInfo, currentInfo) {
		cleanupPublished()
		return BuildResult{}, errors.New("published bundle identity or mode changed")
	}
	if err := root.Remove(temporaryName); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("remove private bundle staging name: %w", err)
	}
	temporaryOwned = false
	if err := parentDirectory.Sync(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("sync private bundle cleanup: %w", err)
	}
	finalInfo, err := root.Lstat(outputName)
	if err != nil || !exactRegularMode(finalInfo, 0o644) ||
		finalInfo.Size() != expectedSize || !singleLink(finalInfo) || !os.SameFile(currentInfo, finalInfo) {
		cleanupPublished()
		return BuildResult{}, errors.New("published bundle final identity, mode, size, or link count is invalid")
	}
	if err := temporary.Close(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("close completed bundle: %w", err)
	}
	published = false
	packageDigest := sha256.Sum256(packageJSON)
	return BuildResult{
		OutputPath: outputPath, Size: info.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil)),
		PackageJSONSHA256: hex.EncodeToString(packageDigest[:]), Package: clonePackage(metadata),
	}, nil
}

func snapshotRegularFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("input must be a bounded non-empty regular file, not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("input changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) || after.Size() != int64(len(content)) || after.Mode() != opened.Mode() {
		return nil, errors.New("input identity, size, or mode changed while snapshotting")
	}
	if int64(len(content)) > maximum {
		return nil, errors.New("input exceeds size bound")
	}
	return content, nil
}

func randomName(prefix string) (string, error) {
	var value [18]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate private staging name: %w", err)
	}
	return prefix + hex.EncodeToString(value[:]), nil
}
