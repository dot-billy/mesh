package windowsbundle

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
	"runtime"
	"strings"
	"time"

	"mesh/internal/agentstate"
	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/nebulaartifact"
	"mesh/internal/nebulaobserverartifact"
)

// Build creates one deterministic Windows node staging bundle at a new output
// path. The bundle is not an installer and applies no Windows security policy.
func Build(options BuildOptions) (BuildResult, error) {
	if err := requireBuildHost(runtime.GOOS); err != nil {
		return BuildResult{}, err
	}
	arch := strings.TrimSpace(options.Arch)
	policy, err := productionPolicy(arch)
	if err != nil {
		return BuildResult{}, err
	}
	if strings.TrimSpace(options.NebulaDirectory) == "" {
		return BuildResult{}, errors.New("Nebula staging directory is required")
	}
	if err := nebulaartifact.VerifyStagedDirectory(options.NebulaDirectory, "windows", arch); err != nil {
		return BuildResult{}, fmt.Errorf("verify exact staged Nebula dependency tree: %w", err)
	}
	if strings.TrimSpace(options.NebulaRuntimeDirectory) == "" {
		return BuildResult{}, errors.New("security-patched Nebula runtime staging directory is required")
	}
	if _, err := nebulaobserverartifact.VerifyWindowsStagedDirectory(options.NebulaRuntimeDirectory, arch); err != nil {
		return BuildResult{}, fmt.Errorf("verify exact security-patched Nebula runtime tree: %w", err)
	}
	// The complete tree verification above is intentionally not described as a
	// transactional tree anchor: selected files are reopened below. Every copied
	// upstream byte is nevertheless rechecked against its exact locked size and
	// SHA-256 before publication, so a pathname race cannot substitute different
	// bytes into the bundle.
	contents := make(map[string][]byte, len(payloadSpecs(arch)))
	for bundlePath, sourcePath := range policy.inputs {
		input := options.MeshctlPath
		expectation := policy.expectation[bundlePath]
		switch expectation.kind {
		case kindNebula, kindNebulaCert:
			input = filepath.Join(options.NebulaRuntimeDirectory, filepath.FromSlash(sourcePath))
		case kindMeshctl:
			// The explicit Mesh build remains the only non-dependency input.
		default:
			input = filepath.Join(options.NebulaDirectory, filepath.FromSlash(sourcePath))
		}
		if strings.TrimSpace(input) == "" {
			return BuildResult{}, fmt.Errorf("input path for %s is required", bundlePath)
		}
		content, err := snapshotRegularFile(input, maxPayloadFileSize)
		if err != nil {
			return BuildResult{}, fmt.Errorf("snapshot %s: %w", bundlePath, err)
		}
		contents[bundlePath] = content
	}
	for name, expectation := range policy.expectation {
		if expectation.kind == kindEmbedded {
			contents[name] = append([]byte(nil), expectation.bytes...)
		}
	}
	return buildWithPolicy(options, policy, contents)
}

func requireBuildHost(goos string) error {
	if goos != "linux" {
		return errors.New("Windows staging-bundle construction requires a Linux packaging host for exact POSIX staged-tree and publication-mode verification")
	}
	return nil
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
	specs := payloadSpecs(options.Arch)
	if len(contents) != len(specs) {
		return BuildResult{}, errors.New("staging-bundle content set is incomplete")
	}
	expectedIdentity, err := inspectMeshIdentityBytes(contents["bin/meshctl.exe"])
	if err != nil {
		return BuildResult{}, fmt.Errorf("inspect bin/meshctl.exe build identity: %w", err)
	}
	if expectedIdentity.Schema != meshbuildinfo.Schema || expectedIdentity.Version != options.Version ||
		expectedIdentity.Commit != options.Commit || expectedIdentity.BuildTime != buildTimeText ||
		expectedIdentity.SecurityFloor != options.SecurityFloor {
		return BuildResult{}, errors.New("bin/meshctl.exe compiled identity does not match requested package identity")
	}
	if expectedIdentity.AgentStateReadMin > agentstate.CurrentSchemaVersion ||
		expectedIdentity.AgentStateReadMax < agentstate.CurrentSchemaVersion {
		return BuildResult{}, fmt.Errorf("bin/meshctl.exe cannot read current agent-state schema %d", agentstate.CurrentSchemaVersion)
	}
	if expectedIdentity.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
		return BuildResult{}, fmt.Errorf("bin/meshctl.exe writes agent-state schema %d, want current schema %d", expectedIdentity.AgentStateWriteVersion, agentstate.CurrentWriteVersion)
	}
	goVersion, err := verifyMeshBinary(contents["bin/meshctl.exe"], "mesh/cmd/meshctl", policy.arch, expectedIdentity)
	if err != nil {
		return BuildResult{}, fmt.Errorf("validate bin/meshctl.exe: %w", err)
	}
	metadata := Package{
		Schema: Schema, Version: options.Version, Commit: options.Commit,
		BuildTime: buildTimeText, SecurityFloor: options.SecurityFloor,
		AgentStateReadMin: expectedIdentity.AgentStateReadMin, AgentStateReadMax: expectedIdentity.AgentStateReadMax,
		AgentStateWriteVersion: expectedIdentity.AgentStateWriteVersion,
		GoVersion:              goVersion, Target: Target{OS: "windows", Arch: policy.arch}, Nebula: policy.nebula,
		Runtime: policy.runtime,
		Entries: make([]Entry, 0, len(specs)),
	}
	var total int64
	for _, spec := range specs {
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
			Path: spec.path, ArchiveMode: spec.archiveMode,
			Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if _, err := validatePackage(metadata); err != nil {
		return BuildResult{}, err
	}
	if err := policy.validateMetadata(metadata); err != nil {
		return BuildResult{}, err
	}
	for _, spec := range specs {
		if err := policy.validateContent(spec.path, contents[spec.path], metadata); err != nil {
			return BuildResult{}, err
		}
	}
	return publishBundle(metadata, contents, options.OutputPath, buildTime)
}

func publishBundle(metadata Package, contents map[string][]byte, rawOutputPath string, buildTime time.Time) (BuildResult, error) {
	specs := payloadSpecs(metadata.Target.Arch)
	packageJSON, err := marshalPackage(metadata)
	if err != nil {
		return BuildResult{}, err
	}
	expectedSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil {
		return BuildResult{}, err
	}
	outputPath, parentPath, outputName, err := prepareOutputPath(rawOutputPath)
	if err != nil {
		return BuildResult{}, err
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
	temporaryName, err := randomName(".mesh-windows-bundle-")
	if err != nil {
		return BuildResult{}, err
	}
	temporary, err := root.OpenFile(temporaryName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return BuildResult{}, fmt.Errorf("create private staging-bundle output: %w", err)
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
	if err := writeMember(tarWriter, packageJSONPath, packageJSONArchiveMode, packageJSON, buildTime); err != nil {
		return BuildResult{}, err
	}
	for _, spec := range specs {
		if err := writeMember(tarWriter, spec.path, spec.archiveMode, contents[spec.path], buildTime); err != nil {
			return BuildResult{}, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return BuildResult{}, fmt.Errorf("finish canonical USTAR: %w", err)
	}
	info, err := temporary.Stat()
	if err != nil {
		return BuildResult{}, fmt.Errorf("inspect completed staging bundle: %w", err)
	}
	if info.Size() != expectedSize || info.Size() > MaxArchiveSize {
		return BuildResult{}, fmt.Errorf("canonical staging-bundle size is %d, want %d", info.Size(), expectedSize)
	}
	if err := temporary.Chmod(0o644); err != nil {
		return BuildResult{}, fmt.Errorf("set published staging-bundle transport mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return BuildResult{}, fmt.Errorf("sync completed staging bundle: %w", err)
	}
	if err := root.Link(temporaryName, outputName); err != nil {
		return BuildResult{}, fmt.Errorf("publish staging bundle without replacement: %w", err)
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
		return BuildResult{}, fmt.Errorf("sync staging-bundle publication: %w", err)
	}
	outputInfo, err := root.Lstat(outputName)
	currentInfo, currentErr := temporary.Stat()
	if err != nil || currentErr != nil || !exactRegularMode(outputInfo, 0o644) || !os.SameFile(outputInfo, currentInfo) {
		cleanupPublished()
		return BuildResult{}, errors.New("published staging-bundle identity or transport mode changed")
	}
	if err := root.Remove(temporaryName); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("remove private staging-bundle name: %w", err)
	}
	temporaryOwned = false
	if err := parentDirectory.Sync(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("sync private staging-bundle cleanup: %w", err)
	}
	finalInfo, err := root.Lstat(outputName)
	if err != nil || !exactRegularMode(finalInfo, 0o644) || finalInfo.Size() != expectedSize || !os.SameFile(currentInfo, finalInfo) {
		cleanupPublished()
		return BuildResult{}, errors.New("published staging-bundle final identity, transport mode, or size is invalid")
	}
	if err := temporary.Close(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("close completed staging bundle: %w", err)
	}
	published = false
	packageDigest := sha256.Sum256(packageJSON)
	return BuildResult{
		OutputPath: outputPath, Size: info.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil)),
		PackageJSONSHA256: hex.EncodeToString(packageDigest[:]), Package: clonePackage(metadata),
	}, nil
}

func prepareOutputPath(raw string) (outputPath, parentPath, outputName string, err error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", "", errors.New("output path is required")
	}
	outputPath, err = filepath.Abs(strings.TrimSpace(raw))
	if err != nil {
		return "", "", "", fmt.Errorf("resolve output path: %w", err)
	}
	outputPath = filepath.Clean(outputPath)
	parentPath, outputName = filepath.Split(outputPath)
	parentPath = filepath.Clean(parentPath)
	if outputName == "" || outputName == "." || outputName == ".." {
		return "", "", "", errors.New("output path must name a new regular file")
	}
	return outputPath, parentPath, outputName, nil
}

func snapshotRegularFile(name string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("input must be a bounded non-empty regular file, not a symlink")
	}
	file, err := os.Open(name)
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
	pathAfter, pathErr := os.Lstat(name)
	if statErr != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) ||
		after.Size() != int64(len(content)) || after.Mode() != opened.Mode() {
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

func exactRegularMode(info os.FileInfo, mode uint32) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() &&
		info.Mode().Perm() == os.FileMode(mode) && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
