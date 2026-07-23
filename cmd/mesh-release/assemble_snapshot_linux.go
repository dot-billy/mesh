//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"mesh/internal/linuxbundle"
	"mesh/internal/linuxinstall"
	releasetrust "mesh/internal/release"
)

const (
	snapshotChannelManifestName = "channel.json"
	snapshotReleaseManifestName = "release.json"
	snapshotArtifactName        = "mesh-linux-bundle.tar"
	snapshotFileMode            = 0o400
	snapshotDirectoryMode       = 0o700
)

type snapshotAssemblyOptions struct {
	outputPath            string
	rootUpdatePaths       []string
	channelManifestPath   string
	channelSignaturePaths []string
	releaseManifestPath   string
	releaseSignaturePaths []string
	artifactPath          string
}

// snapshotAssemblyHooks exposes deterministic race seams to this package's
// tests. Production uses no hooks.
type snapshotAssemblyHooks struct {
	afterInputRead func(path string)
	beforePublish  func()
}

func assembleSnapshot(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("assemble-snapshot", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new snapshot directory (created 0700, never overwritten)")
	channelManifest := flags.String("channel-manifest", "", "exact signed channel manifest")
	releaseManifest := flags.String("release-manifest", "", "exact signed release manifest")
	artifact := flags.String("artifact", "", "exact Linux bundle artifact")
	var rootUpdates repeatedFlag
	var channelSignatures repeatedFlag
	var releaseSignatures repeatedFlag
	flags.Var(&channelSignatures, "channel-signature", "detached channel signature envelope (repeat for each signer)")
	flags.Var(&releaseSignatures, "release-signature", "detached release signature envelope (repeat for each signer)")
	flags.Var(&rootUpdates, "root-update", "canonical root-update envelope to carry (repeat; sorted by root version)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("assemble-snapshot does not accept positional arguments")
	}
	options := snapshotAssemblyOptions{
		outputPath: *outputPath, rootUpdatePaths: append([]string(nil), rootUpdates...), channelManifestPath: *channelManifest,
		channelSignaturePaths: append([]string(nil), channelSignatures...),
		releaseManifestPath:   *releaseManifest,
		releaseSignaturePaths: append([]string(nil), releaseSignatures...),
		artifactPath:          *artifact,
	}
	path, err := assembleSnapshotUsing(options, snapshotAssemblyHooks{})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Assembled private Linux install snapshot %s. No metadata was trusted and no software was installed or started.\n", path)
	return err
}

type snapshotInputIdentity struct {
	device                   uint64
	inode                    uint64
	linkCount                uint64
	size                     int64
	ownerUID                 uint32
	ownerGID                 uint32
	mode                     uint32
	modificationTimeUnixNano int64
	changeTimeUnixNano       int64
}

type openedSnapshotInput struct {
	role     string
	path     string
	file     *os.File
	identity snapshotInputIdentity
	raw      []byte
	digest   [sha256.Size]byte
}

type snapshotInputSpec struct {
	role  string
	path  string
	limit int64
}

func assembleSnapshotUsing(options snapshotAssemblyOptions, hooks snapshotAssemblyHooks) (string, error) {
	if err := validateSnapshotAssemblyOptions(options); err != nil {
		return "", err
	}
	parentPath, targetName, targetPath, err := resolveSnapshotTarget(options.outputPath)
	if err != nil {
		return "", err
	}
	parent, err := openStableSnapshotParent(parentPath)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if err := requireSnapshotTargetAbsent(targetPath); err != nil {
		return "", err
	}

	specs := snapshotInputSpecs(options)
	inputs, err := openSnapshotInputs(specs)
	if err != nil {
		return "", err
	}
	defer closeSnapshotInputs(inputs)

	for _, input := range inputs {
		if !inputIsReadInMemory(input.role) {
			continue
		}
		input.raw, err = readStableSnapshotInput(input, hooks)
		if err != nil {
			return "", fmt.Errorf("read %s %q: %w", input.role, input.path, err)
		}
		if inputIsSignature(input.role) {
			input.digest = sha256.Sum256(input.raw)
		}
	}
	channelSignatures, releaseSignatures, err := sortedSnapshotSignatures(inputs)
	if err != nil {
		return "", err
	}
	rootUpdates, err := sortedSnapshotRootUpdates(inputs)
	if err != nil {
		return "", err
	}

	temporaryPath, err := os.MkdirTemp(parentPath, ".mesh-install-snapshot-")
	if err != nil {
		return "", fmt.Errorf("create private snapshot staging directory: %w", err)
	}
	temporaryName := filepath.Base(temporaryPath)
	removeTemporary := true
	// An ordinary error removes only the exact staging directory created by
	// this invocation. SIGKILL can leave that private directory behind; a later
	// run deliberately does not guess that an arbitrary same-prefix entry is
	// safe to delete.
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporaryPath)
			_ = parent.Sync()
		}
	}()
	if err := os.Chmod(temporaryPath, snapshotDirectoryMode); err != nil {
		return "", fmt.Errorf("set snapshot staging directory mode: %w", err)
	}
	stagedInfo, err := validateSnapshotOutputDirectory(temporaryPath)
	if err != nil {
		return "", err
	}

	channelManifest := findSnapshotInput(inputs, "channel manifest")
	releaseManifest := findSnapshotInput(inputs, "release manifest")
	artifact := findSnapshotInput(inputs, "Linux bundle artifact")
	if channelManifest == nil || releaseManifest == nil || artifact == nil {
		return "", errors.New("internal snapshot input classification failure")
	}
	rootUpdateNames := make([]string, len(rootUpdates))
	for index, update := range rootUpdates {
		name := fmt.Sprintf("root-update-%03d.json", index)
		if err := writeSnapshotBytes(temporaryPath, name, update.raw); err != nil {
			return "", err
		}
		rootUpdateNames[index] = name
	}
	if err := writeSnapshotBytes(temporaryPath, snapshotChannelManifestName, channelManifest.raw); err != nil {
		return "", err
	}
	channelNames := make([]string, len(channelSignatures))
	for index, signature := range channelSignatures {
		name := fmt.Sprintf("channel-signature-%03d.json", index+1)
		if err := writeSnapshotBytes(temporaryPath, name, signature.raw); err != nil {
			return "", err
		}
		channelNames[index] = name
	}
	if err := writeSnapshotBytes(temporaryPath, snapshotReleaseManifestName, releaseManifest.raw); err != nil {
		return "", err
	}
	releaseNames := make([]string, len(releaseSignatures))
	for index, signature := range releaseSignatures {
		name := fmt.Sprintf("release-signature-%03d.json", index+1)
		if err := writeSnapshotBytes(temporaryPath, name, signature.raw); err != nil {
			return "", err
		}
		releaseNames[index] = name
	}
	if err := writeSnapshotReader(temporaryPath, snapshotArtifactName, artifact.file, artifact.identity.size); err != nil {
		return "", fmt.Errorf("copy Linux bundle artifact %q: %w", artifact.path, err)
	}
	if hooks.afterInputRead != nil {
		hooks.afterInputRead(artifact.path)
	}
	if err := validateOpenedSnapshotInput(artifact); err != nil {
		return "", fmt.Errorf("Linux bundle artifact %q changed while copying: %w", artifact.path, err)
	}

	descriptor := linuxinstall.InstallSnapshotDescriptor{
		Schema: linuxinstall.InstallSnapshotSchema, RootUpdates: rootUpdateNames,
		ChannelManifest: snapshotChannelManifestName, ChannelSignatures: channelNames,
		ReleaseManifest: snapshotReleaseManifestName, ReleaseSignatures: releaseNames,
		Artifact: snapshotArtifactName,
	}
	descriptorRaw, err := linuxinstall.EncodeInstallSnapshotDescriptor(descriptor)
	if err != nil {
		return "", fmt.Errorf("encode install snapshot descriptor: %w", err)
	}
	if err := writeSnapshotBytes(temporaryPath, linuxinstall.InstallSnapshotFile, descriptorRaw); err != nil {
		return "", err
	}
	if err := validateAllSnapshotInputs(inputs); err != nil {
		return "", err
	}
	if err := syncSnapshotDirectory(temporaryPath); err != nil {
		return "", err
	}
	if err := validateAssembledSnapshot(temporaryPath, rootUpdates, channelManifest.raw, channelSignatures, releaseManifest.raw, releaseSignatures); err != nil {
		return "", err
	}
	if err := validateStableSnapshotParent(parentPath, parent); err != nil {
		return "", err
	}
	if hooks.beforePublish != nil {
		hooks.beforePublish()
	}
	if err := renameSnapshotNoReplace(int(parent.Fd()), temporaryName, targetName); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("refusing to overwrite existing snapshot directory %s", targetPath)
		}
		return "", fmt.Errorf("atomically publish snapshot: %w", err)
	}
	removeTemporary = false
	finalInfo, err := os.Lstat(targetPath)
	if err != nil || !os.SameFile(stagedInfo, finalInfo) || !finalInfo.IsDir() || finalInfo.Mode().Perm() != snapshotDirectoryMode || hasSnapshotSpecialMode(finalInfo.Mode()) {
		return "", errors.New("published snapshot directory identity or mode changed unexpectedly")
	}
	if err := parent.Sync(); err != nil {
		return "", fmt.Errorf("fsync snapshot parent directory after publication: %w", err)
	}
	return targetPath, nil
}

func validateSnapshotAssemblyOptions(options snapshotAssemblyOptions) error {
	if err := validateMetadataAssemblyOptions(
		options.outputPath,
		options.channelManifestPath,
		options.channelSignaturePaths,
		options.releaseManifestPath,
		options.releaseSignaturePaths,
	); err != nil {
		return err
	}
	if strings.TrimSpace(options.artifactPath) == "" {
		return errors.New("--artifact is required")
	}
	if len(options.rootUpdatePaths) > releasetrust.MaxRootUpdatesPerInput {
		return fmt.Errorf("--root-update count must not exceed %d", releasetrust.MaxRootUpdatesPerInput)
	}
	return nil
}

func validateMetadataAssemblyOptions(outputPath, channelManifestPath string, channelSignaturePaths []string, releaseManifestPath string, releaseSignaturePaths []string) error {
	required := []struct {
		name  string
		value string
	}{
		{"--output", outputPath},
		{"--channel-manifest", channelManifestPath},
		{"--release-manifest", releaseManifestPath},
	}
	for _, value := range required {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	if len(channelSignaturePaths) == 0 || len(channelSignaturePaths) > releasetrust.MaxSignatureEnvelopes {
		return fmt.Errorf("--channel-signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	if len(releaseSignaturePaths) == 0 || len(releaseSignaturePaths) > releasetrust.MaxSignatureEnvelopes {
		return fmt.Errorf("--release-signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	return nil
}

func snapshotInputSpecs(options snapshotAssemblyOptions) []snapshotInputSpec {
	specs := make([]snapshotInputSpec, 0, len(options.rootUpdatePaths)+3+len(options.channelSignaturePaths)+len(options.releaseSignaturePaths))
	for _, path := range options.rootUpdatePaths {
		specs = append(specs, snapshotInputSpec{role: "root update", path: path, limit: releasetrust.MaxRootUpdateSize})
	}
	specs = append(specs, metadataInputSpecs(options.channelManifestPath, options.channelSignaturePaths, options.releaseManifestPath, options.releaseSignaturePaths)...)
	return append(specs, snapshotInputSpec{role: "Linux bundle artifact", path: options.artifactPath, limit: linuxbundle.MaxArchiveSize})
}

func metadataInputSpecs(channelManifestPath string, channelSignaturePaths []string, releaseManifestPath string, releaseSignaturePaths []string) []snapshotInputSpec {
	specs := make([]snapshotInputSpec, 0, 2+len(channelSignaturePaths)+len(releaseSignaturePaths))
	specs = append(specs, snapshotInputSpec{role: "channel manifest", path: channelManifestPath, limit: releasetrust.MaxManifestSize})
	for _, path := range channelSignaturePaths {
		specs = append(specs, snapshotInputSpec{role: "channel signature", path: path, limit: releasetrust.MaxEnvelopeSize})
	}
	specs = append(specs, snapshotInputSpec{role: "release manifest", path: releaseManifestPath, limit: releasetrust.MaxManifestSize})
	for _, path := range releaseSignaturePaths {
		specs = append(specs, snapshotInputSpec{role: "release signature", path: path, limit: releasetrust.MaxEnvelopeSize})
	}
	return specs
}

func inputIsReadInMemory(role string) bool { return role != "Linux bundle artifact" }
func inputIsSignature(role string) bool {
	return role == "channel signature" || role == "release signature"
}

func resolveSnapshotTarget(requested string) (string, string, string, error) {
	absolute, err := filepath.Abs(requested)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve snapshot output: %w", err)
	}
	absolute = filepath.Clean(absolute)
	name := filepath.Base(absolute)
	if name == "." || name == string(filepath.Separator) {
		return "", "", "", errors.New("snapshot output must name a new child directory")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", "", "", fmt.Errorf("resolve snapshot output parent: %w", err)
	}
	parent = filepath.Clean(parent)
	if !filepath.IsAbs(parent) {
		return "", "", "", errors.New("snapshot output parent did not resolve to an absolute path")
	}
	return parent, name, filepath.Join(parent, name), nil
}

func openStableSnapshotParent(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect snapshot output parent: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("snapshot output parent must be a real directory")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open snapshot output parent: %w", err)
	}
	parent := os.NewFile(uintptr(fd), path)
	if parent == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open snapshot output parent descriptor")
	}
	after, statErr := parent.Stat()
	if statErr != nil || !os.SameFile(before, after) || !after.IsDir() {
		_ = parent.Close()
		return nil, errors.New("snapshot output parent changed while opening")
	}
	return parent, nil
}

func validateStableSnapshotParent(path string, parent *os.File) error {
	pathInfo, pathErr := os.Lstat(path)
	openedInfo, openedErr := parent.Stat()
	if pathErr != nil || openedErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("snapshot output parent changed before publication")
	}
	return nil
}

func requireSnapshotTargetAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("refusing to overwrite existing snapshot directory %s", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect snapshot output: %w", err)
	}
	return nil
}

func openSnapshotInputs(specs []snapshotInputSpec) ([]*openedSnapshotInput, error) {
	inputs := make([]*openedSnapshotInput, 0, len(specs))
	identities := make(map[[2]uint64]string, len(specs))
	for _, spec := range specs {
		input, err := openSnapshotInput(spec)
		if err != nil {
			closeSnapshotInputs(inputs)
			return nil, fmt.Errorf("open %s %q: %w", spec.role, spec.path, err)
		}
		key := [2]uint64{input.identity.device, input.identity.inode}
		if previous, duplicate := identities[key]; duplicate {
			_ = input.file.Close()
			closeSnapshotInputs(inputs)
			return nil, fmt.Errorf("input collision: %s %q is the same file as %s", spec.role, spec.path, previous)
		}
		identities[key] = fmt.Sprintf("%s %q", spec.role, spec.path)
		inputs = append(inputs, input)
	}
	return inputs, nil
}

func openSnapshotInput(spec snapshotInputSpec) (*openedSnapshotInput, error) {
	if strings.TrimSpace(spec.path) == "" {
		return nil, errors.New("path cannot be empty")
	}
	before, err := os.Lstat(spec.path)
	if err != nil {
		return nil, err
	}
	identity, ok := snapshotInputIdentityFromInfo(before)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file, not a symlink")
	}
	if identity.linkCount != 1 {
		return nil, errors.New("input regular file must have link count 1")
	}
	if identity.size <= 0 || identity.size > spec.limit {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", spec.limit)
	}
	fd, err := syscall.Open(spec.path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), spec.path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open input descriptor")
	}
	opened, statErr := file.Stat()
	if statErr != nil || !matchesSnapshotInputIdentity(identity, opened) {
		_ = file.Close()
		return nil, errors.New("input changed while opening without symlink following")
	}
	return &openedSnapshotInput{role: spec.role, path: spec.path, file: file, identity: identity}, nil
}

func readStableSnapshotInput(input *openedSnapshotInput, hooks snapshotAssemblyHooks) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(input.file, input.identity.size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != input.identity.size {
		return nil, errors.New("input was truncated or appended while reading")
	}
	if hooks.afterInputRead != nil {
		hooks.afterInputRead(input.path)
	}
	if err := validateOpenedSnapshotInput(input); err != nil {
		return nil, err
	}
	return raw, nil
}

func validateOpenedSnapshotInput(input *openedSnapshotInput) error {
	opened, openedErr := input.file.Stat()
	pathInfo, pathErr := os.Lstat(input.path)
	if openedErr != nil || pathErr != nil || !matchesSnapshotInputIdentity(input.identity, opened) || !matchesSnapshotInputIdentity(input.identity, pathInfo) {
		return errors.New("input identity, size, mode, ownership, link count, or timestamps changed")
	}
	return nil
}

func validateAllSnapshotInputs(inputs []*openedSnapshotInput) error {
	for _, input := range inputs {
		if err := validateOpenedSnapshotInput(input); err != nil {
			return fmt.Errorf("%s %q changed while assembling snapshot: %w", input.role, input.path, err)
		}
	}
	return nil
}

func snapshotInputIdentityFromInfo(info os.FileInfo) (snapshotInputIdentity, bool) {
	if info == nil {
		return snapshotInputIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return snapshotInputIdentity{}, false
	}
	return snapshotInputIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, linkCount: uint64(stat.Nlink), size: stat.Size,
		ownerUID: stat.Uid, ownerGID: stat.Gid, mode: stat.Mode,
		modificationTimeUnixNano: int64(stat.Mtim.Sec)*1e9 + int64(stat.Mtim.Nsec),
		changeTimeUnixNano:       int64(stat.Ctim.Sec)*1e9 + int64(stat.Ctim.Nsec),
	}, true
}

func matchesSnapshotInputIdentity(expected snapshotInputIdentity, info os.FileInfo) bool {
	actual, ok := snapshotInputIdentityFromInfo(info)
	return ok && actual == expected && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func closeSnapshotInputs(inputs []*openedSnapshotInput) {
	for _, input := range inputs {
		if input != nil && input.file != nil {
			_ = input.file.Close()
		}
	}
}

func sortedSnapshotSignatures(inputs []*openedSnapshotInput) ([]*openedSnapshotInput, []*openedSnapshotInput, error) {
	channel := make([]*openedSnapshotInput, 0)
	release := make([]*openedSnapshotInput, 0)
	seen := make(map[string]string)
	for _, input := range inputs {
		if !inputIsSignature(input.role) {
			continue
		}
		key := string(input.raw)
		if previous, duplicate := seen[key]; duplicate {
			return nil, nil, fmt.Errorf("signature envelope collision: %s %q is byte-identical to %s", input.role, input.path, previous)
		}
		seen[key] = fmt.Sprintf("%s %q", input.role, input.path)
		if input.role == "channel signature" {
			channel = append(channel, input)
		} else {
			release = append(release, input)
		}
	}
	less := func(values []*openedSnapshotInput) func(int, int) bool {
		return func(left, right int) bool {
			if compared := bytes.Compare(values[left].digest[:], values[right].digest[:]); compared != 0 {
				return compared < 0
			}
			return bytes.Compare(values[left].raw, values[right].raw) < 0
		}
	}
	sort.Slice(channel, less(channel))
	sort.Slice(release, less(release))
	return channel, release, nil
}

func sortedSnapshotRootUpdates(inputs []*openedSnapshotInput) ([]*openedSnapshotInput, error) {
	type versioned struct {
		input   *openedSnapshotInput
		version uint64
	}
	values := make([]versioned, 0)
	for _, input := range inputs {
		if input.role != "root update" {
			continue
		}
		update, err := releasetrust.ParseRootUpdate(input.raw)
		if err != nil {
			return nil, fmt.Errorf("parse root update %q: %w", input.path, err)
		}
		root, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil {
			return nil, fmt.Errorf("parse root update manifest %q: %w", input.path, err)
		}
		values = append(values, versioned{input: input, version: root.Document.Version})
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].version != values[right].version {
			return values[left].version < values[right].version
		}
		return bytes.Compare(values[left].input.raw, values[right].input.raw) < 0
	})
	result := make([]*openedSnapshotInput, len(values))
	for index, value := range values {
		if index > 0 {
			previous := values[index-1].version
			if value.version == previous {
				return nil, fmt.Errorf("duplicate root update version %d", value.version)
			}
			if previous == ^uint64(0) || value.version != previous+1 {
				return nil, fmt.Errorf("root update version %d does not continue version %d", value.version, previous)
			}
		}
		result[index] = value.input
	}
	return result, nil
}

func findSnapshotInput(inputs []*openedSnapshotInput, role string) *openedSnapshotInput {
	for _, input := range inputs {
		if input.role == role {
			return input
		}
	}
	return nil
}

func writeSnapshotBytes(directory, name string, raw []byte) error {
	return writeSnapshotReader(directory, name, bytes.NewReader(raw), int64(len(raw)))
}

func writeSnapshotReader(directory, name string, source io.Reader, expectedSize int64) (returnErr error) {
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, snapshotFileMode)
	if err != nil {
		return fmt.Errorf("create snapshot file %q: %w", name, err)
	}
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil && returnErr == nil {
				returnErr = fmt.Errorf("close snapshot file %q: %w", name, err)
			}
		}
	}()
	if err := file.Chmod(snapshotFileMode); err != nil {
		return fmt.Errorf("set snapshot file %q mode: %w", name, err)
	}
	written, err := io.Copy(file, io.LimitReader(source, expectedSize+1))
	if err != nil {
		return fmt.Errorf("write snapshot file %q: %w", name, err)
	}
	if written != expectedSize {
		return fmt.Errorf("snapshot source for %q changed size from %d to %d bytes", name, expectedSize, written)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("fsync snapshot file %q: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close snapshot file %q: %w", name, err)
	}
	closed = true
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect snapshot file %q: %w", name, err)
	}
	identity, ok := snapshotInputIdentityFromInfo(info)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != snapshotFileMode ||
		hasSnapshotSpecialMode(info.Mode()) || identity.ownerUID != uint32(os.Geteuid()) || identity.linkCount != 1 || identity.size != expectedSize {
		return fmt.Errorf("snapshot file %q does not have exact effective-user-owned single-link mode-0400 regular-file metadata", name)
	}
	return nil
}

func validateSnapshotOutputDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect snapshot staging directory: %w", err)
	}
	identity, ok := snapshotInputIdentityFromInfo(info)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != snapshotDirectoryMode ||
		hasSnapshotSpecialMode(info.Mode()) || identity.ownerUID != uint32(os.Geteuid()) {
		return nil, errors.New("snapshot staging directory must be an effective-user-owned real mode-0700 directory")
	}
	return info, nil
}

func hasSnapshotSpecialMode(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func syncSnapshotDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open snapshot staging directory for fsync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("fsync snapshot staging directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close snapshot staging directory: %w", err)
	}
	return nil
}

func validateAssembledSnapshot(directory string, rootUpdates []*openedSnapshotInput, channelManifest []byte, channelSignatures []*openedSnapshotInput, releaseManifest []byte, releaseSignatures []*openedSnapshotInput) error {
	snapshot, err := linuxinstall.OpenMetadataSnapshot(directory)
	if err != nil {
		return fmt.Errorf("read back assembled snapshot: %w", err)
	}
	if len(snapshot.RootUpdates) != len(rootUpdates) || !bytes.Equal(snapshot.Metadata.ChannelManifest, channelManifest) || !bytes.Equal(snapshot.Metadata.ReleaseManifest, releaseManifest) ||
		len(snapshot.Metadata.ChannelSignatures) != len(channelSignatures) || len(snapshot.Metadata.ReleaseSignatures) != len(releaseSignatures) ||
		filepath.Base(snapshot.Artifact.Path) != snapshotArtifactName {
		return errors.New("assembled snapshot readback did not preserve its exact inputs")
	}
	for index, update := range rootUpdates {
		if !bytes.Equal(snapshot.RootUpdates[index], update.raw) {
			return errors.New("assembled root-update readback changed exact bytes")
		}
	}
	for index, signature := range channelSignatures {
		if !bytes.Equal(snapshot.Metadata.ChannelSignatures[index], signature.raw) {
			return errors.New("assembled channel signature readback changed exact bytes")
		}
	}
	for index, signature := range releaseSignatures {
		if !bytes.Equal(snapshot.Metadata.ReleaseSignatures[index], signature.raw) {
			return errors.New("assembled release signature readback changed exact bytes")
		}
	}
	return nil
}
