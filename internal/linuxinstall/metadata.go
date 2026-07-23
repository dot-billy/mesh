//go:build linux

package linuxinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"

	releasetrust "mesh/internal/release"
)

const (
	// InstallSnapshotSchema identifies the unsigned, root-private locator used
	// to assemble one complete offline installation input. Authentication still
	// comes exclusively from the compiled installer policy and signed manifests.
	InstallSnapshotSchemaV1 = "mesh-linux-install-snapshot-v1"
	InstallSnapshotSchemaV2 = "mesh-linux-install-snapshot-v2"
	InstallSnapshotSchema   = InstallSnapshotSchemaV2
	InstallSnapshotFile     = "install.json"

	maxInstallSnapshotSize = 128 << 10
)

var snapshotBasenamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// InstallSnapshotDescriptor contains only rooted basenames. It deliberately
// has no digest, size, policy, clock, platform, or security-floor fields that
// an unsigned locator could use to influence authentication.
type InstallSnapshotDescriptor struct {
	Schema            string   `json:"schema"`
	RootUpdates       []string `json:"root_updates,omitempty"`
	ChannelManifest   string   `json:"channel_manifest"`
	ChannelSignatures []string `json:"channel_signatures"`
	ReleaseManifest   string   `json:"release_manifest"`
	ReleaseSignatures []string `json:"release_signatures"`
	Artifact          string   `json:"artifact"`
}

// SourceFileIdentity is an observed Linux inode identity. The artifact fields
// are informational and suitable for a subsequent same-source check, but they
// never replace the size and SHA-256 authenticated by CandidateMetadata.
type SourceFileIdentity struct {
	Device                   uint64
	Inode                    uint64
	LinkCount                uint64
	Size                     int64
	OwnerUID                 uint32
	Mode                     uint32
	ModificationTimeUnixNano int64
	ChangeTimeUnixNano       int64
}

type ArtifactSource struct {
	Path     string
	Identity SourceFileIdentity
}

// MetadataSnapshot owns copied metadata bytes only. Source descriptors are
// closed before it is returned. CaptureArtifact must later re-open and hash the
// artifact against the threshold-authenticated CandidateMetadata.Artifact.
type MetadataSnapshot struct {
	RootUpdates [][]byte
	Metadata    SignedMetadata
	Artifact    ArtifactSource
}

// EncodeInstallSnapshotDescriptor emits the one accepted install.json form:
// compact encoding/json field order followed by exactly one LF byte.
func EncodeInstallSnapshotDescriptor(descriptor InstallSnapshotDescriptor) ([]byte, error) {
	if err := validateInstallSnapshotDescriptor(descriptor); err != nil {
		return nil, err
	}
	var raw []byte
	var err error
	switch descriptor.Schema {
	case InstallSnapshotSchemaV1:
		raw, err = json.Marshal(struct {
			Schema            string   `json:"schema"`
			ChannelManifest   string   `json:"channel_manifest"`
			ChannelSignatures []string `json:"channel_signatures"`
			ReleaseManifest   string   `json:"release_manifest"`
			ReleaseSignatures []string `json:"release_signatures"`
			Artifact          string   `json:"artifact"`
		}{descriptor.Schema, descriptor.ChannelManifest, descriptor.ChannelSignatures, descriptor.ReleaseManifest, descriptor.ReleaseSignatures, descriptor.Artifact})
	case InstallSnapshotSchemaV2:
		raw, err = json.Marshal(struct {
			Schema            string   `json:"schema"`
			RootUpdates       []string `json:"root_updates"`
			ChannelManifest   string   `json:"channel_manifest"`
			ChannelSignatures []string `json:"channel_signatures"`
			ReleaseManifest   string   `json:"release_manifest"`
			ReleaseSignatures []string `json:"release_signatures"`
			Artifact          string   `json:"artifact"`
		}{descriptor.Schema, descriptor.RootUpdates, descriptor.ChannelManifest, descriptor.ChannelSignatures, descriptor.ReleaseManifest, descriptor.ReleaseSignatures, descriptor.Artifact})
	}
	if err != nil {
		return nil, fmt.Errorf("encode install snapshot descriptor: %w", err)
	}
	return append(raw, '\n'), nil
}

// OpenMetadataSnapshot anchors sourceDirectory once and snapshots the fixed
// install.json input. Production callers should first establish their
// privileged execution boundary; ownership is always checked against the
// process effective UID (therefore UID 0 in a privileged installer).
func OpenMetadataSnapshot(sourceDirectory string) (MetadataSnapshot, error) {
	if sourceDirectory == "" || !filepath.IsAbs(sourceDirectory) || filepath.Clean(sourceDirectory) != sourceDirectory {
		return MetadataSnapshot{}, errors.New("install snapshot directory must be a canonical absolute path")
	}
	resolved, err := filepath.EvalSymlinks(sourceDirectory)
	if err != nil || filepath.Clean(resolved) != sourceDirectory {
		return MetadataSnapshot{}, errors.New("install snapshot directory path cannot traverse symlinks")
	}
	root, err := os.OpenRoot(sourceDirectory)
	if err != nil {
		return MetadataSnapshot{}, fmt.Errorf("anchor install snapshot directory: %w", err)
	}
	defer root.Close()
	return openMetadataSnapshotAtRoot(root, uint32(os.Geteuid()), metadataSnapshotHooks{})
}

type metadataSnapshotHooks struct {
	// afterRead is a deterministic test-only race seam. It runs after bytes (or
	// artifact identity) are observed but before the descriptor/path is checked
	// again. Production never supplies it.
	afterRead func(name string)
}

type sourceSnapshot struct {
	name     string
	raw      []byte
	identity SourceFileIdentity
}

// openMetadataSnapshotAtRoot is the explicit rooted test seam. It does not
// accept policy, floor, platform, or time inputs.
func openMetadataSnapshotAtRoot(root *os.Root, expectedUID uint32, hooks metadataSnapshotHooks) (MetadataSnapshot, error) {
	if root == nil {
		return MetadataSnapshot{}, errors.New("install snapshot root is required")
	}
	rootBefore, rootPath, err := validateMetadataSnapshotRoot(root, expectedUID)
	if err != nil {
		return MetadataSnapshot{}, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return MetadataSnapshot{}, fmt.Errorf("open install snapshot directory descriptor: %w", err)
	}
	defer directory.Close()
	directoryInfo, err := directory.Stat()
	if err != nil || !stableSnapshotDirectory(rootBefore, directoryInfo, expectedUID) {
		return MetadataSnapshot{}, errors.New("install snapshot directory changed while opening")
	}

	records := make([]sourceSnapshot, 0, 5+releasetrust.MaxRootUpdatesPerInput)
	read := func(name string, maximum int64) ([]byte, error) {
		record, err := readSnapshotFile(root, int(directory.Fd()), name, maximum, expectedUID, hooks)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		return record.raw, nil
	}

	descriptorRaw, err := read(InstallSnapshotFile, maxInstallSnapshotSize)
	if err != nil {
		return MetadataSnapshot{}, fmt.Errorf("read %s: %w", InstallSnapshotFile, err)
	}
	descriptor, err := parseInstallSnapshotDescriptor(descriptorRaw)
	if err != nil {
		return MetadataSnapshot{}, err
	}
	if err := validateSnapshotTreeNames(directory, descriptor); err != nil {
		return MetadataSnapshot{}, err
	}
	rootUpdates := make([][]byte, len(descriptor.RootUpdates))
	var previousRootVersion uint64
	for index, name := range descriptor.RootUpdates {
		raw, err := read(name, releasetrust.MaxRootUpdateSize)
		if err != nil {
			return MetadataSnapshot{}, fmt.Errorf("read root update %d: %w", index, err)
		}
		update, err := releasetrust.ParseRootUpdate(raw)
		if err != nil {
			return MetadataSnapshot{}, fmt.Errorf("parse root update %d: %w", index, err)
		}
		root, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil {
			return MetadataSnapshot{}, fmt.Errorf("parse root update %d manifest: %w", index, err)
		}
		if index > 0 && (previousRootVersion == ^uint64(0) || root.Document.Version != previousRootVersion+1) {
			return MetadataSnapshot{}, fmt.Errorf("root update %d version %d does not continue version %d", index, root.Document.Version, previousRootVersion)
		}
		previousRootVersion = root.Document.Version
		rootUpdates[index] = raw
	}
	// Do not parse unauthenticated manifest or signature semantics here.
	// VerifySignedCandidate delegates those strict JSON checks to release after
	// the compiled threshold policy authenticates the exact copied bytes.
	channelManifest, err := read(descriptor.ChannelManifest, releasetrust.MaxManifestSize)
	if err != nil {
		return MetadataSnapshot{}, fmt.Errorf("read channel manifest: %w", err)
	}
	channelSignatures, err := readSnapshotSignatures(read, descriptor.ChannelSignatures, "channel")
	if err != nil {
		return MetadataSnapshot{}, err
	}
	releaseManifest, err := read(descriptor.ReleaseManifest, releasetrust.MaxManifestSize)
	if err != nil {
		return MetadataSnapshot{}, fmt.Errorf("read release manifest: %w", err)
	}
	releaseSignatures, err := readSnapshotSignatures(read, descriptor.ReleaseSignatures, "release")
	if err != nil {
		return MetadataSnapshot{}, err
	}
	artifact, err := inspectSnapshotFile(root, int(directory.Fd()), descriptor.Artifact, releasetrust.MaxArtifactSize, expectedUID, hooks)
	if err != nil {
		return MetadataSnapshot{}, fmt.Errorf("inspect artifact source: %w", err)
	}
	records = append(records, artifact)

	// Re-check every earlier source after all reads. This catches an entry or
	// inode mutated after its immediate post-read validation but before the
	// complete metadata set was assembled.
	for _, record := range records {
		current, err := root.Lstat(record.name)
		if err != nil || !matchesSourceIdentity(record.identity, current) {
			return MetadataSnapshot{}, fmt.Errorf("install snapshot source %q changed while assembling metadata", record.name)
		}
	}
	rootAfter, statErr := root.Stat(".")
	pathAfter, pathErr := os.Lstat(rootPath)
	resolved, resolveErr := filepath.EvalSymlinks(rootPath)
	if statErr != nil || pathErr != nil || resolveErr != nil || filepath.Clean(resolved) != rootPath ||
		!stableSnapshotDirectory(rootBefore, rootAfter, expectedUID) ||
		!stableSnapshotDirectory(rootBefore, pathAfter, expectedUID) {
		return MetadataSnapshot{}, errors.New("install snapshot directory changed while assembling metadata")
	}

	return MetadataSnapshot{
		RootUpdates: rootUpdates,
		Metadata: SignedMetadata{
			ChannelManifest: channelManifest, ChannelSignatures: channelSignatures,
			ReleaseManifest: releaseManifest, ReleaseSignatures: releaseSignatures,
		},
		Artifact: ArtifactSource{
			Path: filepath.Join(rootPath, descriptor.Artifact), Identity: artifact.identity,
		},
	}, nil
}

func validateSnapshotTreeNames(directory *os.File, descriptor InstallSnapshotDescriptor) error {
	if _, err := directory.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind install snapshot directory: %w", err)
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("list install snapshot directory: %w", err)
	}
	expected := make(map[string]struct{}, 4+len(descriptor.RootUpdates)+len(descriptor.ChannelSignatures)+len(descriptor.ReleaseSignatures))
	expected[InstallSnapshotFile] = struct{}{}
	expected[descriptor.ChannelManifest] = struct{}{}
	expected[descriptor.ReleaseManifest] = struct{}{}
	expected[descriptor.Artifact] = struct{}{}
	for _, name := range descriptor.RootUpdates {
		expected[name] = struct{}{}
	}
	for _, name := range descriptor.ChannelSignatures {
		expected[name] = struct{}{}
	}
	for _, name := range descriptor.ReleaseSignatures {
		expected[name] = struct{}{}
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("install snapshot contains %d entries, want exactly %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("install snapshot contains unexpected entry %q", entry.Name())
		}
	}
	return nil
}

func parseInstallSnapshotDescriptor(raw []byte) (InstallSnapshotDescriptor, error) {
	var descriptor InstallSnapshotDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return InstallSnapshotDescriptor{}, fmt.Errorf("parse %s: %w", InstallSnapshotFile, err)
	}
	canonical, err := EncodeInstallSnapshotDescriptor(descriptor)
	if err != nil {
		return InstallSnapshotDescriptor{}, fmt.Errorf("validate %s: %w", InstallSnapshotFile, err)
	}
	if !bytes.Equal(raw, canonical) {
		return InstallSnapshotDescriptor{}, fmt.Errorf("%s must use canonical compact JSON followed by one LF", InstallSnapshotFile)
	}
	return descriptor, nil
}

func validateInstallSnapshotDescriptor(descriptor InstallSnapshotDescriptor) error {
	switch descriptor.Schema {
	case InstallSnapshotSchemaV1:
		if descriptor.RootUpdates != nil {
			return errors.New("v1 install snapshot cannot carry root_updates")
		}
	case InstallSnapshotSchemaV2:
		if descriptor.RootUpdates == nil {
			return errors.New("v2 install snapshot requires root_updates, which may be an empty array")
		}
		if len(descriptor.RootUpdates) > releasetrust.MaxRootUpdatesPerInput {
			return fmt.Errorf("root update count must not exceed %d", releasetrust.MaxRootUpdatesPerInput)
		}
	default:
		return fmt.Errorf("unsupported install snapshot schema %q", descriptor.Schema)
	}
	if len(descriptor.ChannelSignatures) == 0 || len(descriptor.ChannelSignatures) > releasetrust.MaxSignatureEnvelopes {
		return fmt.Errorf("channel signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	if len(descriptor.ReleaseSignatures) == 0 || len(descriptor.ReleaseSignatures) > releasetrust.MaxSignatureEnvelopes {
		return fmt.Errorf("release signature count must be between 1 and %d", releasetrust.MaxSignatureEnvelopes)
	}
	names := make(map[string]string, 5+len(descriptor.RootUpdates)+len(descriptor.ChannelSignatures)+len(descriptor.ReleaseSignatures))
	names[InstallSnapshotFile] = "install snapshot descriptor"
	add := func(name, role string) error {
		if !snapshotBasenamePattern.MatchString(name) || name == "." || name == ".." || filepath.Base(name) != name {
			return fmt.Errorf("%s must be a canonical lowercase basename", role)
		}
		if previous, duplicate := names[name]; duplicate {
			return fmt.Errorf("%s repeats basename %q already used by %s", role, name, previous)
		}
		names[name] = role
		return nil
	}
	for index, name := range descriptor.RootUpdates {
		want := fmt.Sprintf("root-update-%03d.json", index)
		if name != want {
			return fmt.Errorf("root update %d basename must be %q", index, want)
		}
		if err := add(name, "root update"); err != nil {
			return err
		}
	}
	if err := add(descriptor.ChannelManifest, "channel manifest"); err != nil {
		return err
	}
	if err := add(descriptor.ReleaseManifest, "release manifest"); err != nil {
		return err
	}
	if err := add(descriptor.Artifact, "artifact"); err != nil {
		return err
	}
	if !sort.StringsAreSorted(descriptor.ChannelSignatures) || hasAdjacentDuplicate(descriptor.ChannelSignatures) {
		return errors.New("channel signature basenames must be strictly sorted")
	}
	for _, name := range descriptor.ChannelSignatures {
		if err := add(name, "channel signature"); err != nil {
			return err
		}
	}
	if !sort.StringsAreSorted(descriptor.ReleaseSignatures) || hasAdjacentDuplicate(descriptor.ReleaseSignatures) {
		return errors.New("release signature basenames must be strictly sorted")
	}
	for _, name := range descriptor.ReleaseSignatures {
		if err := add(name, "release signature"); err != nil {
			return err
		}
	}
	return nil
}

func hasAdjacentDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func readSnapshotSignatures(read func(string, int64) ([]byte, error), names []string, kind string) ([][]byte, error) {
	result := make([][]byte, 0, len(names))
	for _, name := range names {
		raw, err := read(name, releasetrust.MaxEnvelopeSize)
		if err != nil {
			return nil, fmt.Errorf("read %s signature %q: %w", kind, name, err)
		}
		result = append(result, raw)
	}
	return result, nil
}

func validateMetadataSnapshotRoot(root *os.Root, expectedUID uint32) (os.FileInfo, string, error) {
	rootPath := root.Name()
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, "", errors.New("install snapshot root must have a canonical absolute name")
	}
	resolved, resolveErr := filepath.EvalSymlinks(rootPath)
	pathInfo, pathErr := os.Lstat(rootPath)
	rootInfo, rootErr := root.Stat(".")
	if resolveErr != nil || filepath.Clean(resolved) != rootPath || pathErr != nil || rootErr != nil ||
		!stableSnapshotDirectory(pathInfo, rootInfo, expectedUID) {
		return nil, "", errors.New("install snapshot root must be an effective-user-owned real mode-0700 directory without special bits or symlink traversal")
	}
	return rootInfo, rootPath, nil
}

func stableSnapshotDirectory(before, after os.FileInfo, expectedUID uint32) bool {
	if before == nil || after == nil || !os.SameFile(before, after) || !after.IsDir() ||
		after.Mode()&os.ModeSymlink != 0 || after.Mode().Perm() != 0o700 ||
		after.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	beforeIdentity, beforeOK := sourceIdentity(before)
	afterIdentity, afterOK := sourceIdentity(after)
	return beforeOK && afterOK && beforeIdentity == afterIdentity && afterIdentity.OwnerUID == expectedUID
}

func readSnapshotFile(root *os.Root, directoryFD int, name string, maximum int64, expectedUID uint32, hooks metadataSnapshotHooks) (sourceSnapshot, error) {
	return openSnapshotFile(root, directoryFD, name, maximum, expectedUID, hooks, true)
}

func inspectSnapshotFile(root *os.Root, directoryFD int, name string, maximum int64, expectedUID uint32, hooks metadataSnapshotHooks) (sourceSnapshot, error) {
	return openSnapshotFile(root, directoryFD, name, maximum, expectedUID, hooks, false)
}

func openSnapshotFile(root *os.Root, directoryFD int, name string, maximum int64, expectedUID uint32, hooks metadataSnapshotHooks, readContent bool) (record sourceSnapshot, returnErr error) {
	before, err := root.Lstat(name)
	if err != nil {
		return sourceSnapshot{}, err
	}
	beforeIdentity, err := validateSnapshotSource(before, maximum, expectedUID)
	if err != nil {
		return sourceSnapshot{}, err
	}
	fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return sourceSnapshot{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return sourceSnapshot{}, errors.New("open source descriptor")
	}
	defer func() {
		if err := file.Close(); err != nil && returnErr == nil {
			returnErr = err
		}
	}()
	opened, err := file.Stat()
	if err != nil || !matchesSourceIdentity(beforeIdentity, opened) {
		return sourceSnapshot{}, errors.New("source changed while opening without symlink following")
	}
	var raw []byte
	if readContent {
		raw, err = io.ReadAll(io.LimitReader(file, maximum+1))
		if err != nil {
			return sourceSnapshot{}, err
		}
		if int64(len(raw)) != beforeIdentity.Size {
			return sourceSnapshot{}, errors.New("source was truncated, appended, or replaced while reading")
		}
	}
	if hooks.afterRead != nil {
		hooks.afterRead(name)
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !matchesSourceIdentity(beforeIdentity, after) || !matchesSourceIdentity(beforeIdentity, pathAfter) {
		return sourceSnapshot{}, errors.New("source identity, size, owner, mode, or timestamps changed while snapshotting")
	}
	return sourceSnapshot{name: name, raw: raw, identity: beforeIdentity}, nil
}

func validateSnapshotSource(info os.FileInfo, maximum int64, expectedUID uint32) (SourceFileIdentity, error) {
	identity, ok := sourceIdentity(info)
	permissions := info.Mode().Perm()
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		permissions&0o400 == 0 || permissions&0o133 != 0 ||
		identity.OwnerUID != expectedUID || identity.Size <= 0 || identity.Size > maximum ||
		identity.Mode&syscall.S_IFMT != syscall.S_IFREG || identity.LinkCount != 1 {
		return SourceFileIdentity{}, fmt.Errorf("source must be a non-empty bounded effective-user-owned single-link regular file without write access outside its owner, execute bits, or special bits")
	}
	return identity, nil
}

func sourceIdentity(info os.FileInfo) (SourceFileIdentity, bool) {
	if info == nil {
		return SourceFileIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return SourceFileIdentity{}, false
	}
	return SourceFileIdentity{
		Device: uint64(stat.Dev), Inode: stat.Ino, LinkCount: uint64(stat.Nlink),
		Size: stat.Size, OwnerUID: stat.Uid, Mode: stat.Mode,
		ModificationTimeUnixNano: int64(stat.Mtim.Sec)*1e9 + int64(stat.Mtim.Nsec),
		ChangeTimeUnixNano:       int64(stat.Ctim.Sec)*1e9 + int64(stat.Ctim.Nsec),
	}, true
}

func matchesSourceIdentity(expected SourceFileIdentity, info os.FileInfo) bool {
	actual, ok := sourceIdentity(info)
	return ok && actual == expected && actual.LinkCount == 1
}
