//go:build darwin

package darwininstall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/darwinbundle"
	"mesh/internal/installtrust"
	"mesh/internal/nodeagent"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"

	"golang.org/x/sys/unix"
)

const (
	darwinOfflineSnapshotDirectoryMode = uint16(0o700)
	darwinOfflineSnapshotFileMode      = uint16(0o400)
)

type darwinOfflineSnapshot struct {
	path              string
	directory         *os.File
	directoryFD       int
	directoryIdentity darwinInstallStatSnapshot
	bundle            onlinerelease.Bundle
	artifact          *os.File
	artifactIdentity  darwinInstallStatSnapshot
	closed            bool
}

// ImportProductionDarwinSnapshot authenticates one root-private offline
// snapshot through the same compiled trust, root history, replay state, and
// durable intake used by online installation. It then streams the exact local
// artifact into the existing immutable capture boundary without consulting
// any unsigned size, digest, platform, floor, time, or key field.
func (store *InstallerJournalStore) ImportProductionDarwinSnapshot(ctx context.Context, sourceDirectory string, now time.Time) (intake VerifiedDarwinIntake, capture *DarwinArtifactCapture, returnErr error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return intake, nil, fmt.Errorf("load compiled Darwin installer trust: %w", err)
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return intake, nil, fmt.Errorf("load compiled Darwin installer identity: %w", err)
	}
	return store.importDarwinSnapshotUsing(ctx, sourceDirectory, now, bootstrap, build)
}

func (store *InstallerJournalStore) importDarwinSnapshotUsing(ctx context.Context, sourceDirectory string, now time.Time, bootstrap installtrust.Bootstrap, build buildinfo.Info) (intake VerifiedDarwinIntake, capture *DarwinArtifactCapture, returnErr error) {
	if ctx == nil {
		return intake, nil, errors.New("Darwin offline snapshot import requires a context")
	}
	snapshot, err := openDarwinOfflineSnapshot(sourceDirectory)
	if err != nil {
		return intake, nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, snapshot.Close()) }()
	intake, err = store.authenticateDarwinCandidateUsing(snapshot.bundle, now, bootstrap, build)
	if err != nil {
		return VerifiedDarwinIntake{}, nil, fmt.Errorf("authenticate Darwin offline snapshot metadata: %w", err)
	}
	if snapshot.artifactIdentity.size != intake.Candidate.Artifact.Size {
		return VerifiedDarwinIntake{}, nil, errors.New("Darwin offline artifact size differs from the threshold-authenticated release")
	}
	capture, err = store.BeginAcceptedArtifactCapture(intake)
	if err != nil {
		return VerifiedDarwinIntake{}, nil, err
	}
	owned := true
	defer func() {
		if returnErr != nil && owned {
			returnErr = errors.Join(returnErr, capture.Close())
		}
	}()
	if capture.Path() != "" {
		if err := snapshot.copyArtifact(ctx, io.Discard, intake.Candidate.Artifact); err != nil {
			return VerifiedDarwinIntake{}, nil, err
		}
		owned = false
		return intake, capture, nil
	}
	destination, err := capture.Destination()
	if err != nil {
		return VerifiedDarwinIntake{}, nil, err
	}
	if err := snapshot.copyArtifact(ctx, destination, intake.Candidate.Artifact); err != nil {
		return VerifiedDarwinIntake{}, nil, err
	}
	if err := capture.Publish(); err != nil {
		return VerifiedDarwinIntake{}, nil, err
	}
	owned = false
	return intake, capture, nil
}

func openDarwinOfflineSnapshot(path string) (snapshot *darwinOfflineSnapshot, returnErr error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("Darwin offline snapshot import requires root:wheel execution")
	}
	if !cleanDarwinInstallPath(path) {
		return nil, errors.New("Darwin offline snapshot directory must be a canonical absolute path")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return nil, fmt.Errorf("authenticate Darwin offline snapshot path: %w", err)
	}
	var visibleBefore unix.Stat_t
	if err := unix.Lstat(path, &visibleBefore); err != nil {
		return nil, err
	}
	if err := validateDarwinOfflineSnapshotDirectoryStat(visibleBefore); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt Darwin offline snapshot directory descriptor")
	}
	ownedDirectory := true
	defer func() {
		if returnErr != nil && ownedDirectory {
			returnErr = errors.Join(returnErr, directory.Close())
		}
	}()
	var opened, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if err := unix.Lstat(path, &visibleAfter); err != nil {
		return nil, err
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(opened) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return nil, errors.New("Darwin offline snapshot directory changed while anchoring")
	}
	if err := validateDarwinOfflineSnapshotDirectoryStat(opened); err != nil {
		return nil, err
	}
	snapshot = &darwinOfflineSnapshot{path: path, directory: directory, directoryFD: fd, directoryIdentity: identity}
	descriptorRaw, err := snapshot.readFile(DarwinInstallSnapshotFile, maximumDarwinInstallSnapshotDescriptorSize)
	if err != nil {
		return nil, fmt.Errorf("read Darwin offline snapshot descriptor: %w", err)
	}
	if _, err := ParseDarwinInstallSnapshotDescriptor(descriptorRaw); err != nil {
		return nil, err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("list Darwin offline snapshot directory: %w", err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	wantNames := []string{DarwinInstallSnapshotArtifact, DarwinInstallSnapshotBundleFile, DarwinInstallSnapshotFile}
	sort.Strings(wantNames)
	if fmt.Sprint(names) != fmt.Sprint(wantNames) {
		return nil, fmt.Errorf("Darwin offline snapshot entries %v differ from the exact contract %v", names, wantNames)
	}
	bundleRaw, err := snapshot.readFile(DarwinInstallSnapshotBundleFile, onlinerelease.MaxEncodedBundleSize)
	if err != nil {
		return nil, fmt.Errorf("read Darwin offline release bundle: %w", err)
	}
	snapshot.bundle, err = onlinerelease.Parse(bundleRaw)
	if err != nil {
		return nil, fmt.Errorf("parse Darwin offline release bundle: %w", err)
	}
	snapshot.artifact, snapshot.artifactIdentity, err = snapshot.openFile(DarwinInstallSnapshotArtifact, darwinbundle.MaxArchiveSize)
	if err != nil {
		return nil, fmt.Errorf("open Darwin offline artifact: %w", err)
	}
	if err := snapshot.validateDirectory(); err != nil {
		_ = snapshot.artifact.Close()
		snapshot.artifact = nil
		return nil, err
	}
	ownedDirectory = false
	return snapshot, nil
}

func (snapshot *darwinOfflineSnapshot) readFile(name string, maximum int) (raw []byte, returnErr error) {
	file, identity, err := snapshot.openFile(name, int64(maximum))
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	raw, err = io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maximum || int64(len(raw)) != identity.size {
		return nil, fmt.Errorf("Darwin offline snapshot file %q changed size while reading", name)
	}
	if err := snapshot.validateFile(name, file, identity, int64(maximum)); err != nil {
		return nil, err
	}
	return raw, nil
}

func (snapshot *darwinOfflineSnapshot) openFile(name string, maximum int64) (*os.File, darwinInstallStatSnapshot, error) {
	if snapshot == nil || snapshot.closed || snapshot.directory == nil || snapshot.directoryFD < 0 {
		return nil, darwinInstallStatSnapshot{}, errors.New("Darwin offline snapshot is closed")
	}
	fullPath := filepath.Join(snapshot.path, name)
	if err := nodeagent.InspectDarwinSensitivePath(fullPath); err != nil {
		return nil, darwinInstallStatSnapshot{}, err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(snapshot.directoryFD, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, darwinInstallStatSnapshot{}, err
	}
	if err := validateDarwinOfflineSnapshotFileStat(visibleBefore, maximum); err != nil {
		return nil, darwinInstallStatSnapshot{}, fmt.Errorf("Darwin offline snapshot file %q: %w", name, err)
	}
	fd, err := unix.Openat(snapshot.directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, darwinInstallStatSnapshot{}, err
	}
	file := os.NewFile(uintptr(fd), fullPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, darwinInstallStatSnapshot{}, errors.New("adopt Darwin offline snapshot file descriptor")
	}
	var opened, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, err
	}
	if err := unix.Fstatat(snapshot.directoryFD, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, err
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(opened) || identity != snapshotDarwinInstallStat(visibleAfter) {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, fmt.Errorf("Darwin offline snapshot file %q changed while opening", name)
	}
	if err := nodeagent.InspectDarwinSensitivePath(fullPath); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, err
	}
	return file, identity, nil
}

func (snapshot *darwinOfflineSnapshot) validateFile(name string, file *os.File, expected darwinInstallStatSnapshot, maximum int64) error {
	if snapshot == nil || file == nil {
		return errors.New("Darwin offline snapshot file validation requires anchored descriptors")
	}
	var opened, visible unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(snapshot.directoryFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := validateDarwinOfflineSnapshotFileStat(opened, maximum); err != nil {
		return err
	}
	if err := validateDarwinOfflineSnapshotFileStat(visible, maximum); err != nil {
		return err
	}
	if expected != snapshotDarwinInstallStat(opened) || expected != snapshotDarwinInstallStat(visible) {
		return fmt.Errorf("Darwin offline snapshot file %q changed while in use", name)
	}
	return nodeagent.InspectDarwinSensitivePath(filepath.Join(snapshot.path, name))
}

func (snapshot *darwinOfflineSnapshot) copyArtifact(ctx context.Context, destination io.Writer, expected releasetrust.Artifact) error {
	if snapshot == nil || snapshot.closed || snapshot.artifact == nil {
		return errors.New("Darwin offline snapshot is closed")
	}
	if snapshot.artifactIdentity.size != expected.Size {
		return errors.New("Darwin offline artifact size differs from authenticated metadata")
	}
	if err := snapshot.validateFile(DarwinInstallSnapshotArtifact, snapshot.artifact, snapshot.artifactIdentity, expected.Size); err != nil {
		return err
	}
	if _, err := snapshot.artifact.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind Darwin offline artifact: %w", err)
	}
	if err := copyExactDarwinOfflineArtifact(ctx, snapshot.artifact, destination, expected); err != nil {
		return err
	}
	if err := snapshot.validateFile(DarwinInstallSnapshotArtifact, snapshot.artifact, snapshot.artifactIdentity, expected.Size); err != nil {
		return err
	}
	return snapshot.validateDirectory()
}

func (snapshot *darwinOfflineSnapshot) validateDirectory() error {
	if snapshot == nil || snapshot.closed || snapshot.directory == nil || snapshot.directoryFD < 0 {
		return errors.New("Darwin offline snapshot is closed")
	}
	var opened, visible unix.Stat_t
	if err := unix.Fstat(snapshot.directoryFD, &opened); err != nil {
		return err
	}
	if err := unix.Lstat(snapshot.path, &visible); err != nil {
		return err
	}
	if err := validateDarwinOfflineSnapshotDirectoryStat(opened); err != nil {
		return err
	}
	if err := validateDarwinOfflineSnapshotDirectoryStat(visible); err != nil {
		return err
	}
	if snapshot.directoryIdentity != snapshotDarwinInstallStat(opened) || snapshot.directoryIdentity != snapshotDarwinInstallStat(visible) {
		return errors.New("Darwin offline snapshot directory changed while in use")
	}
	return nodeagent.InspectDarwinSensitivePath(snapshot.path)
}

func validateDarwinOfflineSnapshotDirectoryStat(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != darwinOfflineSnapshotDirectoryMode || stat.Uid != 0 || stat.Gid != 0 || stat.Flags != 0 {
		return errors.New("Darwin offline snapshot must be an exact root:wheel mode-0700 real directory without file flags")
	}
	return nil
}

func validateDarwinOfflineSnapshotFileStat(stat unix.Stat_t, maximum int64) error {
	if maximum < 1 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != darwinOfflineSnapshotFileMode || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Flags != 0 || stat.Size < 1 || stat.Size > maximum {
		return errors.New("must be one bounded root:wheel single-link mode-0400 regular file without flags")
	}
	return nil
}

func (snapshot *darwinOfflineSnapshot) Close() error {
	if snapshot == nil || snapshot.closed {
		return nil
	}
	snapshot.closed = true
	var err error
	if snapshot.artifact != nil {
		err = errors.Join(err, snapshot.artifact.Close())
		snapshot.artifact = nil
	}
	if snapshot.directory != nil {
		err = errors.Join(err, snapshot.directory.Close())
		snapshot.directory = nil
	}
	snapshot.directoryFD = -1
	return err
}
