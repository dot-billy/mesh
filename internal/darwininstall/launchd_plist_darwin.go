//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"mesh/internal/darwinbundle"
	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	ProductionLaunchdDirectory = "/Library/LaunchDaemons"
	LaunchdPlistName           = "io.mesh.node-agent.plist"

	launchdPlistReleasePath = "Library/LaunchDaemons/" + LaunchdPlistName
	launchdPlistPendingName = ".io.mesh.node-agent.plist.mesh-pending"
	launchdPlistMode        = uint16(0o644)
	launchdPlistPendingMode = uint16(0o600)
	maximumLaunchdPlistSize = int64(64 << 10)
)

// LaunchdPlistPublisher owns one descriptor-anchored publication target and
// the exact plist bytes authenticated from a journal-bound immutable release.
type LaunchdPlistPublisher struct {
	mu sync.Mutex

	directoryPath string
	directory     *os.File
	fd            int
	identity      darwinInstallObjectIdentity
	expected      []byte
	closed        bool
}

type launchdPlistSnapshot struct {
	found    bool
	state    launchdPlistFileState
	mode     uint16
	contents []byte
	identity darwinInstallStatSnapshot
}

func NewProductionLaunchdPlistPublisher(layout *ReleaseLayout, installedID string, inspection darwinbundle.CandidateInspection) (*LaunchdPlistPublisher, error) {
	return NewLaunchdPlistPublisher(layout, installedID, inspection, ProductionLaunchdDirectory)
}

// NewLaunchdPlistPublisher authenticates the source release before anchoring
// the fixed destination directory. directoryPath is exposed for the root-only
// native fault harness; production callers use NewProductionLaunchdPlistPublisher.
func NewLaunchdPlistPublisher(layout *ReleaseLayout, installedID string, inspection darwinbundle.CandidateInspection, directoryPath string) (*LaunchdPlistPublisher, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("Darwin launchd plist publication requires root:wheel execution")
	}
	contents, err := readAuthenticatedLaunchdPlist(layout, installedID, inspection)
	if err != nil {
		return nil, err
	}
	if !cleanDarwinInstallPath(directoryPath) {
		return nil, errors.New("Darwin launchd directory must be an exact absolute non-root path")
	}
	directory, fd, stat, err := openDarwinManagedReleaseDirectory(directoryPath)
	if err != nil {
		return nil, err
	}
	publisher := &LaunchdPlistPublisher{
		directoryPath: directoryPath,
		directory:     directory,
		fd:            fd,
		identity:      darwinObjectIdentity(stat),
		expected:      append([]byte(nil), contents...),
	}
	if err := publisher.validateDirectoryLocked(); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return publisher, nil
}

func readAuthenticatedLaunchdPlist(layout *ReleaseLayout, installedID string, inspection darwinbundle.CandidateInspection) ([]byte, error) {
	if layout == nil {
		return nil, errors.New("Darwin release layout is required for launchd plist publication")
	}
	if err := darwinbundle.ValidateCandidateInspection(inspection); err != nil {
		return nil, err
	}
	if !darwinInstalledIDPattern.MatchString(installedID) || !strings.HasSuffix(installedID, "-a"+inspection.ArtifactSHA256[:16]) {
		return nil, errors.New("Darwin launchd plist release identity is not canonical")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return nil, err
	}
	if err := layout.validatePublishedReleaseLocked(installedID, inspection); err != nil {
		return nil, err
	}
	files, _, err := darwinReleaseExpectations(inspection)
	if err != nil {
		return nil, err
	}
	expectation, ok := files[launchdPlistReleasePath]
	if !ok || expectation.size < 1 || expectation.size > maximumLaunchdPlistSize || expectation.mode != 0o444 {
		return nil, errors.New("authenticated Darwin release has no bounded mode-0444 launchd plist")
	}
	return readDarwinReleaseFile(
		layout.releasesFD,
		layout.releasesPath,
		filepath.Join(installedID, launchdPlistReleasePath),
		expectation,
	)
}

func (publisher *LaunchdPlistPublisher) Publish() error {
	if publisher == nil {
		return errors.New("Darwin launchd plist publisher is required")
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := publisher.validateDirectoryLocked(); err != nil {
		return err
	}
	return publishLaunchdPlist(publisher)
}

func (publisher *LaunchdPlistPublisher) Inspect() error {
	if publisher == nil {
		return errors.New("Darwin launchd plist publisher is required")
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := publisher.validateDirectoryLocked(); err != nil {
		return err
	}
	return proveLaunchdPlist(publisher)
}

func (publisher *LaunchdPlistPublisher) InspectLive() (launchdPlistFileState, error) {
	snapshot, err := publisher.inspectFileLocked(LaunchdPlistName, false)
	return snapshot.state, err
}

func (publisher *LaunchdPlistPublisher) InspectPending() (launchdPlistFileState, error) {
	snapshot, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	return snapshot.state, err
}

func (publisher *LaunchdPlistPublisher) CreatePending() (returnErr error) {
	if err := publisher.validateDirectoryLocked(); err != nil {
		return err
	}
	snapshot, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if snapshot.found {
		return errors.New("Darwin launchd pending plist already exists")
	}
	fd, err := unix.Openat(publisher.fd, launchdPlistPendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(launchdPlistPendingMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(publisher.directoryPath, launchdPlistPendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin launchd pending-plist descriptor")
	}
	open := true
	defer func() {
		if open {
			returnErr = errors.Join(returnErr, file.Close())
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, uint32(launchdPlistPendingMode)); err != nil {
		return err
	}
	written, writeErr := file.Write(publisher.expected)
	if writeErr != nil || written != len(publisher.expected) {
		return errors.Join(writeErr, shortWriteError(written, len(publisher.expected)))
	}
	if err := file.Close(); err != nil {
		open = false
		return err
	}
	open = false
	created, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if !created.found || created.mode != launchdPlistPendingMode || !bytes.Equal(created.contents, publisher.expected) {
		return errors.New("Darwin launchd pending plist differs after creation")
	}
	return nil
}

func (publisher *LaunchdPlistPublisher) SyncPending() (returnErr error) {
	before, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if !before.found {
		return errors.New("Darwin launchd pending plist is absent before sync")
	}
	fd, err := unix.Openat(publisher.fd, launchdPlistPendingName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(publisher.directoryPath, launchdPlistPendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin launchd pending-plist sync descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if snapshotDarwinInstallStat(opened) != before.identity {
		return errors.New("Darwin launchd pending plist changed before sync")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	after, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if !sameLaunchdPlistSnapshot(before, after) {
		return errors.New("Darwin launchd pending plist changed while syncing")
	}
	return nil
}

func (publisher *LaunchdPlistPublisher) FinalizePending() (returnErr error) {
	before, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if before.state == launchdPlistComplete {
		return nil
	}
	if !before.found || before.mode != launchdPlistPendingMode || !bytes.Equal(before.contents, publisher.expected) {
		return errors.New("Darwin launchd pending plist is not the complete private recovery object")
	}
	fd, err := unix.Openat(publisher.fd, launchdPlistPendingName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(publisher.directoryPath, launchdPlistPendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin launchd pending-plist finalization descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if snapshotDarwinInstallStat(opened) != before.identity {
		return errors.New("Darwin launchd pending plist changed before finalization")
	}
	if err := unix.Fchmod(fd, uint32(launchdPlistMode)); err != nil {
		return err
	}
	after, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if after.state != launchdPlistComplete {
		return errors.New("Darwin launchd pending plist is not exact after finalization")
	}
	return nil
}

func (publisher *LaunchdPlistPublisher) RemovePending() error {
	before, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil || !before.found {
		return err
	}
	again, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if !sameLaunchdPlistSnapshot(before, again) {
		return errors.New("Darwin launchd pending plist changed before removal")
	}
	if err := unix.Unlinkat(publisher.fd, launchdPlistPendingName, 0); err != nil {
		return err
	}
	after, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if after.found {
		return errors.New("Darwin launchd pending plist remains after removal")
	}
	return nil
}

func (publisher *LaunchdPlistPublisher) PublishPending() error {
	if err := publisher.validateDirectoryLocked(); err != nil {
		return err
	}
	live, err := publisher.inspectFileLocked(LaunchdPlistName, false)
	if err != nil {
		return err
	}
	if live.state == launchdPlistComplete {
		return errors.New("exact Darwin launchd plist is already live before pending publication")
	}
	pending, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if pending.state != launchdPlistComplete {
		return errors.New("Darwin launchd pending plist is not complete at publication")
	}
	if err := unix.Renameat(publisher.fd, launchdPlistPendingName, publisher.fd, LaunchdPlistName); err != nil {
		return err
	}
	liveAfter, err := publisher.inspectFileLocked(LaunchdPlistName, false)
	if err != nil {
		return err
	}
	pendingAfter, err := publisher.inspectFileLocked(launchdPlistPendingName, true)
	if err != nil {
		return err
	}
	if liveAfter.state != launchdPlistComplete || pendingAfter.found {
		return errors.New("Darwin launchd plist replacement is not exact after rename")
	}
	return nil
}

func (publisher *LaunchdPlistPublisher) SyncDirectory() error {
	if err := publisher.validateDirectoryLocked(); err != nil {
		return err
	}
	if err := publisher.directory.Sync(); err != nil {
		return err
	}
	return publisher.validateDirectoryLocked()
}

func (publisher *LaunchdPlistPublisher) inspectFileLocked(name string, pending bool) (result launchdPlistSnapshot, returnErr error) {
	if err := publisher.validateDirectoryLocked(); err != nil {
		return result, err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(publisher.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return launchdPlistSnapshot{state: launchdPlistAbsent}, nil
	} else if err != nil {
		return result, err
	}
	if err := validateLaunchdPlistStat(visibleBefore, pending, int64(len(publisher.expected))); err != nil {
		return result, fmt.Errorf("Darwin launchd plist %q: %w", name, err)
	}
	path := filepath.Join(publisher.directoryPath, name)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	fd, err := unix.Openat(publisher.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("adopt Darwin launchd plist descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return result, err
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumLaunchdPlistSize+1))
	if err != nil || int64(len(contents)) != visibleBefore.Size {
		return result, errors.Join(err, errors.New("Darwin launchd plist changed or exceeded its bound while reading"))
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return result, err
	}
	if err := unix.Fstatat(publisher.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return result, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateLaunchdPlistStat(stat, pending, int64(len(publisher.expected))); err != nil {
			return result, err
		}
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(openedBefore) || identity != snapshotDarwinInstallStat(openedAfter) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return result, errors.New("Darwin launchd plist changed while reading")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	state := launchdPlistReplaceable
	mode := uint16(visibleBefore.Mode & 0o7777)
	if bytes.Equal(contents, publisher.expected) && mode == launchdPlistMode {
		state = launchdPlistComplete
	} else if pending && (!privateLaunchdPlistRecoveryMode(mode) || !bytes.HasPrefix(publisher.expected, contents)) {
		return result, errors.New("Darwin launchd pending plist is not a recognized recovery object")
	}
	return launchdPlistSnapshot{
		found: true, state: state, mode: mode,
		contents: append([]byte(nil), contents...), identity: identity,
	}, nil
}

func validateLaunchdPlistStat(stat unix.Stat_t, pending bool, expectedSize int64) error {
	mode := uint16(stat.Mode & 0o7777)
	modeOK := mode == launchdPlistMode
	maximum := maximumLaunchdPlistSize
	if pending {
		modeOK = mode == launchdPlistMode || privateLaunchdPlistRecoveryMode(mode)
		maximum = expectedSize
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || !modeOK || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Flags != 0 || stat.Size < 0 || stat.Size > maximum {
		return errors.New("must be an exact root:wheel single-link bounded regular file with a recognized mode and no flags")
	}
	return nil
}

func privateLaunchdPlistRecoveryMode(mode uint16) bool {
	return mode&^launchdPlistPendingMode == 0
}

func sameLaunchdPlistSnapshot(left, right launchdPlistSnapshot) bool {
	return left.found == right.found && left.state == right.state && left.mode == right.mode &&
		left.identity == right.identity && bytes.Equal(left.contents, right.contents)
}

func (publisher *LaunchdPlistPublisher) validateDirectoryLocked() error {
	if publisher == nil || publisher.closed || publisher.directory == nil || publisher.fd < 0 || len(publisher.expected) == 0 {
		return errors.New("Darwin launchd plist publisher is closed or incomplete")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(publisher.fd, &stat); err != nil {
		return err
	}
	if darwinObjectIdentity(stat) != publisher.identity {
		return errors.New("Darwin launchd directory changed identity")
	}
	if err := validateDarwinReleaseDirectoryStat(stat, darwinManagedReleaseDirectoryMode); err != nil {
		return err
	}
	return nodeagent.InspectDarwinSensitivePath(publisher.directoryPath)
}

func (publisher *LaunchdPlistPublisher) Close() error {
	if publisher == nil {
		return nil
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if publisher.closed {
		return nil
	}
	publisher.closed = true
	if publisher.directory == nil {
		return nil
	}
	err := publisher.directory.Close()
	publisher.directory = nil
	publisher.fd = -1
	return err
}
