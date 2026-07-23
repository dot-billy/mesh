//go:build darwin

package darwininstall

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mesh/internal/nodeagent"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"

	"golang.org/x/sys/unix"
)

const (
	darwinArtifactCapturePendingMode = uint16(0o600)
	darwinArtifactCaptureLiveMode    = uint16(0o400)
)

type darwinArtifactCaptureSnapshot struct {
	found    bool
	rawSHA   string
	identity darwinInstallStatSnapshot
}

// DarwinArtifactCapture owns the installer transaction lock from creation
// through publication. Close leaves a bounded private partial file for the
// next exact recovery attempt rather than deleting an unresolved pathname.
type DarwinArtifactCapture struct {
	lock        *InstallerJournalLock
	expected    releasetrust.Artifact
	pendingName string
	liveName    string
	writer      *os.File
	live        bool
	closed      bool
}

type darwinArtifactFetcher interface {
	FetchArtifact(context.Context, releasetrust.Artifact, *os.File) error
}

// FetchProductionDarwinArtifact streams only the artifact selected by the
// verified intake through the bounded no-redirect online client and returns a
// locked, immutable capture ready for staging.
func (store *InstallerJournalStore) FetchProductionDarwinArtifact(ctx context.Context, intake VerifiedDarwinIntake) (*DarwinArtifactCapture, error) {
	return store.fetchDarwinArtifactUsing(ctx, intake, onlinerelease.NewClient())
}

func (store *InstallerJournalStore) fetchDarwinArtifactUsing(ctx context.Context, intake VerifiedDarwinIntake, fetcher darwinArtifactFetcher) (capture *DarwinArtifactCapture, returnErr error) {
	if ctx == nil || fetcher == nil {
		return nil, errors.New("Darwin artifact fetch requires a context and bounded fetcher")
	}
	if intake.InstallerBootstrapRootSHA256 == "" || intake.Candidate.Artifact.SHA256 == "" {
		return nil, errors.New("verified Darwin intake is incomplete")
	}
	capture, err := store.BeginAcceptedArtifactCapture(intake)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if returnErr != nil && owned {
			returnErr = errors.Join(returnErr, capture.Close())
		}
	}()
	if capture.Path() != "" {
		owned = false
		return capture, nil
	}
	destination, err := capture.Destination()
	if err != nil {
		return nil, err
	}
	if err := fetcher.FetchArtifact(ctx, intake.Candidate.Artifact, destination); err != nil {
		return nil, err
	}
	if err := capture.Publish(); err != nil {
		return nil, err
	}
	owned = false
	return capture, nil
}

// BeginArtifactCapture creates or recovers the one deterministic capture for
// a threshold-authenticated Darwin artifact. It refuses to overlap an active
// publication/activation/rollback journal.
func (store *InstallerJournalStore) BeginArtifactCapture(expected releasetrust.Artifact) (capture *DarwinArtifactCapture, returnErr error) {
	return store.beginArtifactCapture(expected, nil)
}

// BeginAcceptedArtifactCapture requires the exact durable intake record that
// authorized the artifact. The record remains active after the capture lock is
// released so a restart can reproduce the same decision.
func (store *InstallerJournalStore) BeginAcceptedArtifactCapture(intake VerifiedDarwinIntake) (capture *DarwinArtifactCapture, returnErr error) {
	if err := validateVerifiedDarwinCandidate(intake.Candidate); err != nil || !darwinDigestPattern.MatchString(intake.InstallerBootstrapRootSHA256) {
		return nil, errors.Join(err, errors.New("verified Darwin intake is invalid"))
	}
	return store.beginArtifactCapture(intake.Candidate.Artifact, &intake)
}

func (store *InstallerJournalStore) beginArtifactCapture(expected releasetrust.Artifact, required *VerifiedDarwinIntake) (capture *DarwinArtifactCapture, returnErr error) {
	if store == nil {
		return nil, errors.New("Darwin installer journal store is required")
	}
	if err := validateDarwinArtifactReference(expected); err != nil {
		return nil, err
	}
	liveName, _ := darwinArtifactCaptureName(expected.SHA256)
	pendingName, _ := darwinArtifactCapturePendingName(expected.SHA256)
	lock, err := store.AcquireLock()
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if returnErr != nil && owned {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	if _, found, err := lock.Load(); err != nil {
		return nil, err
	} else if found {
		return nil, errors.New("Darwin artifact capture cannot overlap an active installer journal")
	}
	if required != nil {
		record, found, err := lock.LoadIntakeRecord()
		if err != nil {
			return nil, err
		}
		persisted, intakeErr := record.Intake()
		if !found || intakeErr != nil || persisted != *required {
			return nil, errors.Join(intakeErr, errors.New("Darwin artifact capture requires the exact active accepted intake"))
		}
	}
	capture = &DarwinArtifactCapture{
		lock: lock, expected: expected, pendingName: pendingName, liveName: liveName,
	}
	if err := capture.reconcile(); err != nil {
		return nil, err
	}
	if capture.live {
		owned = false
		return capture, nil
	}
	if err := capture.createPending(); err != nil {
		return nil, err
	}
	owned = false
	return capture, nil
}

// Destination returns the sole private writer accepted by the bounded online
// release client. A recovered complete capture has no writable destination.
func (capture *DarwinArtifactCapture) Destination() (*os.File, error) {
	if err := capture.validate(); err != nil {
		return nil, err
	}
	if capture.live || capture.writer == nil {
		return nil, errors.New("Darwin artifact capture is already finalized")
	}
	return capture.writer, nil
}

func (capture *DarwinArtifactCapture) Path() string {
	if capture == nil || capture.closed || !capture.live || capture.lock == nil {
		return ""
	}
	return filepath.Join(capture.lock.store.directory, capture.liveName)
}

// Publish independently rehashes the downloaded descriptor, finalizes it
// mode-0400, publishes create-only, syncs the state directory, and rehashes the
// exact visible object before exposing its path.
func (capture *DarwinArtifactCapture) Publish() error {
	if err := capture.validate(); err != nil {
		return err
	}
	if capture.live {
		return nil
	}
	if capture.writer == nil {
		return errors.New("Darwin artifact capture has no pending writer")
	}
	if err := capture.writer.Sync(); err != nil {
		return err
	}
	if err := capture.authenticateOpenWriter(); err != nil {
		return err
	}
	fd := int(capture.writer.Fd())
	if err := unix.Fchmod(fd, uint32(darwinArtifactCaptureLiveMode)); err != nil {
		return err
	}
	if err := capture.writer.Sync(); err != nil {
		return err
	}
	if err := capture.writer.Close(); err != nil {
		capture.writer = nil
		return err
	}
	capture.writer = nil
	pending, err := capture.read(capture.pendingName, darwinArtifactCaptureLiveMode, true)
	if err != nil {
		return err
	}
	if !pending.found || pending.rawSHA != capture.expected.SHA256 {
		return errors.New("finalized Darwin artifact capture differs before publication")
	}
	if err := unix.RenameatxNp(capture.lock.directory.fd, capture.pendingName, capture.lock.directory.fd, capture.liveName, unix.RENAME_EXCL); err != nil {
		return err
	}
	if err := capture.lock.directory.directory.Sync(); err != nil {
		return err
	}
	live, err := capture.read(capture.liveName, darwinArtifactCaptureLiveMode, true)
	if err != nil {
		return err
	}
	if !live.found || live.rawSHA != capture.expected.SHA256 {
		return errors.New("published Darwin artifact capture differs after directory sync")
	}
	capture.live = true
	return nil
}

// Discard removes only the exact authenticated live capture owned by this
// handle. Callers use it after the stage and activation journal are durable.
func (capture *DarwinArtifactCapture) Discard() error {
	if err := capture.validate(); err != nil {
		return err
	}
	if !capture.live || capture.writer != nil {
		return errors.New("only a finalized Darwin artifact capture can be discarded")
	}
	snapshot, err := capture.read(capture.liveName, darwinArtifactCaptureLiveMode, true)
	if err != nil {
		return err
	}
	if !snapshot.found || snapshot.rawSHA != capture.expected.SHA256 {
		return errors.New("Darwin artifact capture changed before discard")
	}
	stable, err := capture.read(capture.liveName, darwinArtifactCaptureLiveMode, true)
	if err != nil || !sameDarwinArtifactCaptureSnapshot(snapshot, stable) {
		return errors.Join(err, errors.New("Darwin artifact capture changed while preparing discard"))
	}
	if err := unix.Unlinkat(capture.lock.directory.fd, capture.liveName, 0); err != nil {
		return err
	}
	if err := capture.lock.directory.directory.Sync(); err != nil {
		return err
	}
	after, err := capture.read(capture.liveName, darwinArtifactCaptureLiveMode, false)
	if err != nil || after.found {
		return errors.Join(err, errors.New("discarded Darwin artifact capture remains visible"))
	}
	capture.live = false
	return nil
}

// discardAcceptedArtifact removes the exact immutable capture after the
// activation journal has made the finalized stage independently recoverable.
// Absence is an idempotent success for the crash window before intake clear.
func (lock *InstallerJournalLock) discardAcceptedArtifact(expected releasetrust.Artifact) error {
	if err := validateDarwinArtifactReference(expected); err != nil {
		return err
	}
	liveName, _ := darwinArtifactCaptureName(expected.SHA256)
	pendingName, _ := darwinArtifactCapturePendingName(expected.SHA256)
	capture := &DarwinArtifactCapture{
		lock: lock, expected: expected, liveName: liveName, pendingName: pendingName,
	}
	if _, pending, err := capture.inspectPending(); err != nil || pending.found {
		return errors.Join(err, errors.New("cannot discard a Darwin artifact capture with pending bytes"))
	}
	live, err := capture.read(liveName, darwinArtifactCaptureLiveMode, true)
	if err != nil || !live.found {
		return err
	}
	if live.rawSHA != expected.SHA256 {
		return errors.New("Darwin artifact capture differs from accepted intake before discard")
	}
	capture.live = true
	return capture.Discard()
}

func (capture *DarwinArtifactCapture) reconcile() error {
	live, err := capture.read(capture.liveName, darwinArtifactCaptureLiveMode, false)
	if err != nil {
		return err
	}
	pendingMode, pending, err := capture.inspectPending()
	if err != nil {
		return err
	}
	if live.found {
		if pending.found {
			return errors.New("Darwin artifact capture has ambiguous live and pending objects")
		}
		if live.rawSHA != capture.expected.SHA256 {
			return errors.New("existing Darwin artifact capture differs from authenticated bytes")
		}
		capture.live = true
		return nil
	}
	if !pending.found {
		return nil
	}
	if pendingMode == darwinArtifactCaptureLiveMode {
		if pending.rawSHA != capture.expected.SHA256 {
			return errors.New("finalized pending Darwin artifact capture differs from authenticated bytes")
		}
		if err := unix.RenameatxNp(capture.lock.directory.fd, capture.pendingName, capture.lock.directory.fd, capture.liveName, unix.RENAME_EXCL); err != nil {
			return err
		}
		if err := capture.lock.directory.directory.Sync(); err != nil {
			return err
		}
		confirmed, err := capture.read(capture.liveName, darwinArtifactCaptureLiveMode, true)
		if err != nil || !confirmed.found || confirmed.rawSHA != capture.expected.SHA256 {
			return errors.Join(err, errors.New("recovered Darwin artifact capture differs after publication"))
		}
		capture.live = true
		return nil
	}
	// A mode-0600 object is necessarily an interrupted download: Publish
	// changes the mode and syncs it before attempting the create-only rename.
	stableMode, stable, err := capture.inspectPending()
	if err != nil || stableMode != darwinArtifactCapturePendingMode || !sameDarwinArtifactCaptureSnapshot(pending, stable) {
		return errors.Join(err, errors.New("partial Darwin artifact capture changed during recovery"))
	}
	if err := unix.Unlinkat(capture.lock.directory.fd, capture.pendingName, 0); err != nil {
		return err
	}
	return capture.lock.directory.directory.Sync()
}

func (capture *DarwinArtifactCapture) createPending() error {
	fd, err := unix.Openat(capture.lock.directory.fd, capture.pendingName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(darwinArtifactCapturePendingMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(capture.lock.store.directory, capture.pendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin artifact capture descriptor")
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Fchmod(fd, uint32(darwinArtifactCapturePendingMode)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := capture.lock.directory.directory.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	capture.writer = file
	return nil
}

func (capture *DarwinArtifactCapture) authenticateOpenWriter() error {
	if _, err := capture.writer.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, io.LimitReader(capture.writer, capture.expected.Size+1))
	if err != nil || read != capture.expected.Size {
		return errors.Join(err, fmt.Errorf("Darwin artifact capture size is %d, want %d", read, capture.expected.Size))
	}
	expected, _ := hex.DecodeString(capture.expected.SHA256)
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return errors.New("Darwin artifact capture digest differs from authenticated metadata")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(capture.writer.Fd()), &stat); err != nil {
		return err
	}
	return validateDarwinArtifactCaptureStat(stat, darwinArtifactCapturePendingMode, capture.expected.Size, false)
}

func (capture *DarwinArtifactCapture) inspectPending() (uint16, darwinArtifactCaptureSnapshot, error) {
	for _, mode := range []uint16{darwinArtifactCapturePendingMode, darwinArtifactCaptureLiveMode} {
		snapshot, err := capture.read(capture.pendingName, mode, false)
		if err == nil && snapshot.found {
			return mode, snapshot, nil
		}
		if err != nil && !errors.Is(err, errDarwinArtifactCaptureMode) {
			return 0, darwinArtifactCaptureSnapshot{}, err
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(capture.lock.directory.fd, capture.pendingName, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return 0, darwinArtifactCaptureSnapshot{}, nil
	} else if err != nil {
		return 0, darwinArtifactCaptureSnapshot{}, err
	}
	return 0, darwinArtifactCaptureSnapshot{}, errors.New("pending Darwin artifact capture has unsafe metadata")
}

var errDarwinArtifactCaptureMode = errors.New("Darwin artifact capture mode differs")

func (capture *DarwinArtifactCapture) read(name string, mode uint16, requireExact bool) (result darwinArtifactCaptureSnapshot, returnErr error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(capture.lock.directory.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	if visibleBefore.Mode&0o7777 != mode {
		return result, errDarwinArtifactCaptureMode
	}
	if err := validateDarwinArtifactCaptureStat(visibleBefore, mode, capture.expected.Size, !requireExact); err != nil {
		return result, err
	}
	path := filepath.Join(capture.lock.store.directory, name)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	fd, err := unix.Openat(capture.lock.directory.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("adopt Darwin artifact capture read descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return result, err
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, io.LimitReader(file, capture.expected.Size+1))
	if err != nil {
		return result, err
	}
	if requireExact && read != capture.expected.Size {
		return result, fmt.Errorf("Darwin artifact capture size is %d, want %d", read, capture.expected.Size)
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return result, err
	}
	if err := unix.Fstatat(capture.lock.directory.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return result, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinArtifactCaptureStat(stat, mode, capture.expected.Size, !requireExact); err != nil {
			return result, err
		}
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(openedBefore) || identity != snapshotDarwinInstallStat(openedAfter) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return result, errors.New("Darwin artifact capture changed while reading")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	return darwinArtifactCaptureSnapshot{found: true, rawSHA: hex.EncodeToString(hasher.Sum(nil)), identity: identity}, nil
}

func validateDarwinArtifactCaptureStat(stat unix.Stat_t, mode uint16, expectedSize int64, allowPartial bool) error {
	maximum := expectedSize
	minimum := expectedSize
	if allowPartial {
		minimum = 0
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != mode || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size < minimum || stat.Size > maximum {
		return fmt.Errorf("must be exact root:wheel, single-link, mode-%04o, flag-free, and within the authenticated size bound", mode)
	}
	return nil
}

func sameDarwinArtifactCaptureSnapshot(left, right darwinArtifactCaptureSnapshot) bool {
	if left.found != right.found {
		return false
	}
	return !left.found || left.identity == right.identity && left.rawSHA == right.rawSHA
}

func (capture *DarwinArtifactCapture) validate() error {
	if capture == nil || capture.closed || capture.lock == nil {
		return errors.New("Darwin artifact capture is closed")
	}
	return capture.lock.validateHeld()
}

func (capture *DarwinArtifactCapture) Close() error {
	if capture == nil || capture.closed {
		return nil
	}
	capture.closed = true
	var writerErr, lockErr error
	if capture.writer != nil {
		writerErr = capture.writer.Close()
		capture.writer = nil
	}
	if capture.lock != nil {
		lockErr = capture.lock.Close()
		capture.lock = nil
	}
	return errors.Join(writerErr, lockErr)
}
