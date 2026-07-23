//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	ProductionInstallerJournalPath = ProductionStateDirectory + "/transaction.json"
	installerJournalName           = "transaction.json"
	installerJournalPendingName    = ".transaction.json.new"
	installerJournalLockName       = "transaction.lock"
	installerJournalFileMode       = uint16(0o400)
	installerJournalLockMode       = uint16(0o600)
)

// InstallerJournalStore owns one root-private cross-process transaction lock
// and canonical crash journal. It shares the installer state directory with
// the independent persistent runtime gate but never mutates that gate.
type InstallerJournalStore struct {
	directory string
	mu        sync.Mutex
}

func NewInstallerJournalStore(directory string) (*InstallerJournalStore, error) {
	if !cleanDarwinInstallPath(directory) {
		return nil, errors.New("Darwin installer journal directory must be an exact absolute non-root path")
	}
	return &InstallerJournalStore{directory: directory}, nil
}

func ProductionInstallerJournalStore() *InstallerJournalStore {
	return &InstallerJournalStore{directory: ProductionStateDirectory}
}

type darwinInstallerJournalSnapshot struct {
	found    bool
	raw      []byte
	journal  InstallerJournal
	identity darwinInstallStatSnapshot
}

type InstallerJournalLock struct {
	store          *InstallerJournalStore
	directory      *filesystemRuntimeGateOperations
	lockFile       *os.File
	lockIdentity   darwinInstallStatSnapshot
	storeHeld      bool
	loaded         bool
	snapshot       darwinInstallerJournalSnapshot
	stateLoaded    bool
	stateSnapshot  darwinInstallStateSnapshot
	intakeLoaded   bool
	intakeSnapshot darwinIntakeRecordSnapshot
	rootHistory    darwinRootHistoryLockState
	closed         bool
}

func (store *InstallerJournalStore) AcquireLock() (*InstallerJournalLock, error) {
	if store == nil {
		return nil, errors.New("Darwin installer journal store is required")
	}
	if !store.mu.TryLock() {
		return nil, errors.New("another Darwin installer transaction holds the in-process journal lock")
	}
	directory, err := openFilesystemRuntimeGateOperations(store.directory)
	if err != nil {
		store.mu.Unlock()
		return nil, err
	}
	file, identity, created, err := openDarwinInstallerJournalLock(directory)
	if err != nil {
		_ = directory.Close()
		store.mu.Unlock()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		_ = directory.Close()
		store.mu.Unlock()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("another Darwin installer transaction holds the journal lock")
		}
		return nil, err
	}
	lock := &InstallerJournalLock{
		store: store, directory: directory, lockFile: file, lockIdentity: identity, storeHeld: true,
	}
	if created {
		if err := directory.directory.Sync(); err != nil {
			_ = lock.Close()
			return nil, err
		}
	}
	if err := lock.validateHeld(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func openDarwinInstallerJournalLock(directory *filesystemRuntimeGateOperations) (*os.File, darwinInstallStatSnapshot, bool, error) {
	if directory == nil || directory.directory == nil || directory.fd < 0 {
		return nil, darwinInstallStatSnapshot{}, false, errors.New("Darwin installer journal directory is closed")
	}
	flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NOFOLLOW_ANY | unix.O_NONBLOCK
	fd, err := unix.Openat(directory.fd, installerJournalLockName, flags, uint32(installerJournalLockMode))
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(directory.fd, installerJournalLockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, darwinInstallStatSnapshot{}, false, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(directory.directoryPath, installerJournalLockName))
	if file == nil {
		_ = unix.Close(fd)
		return nil, darwinInstallStatSnapshot{}, false, errors.New("adopt Darwin installer journal-lock descriptor")
	}
	if created {
		if err := unix.Fchown(fd, 0, 0); err != nil {
			_ = file.Close()
			return nil, darwinInstallStatSnapshot{}, false, err
		}
		if err := unix.Fchmod(fd, uint32(installerJournalLockMode)); err != nil {
			_ = file.Close()
			return nil, darwinInstallStatSnapshot{}, false, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, darwinInstallStatSnapshot{}, false, err
		}
	}
	var opened, visible unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, false, err
	}
	if err := unix.Fstatat(directory.fd, installerJournalLockName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, false, err
	}
	if err := validateDarwinInstallerJournalStat(opened, installerJournalLockMode, true); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, false, err
	}
	identity := snapshotDarwinInstallStat(opened)
	if identity != snapshotDarwinInstallStat(visible) {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, false, errors.New("Darwin installer journal lock path does not identify its opened descriptor")
	}
	if err := nodeagent.InspectDarwinSensitivePath(filepath.Join(directory.directoryPath, installerJournalLockName)); err != nil {
		_ = file.Close()
		return nil, darwinInstallStatSnapshot{}, false, err
	}
	return file, identity, created, nil
}

func (lock *InstallerJournalLock) validateHeld() error {
	if lock == nil || lock.closed || lock.directory == nil || lock.directory.directory == nil || lock.lockFile == nil {
		return errors.New("Darwin installer journal lock is closed")
	}
	if err := validateDarwinInstallerDirectoryDescriptor(lock.directory.fd); err != nil {
		return err
	}
	var opened, visible unix.Stat_t
	if err := unix.Fstat(int(lock.lockFile.Fd()), &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(lock.directory.fd, installerJournalLockName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := validateDarwinInstallerJournalStat(opened, installerJournalLockMode, true); err != nil {
		return err
	}
	if lock.lockIdentity != snapshotDarwinInstallStat(opened) || lock.lockIdentity != snapshotDarwinInstallStat(visible) {
		return errors.New("Darwin installer journal lock changed while held")
	}
	return nodeagent.InspectDarwinSensitivePath(filepath.Join(lock.store.directory, installerJournalLockName))
}

// Load first reconciles only the exact deterministic pending publication for
// the current journal phase, syncs the directory, and snapshots the canonical
// live journal. It may be called exactly once per acquired lock.
func (lock *InstallerJournalLock) Load() (InstallerJournal, bool, error) {
	if err := lock.validateHeld(); err != nil {
		return InstallerJournal{}, false, err
	}
	if lock.loaded {
		return InstallerJournal{}, false, errors.New("Darwin installer journal lock already loaded a snapshot")
	}
	if err := lock.reconcilePending(); err != nil {
		return InstallerJournal{}, false, err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return InstallerJournal{}, false, err
	}
	snapshot, err := lock.readJournal(installerJournalName)
	if err != nil {
		return InstallerJournal{}, false, err
	}
	stable, err := lock.readJournal(installerJournalName)
	if err != nil {
		return InstallerJournal{}, false, err
	}
	if !sameDarwinInstallerJournalSnapshot(snapshot, stable) {
		return InstallerJournal{}, false, errors.New("Darwin installer journal changed while loading")
	}
	lock.loaded = true
	lock.snapshot = snapshot
	return cloneInstallerJournal(snapshot.journal), snapshot.found, nil
}

func (lock *InstallerJournalLock) reconcilePending() error {
	pendingRaw, err := lock.readJournalRaw(installerJournalPendingName)
	if err != nil {
		return err
	}
	if !pendingRaw.found {
		return nil
	}
	pending, decodeErr := decodeInstallerJournal(pendingRaw.raw)
	if decodeErr != nil {
		if err := lock.removeExactRaw(installerJournalPendingName, pendingRaw); err != nil {
			return errors.Join(decodeErr, err)
		}
		return lock.directory.directory.Sync()
	}
	live, err := lock.readJournal(installerJournalName)
	if err != nil {
		return err
	}
	if !live.found {
		if pending.Operation == JournalOperationActivate && pending.Phase != JournalPhaseStaged ||
			pending.Operation == JournalOperationRollback && pending.Phase != JournalPhasePrepared {
			return errors.New("Darwin installer pending journal without a live journal has the wrong initial phase")
		}
		if err := unix.RenameatxNp(lock.directory.fd, installerJournalPendingName, lock.directory.fd, installerJournalName, unix.RENAME_EXCL); err != nil {
			return err
		}
		return lock.directory.directory.Sync()
	}
	nextPhase, ok := nextInstallerJournalPhase(live.journal.Phase)
	if !ok {
		return errors.New("Darwin installer pending journal exists after the terminal activated phase")
	}
	want, err := live.journal.WithPhase(nextPhase)
	if err != nil {
		return err
	}
	if !reflectInstallerJournalsEqual(want, pending) {
		return errors.New("Darwin installer pending journal differs from the sole allowed next transition")
	}
	liveAgain, err := lock.readJournal(installerJournalName)
	if err != nil {
		return err
	}
	pendingAgain, err := lock.readJournalRaw(installerJournalPendingName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallerJournalSnapshot(live, liveAgain) || !sameDarwinInstallerJournalSnapshot(pendingRaw, pendingAgain) {
		return errors.New("Darwin installer journal changed while reconciling its pending phase")
	}
	if err := unix.Renameat(lock.directory.fd, installerJournalPendingName, lock.directory.fd, installerJournalName); err != nil {
		return err
	}
	return lock.directory.directory.Sync()
}

func reflectInstallerJournalsEqual(left, right InstallerJournal) bool {
	leftRaw, leftErr := encodeInstallerJournal(left)
	rightRaw, rightErr := encodeInstallerJournal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

// Commit durably creates the initial staged journal or advances exactly one
// immutable phase through a file-sync, atomic rename, directory-sync, readback
// ordering. A valid interrupted pending publication is recovered by Load.
func (lock *InstallerJournalLock) Commit(next InstallerJournal) error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if !lock.loaded {
		return errors.New("Darwin installer journal must be loaded before commit")
	}
	current, err := lock.readJournal(installerJournalName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallerJournalSnapshot(lock.snapshot, current) {
		return errors.New("Darwin installer journal changed after its locked snapshot")
	}
	if err := validateInstallerJournalTransition(current.found, current.journal, next); err != nil {
		return err
	}
	raw, err := encodeInstallerJournal(next)
	if err != nil {
		return err
	}
	if current.found && bytes.Equal(current.raw, raw) {
		return nil
	}
	pending, err := lock.readJournalRaw(installerJournalPendingName)
	if err != nil {
		return err
	}
	if pending.found {
		return errors.New("Darwin installer pending journal was not reconciled before commit")
	}
	if err := lock.writePending(raw); err != nil {
		return err
	}
	currentAgain, err := lock.readJournal(installerJournalName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallerJournalSnapshot(lock.snapshot, currentAgain) {
		return errors.New("Darwin installer journal changed while preparing its next phase")
	}
	if current.found {
		err = unix.Renameat(lock.directory.fd, installerJournalPendingName, lock.directory.fd, installerJournalName)
	} else {
		err = unix.RenameatxNp(lock.directory.fd, installerJournalPendingName, lock.directory.fd, installerJournalName, unix.RENAME_EXCL)
	}
	if err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	committed, err := lock.readJournal(installerJournalName)
	if err != nil {
		return err
	}
	if !committed.found || !bytes.Equal(committed.raw, raw) {
		return errors.New("committed Darwin installer journal differs from the requested phase")
	}
	lock.snapshot = committed
	return nil
}

func (lock *InstallerJournalLock) writePending(raw []byte) (returnErr error) {
	fd, err := unix.Openat(lock.directory.fd, installerJournalPendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(installerJournalFileMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(lock.store.directory, installerJournalPendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin installer pending-journal descriptor")
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
	if err := unix.Fchmod(fd, uint32(installerJournalFileMode)); err != nil {
		return err
	}
	written, writeErr := file.Write(raw)
	if writeErr != nil || written != len(raw) {
		return errors.Join(writeErr, shortWriteError(written, len(raw)))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		open = false
		return err
	}
	open = false
	pending, err := lock.readJournal(installerJournalPendingName)
	if err != nil {
		return err
	}
	if !pending.found || !bytes.Equal(pending.raw, raw) {
		return errors.New("Darwin installer pending journal differs after write and sync")
	}
	return nil
}

// Clear is legal only after the complete launchd activation is durably proven.
// It removes the journal, syncs the state directory, and proves absence before
// returning.
func (lock *InstallerJournalLock) Clear() error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if !lock.loaded || !lock.snapshot.found || lock.snapshot.journal.Phase != JournalPhaseActivated {
		return errors.New("only an activated Darwin installer journal can be cleared")
	}
	current, err := lock.readJournal(installerJournalName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallerJournalSnapshot(lock.snapshot, current) {
		return errors.New("Darwin installer journal changed before clear")
	}
	pending, err := lock.readJournalRaw(installerJournalPendingName)
	if err != nil {
		return err
	}
	if pending.found {
		return errors.New("Darwin installer pending journal exists before clear")
	}
	if err := unix.Unlinkat(lock.directory.fd, installerJournalName, 0); err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	after, err := lock.readJournalRaw(installerJournalName)
	if err != nil {
		return err
	}
	if after.found {
		return errors.New("cleared Darwin installer journal remains visible")
	}
	lock.snapshot = darwinInstallerJournalSnapshot{}
	return nil
}

func (lock *InstallerJournalLock) readJournal(name string) (darwinInstallerJournalSnapshot, error) {
	raw, err := lock.readJournalRaw(name)
	if err != nil || !raw.found {
		return raw, err
	}
	journal, err := decodeInstallerJournal(raw.raw)
	if err != nil {
		return darwinInstallerJournalSnapshot{}, err
	}
	raw.journal = journal
	return raw, nil
}

func (lock *InstallerJournalLock) readJournalRaw(name string) (result darwinInstallerJournalSnapshot, returnErr error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(lock.directory.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	if err := validateDarwinInstallerJournalStat(visibleBefore, installerJournalFileMode, false); err != nil {
		return result, fmt.Errorf("Darwin installer journal file %q: %w", name, err)
	}
	path := filepath.Join(lock.store.directory, name)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	fd, err := unix.Openat(lock.directory.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("adopt Darwin installer journal descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxInstallerJournalSize+1))
	if err != nil || len(raw) == 0 || len(raw) > maxInstallerJournalSize {
		return result, errors.Join(err, errors.New("Darwin installer journal changed or exceeded its bound while reading"))
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return result, err
	}
	if err := unix.Fstatat(lock.directory.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return result, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinInstallerJournalStat(stat, installerJournalFileMode, false); err != nil {
			return result, err
		}
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(openedBefore) || identity != snapshotDarwinInstallStat(openedAfter) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return result, errors.New("Darwin installer journal changed while reading")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	return darwinInstallerJournalSnapshot{found: true, raw: raw, identity: identity}, nil
}

func (lock *InstallerJournalLock) removeExactRaw(name string, expected darwinInstallerJournalSnapshot) error {
	current, err := lock.readJournalRaw(name)
	if err != nil {
		return err
	}
	if !sameDarwinInstallerJournalSnapshot(expected, current) {
		return errors.New("Darwin installer pending journal changed before cleanup")
	}
	return unix.Unlinkat(lock.directory.fd, name, 0)
}

func sameDarwinInstallerJournalSnapshot(left, right darwinInstallerJournalSnapshot) bool {
	if left.found != right.found {
		return false
	}
	if !left.found {
		return true
	}
	return left.identity == right.identity && bytes.Equal(left.raw, right.raw)
}

func validateDarwinInstallerJournalStat(stat unix.Stat_t, mode uint16, empty bool) error {
	minimum := int64(1)
	maximum := int64(maxInstallerJournalSize)
	if empty {
		minimum, maximum = 0, 0
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != mode || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size < minimum || stat.Size > maximum {
		return fmt.Errorf("must be exact root:wheel, single-link, mode-%04o, flag-free, and within its size bound", mode)
	}
	return nil
}

func (lock *InstallerJournalLock) Close() error {
	if lock == nil || lock.closed {
		return nil
	}
	lock.closed = true
	var unlockErr, fileErr, directoryErr error
	if lock.lockFile != nil {
		unlockErr = unix.Flock(int(lock.lockFile.Fd()), unix.LOCK_UN)
		fileErr = lock.lockFile.Close()
		lock.lockFile = nil
	}
	if lock.directory != nil {
		directoryErr = lock.directory.Close()
		lock.directory = nil
	}
	if lock.storeHeld {
		lock.storeHeld = false
		lock.store.mu.Unlock()
	}
	return errors.Join(unlockErr, fileErr, directoryErr)
}

// Begin proves the exact finalized stage, expected-prior current selection,
// and journaled pre-activation runtime-gate intent. It writes the only legal
// initial phase and refuses to replace a live transaction.
func (store *InstallerJournalStore) Begin(layout *ReleaseLayout, journal InstallerJournal, operations launchdActivationOperations) (returnErr error) {
	return store.begin(layout, journal, operations, nil)
}

// BeginAcceptedIntake consumes only the durable intake that reproduces the
// journal authority from this exact finalized stage. The intake is cleared
// only after both high-water state and the initial journal are durable.
func (store *InstallerJournalStore) BeginAcceptedIntake(layout *ReleaseLayout, journal InstallerJournal, operations launchdActivationOperations, intake VerifiedDarwinIntake) (returnErr error) {
	if err := validateVerifiedDarwinCandidate(intake.Candidate); err != nil || !darwinDigestPattern.MatchString(intake.InstallerBootstrapRootSHA256) {
		return errors.Join(err, errors.New("verified Darwin intake is invalid"))
	}
	return store.begin(layout, journal, operations, &intake)
}

func (store *InstallerJournalStore) begin(layout *ReleaseLayout, journal InstallerJournal, operations launchdActivationOperations, required *VerifiedDarwinIntake) (returnErr error) {
	if layout == nil {
		return errors.New("Darwin release layout is required to begin an installer journal")
	}
	if operations == nil {
		return errors.New("Darwin launchd activation operations are required to begin an installer journal")
	}
	if err := validateInstallerJournalTransition(false, InstallerJournal{}, journal); err != nil {
		return err
	}
	if journal.Operation != JournalOperationActivate {
		return errors.New("Darwin activation begin requires an activation journal")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	_, found, err := lock.Load()
	if err != nil {
		return err
	}
	if found {
		return errors.New("a Darwin installer journal is already active")
	}
	intakeRecord, intakeFound, err := lock.LoadIntakeRecord()
	if err != nil {
		return err
	}
	if required == nil && intakeFound {
		return errors.New("a durable Darwin accepted intake must be consumed with BeginAcceptedIntake")
	}
	if required != nil {
		persisted, intakeErr := intakeRecord.Intake()
		if !intakeFound || intakeErr != nil || persisted != *required {
			return errors.Join(intakeErr, errors.New("Darwin activation requires the exact active accepted intake"))
		}
		completed, completeErr := required.Complete(journal.Inspection)
		if completeErr != nil || completed != journal.Authority {
			return errors.Join(completeErr, errors.New("Darwin accepted intake differs from the activation journal authority"))
		}
	}
	stage, err := layout.ResumeStage(journal.InstalledID, journal.StageName, journal.Inspection)
	if err != nil {
		return err
	}
	if err := stage.Close(); err != nil {
		return err
	}
	layout.mu.Lock()
	if err := layout.validateAnchorsLocked(); err != nil {
		layout.mu.Unlock()
		return err
	}
	current, err := layout.readCurrentLocked()
	layout.mu.Unlock()
	if err != nil {
		return err
	}
	if currentSelectionID(current) != journal.ExpectedPrior {
		return errors.New("Darwin current release differs from the journal's expected prior at begin")
	}
	gateOpen, err := operations.InspectRuntimeGate()
	if err != nil {
		return err
	}
	if gateOpen != journal.RestoreRuntimeGate {
		return errors.New("Darwin runtime gate differs from the journal's pre-activation intent at begin")
	}
	state, stateFound, err := lock.LoadInstallState()
	if err != nil {
		return err
	}
	var nextState DarwinInstallState
	if !stateFound {
		if journal.ExpectedPrior != "" {
			return errors.New("initial Darwin install state requires an absent current release")
		}
		nextState = DarwinInstallState{
			Schema: DarwinInstallStateSchema, BootstrapTrustSHA256: journal.Authority.InstallerBootstrapRootSHA256,
			Channel: journal.Authority.Channel, Arch: journal.Authority.Arch, HighWater: journal.Authority,
		}
	} else {
		activeID := ""
		if state.Active != nil {
			activeID = state.Active.InstalledID
		}
		if activeID != journal.ExpectedPrior {
			return errors.New("Darwin install state active release differs from the journal's expected prior")
		}
		nextState, err = state.AdvanceHighWater(journal.Authority)
		if err != nil {
			return err
		}
	}
	if err := lock.CommitInstallState(nextState); err != nil {
		return err
	}
	if err := lock.Commit(journal); err != nil {
		return err
	}
	if intakeFound {
		if err := lock.discardAcceptedArtifact(intakeRecord.Candidate.Artifact); err != nil {
			return err
		}
		return lock.ClearIntakeRecord(intakeRecord)
	}
	return nil
}

// Resume completes release publication and fail-closed launchd activation from
// the journal's authenticated inspection. Every action is proven before its
// subsequent journal phase is committed.
func (store *InstallerJournalStore) Resume(layout *ReleaseLayout, operations launchdActivationOperations) (returnErr error) {
	if layout == nil {
		return errors.New("Darwin release layout is required for journal recovery")
	}
	if operations == nil {
		return errors.New("Darwin launchd activation operations are required for journal recovery")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	journal, found, err := lock.Load()
	if err != nil || !found {
		return err
	}
	if bound, ok := operations.(installerJournalBoundOperations); ok {
		if err := bound.ValidateInstallerJournal(journal); err != nil {
			return err
		}
	}
	intakeRecord, intakeFound, err := lock.LoadIntakeRecord()
	if err != nil {
		return err
	}
	state, stateFound, err := lock.LoadInstallState()
	if err != nil {
		return err
	}
	if !stateFound {
		return errors.New("Darwin install state is absent for the active journal")
	}
	switch journal.Operation {
	case JournalOperationActivate:
		if state.HighWater != journal.Authority {
			return errors.New("Darwin install-state high-water authority differs from the activation journal")
		}
	case JournalOperationRollback:
		alreadyCommitted, err := rollbackJournalStateStatus(journal, state)
		if err != nil || alreadyCommitted && journal.Phase != JournalPhaseActivated {
			return errors.Join(err, errors.New("Darwin install-state active/previous authorities differ from the rollback journal phase"))
		}
	default:
		return errors.New("Darwin installer journal operation is unsupported")
	}
	if intakeFound {
		if journal.Operation != JournalOperationActivate {
			return errors.New("a Darwin rollback journal cannot overlap an accepted intake")
		}
		intake, err := intakeRecord.Intake()
		if err != nil {
			return err
		}
		authority, err := intake.Complete(journal.Inspection)
		if err != nil || authority != journal.Authority {
			return errors.Join(err, errors.New("stale Darwin accepted intake differs from the active journal"))
		}
		if err := lock.discardAcceptedArtifact(intakeRecord.Candidate.Artifact); err != nil {
			return err
		}
		if err := lock.ClearIntakeRecord(intakeRecord); err != nil {
			return err
		}
	}
	activationProven := false
	for {
		switch journal.Phase {
		case JournalPhaseStaged:
			if journal.Operation != JournalOperationActivate {
				return errors.New("Darwin rollback journal entered an activation publication phase")
			}
			stage, err := layout.ResumeStage(journal.InstalledID, journal.StageName, journal.Inspection)
			if err != nil {
				return err
			}
			publishErr := stage.Publish()
			closeErr := stage.Close()
			if err := errors.Join(publishErr, closeErr); err != nil {
				return err
			}
			next, err := journal.WithPhase(JournalPhasePublished)
			if err != nil {
				return err
			}
			if err := lock.Commit(next); err != nil {
				return err
			}
			journal = next
		case JournalPhasePublished, JournalPhasePrepared:
			if journal.Operation == JournalOperationActivate && journal.Phase != JournalPhasePublished ||
				journal.Operation == JournalOperationRollback && journal.Phase != JournalPhasePrepared {
				return errors.New("Darwin installer journal phase differs from its operation")
			}
			if err := activateLaunchdRelease(operations, journal.RestoreRuntimeGate); err != nil {
				return err
			}
			activationProven = true
			next, err := journal.WithPhase(JournalPhaseActivated)
			if err != nil {
				return err
			}
			if err := lock.Commit(next); err != nil {
				return err
			}
			journal = next
		case JournalPhaseActivated:
			// Re-establish the complete fail-closed service state after a crash.
			// Terminal recovery repeats the idempotent gate-close/bootout/switch/
			// plist/bootstrap sequence instead of interpreting command output.
			if !activationProven {
				if err := activateLaunchdRelease(operations, journal.RestoreRuntimeGate); err != nil {
					return err
				}
				activationProven = true
			}
			var nextState DarwinInstallState
			var err error
			if journal.Operation == JournalOperationRollback {
				nextState, err = completeRollbackJournalState(journal, state)
			} else {
				nextState, err = state.ActivateAccepted()
			}
			if err != nil {
				return err
			}
			if err := lock.CommitInstallState(nextState); err != nil {
				return err
			}
			return lock.Clear()
		default:
			return errors.New("Darwin installer journal phase is unsupported")
		}
	}
}
