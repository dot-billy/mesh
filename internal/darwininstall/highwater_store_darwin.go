//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	ProductionDarwinInstallStatePath = ProductionStateDirectory + "/install-state.json"
	darwinInstallStateName           = "install-state.json"
	darwinInstallStatePendingName    = ".install-state.json.new"
	darwinInstallStateFileMode       = uint16(0o400)
)

type darwinInstallStateSnapshot struct {
	found    bool
	raw      []byte
	state    DarwinInstallState
	identity darwinInstallStatSnapshot
}

// LoadInstallState uses the same cross-process lock as the activation journal.
func (store *InstallerJournalStore) LoadInstallState() (state DarwinInstallState, found bool, returnErr error) {
	lock, err := store.AcquireLock()
	if err != nil {
		return DarwinInstallState{}, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	return lock.LoadInstallState()
}

// CommitInstallState is the standalone mutation path used only when no
// activation journal is live. Journal-integrated callers retain the lock and
// use CommitInstallState on it so authority and activation ordering serialize.
func (store *InstallerJournalStore) CommitInstallState(next DarwinInstallState) (returnErr error) {
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil {
		return err
	} else if found {
		return errors.New("Darwin install state cannot change outside an active journal transaction")
	}
	if _, found, err := lock.LoadIntakeRecord(); err != nil {
		return err
	} else if found {
		return errors.New("Darwin install state cannot change while an accepted intake is active")
	}
	if _, _, err := lock.LoadInstallState(); err != nil {
		return err
	}
	return lock.CommitInstallState(next)
}

func (lock *InstallerJournalLock) LoadInstallState() (DarwinInstallState, bool, error) {
	if err := lock.validateHeld(); err != nil {
		return DarwinInstallState{}, false, err
	}
	if lock.stateLoaded {
		return DarwinInstallState{}, false, errors.New("Darwin installer lock already loaded an install-state snapshot")
	}
	if err := lock.reconcileInstallStatePending(); err != nil {
		return DarwinInstallState{}, false, err
	}
	snapshot, err := lock.readInstallState(darwinInstallStateName)
	if err != nil {
		return DarwinInstallState{}, false, err
	}
	lock.stateLoaded = true
	lock.stateSnapshot = snapshot
	return cloneDarwinInstallState(snapshot.state), snapshot.found, nil
}

// CommitInstallState publishes only one exact legal authority, activation, or
// rollback transition through file-sync, atomic rename, directory-sync, and
// canonical readback.
func (lock *InstallerJournalLock) CommitInstallState(next DarwinInstallState) error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if !lock.stateLoaded {
		return errors.New("Darwin install state must be loaded before commit")
	}
	current, err := lock.readInstallState(darwinInstallStateName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallStateSnapshot(lock.stateSnapshot, current) {
		return errors.New("Darwin install state changed after its locked snapshot")
	}
	if err := validateDarwinInstallStateTransition(current.found, current.state, next); err != nil {
		return err
	}
	raw, err := encodeDarwinInstallState(next)
	if err != nil {
		return err
	}
	if current.found && bytes.Equal(current.raw, raw) {
		return nil
	}
	pending, err := lock.readInstallStateRaw(darwinInstallStatePendingName)
	if err != nil {
		return err
	}
	if pending.found {
		return errors.New("Darwin install-state pending file was not reconciled before commit")
	}
	if err := lock.writeInstallStatePending(raw); err != nil {
		return err
	}
	currentAgain, err := lock.readInstallState(darwinInstallStateName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallStateSnapshot(lock.stateSnapshot, currentAgain) {
		return errors.New("Darwin install state changed while preparing its next value")
	}
	if current.found {
		err = unix.Renameat(lock.directory.fd, darwinInstallStatePendingName, lock.directory.fd, darwinInstallStateName)
	} else {
		err = unix.RenameatxNp(lock.directory.fd, darwinInstallStatePendingName, lock.directory.fd, darwinInstallStateName, unix.RENAME_EXCL)
	}
	if err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	committed, err := lock.readInstallState(darwinInstallStateName)
	if err != nil {
		return err
	}
	if !committed.found || !bytes.Equal(committed.raw, raw) {
		return errors.New("committed Darwin install state differs from requested bytes")
	}
	lock.stateSnapshot = committed
	return nil
}

func (lock *InstallerJournalLock) reconcileInstallStatePending() error {
	pendingRaw, err := lock.readInstallStateRaw(darwinInstallStatePendingName)
	if err != nil || !pendingRaw.found {
		return err
	}
	pending, err := decodeDarwinInstallState(pendingRaw.raw)
	if err != nil {
		return err
	}
	live, err := lock.readInstallState(darwinInstallStateName)
	if err != nil {
		return err
	}
	if err := validateDarwinInstallStateTransition(live.found, live.state, pending); err != nil {
		return fmt.Errorf("pending Darwin install-state transition: %w", err)
	}
	liveAgain, err := lock.readInstallState(darwinInstallStateName)
	if err != nil {
		return err
	}
	pendingAgain, err := lock.readInstallStateRaw(darwinInstallStatePendingName)
	if err != nil {
		return err
	}
	if !sameDarwinInstallStateSnapshot(live, liveAgain) || !sameDarwinInstallStateSnapshot(pendingRaw, pendingAgain) {
		return errors.New("Darwin install state changed while reconciling pending bytes")
	}
	if live.found {
		err = unix.Renameat(lock.directory.fd, darwinInstallStatePendingName, lock.directory.fd, darwinInstallStateName)
	} else {
		err = unix.RenameatxNp(lock.directory.fd, darwinInstallStatePendingName, lock.directory.fd, darwinInstallStateName, unix.RENAME_EXCL)
	}
	if err != nil {
		return err
	}
	return lock.directory.directory.Sync()
}

func (lock *InstallerJournalLock) writeInstallStatePending(raw []byte) (returnErr error) {
	fd, err := unix.Openat(lock.directory.fd, darwinInstallStatePendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(darwinInstallStateFileMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(lock.store.directory, darwinInstallStatePendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin install-state pending descriptor")
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
	if err := unix.Fchmod(fd, uint32(darwinInstallStateFileMode)); err != nil {
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
	pending, err := lock.readInstallStateRaw(darwinInstallStatePendingName)
	if err != nil {
		return err
	}
	if !pending.found || !bytes.Equal(pending.raw, raw) {
		return errors.New("Darwin install-state pending bytes differ after write and sync")
	}
	return nil
}

func (lock *InstallerJournalLock) readInstallState(name string) (darwinInstallStateSnapshot, error) {
	raw, err := lock.readInstallStateRaw(name)
	if err != nil || !raw.found {
		return raw, err
	}
	state, err := decodeDarwinInstallState(raw.raw)
	if err != nil {
		return darwinInstallStateSnapshot{}, err
	}
	raw.state = state
	return raw, nil
}

func (lock *InstallerJournalLock) readInstallStateRaw(name string) (result darwinInstallStateSnapshot, returnErr error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(lock.directory.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	if err := validateDarwinInstallStateStat(visibleBefore); err != nil {
		return result, fmt.Errorf("Darwin install-state file %q: %w", name, err)
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
		return result, errors.New("adopt Darwin install-state descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumDarwinInstallStateSize+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumDarwinInstallStateSize {
		return result, errors.Join(err, errors.New("Darwin install state changed or exceeded its bound while reading"))
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return result, err
	}
	if err := unix.Fstatat(lock.directory.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return result, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinInstallStateStat(stat); err != nil {
			return result, err
		}
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(openedBefore) || identity != snapshotDarwinInstallStat(openedAfter) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return result, errors.New("Darwin install state changed while reading")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	return darwinInstallStateSnapshot{found: true, raw: raw, identity: identity}, nil
}

func validateDarwinInstallStateStat(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != darwinInstallStateFileMode || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size < 1 || stat.Size > maximumDarwinInstallStateSize {
		return errors.New("must be exact root:wheel, single-link, mode-0400, flag-free, and within the state-size bound")
	}
	return nil
}

func sameDarwinInstallStateSnapshot(left, right darwinInstallStateSnapshot) bool {
	if left.found != right.found {
		return false
	}
	if !left.found {
		return true
	}
	return left.identity == right.identity && bytes.Equal(left.raw, right.raw)
}
