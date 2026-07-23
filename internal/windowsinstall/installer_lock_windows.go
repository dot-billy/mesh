//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

const windowsInstallerLockName = "installer.lock"

type windowsInstallerLock struct {
	file       *os.File
	overlapped windows.Overlapped
	locked     bool
}

// acquireInstallerLock serializes every root-history and activation-journal
// mutation across processes. It deliberately fails immediately when another
// installer owns the byte-range lock; callers never guess whether a distinct
// transaction is active.
func (store *ActivationJournalStore) acquireInstallerLock() (*windowsInstallerLock, error) {
	root, err := store.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	before, err := root.Lstat(windowsInstallerLockName)
	var file *os.File
	if errors.Is(err, os.ErrNotExist) {
		file, err = root.OpenFile(windowsInstallerLockName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create Windows installer lock: %w", err)
		}
		if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
			file.Close()
			return nil, fmt.Errorf("protect Windows installer lock: %w", err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return nil, fmt.Errorf("sync Windows installer lock: %w", err)
		}
		before, err = root.Lstat(windowsInstallerLockName)
	} else if err == nil {
		file, err = root.OpenFile(windowsInstallerLockName, os.O_RDWR, 0)
	}
	if err != nil || file == nil || before == nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != 0 {
		if file != nil {
			file.Close()
		}
		return nil, errors.Join(err, errors.New("Windows installer lock is not one empty real regular file"))
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() != 0 {
		file.Close()
		return nil, errors.New("Windows installer lock changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		file.Close()
		return nil, fmt.Errorf("authenticate Windows installer lock: %w", err)
	}
	lock := &windowsInstallerLock{file: file}
	if err := windows.LockFileEx(
		windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &lock.overlapped,
	); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire Windows installer transaction lock: %w", err)
	}
	runtime.KeepAlive(file)
	lock.locked = true
	return lock, nil
}

func (lock *windowsInstallerLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	var unlockErr error
	if lock.locked {
		unlockErr = windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
		runtime.KeepAlive(lock.file)
		lock.locked = false
	}
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
