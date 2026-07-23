//go:build linux

package backupio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// StartupFence serializes a restore with mesh-server's state-directory
// creation and initial marker checks. The lock is advisory: every supported
// restore and server startup must participate, while unrelated programs can
// still mutate the namespace.
type StartupFence struct {
	directory  *os.File
	parentInfo os.FileInfo
	parentPath string
	dataDir    string
}

// AcquireStartupFence takes an exclusive, nonblocking flock on the opened
// parent directory. Directory-FD locking avoids a writable lockfile that could
// itself be replaced and works before the restore target exists.
func AcquireStartupFence(dataDir string) (*StartupFence, error) {
	if _, err := RestoreMarkerPath(dataDir); err != nil {
		return nil, err
	}
	parent := filepath.Dir(dataDir)
	directory, err := os.Open(parent)
	if err != nil {
		return nil, fmt.Errorf("open restore/startup fence parent: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = directory.Close()
		}
	}()
	info, err := directory.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect restore/startup fence parent: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("restore/startup fence parent must be a directory")
	}
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrStartupFenceBusy, parent)
		}
		return nil, fmt.Errorf("lock restore/startup fence parent: %w", err)
	}
	pathInfo, err := os.Stat(parent)
	if err != nil || !os.SameFile(info, pathInfo) {
		_ = syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
		if err != nil {
			return nil, fmt.Errorf("recheck restore/startup fence parent: %w", err)
		}
		return nil, errors.New("restore/startup fence parent changed while locking")
	}
	closeOnError = false
	return &StartupFence{directory: directory, parentInfo: info, parentPath: parent, dataDir: dataDir}, nil
}

func (fence *StartupFence) verifyParent() error {
	if fence == nil || fence.directory == nil || fence.parentInfo == nil {
		return errors.New("restore/startup fence is not held")
	}
	pathInfo, err := os.Stat(fence.parentPath)
	if err != nil {
		return fmt.Errorf("recheck restore/startup fence parent: %w", err)
	}
	if !os.SameFile(fence.parentInfo, pathInfo) {
		return errors.New("restore/startup fence parent changed while the lock was held")
	}
	return nil
}

// Check revalidates the locked parent identity and applies the exact and
// alias-aware incomplete-restore marker checks for the bound data directory.
func (fence *StartupFence) Check() error {
	if err := fence.verifyParent(); err != nil {
		return err
	}
	return RefuseIncompleteRestore(fence.dataDir)
}

// Close releases the parent-directory fence. Callers must treat a release
// error as a failed startup or restore boundary.
func (fence *StartupFence) Close() error {
	if fence == nil || fence.directory == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(fence.directory.Fd()), syscall.LOCK_UN)
	closeErr := fence.directory.Close()
	fence.directory = nil
	if err := errors.Join(unlockErr, closeErr); err != nil {
		return fmt.Errorf("release restore/startup fence: %w", err)
	}
	return nil
}
