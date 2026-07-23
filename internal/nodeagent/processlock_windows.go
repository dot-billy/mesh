//go:build windows

package nodeagent

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errorLockViolation      = syscall.Errno(33)
)

var (
	ErrAgentAlreadyRunning = errors.New("another Mesh node agent owns this state")
	kernel32DLL            = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc         = kernel32DLL.NewProc("LockFileEx")
	unlockFileExProc       = kernel32DLL.NewProc("UnlockFileEx")
)

type ProcessLock struct {
	file       *os.File
	overlapped syscall.Overlapped
}

func acquireProcessLock(path string) (*ProcessLock, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !privateRegularFile(info) {
			return nil, errors.New("agent process lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect agent process lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open agent process lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect agent process lock: %w", err)
	}
	if err := validateOpenedPrivateFile(file, info); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("agent process lock: %w", err)
	}
	lock := &ProcessLock{file: file}
	result, _, callErr := lockFileExProc.Call(
		file.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0,
		uintptr(unsafe.Pointer(&lock.overlapped)),
	)
	if result == 0 {
		_ = file.Close()
		if errors.Is(callErr, errorLockViolation) {
			return nil, ErrAgentAlreadyRunning
		}
		return nil, fmt.Errorf("lock agent state: %w", callErr)
	}
	if err := file.Truncate(0); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("truncate agent process lock: %w", err)
	}
	if _, err := file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("record agent process lock owner: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("sync agent process lock: %w", err)
	}
	return lock, nil
}

func (l *ProcessLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	result, _, callErr := unlockFileExProc.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&l.overlapped)))
	var unlockErr error
	if result == 0 {
		unlockErr = callErr
	}
	return errors.Join(unlockErr, file.Close())
}
