//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package nodeagent

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

var ErrAgentAlreadyRunning = errors.New("another Mesh node agent owns this state")

type ProcessLock struct {
	file *os.File
}

func acquireProcessLock(path string) (*ProcessLock, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !privateRegularFile(info) {
			return nil, errors.New("agent process lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect agent process lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open agent process lock: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !privateRegularFile(info) {
		return nil, errors.New("agent process lock must be an owned private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrAgentAlreadyRunning
		}
		return nil, fmt.Errorf("lock agent state: %w", err)
	}
	if err := file.Truncate(0); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return nil, fmt.Errorf("truncate agent process lock: %w", err)
	}
	if _, err := file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return nil, fmt.Errorf("record agent process lock owner: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return nil, fmt.Errorf("sync agent process lock: %w", err)
	}
	failed = false
	return &ProcessLock{file: file}, nil
}

func (l *ProcessLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}
