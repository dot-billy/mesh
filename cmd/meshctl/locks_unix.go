//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// processLock is deliberately adjacent to, rather than inside, the target.
// Agent state is atomically replaced and bundle revisions are immutable, so a
// stable neighboring inode is the only safe place for a lifetime lock.
type processLock struct {
	file *os.File
	path string
}

func acquireProcessLock(target, label string) (*processLock, error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve %s lock target: %w", label, err)
	}
	lockPath := filepath.Clean(absTarget) + ".meshctl.lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create %s lock directory: %w", label, err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s lock: %w", label, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect %s lock: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s lock must be a regular file", label)
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("secure %s lock: %w", label, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another meshctl process holds the %s lock", label)
		}
		return nil, fmt.Errorf("acquire %s lock: %w", label, err)
	}
	closeOnError = false
	return &processLock{file: file, path: lockPath}, nil
}

func (l *processLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock %s: %w", l.path, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", l.path, closeErr)
	}
	return nil
}
