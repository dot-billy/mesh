//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Windows opens the stable adjacent lock without any sharing. A second agent
// cannot open the same inode until the lifetime handle is closed.
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
	pathPointer, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("encode %s lock path: %w", label, err)
	}
	handle, err := syscall.CreateFile(
		pathPointer,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open exclusive %s lock: %w", label, err)
	}
	file := os.NewFile(uintptr(handle), lockPath)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("open exclusive %s lock", label)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect %s lock: %w", label, err)
		}
		return nil, fmt.Errorf("%s lock must be a regular file", label)
	}
	return &processLock{file: file, path: lockPath}, nil
}

func (l *processLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return fmt.Errorf("close %s: %w", l.path, err)
	}
	return nil
}
