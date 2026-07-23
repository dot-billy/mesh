//go:build windows

package nebulaartifact

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const fileFlagBackupSemantics = 0x02000000

func requireSecureIntakeHost(_ string, _ os.FileInfo) error {
	return errors.New("dependency intake is disabled on Windows hosts because this stdlib-only build cannot verify the parent DACL and durable directory publication; cross-stage the Windows artifact from a supported POSIX host")
}

func syncDirectory(path string) error {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(pointer, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, fileFlagBackupSemantics, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(handle)
	if err := syscall.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("FlushFileBuffers: %w", err)
	}
	return nil
}

func syncOpenDirectory(_ *os.File, path string) error { return syncDirectory(path) }

func syncRootDirectory(_ *os.Root, _ string) error {
	return errors.New("rooted directory durability is unsupported on Windows hosts")
}
