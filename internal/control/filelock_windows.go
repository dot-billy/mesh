//go:build windows

package control

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

func lockStateFile(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := procLockFileEx.Call(file.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		return callErr
	}
	return nil
}

func unlockStateFile(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := procUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		return callErr
	}
	return nil
}

// Windows does not expose durable directory handles through os.Open. File
// replacement remains atomic, while file.Sync above provides the available
// durability boundary.
func syncStateDirectory(string) error { return nil }

// Access control is governed by the directory/file DACL on Windows rather than
// synthesized POSIX mode bits. Installation must grant only the service account.
func statePathPrivate(os.FileInfo) bool { return true }
