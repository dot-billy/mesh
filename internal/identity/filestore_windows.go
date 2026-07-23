//go:build windows

package identity

import (
	"os"
	"syscall"
	"unsafe"

	"mesh/internal/windowssecurity"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

var (
	identityKernel32     = syscall.NewLazyDLL("kernel32.dll")
	identityLockFileEx   = identityKernel32.NewProc("LockFileEx")
	identityUnlockFileEx = identityKernel32.NewProc("UnlockFileEx")
)

func lockIdentityFile(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := identityLockFileEx.Call(file.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		return callErr
	}
	return nil
}

func unlockIdentityFile(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := identityUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		return callErr
	}
	return nil
}

func requirePrivateFile(file *os.File, _ os.FileInfo) error {
	return windowssecurity.InspectPrivateChildFile(file)
}

func requirePrivateRoot(path string, _ *os.Root, info os.FileInfo) error {
	return windowssecurity.InspectPrivatePath(path, info, windowssecurity.Directory)
}

func requirePrivateOIDCSecret(file *os.File, _ os.FileInfo) error {
	return windowssecurity.InspectPrivateFileSingleLink(file, windowssecurity.RegularFile)
}

func syncIdentityRoot(*os.Root) error { return nil }
