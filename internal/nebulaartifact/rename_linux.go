//go:build linux && (amd64 || arm64)

package nebulaartifact

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const renameNoReplaceFlag = 1

func renameNoReplace(parent *os.File, _ string, oldName, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(renameat2Trap, parent.Fd(), uintptr(unsafe.Pointer(oldPointer)), parent.Fd(), uintptr(unsafe.Pointer(newPointer)), renameNoReplaceFlag, 0)
	runtime.KeepAlive(parent)
	if errno != 0 {
		return errno
	}
	return nil
}
