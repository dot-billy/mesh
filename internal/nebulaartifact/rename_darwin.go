//go:build darwin

package nebulaartifact

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	darwinRenameatxNP = 488
	darwinRenameExcl  = 4
)

func renameNoReplace(parent *os.File, _ string, oldName, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(darwinRenameatxNP, parent.Fd(), uintptr(unsafe.Pointer(oldPointer)), parent.Fd(), uintptr(unsafe.Pointer(newPointer)), darwinRenameExcl, 0)
	runtime.KeepAlive(parent)
	if errno != 0 {
		return errno
	}
	return nil
}
