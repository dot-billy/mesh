//go:build linux && amd64

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	renameat2SystemCall = 316
	renameNoReplaceFlag = 1
)

func renameSnapshotNoReplace(parentFD int, oldName, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		renameat2SystemCall,
		uintptr(parentFD), uintptr(unsafe.Pointer(oldPointer)),
		uintptr(parentFD), uintptr(unsafe.Pointer(newPointer)),
		renameNoReplaceFlag, 0,
	)
	runtime.KeepAlive(oldPointer)
	runtime.KeepAlive(newPointer)
	if errno != 0 {
		return errno
	}
	return nil
}
