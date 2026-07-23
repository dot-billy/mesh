//go:build windows

package nebulaartifact

import (
	"os"
	"path/filepath"
	"syscall"
)

func renameNoReplace(_ *os.File, parentPath, oldName, newName string) error {
	oldPointer, err := syscall.UTF16PtrFromString(filepath.Join(parentPath, oldName))
	if err != nil {
		return err
	}
	newPointer, err := syscall.UTF16PtrFromString(filepath.Join(parentPath, newName))
	if err != nil {
		return err
	}
	// MoveFile (unlike MoveFileEx with replace flags) fails if newName exists.
	return syscall.MoveFile(oldPointer, newPointer)
}
