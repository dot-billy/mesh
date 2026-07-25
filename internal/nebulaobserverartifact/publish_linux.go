//go:build linux

package nebulaobserverartifact

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameNoReplace(parent *os.File, oldName, newName string) error {
	return unix.Renameat2(int(parent.Fd()), oldName, int(parent.Fd()), newName, unix.RENAME_NOREPLACE)
}
