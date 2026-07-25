//go:build linux

package releaseorigin

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameGenerationNoReplace(parentPath, oldName, newName string) error {
	parent, err := os.Open(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	return unix.Renameat2(int(parent.Fd()), oldName, int(parent.Fd()), newName, unix.RENAME_NOREPLACE)
}
