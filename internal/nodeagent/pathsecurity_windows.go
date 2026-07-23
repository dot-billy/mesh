//go:build windows

package nodeagent

import (
	"fmt"
	"os"

	"mesh/internal/windowssecurity"
)

// Windows access control is expressed by DACLs rather than synthesized POSIX
// mode bits. The installer must grant access only to the agent service account.
func privateStateParent(info os.FileInfo) bool      { return info.IsDir() }
func privateRegularFile(info os.FileInfo) bool      { return info.Mode().IsRegular() }
func privateManagedDirectory(info os.FileInfo) bool { return info.IsDir() }
func safeManagedParent(info os.FileInfo) bool       { return info.IsDir() }

func validatePrivateStateParentPath(path string, info os.FileInfo) error {
	if err := windowssecurity.InspectPrivatePath(path, info, windowssecurity.Directory); err != nil {
		return fmt.Errorf("authenticate Windows agent-state directory DACL: %w", err)
	}
	return nil
}

func validateOpenedPrivateFile(file *os.File, _ os.FileInfo) error {
	if err := windowssecurity.InspectPrivateChildFile(file); err != nil {
		return fmt.Errorf("authenticate Windows agent-state child DACL: %w", err)
	}
	return nil
}

// File Sync plus atomic replacement is the standard-library durability bound
// available on Windows; opening directories for Sync is not supported.
func syncDir(string) error { return nil }
