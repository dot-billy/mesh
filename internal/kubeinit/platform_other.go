//go:build !linux

package kubeinit

import "os"

func platformSupported() bool { return false }

func openExclusive(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
}

func ownedBy(os.FileInfo, int, int) bool { return false }

func ownedDirectoryBy(os.FileInfo, int, int) bool { return false }
