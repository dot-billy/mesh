//go:build linux

package kubeinit

import (
	"os"
	"syscall"
)

func platformSupported() bool { return true }

func openExclusive(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
}

func ownedBy(info os.FileInfo, uid, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(uid) && stat.Gid == uint32(gid) && stat.Nlink == 1
}

func ownedDirectoryBy(info os.FileInfo, uid, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(uid) && stat.Gid == uint32(gid)
}
