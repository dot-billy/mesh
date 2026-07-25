//go:build !windows

package originimage

import (
	"os"
	"syscall"
)

func isSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
