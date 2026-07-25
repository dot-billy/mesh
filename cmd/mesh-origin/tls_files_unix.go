//go:build !windows

package main

import (
	"os"
	"syscall"
)

func originTLSFileAllowed(info os.FileInfo, private bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return false
	}
	if !private {
		return true
	}
	return stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o077 == 0
}
