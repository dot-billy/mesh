//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func validateEnrollmentTokenFileSecurity(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("enrollment-token file must not be accessible by group or other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("enrollment-token file must be owned by the current user and have one link")
	}
	return nil
}
