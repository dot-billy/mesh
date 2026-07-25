//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func validateRecoveryTokenFileSecurity(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("recovery-token file must not be accessible by group or other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("recovery-token file must be owned by the current user")
	}
	return nil
}
