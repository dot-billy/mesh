//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func requirePrivateKeyOperationsSupported() error {
	return nil
}

func validatePrivateFileSecurity(info os.FileInfo) error {
	return validatePrivateFileSecurityForUID(info, uint32(os.Geteuid()))
}

func validatePrivateFileSecurityForUID(info os.FileInfo, effectiveUID uint32) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("private key must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != effectiveUID {
		return fmt.Errorf("private key must be owned by the effective user")
	}
	permissions := info.Mode().Perm()
	if permissions != 0o400 && permissions != 0o600 {
		return fmt.Errorf("private key permissions must be exactly 0400 or 0600")
	}
	return nil
}

func syncOutputParent(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("fsync parent directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close parent directory: %w", err)
	}
	return nil
}
