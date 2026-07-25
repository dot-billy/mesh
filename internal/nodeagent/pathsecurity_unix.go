//go:build !windows && !darwin

package nodeagent

import (
	"fmt"
	"os"
	"syscall"
)

func privateStateParent(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.IsDir() && info.Mode().Perm()&0o077 == 0
}

func privateRegularFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func privateManagedDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.IsDir() && info.Mode().Perm() == 0o700
}

func safeManagedParent(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.IsDir() && info.Mode().Perm()&0o022 == 0
}

func validatePrivateStateParentPath(_ string, info os.FileInfo) error {
	if !privateStateParent(info) {
		return fmt.Errorf("agent state parent must be owned by the agent and have private permissions")
	}
	return nil
}

func validateOpenedPrivateFile(_ *os.File, info os.FileInfo) error {
	if !privateRegularFile(info) {
		return fmt.Errorf("file must be owned by the agent and have private permissions")
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
