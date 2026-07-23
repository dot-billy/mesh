//go:build !windows

package identity

import (
	"errors"
	"os"
	"syscall"
)

func lockIdentityFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockIdentityFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

func requirePrivatePath(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("path must be owned by the current effective user")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("path must not be accessible by group or other users")
	}
	return nil
}

func requirePrivateFile(_ *os.File, info os.FileInfo) error {
	return requirePrivatePath(info)
}

func requirePrivateRoot(_ string, _ *os.Root, info os.FileInfo) error {
	return requirePrivatePath(info)
}

func requirePrivateOIDCSecret(_ *os.File, info os.FileInfo) error {
	if err := requirePrivatePath(info); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("secret file must have exactly one hard link")
	}
	if info.Mode().Perm()&0o400 == 0 || info.Mode().Perm()&0o100 != 0 {
		return errors.New("secret file must be owner-readable and non-executable")
	}
	return nil
}

func syncIdentityRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
