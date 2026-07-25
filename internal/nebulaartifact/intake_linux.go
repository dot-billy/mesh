//go:build linux

package nebulaartifact

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func requireSecureIntakeHost(parentPath string, parent os.FileInfo) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("dependency intake requires a Linux amd64 or arm64 host for atomic no-replace publication")
	}
	if parent == nil {
		return errors.New("cannot verify a missing output parent")
	}
	abs, err := filepath.Abs(parentPath)
	if err != nil || !filepath.IsAbs(abs) {
		return errors.New("output parent path is not absolute")
	}
	currentPath := string(filepath.Separator)
	previous, err := os.Lstat(currentPath)
	if err != nil || !previous.IsDir() || previous.Mode()&os.ModeSymlink != 0 {
		return errors.New("filesystem root cannot be securely inspected")
	}
	rootStat, ok := previous.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 && rootStat.Uid != uint32(os.Geteuid()) {
		return errors.New("filesystem root is not owned by root or the effective user")
	}
	if err := rejectPOSIXACL(currentPath); err != nil {
		return err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		info, err := os.Lstat(currentPath)
		if err != nil {
			return fmt.Errorf("inspect output ancestor %q: %w", currentPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("output ancestor %q must be a real directory", currentPath)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("output ancestor %q is not owned by root or the effective user", currentPath)
		}
		if err := rejectPOSIXACL(currentPath); err != nil {
			return err
		}
		if previous.Mode().Perm()&0o022 != 0 && previous.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("output ancestor parent of %q is group/world writable without the sticky bit", currentPath)
		}
		previous = info
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify output parent ownership on this Linux host")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("output parent must be owned by the effective user")
	}
	if parent.Mode().Perm()&0o022 != 0 {
		return errors.New("output parent must not be writable by group or other users")
	}
	return nil
}

func rejectPOSIXACL(path string) error {
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		size, err := syscall.Getxattr(path, attribute, nil)
		if err == nil && size > 0 {
			return fmt.Errorf("output ancestor %q has extended POSIX ACL %q", path, attribute)
		}
		if err != nil && !errors.Is(err, syscall.ENODATA) && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.EOPNOTSUPP) {
			return fmt.Errorf("verify output ancestor ACL %q: %w", path, err)
		}
	}
	return nil
}
