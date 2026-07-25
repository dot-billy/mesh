package originaudit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func WriteNewReceipt(path string, raw []byte) (returnErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("release origin audit receipt output must be a clean absolute path")
	}
	if err := rejectSymlinkDirectoryPath(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := ParseReceipt(raw); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create release origin audit receipt: %w", err)
	}
	remove := true
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if remove {
			returnErr = errors.Join(returnErr, os.Remove(path))
		}
	}()
	written, err := file.Write(raw)
	if err != nil || written != len(raw) {
		return fmt.Errorf("write release origin audit receipt: wrote %d of %d bytes: %w", written, len(raw), err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync release origin audit receipt: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close release origin audit receipt: %w", err)
	}
	closed = true
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open release origin audit receipt directory: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync release origin audit receipt directory: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close release origin audit receipt directory: %w", err)
	}
	remove = false
	return nil
}

func rejectSymlinkDirectoryPath(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect release origin audit receipt directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("release origin audit receipt path component %q is not a real directory", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}
