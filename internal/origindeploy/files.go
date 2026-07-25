package origindeploy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readStableFile(path, label string, maximum int64) ([]byte, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, "", fmt.Errorf("%s must be a clean absolute non-root path", label)
	}
	if err := rejectSymlinkPath(path, false); err != nil {
		return nil, "", err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", fmt.Errorf("inspect %s: %w", label, err)
	}
	if !before.Mode().IsRegular() || !singleLink(before) || before.Size() < 1 || before.Size() > maximum ||
		before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Mode().Perm()&0o022 != 0 {
		return nil, "", fmt.Errorf("%s must be one bounded single-link regular file without special bits or group/other write access", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, "", fmt.Errorf("%s changed while it was opened", label)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) < 1 || int64(len(raw)) > maximum {
		return nil, "", fmt.Errorf("read bounded %s: %w", label, err)
	}
	afterOpen, err := file.Stat()
	if err != nil || !sameMetadata(opened, afterOpen) {
		return nil, "", fmt.Errorf("%s changed during its stable read", label)
	}
	if err := rejectSymlinkPath(path, false); err != nil {
		return nil, "", err
	}
	afterPath, err := os.Lstat(path)
	if err != nil || !sameMetadata(opened, afterPath) {
		return nil, "", fmt.Errorf("%s path changed during its stable read", label)
	}
	digest := sha256.Sum256(raw)
	return raw, hex.EncodeToString(digest[:]), nil
}

func sameMetadata(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && singleLink(right) &&
		left.Size() == right.Size() && left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

func inspectDockerSocket(path string) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("Docker socket must be a clean absolute non-root path")
	}
	if err := rejectSymlinkPath(path, false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect Docker socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || !singleLink(info) {
		return nil, errors.New("Docker endpoint must be one single-link local Unix socket")
	}
	return info, nil
}

func sameDockerSocket(path string, before os.FileInfo) bool {
	after, err := inspectDockerSocket(path)
	return err == nil && os.SameFile(before, after) && before.Mode() == after.Mode()
}

func rejectSymlinkPath(path string, leafDirectory bool) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symbolic link", current)
		}
		if current != path || leafDirectory {
			if !info.IsDir() {
				return fmt.Errorf("path component %q is not a directory", current)
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func writeNewReceipt(path string, raw []byte) (returnErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("origin runtime verification receipt output must be a clean absolute path")
	}
	if err := rejectSymlinkPath(filepath.Dir(path), true); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create origin runtime verification receipt: %w", err)
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
		return fmt.Errorf("write origin runtime verification receipt: wrote %d of %d bytes: %w", written, len(raw), err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync origin runtime verification receipt: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close origin runtime verification receipt: %w", err)
	}
	closed = true
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open origin runtime verification receipt directory: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync origin runtime verification receipt directory: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close origin runtime verification receipt directory: %w", err)
	}
	remove = false
	return nil
}
