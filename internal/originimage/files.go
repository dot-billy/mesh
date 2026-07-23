package originimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	maxPublicKeySize = 64 << 10
	maxCosignSize    = 256 << 20
)

func loadPublicKey(path string) ([]byte, string, error) {
	var captured bytes.Buffer
	digest, err := hashStableFile(path, "Cosign public key", maxPublicKeySize, false, &captured)
	if err != nil {
		return nil, "", err
	}
	return captured.Bytes(), digest, nil
}

func hashCosign(path string) (string, error) {
	return HashExecutable(path, "Cosign executable")
}

// HashExecutable takes a stable bounded SHA-256 snapshot of one exact external
// executable without resolving it through PATH.
func HashExecutable(path, label string) (string, error) {
	if label == "" {
		label = "external executable"
	}
	return hashStableFile(path, label, maxCosignSize, true, nil)
}

// ReadReceiptFile stably reads and parses one canonical image-verification
// receipt. The returned digest covers its exact canonical bytes.
func ReadReceiptFile(path string) (Receipt, []byte, string, error) {
	var captured bytes.Buffer
	digest, err := hashStableFile(path, "origin image verification receipt", MaxReceiptSize, false, &captured)
	if err != nil {
		return Receipt{}, nil, "", err
	}
	raw := captured.Bytes()
	receipt, err := ParseReceipt(raw)
	if err != nil {
		return Receipt{}, nil, "", err
	}
	return receipt, raw, digest, nil
}

func hashStableFile(path, label string, maximum int64, executable bool, capture *bytes.Buffer) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", fmt.Errorf("%s must be a clean absolute non-root path", label)
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return "", fmt.Errorf("inspect %s path: %w", label, err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", label, err)
	}
	if err := validateFileMetadata(before, label, maximum, executable); err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", fmt.Errorf("%s changed while it was opened", label)
	}
	hasher := sha256.New()
	writer := io.Writer(hasher)
	if capture != nil {
		writer = io.MultiWriter(hasher, capture)
	}
	written, err := io.Copy(writer, io.LimitReader(file, maximum+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	if written < 1 || written > maximum {
		return "", fmt.Errorf("%s size must be between 1 and %d bytes", label, maximum)
	}
	afterOpen, err := file.Stat()
	if err != nil || !sameFileMetadata(opened, afterOpen) {
		return "", fmt.Errorf("%s changed during its stable read", label)
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return "", fmt.Errorf("reinspect %s path: %w", label, err)
	}
	afterPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, afterPath) || !sameFileMetadata(opened, afterPath) {
		return "", fmt.Errorf("%s path changed during its stable read", label)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validateFileMetadata(info os.FileInfo, label string, maximum int64, executable bool) error {
	if info == nil || !info.Mode().IsRegular() || !isSingleLink(info) || info.Size() < 1 || info.Size() > maximum {
		return fmt.Errorf("%s must be one bounded single-link regular file", label)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not have special bits or group/other write access", label)
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s must be executable", label)
	}
	return nil
}

func sameFileMetadata(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Size() == right.Size() && left.Mode() == right.Mode() &&
		left.ModTime().Equal(right.ModTime()) && isSingleLink(right)
}

func rejectSymlinkComponents(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symbolic link", current)
		}
		if current != path && !info.IsDir() {
			return fmt.Errorf("path component %q is not a directory", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func writePublicKeySnapshot(raw []byte) (string, func(), error) {
	directory, err := os.MkdirTemp("", "mesh-origin-image-key.*")
	if err != nil {
		return "", nil, fmt.Errorf("create public-key snapshot directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	path := filepath.Join(directory, "cosign.pub")
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("write public-key snapshot: %w", err)
	}
	return path, cleanup, nil
}

func writeNewReceipt(path string, raw []byte) (returnErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("origin image verification receipt output must be a clean absolute path")
	}
	if err := rejectOutputSymlinks(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create origin image verification receipt: %w", err)
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
		return fmt.Errorf("write origin image verification receipt: wrote %d of %d bytes: %w", written, len(raw), err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync origin image verification receipt: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close origin image verification receipt: %w", err)
	}
	closed = true
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open origin image verification receipt directory: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync origin image verification receipt directory: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close origin image verification receipt directory: %w", err)
	}
	remove = false
	return nil
}

func rejectOutputSymlinks(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect origin image verification receipt directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("origin image verification receipt path component %q is not a real directory", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}
