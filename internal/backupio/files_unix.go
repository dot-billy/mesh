//go:build linux

package backupio

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	backupKeyBytes   = 32
	backupKeyFileLen = 44
	maxSecretFile    = 4 << 10
)

type unixOperations struct {
	publication       *publicationHooks
	beforeCapture     func() error
	beforePublication func() error
	beforeMarkerDrop  func() error
	syncRecovered     func(*os.File, string) error
	syncArchiveFile   func(*os.File) error
	syncArchiveDir    func(*os.Root) error
}

func newOperations() Operations { return unixOperations{} }

type verifiedRoot struct {
	root *os.Root
	path string
}

func (r *verifiedRoot) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	err := r.root.Close()
	r.root = nil
	return err
}

func cleanAbsolute(path, label string, allowRoot bool) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.IndexFunc(path, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s must be a clean absolute path", label)
	}
	if !allowRoot && path == string(filepath.Separator) {
		return "", fmt.Errorf("%s cannot be the filesystem root", label)
	}
	return path, nil
}

func rejectSymlinkComponents(path string) error {
	path, err := cleanAbsolute(path, "path", true)
	if err != nil {
		return err
	}
	if path == string(filepath.Separator) {
		return nil
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %s must not be a symbolic link", current)
		}
	}
	return nil
}

func unixStat(info os.FileInfo) (*syscall.Stat_t, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("filesystem ownership metadata is unavailable")
	}
	return stat, nil
}

func requireOwner(info os.FileInfo, label string) (*syscall.Stat_t, error) {
	stat, err := unixStat(info)
	if err != nil || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("%s must be owned by the current effective user", label)
	}
	return stat, nil
}

func requirePrivateDirectory(info os.FileInfo, label string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", label)
	}
	if _, err := requireOwner(info, label); err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o700 != 0o700 {
		return fmt.Errorf("%s must be owner-private and owner-accessible (0700)", label)
	}
	return nil
}

func requirePrivateRegular(info os.FileInfo, label string, singleLink bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a private regular file", label)
	}
	stat, err := requireOwner(info, label)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 || perm&0o400 == 0 || perm&0o111 != 0 {
		return fmt.Errorf("%s must be owner-readable, non-executable, and inaccessible to group or other users", label)
	}
	if singleLink && stat.Nlink != 1 {
		return fmt.Errorf("%s must have exactly one hard link", label)
	}
	return nil
}

func openVerifiedRoot(path, label string, private bool) (*verifiedRoot, error) {
	path, err := cleanAbsolute(path, label, false)
	if err != nil {
		return nil, err
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, fmt.Errorf("%s must be a real directory", label)
	}
	if private {
		if err := requirePrivateDirectory(before, label); err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = root.Close()
		}
	}()
	opened, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("verify %s: %w", label, err)
	}
	after, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("%s changed while opening", label)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s verification handle: %w", label, closeErr)
	}
	closeOnError = false
	return &verifiedRoot{root: root, path: path}, nil
}

func openParent(path, label string, private bool) (*verifiedRoot, string, error) {
	path, err := cleanAbsolute(path, label, false)
	if err != nil {
		return nil, "", err
	}
	base := filepath.Base(path)
	if base == "." || base == "" || base == string(filepath.Separator) || len(base) > 255 {
		return nil, "", fmt.Errorf("%s file name is invalid", label)
	}
	root, err := openVerifiedRoot(filepath.Dir(path), label+" parent directory", private)
	if err != nil {
		return nil, "", err
	}
	return root, base, nil
}

func readStableFile(root *os.Root, name, label string, limit int64, singleLink bool) ([]byte, os.FileInfo, error) {
	file, opened, err := openStableFile(root, name, label, limit, singleLink)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	raw, err := readOpenedStable(root, name, label, file, opened, limit)
	return raw, opened, err
}

func openStableFile(root *os.Root, name, label string, limit int64, singleLink bool) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if err := requirePrivateRegular(before, label, singleLink); err != nil {
		return nil, nil, err
	}
	if before.Size() < 0 || before.Size() > limit {
		return nil, nil, fmt.Errorf("%s exceeds the %d-byte safety limit", label, limit)
	}
	file, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", label, err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s changed while opening", label)
	}
	return file, opened, nil
}

func readOpenedStable(root *os.Root, name, label string, file *os.File, opened os.FileInfo, limit int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind %s: %w", label, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte safety limit", label, limit)
	}
	afterFD, err := file.Stat()
	if err != nil || !sameStableStat(opened, afterFD) {
		return nil, fmt.Errorf("%s changed during read", label)
	}
	afterPath, err := root.Lstat(name)
	if err != nil || !sameStableStat(opened, afterPath) {
		return nil, fmt.Errorf("%s changed during read", label)
	}
	return raw, nil
}

func sameStableStat(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime()) && left.Mode() == right.Mode()
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writeNewSynced(root *os.Root, name, label string, raw []byte, mode os.FileMode) error {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", label, err)
	}
	chmodErr := file.Chmod(mode)
	writeErr := writeAll(file, raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(chmodErr, writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("write %s: %w", label, err)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("verify %s: %w", label, err)
	}
	if err := requirePrivateRegular(info, label, true); err != nil {
		return err
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s mode is %04o, expected %04o", label, info.Mode().Perm(), mode.Perm())
	}
	return nil
}

func writeAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		count, err := file.Write(raw)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		raw = raw[count:]
	}
	return nil
}

func (unixOperations) Keygen(options KeygenOptions) (KeygenResult, error) {
	root, name, err := openParent(options.OutputPath, "backup key output", true)
	if err != nil {
		return KeygenResult{}, err
	}
	defer root.Close()
	rawKey := make([]byte, backupKeyBytes)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		return KeygenResult{}, fmt.Errorf("generate backup key: %w", err)
	}
	defer clear(rawKey)
	encoded := []byte(base64.RawURLEncoding.EncodeToString(rawKey) + "\n")
	defer clear(encoded)
	if err := writeNewSynced(root.root, name, "backup key", encoded, 0o600); err != nil {
		return KeygenResult{}, err
	}
	if err := syncRoot(root.root); err != nil {
		return KeygenResult{}, fmt.Errorf("sync backup key directory: %w", err)
	}
	return KeygenResult{Schema: "mesh-backup-command-result-v1", Status: "created", Path: options.OutputPath}, nil
}

func loadBackupKey(path string) ([]byte, error) {
	decoded, _, err := loadBackupKeyWithInfo(path)
	return decoded, err
}

func loadBackupKeyWithInfo(path string) ([]byte, os.FileInfo, error) {
	root, name, err := openParent(path, "backup key file", true)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	raw, info, err := readStableFile(root.root, name, "backup key file", maxSecretFile, true)
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	if len(raw) != backupKeyFileLen || raw[len(raw)-1] != '\n' || bytes.IndexByte(raw, '\r') >= 0 {
		return nil, nil, errors.New("backup key file must contain exactly 43 canonical base64url characters followed by LF")
	}
	encoded := string(raw[:len(raw)-1])
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != backupKeyBytes || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, nil, errors.New("backup key file must contain exactly 32 bytes as canonical unpadded base64url")
	}
	return decoded, info, nil
}
