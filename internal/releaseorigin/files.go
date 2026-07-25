package releaseorigin

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type fileIdentity struct {
	info    os.FileInfo
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func validateRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) == string(filepath.Separator) {
		return errors.New("release origin root must be a clean absolute non-root directory")
	}
	if err := rejectSymlinkPath(root, true); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect release origin root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("release origin root must be a real directory")
	}
	return nil
}

func rejectSymlinkPath(path string, leafDirectory bool) error {
	start := filepath.Dir(path)
	if leafDirectory {
		start = path
	}
	for current := start; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect release origin path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("release origin path component %q is not a real directory", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func objectFilesystemPath(root, objectPath string) string {
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(objectPath, "/")))
}

func openStableObject(root, objectPath string) (*os.File, fileIdentity, error) {
	if err := validateObjectPath(objectPath); err != nil {
		return nil, fileIdentity{}, err
	}
	target := objectFilesystemPath(root, objectPath)
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fileIdentity{}, fmt.Errorf("release origin object %q escapes its root", objectPath)
	}
	if err := rejectSymlinkPath(target, false); err != nil {
		return nil, fileIdentity{}, err
	}
	before, err := os.Lstat(target)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("inspect release origin object %q: %w", objectPath, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximumObjectFileSize || !singleLink(before) {
		return nil, fileIdentity{}, fmt.Errorf("release origin object %q must be one bounded single-link regular file", objectPath)
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("open release origin object %q: %w", objectPath, err)
	}
	after, err := file.Stat()
	if err != nil || !sameObjectFile(before, after) {
		_ = file.Close()
		return nil, fileIdentity{}, fmt.Errorf("release origin object %q changed while opening", objectPath)
	}
	return file, identityFromInfo(after), nil
}

func identityFromInfo(info os.FileInfo) fileIdentity {
	return fileIdentity{info: info, size: info.Size(), mode: info.Mode(), modTime: info.ModTime()}
}

func sameObjectFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && right.Mode()&os.ModeSymlink == 0 &&
		right.Mode().IsRegular() && right.Size() == left.Size() && right.Mode() == left.Mode() &&
		right.ModTime().Equal(left.ModTime()) && singleLink(right)
}

func hashObject(file *os.File, identity fileIdentity) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if file == nil {
		return zero, errors.New("release origin object file is nil")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.NewSectionReader(file, 0, identity.size))
	if err != nil || written != identity.size {
		return zero, fmt.Errorf("hash release origin object: read %d of %d bytes: %w", written, identity.size, err)
	}
	after, err := file.Stat()
	if err != nil || !sameObjectFile(identity.info, after) {
		return zero, errors.New("release origin object changed while hashing")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}
