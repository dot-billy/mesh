package nebulaobserverartifact

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maximumSourceEntries = 16 << 10
	maximumSourceBytes   = 512 << 20
)

func hashSourceTree(rootPath string) (string, int, int64, error) {
	// The domain-separated stream is sorted by slash-relative path and binds
	// entry type, executable bits, regular-file length, and regular-file bytes.
	// Ownership, timestamps, and read/write bits are deliberately excluded so
	// an authenticated module-cache tree and its private writable copy hash to
	// the same portable identity.
	rootPath, rootInfo, err := inspectRealDirectory(rootPath, "source tree")
	if err != nil {
		return "", 0, 0, err
	}
	paths, err := collectTreePaths(rootPath)
	if err != nil {
		return "", 0, 0, err
	}
	hash := sha256.New()
	_, _ = io.WriteString(hash, "mesh.nebula-observer-source-tree.v1\x00")
	var total int64
	for _, fullPath := range paths {
		relative, err := filepath.Rel(rootPath, fullPath)
		if err != nil {
			return "", 0, 0, fmt.Errorf("relativize source path: %w", err)
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || relative == "" || strings.ContainsRune(relative, '\x00') {
			return "", 0, 0, errors.New("source tree contains a non-canonical path")
		}
		before, err := os.Lstat(fullPath)
		if err != nil {
			return "", 0, 0, fmt.Errorf("inspect source path %q: %w", relative, err)
		}
		if err := validateSourceMode(relative, before.Mode()); err != nil {
			return "", 0, 0, err
		}
		kind := byte('d')
		size := int64(0)
		if before.Mode().IsRegular() {
			kind = 'f'
			size = before.Size()
			if size < 0 || size > maximumSourceBytes-total {
				return "", 0, 0, errors.New("source tree exceeds the aggregate size bound")
			}
			total += size
		}
		_, _ = hash.Write([]byte{kind})
		_ = binary.Write(hash, binary.BigEndian, uint32(len(relative)))
		_, _ = io.WriteString(hash, relative)
		_ = binary.Write(hash, binary.BigEndian, uint32(before.Mode().Perm()&0o111))
		_ = binary.Write(hash, binary.BigEndian, uint64(size))
		if kind == 'f' {
			if err := hashStableFile(hash, fullPath, relative, before); err != nil {
				return "", 0, 0, err
			}
		}
	}
	after, err := os.Lstat(rootPath)
	if err != nil || !stableFileInfo(rootInfo, after) {
		return "", 0, 0, errors.New("source tree root changed during hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), len(paths), total, nil
}

func collectTreePaths(rootPath string) ([]string, error) {
	paths := make([]string, 0, 1024)
	err := filepath.WalkDir(rootPath, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == rootPath {
			return nil
		}
		if len(paths) >= maximumSourceEntries {
			return errors.New("source tree entry count exceeds policy")
		}
		paths = append(paths, current)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk source tree: %w", err)
	}
	sort.Slice(paths, func(left, right int) bool {
		leftPath, _ := filepath.Rel(rootPath, paths[left])
		rightPath, _ := filepath.Rel(rootPath, paths[right])
		return filepath.ToSlash(leftPath) < filepath.ToSlash(rightPath)
	})
	return paths, nil
}

func hashStableFile(destination io.Writer, fullPath, relative string, before os.FileInfo) error {
	file, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", relative, err)
	}
	opened, err := file.Stat()
	if err != nil || !stableFileInfo(before, opened) {
		_ = file.Close()
		return fmt.Errorf("source file %q changed while opening", relative)
	}
	written, copyErr := io.CopyN(destination, file, before.Size())
	var extra [1]byte
	extraCount, extraErr := file.Read(extra[:])
	afterOpen, statErr := file.Stat()
	closeErr := file.Close()
	afterPath, lstatErr := os.Lstat(fullPath)
	if copyErr != nil || written != before.Size() || extraCount != 0 || !errors.Is(extraErr, io.EOF) || statErr != nil ||
		lstatErr != nil || closeErr != nil || !stableFileInfo(before, afterOpen) || !stableFileInfo(before, afterPath) {
		return fmt.Errorf("source file %q changed during hashing", relative)
	}
	return nil
}

func copySourceTree(sourcePath, destinationPath string) error {
	paths, err := collectTreePaths(sourcePath)
	if err != nil {
		return err
	}
	if err := os.Mkdir(destinationPath, 0o700); err != nil {
		return fmt.Errorf("create private source copy: %w", err)
	}
	for _, source := range paths {
		relative, err := filepath.Rel(sourcePath, source)
		if err != nil {
			return err
		}
		destination := filepath.Join(destinationPath, relative)
		before, err := os.Lstat(source)
		if err != nil {
			return fmt.Errorf("inspect source path %q: %w", filepath.ToSlash(relative), err)
		}
		if err := validateSourceMode(filepath.ToSlash(relative), before.Mode()); err != nil {
			return err
		}
		if before.IsDir() {
			if err := os.Mkdir(destination, 0o700); err != nil {
				return fmt.Errorf("copy source directory %q: %w", filepath.ToSlash(relative), err)
			}
			continue
		}
		if err := copyStableSourceFile(source, destination, filepath.ToSlash(relative), before); err != nil {
			return err
		}
	}
	return nil
}

func copyStableSourceFile(source, destination, relative string, before os.FileInfo) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", relative, err)
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !stableFileInfo(before, opened) {
		return fmt.Errorf("source file %q changed while opening", relative)
	}
	mode := os.FileMode(0o600) | before.Mode().Perm()&0o111
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create source-copy file %q: %w", relative, err)
	}
	written, copyErr := io.CopyN(output, input, before.Size())
	var extra [1]byte
	extraCount, extraErr := input.Read(extra[:])
	syncErr := output.Sync()
	closeErr := output.Close()
	afterInput, inputStatErr := input.Stat()
	afterPath, pathErr := os.Lstat(source)
	if copyErr != nil || written != before.Size() || extraCount != 0 || !errors.Is(extraErr, io.EOF) || syncErr != nil || closeErr != nil ||
		inputStatErr != nil || pathErr != nil || !stableFileInfo(before, afterInput) || !stableFileInfo(before, afterPath) {
		_ = os.Remove(destination)
		return fmt.Errorf("source file %q changed during copy", relative)
	}
	return nil
}

func inspectRealDirectory(path, label string) (string, os.FileInfo, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return "", nil, fmt.Errorf("%s path is required", label)
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || hasSpecialMode(info.Mode()) {
		return "", nil, fmt.Errorf("%s must be a real ordinary directory", label)
	}
	return absolute, info, nil
}

func validateSourceMode(relative string, mode os.FileMode) error {
	if hasSpecialMode(mode) || mode&os.ModeSymlink != 0 || (!mode.IsDir() && !mode.IsRegular()) {
		return fmt.Errorf("source path %q has a forbidden type or special mode", relative)
	}
	return nil
}

func hasSpecialMode(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice|os.ModeIrregular) != 0
}

func stableFileInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
