package nebulaartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// VerifyStagedDirectory verifies an existing dependency directory against the
// sole embedded Nebula lock for goos/goarch. It is read-only and rejects a
// symlink root, symlink or special-file members, extra or missing members,
// unexpected output modes, sizes, hashes, and executable identities.
func VerifyStagedDirectory(rootPath, goos, goarch string) error {
	if rootPath == "" {
		return errors.New("staged directory path is required")
	}
	lock, err := EmbeddedLock()
	if err != nil {
		return err
	}
	artifact, err := lock.Select(goos, goarch)
	if err != nil {
		return err
	}
	return verifyStagedDirectory(rootPath, artifact)
}

type stagedPathExpectation struct {
	entry EntryLock
}

func verifyStagedDirectory(rootPath string, artifact ArtifactLock) error {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return fmt.Errorf("resolve staged directory path: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	inspected, err := os.Lstat(absRoot)
	if err != nil {
		return fmt.Errorf("inspect staged directory: %w", err)
	}
	if inspected.Mode()&os.ModeSymlink != 0 || !inspected.IsDir() {
		return errors.New("staged directory must be a real directory, not a symlink")
	}

	expected, err := stagedExpectedPaths(artifact.Entries)
	if err != nil {
		return fmt.Errorf("build staged-directory policy: %w", err)
	}
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return fmt.Errorf("open staged directory: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !stableStagedInfo(inspected, opened) {
		_ = root.Close()
		return errors.New("staged directory changed while opening")
	}
	seen := make(map[string]struct{}, len(expected))
	verifyErr := verifyStagedDirectoryRoot(root, "", expected, seen)
	currentRoot, pathErr := root.Stat(".")
	currentPath, lstatErr := os.Lstat(absRoot)
	if verifyErr == nil && (pathErr != nil || lstatErr != nil || !stableStagedInfo(opened, currentRoot) || !stableStagedInfo(opened, currentPath)) {
		verifyErr = errors.New("staged directory identity or metadata changed during verification")
	}
	if verifyErr == nil && len(seen) != len(expected) {
		missing := make([]string, 0, len(expected)-len(seen))
		for name := range expected {
			if _, ok := seen[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		verifyErr = fmt.Errorf("staged directory is missing locked entries: %s", strings.Join(missing, ", "))
	}
	closeErr := root.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return fmt.Errorf("close staged directory: %w", closeErr)
	}
	return nil
}

func stagedExpectedPaths(entries []EntryLock) (map[string]stagedPathExpectation, error) {
	if len(entries) == 0 {
		return nil, errors.New("lock has no staged entries")
	}
	expected := make(map[string]stagedPathExpectation, len(entries))
	for _, entry := range entries {
		directory := entry.Type == "dir"
		if err := validateArchivePath(entry.Name, directory); err != nil {
			return nil, err
		}
		name := outputPath(entry)
		if _, duplicate := expected[name]; duplicate {
			return nil, fmt.Errorf("duplicate staged path %q", name)
		}
		expected[name] = stagedPathExpectation{entry: entry}
	}
	for _, entry := range entries {
		for parent := path.Dir(outputPath(entry)); parent != "."; parent = path.Dir(parent) {
			if current, ok := expected[parent]; ok {
				if current.entry.Type != "dir" {
					return nil, fmt.Errorf("staged parent %q is locked as a file", parent)
				}
				continue
			}
			expected[parent] = stagedPathExpectation{entry: EntryLock{
				Name:       parent + "/",
				Type:       "dir",
				OutputMode: 0o700,
			}}
		}
	}
	return expected, nil
}

func verifyStagedDirectoryRoot(root *os.Root, prefix string, expected map[string]stagedPathExpectation, seen map[string]struct{}) (returnErr error) {
	before, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect staged directory %q: %w", displayStagedPath(prefix), err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || hasSpecialMode(before.Mode()) {
		return fmt.Errorf("staged path %q is not a real ordinary directory", displayStagedPath(prefix))
	}
	if prefix != "" {
		locked, ok := expected[prefix]
		if !ok || locked.entry.Type != "dir" {
			return fmt.Errorf("staged directory %q is not locked", prefix)
		}
		if err := verifyStagedInfo(prefix, before, locked.entry); err != nil {
			return err
		}
	}

	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open staged directory %q: %w", displayStagedPath(prefix), err)
	}
	defer func() {
		if err := directory.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close staged directory %q: %w", displayStagedPath(prefix), err)
		}
	}()
	opened, err := directory.Stat()
	if err != nil || !stableStagedInfo(before, opened) {
		return fmt.Errorf("staged directory %q changed while opening", displayStagedPath(prefix))
	}
	children, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("list staged directory %q: %w", displayStagedPath(prefix), err)
	}
	for _, child := range children {
		name := child.Name()
		fullName := name
		if prefix != "" {
			fullName = path.Join(prefix, name)
		}
		locked, ok := expected[fullName]
		if !ok {
			return fmt.Errorf("staged directory contains unlocked entry %q", fullName)
		}
		if _, duplicate := seen[fullName]; duplicate {
			return fmt.Errorf("staged entry %q was encountered more than once", fullName)
		}
		seen[fullName] = struct{}{}
		childInfo, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect staged entry %q: %w", fullName, err)
		}
		if err := verifyStagedInfo(fullName, childInfo, locked.entry); err != nil {
			return err
		}
		if locked.entry.Type == "dir" {
			if err := verifyStagedChildDirectory(root, name, fullName, childInfo, expected, seen); err != nil {
				return err
			}
			continue
		}
		if err := verifyStagedFile(root, name, fullName, childInfo, locked.entry); err != nil {
			return err
		}
	}
	afterOpen, statErr := directory.Stat()
	afterPath, lstatErr := root.Stat(".")
	if statErr != nil || lstatErr != nil || !stableStagedInfo(opened, afterOpen) || !stableStagedInfo(opened, afterPath) {
		return fmt.Errorf("staged directory %q changed during verification", displayStagedPath(prefix))
	}
	return nil
}

func verifyStagedChildDirectory(parent *os.Root, name, fullName string, before os.FileInfo, expected map[string]stagedPathExpectation, seen map[string]struct{}) (returnErr error) {
	child, err := parent.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("open staged directory %q: %w", fullName, err)
	}
	defer func() {
		if err := child.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close staged directory %q: %w", fullName, err)
		}
	}()
	opened, err := child.Stat(".")
	if err != nil || !stableStagedInfo(before, opened) {
		return fmt.Errorf("staged directory %q changed while opening", fullName)
	}
	if err := verifyStagedDirectoryRoot(child, fullName, expected, seen); err != nil {
		return err
	}
	afterOpen, statErr := child.Stat(".")
	afterPath, lstatErr := parent.Lstat(name)
	if statErr != nil || lstatErr != nil || !stableStagedInfo(opened, afterOpen) || !stableStagedInfo(opened, afterPath) {
		return fmt.Errorf("staged directory %q changed during verification", fullName)
	}
	return nil
}

func verifyStagedFile(root *os.Root, name, fullName string, before os.FileInfo, locked EntryLock) (returnErr error) {
	file, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open staged file %q: %w", fullName, err)
	}
	defer func() {
		if err := file.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close staged file %q: %w", fullName, err)
		}
	}()
	opened, err := file.Stat()
	if err != nil || !stableStagedInfo(before, opened) {
		return fmt.Errorf("staged file %q changed while opening", fullName)
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, locked.Size+1))
	if err != nil {
		return fmt.Errorf("hash staged file %q: %w", fullName, err)
	}
	if read != locked.Size {
		return fmt.Errorf("staged file %q size is %d, want %d", fullName, read, locked.Size)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != locked.SHA256 {
		return fmt.Errorf("staged file %q SHA-256 is %s, want %s", fullName, got, locked.SHA256)
	}
	if locked.Binary != nil {
		if err := verifyBinary(file, *locked.Binary); err != nil {
			return fmt.Errorf("verify staged executable %q: %w", fullName, err)
		}
	}
	afterOpen, statErr := file.Stat()
	afterPath, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || !stableStagedInfo(opened, afterOpen) || !stableStagedInfo(opened, afterPath) {
		return fmt.Errorf("staged file %q changed during verification", fullName)
	}
	return nil
}

func verifyStagedInfo(name string, info os.FileInfo, locked EntryLock) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || hasSpecialMode(info.Mode()) {
		return fmt.Errorf("staged entry %q has a forbidden type or special mode", name)
	}
	if uint32(info.Mode().Perm()) != locked.OutputMode {
		return fmt.Errorf("staged entry %q mode is %04o, want %04o", name, info.Mode().Perm(), locked.OutputMode)
	}
	if locked.Type == "dir" {
		if !info.IsDir() {
			return fmt.Errorf("staged entry %q is not a directory", name)
		}
		return nil
	}
	if locked.Type != "file" || !info.Mode().IsRegular() {
		return fmt.Errorf("staged entry %q is not a locked regular file", name)
	}
	if info.Size() != locked.Size {
		return fmt.Errorf("staged file %q size is %d, want %d", name, info.Size(), locked.Size)
	}
	return nil
}

func hasSpecialMode(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeAppend|os.ModeExclusive|os.ModeTemporary) != 0
}

func stableStagedInfo(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func displayStagedPath(name string) string {
	if name == "" {
		return "."
	}
	return name
}
