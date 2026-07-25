package linuxbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// VerifyStagedDirectory performs a strict, read-only verification of an
// extracted or installed bundle tree. It is suitable for crash reconciliation
// when the original authenticated archive descriptor is no longer available.
func VerifyStagedDirectory(rootPath string, expected Expected) (StageResult, error) {
	if err := validateExpectedInput(expected); err != nil {
		return StageResult{}, err
	}
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return StageResult{}, fmt.Errorf("resolve staged bundle root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	beforeRoot, err := os.Lstat(absRoot)
	if err != nil || !exactDirectoryMode(beforeRoot, directoryMode) {
		return StageResult{}, errors.New("staged bundle root must be a real 0555 directory")
	}
	resolved, err := filepath.EvalSymlinks(absRoot)
	if err != nil || filepath.Clean(resolved) != absRoot {
		return StageResult{}, errors.New("staged bundle root path cannot traverse symlinks")
	}
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return StageResult{}, fmt.Errorf("anchor staged bundle root: %w", err)
	}
	defer root.Close()
	anchoredRoot, err := root.Stat(".")
	if err != nil || !os.SameFile(beforeRoot, anchoredRoot) {
		return StageResult{}, errors.New("staged bundle root changed while anchoring")
	}
	packageJSON, err := readRootedRegular(root, packageJSONPath, packageJSONMode, maxPackageJSONSize)
	if err != nil {
		return StageResult{}, err
	}
	metadata, err := parsePackage(packageJSON)
	if err != nil {
		return StageResult{}, err
	}
	if err := validateExpected(expected, metadata); err != nil {
		return StageResult{}, err
	}
	policy, err := productionPolicy(expected.Arch)
	if err != nil {
		return StageResult{}, err
	}
	return verifyDirectoryWithPolicy(root, beforeRoot, expected, metadata, packageJSON, policy)
}

func verifyDirectoryWithPolicy(root *os.Root, beforeRoot os.FileInfo, expected Expected, metadata Package, packageJSON []byte, policy bundlePolicy) (StageResult, error) {
	if err := policy.validateMetadata(metadata); err != nil {
		return StageResult{}, err
	}
	allowed := map[string]uint32{packageJSONPath: packageJSONMode}
	for _, directory := range directoryPaths {
		allowed[directory] = directoryMode
	}
	for _, entry := range metadata.Entries {
		allowed[entry.Path] = entry.Mode
	}
	seen := make(map[string]struct{}, len(allowed))
	directoryInfo := make(map[string]os.FileInfo, len(directoryPaths))
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		mode, ok := allowed[path]
		if !ok {
			return fmt.Errorf("staged bundle contains unexpected path %q", path)
		}
		if _, duplicate := seen[path]; duplicate {
			return fmt.Errorf("staged bundle repeats path %q", path)
		}
		seen[path] = struct{}{}
		info, err := root.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("staged bundle path %q is missing or is a symlink", path)
		}
		if entry.IsDir() {
			if !exactDirectoryMode(info, mode) {
				return fmt.Errorf("staged directory %q mode or type is invalid", path)
			}
			directoryInfo[path] = info
			return nil
		}
		if !exactRegularMode(info, mode) {
			return fmt.Errorf("staged file %q mode or type is invalid", path)
		}
		return nil
	})
	if err != nil {
		return StageResult{}, err
	}
	if len(seen) != len(allowed) {
		return StageResult{}, errors.New("staged bundle is missing required paths")
	}
	result := StageResult{Package: clonePackage(metadata), FileCount: len(metadata.Entries) + 1, TotalBytes: int64(len(packageJSON))}
	packageDigest := sha256.Sum256(packageJSON)
	result.PackageJSONSHA256 = hex.EncodeToString(packageDigest[:])
	for _, entry := range metadata.Entries {
		content, err := readRootedRegular(root, entry.Path, entry.Mode, maxPayloadFileSize)
		if err != nil {
			return StageResult{}, err
		}
		if int64(len(content)) != entry.Size {
			return StageResult{}, fmt.Errorf("staged payload %q size differs from package.json", entry.Path)
		}
		if err := policy.validateContent(entry.Path, content, metadata); err != nil {
			return StageResult{}, err
		}
		result.TotalBytes += int64(len(content))
	}
	currentPackageJSON, err := readRootedRegular(root, packageJSONPath, packageJSONMode, maxPackageJSONSize)
	if err != nil || !bytes.Equal(packageJSON, currentPackageJSON) {
		return StageResult{}, errors.New("staged package.json changed during verification")
	}
	for _, path := range directoryPaths {
		before, ok := directoryInfo[path]
		after, statErr := root.Lstat(path)
		if !ok || statErr != nil || !stableDirectoryInfo(before, after, directoryMode) {
			return StageResult{}, fmt.Errorf("staged directory %q changed during verification", path)
		}
	}
	afterRoot, err := root.Stat(".")
	pathRoot, pathErr := os.Lstat(root.Name())
	if err != nil || pathErr != nil || !stableDirectoryInfo(beforeRoot, afterRoot, directoryMode) ||
		!stableDirectoryInfo(beforeRoot, pathRoot, directoryMode) {
		return StageResult{}, errors.New("staged bundle root identity changed during verification")
	}
	return result, nil
}

func readRootedRegular(root *os.Root, path string, mode uint32, maximum int64) ([]byte, error) {
	before, err := root.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect staged file %s: %w", path, err)
	}
	if !exactRegularMode(before, mode) || !singleLink(before) || before.Size() <= 0 || before.Size() > maximum {
		return nil, fmt.Errorf("staged file %q type, mode, or size is invalid", path)
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open staged file %s: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !stableRegularInfo(before, opened) {
		return nil, fmt.Errorf("staged file %q changed while opening", path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read staged file %s: %w", path, err)
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := root.Lstat(path)
	if statErr != nil || pathErr != nil || !stableRegularInfo(opened, after) || !stableRegularInfo(opened, pathAfter) ||
		after.Size() != int64(len(content)) {
		return nil, fmt.Errorf("staged file %q changed while reading", path)
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("staged file %q exceeds size bound", path)
	}
	return content, nil
}

func stableRegularInfo(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) &&
		before.Mode() == after.Mode() && before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime()) && singleLink(after)
}

func stableDirectoryInfo(before, after os.FileInfo, mode uint32) bool {
	return before != nil && after != nil && os.SameFile(before, after) && exactDirectoryMode(after, mode) &&
		before.Mode() == after.Mode() &&
		before.ModTime().Equal(after.ModTime())
}

func exactRegularMode(info os.FileInfo, mode uint32) bool {
	return info != nil && info.Mode() == os.FileMode(mode)
}

func exactDirectoryMode(info os.FileInfo, mode uint32) bool {
	return info != nil && info.Mode() == os.ModeDir|os.FileMode(mode)
}
