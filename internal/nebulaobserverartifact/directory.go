package nebulaobserverartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type VerificationResult struct {
	OutputDir  string
	Target     Target
	Identity   Identity
	Manifest   Manifest
	FileCount  int
	TotalBytes int64
}

// VerifyStagedDirectory authenticates an exact observer stage against the
// embedded source-build lock. It is read-only and rejects alternate policies,
// extra files, links, special files, modes, bytes, targets, and Go identities.
func VerifyStagedDirectory(rootPath, arch string) (VerificationResult, error) {
	return verifyStagedDirectoryTarget(rootPath, "linux", arch)
}

// VerifyWindowsStagedDirectory authenticates one exact reproducible Windows
// runtime stage. It does not evaluate Authenticode or host ACLs.
func VerifyWindowsStagedDirectory(rootPath, arch string) (VerificationResult, error) {
	return verifyStagedDirectoryTarget(rootPath, "windows", arch)
}

// VerifyDarwinStagedDirectory authenticates one exact reproducible Darwin
// runtime stage. It does not evaluate codesigning, notarization, or host ACLs.
func VerifyDarwinStagedDirectory(rootPath, arch string) (VerificationResult, error) {
	return verifyStagedDirectoryTarget(rootPath, "darwin", arch)
}

func verifyStagedDirectoryTarget(rootPath, targetOS, arch string) (VerificationResult, error) {
	policy, policyDigest, err := EmbeddedPolicy()
	if err != nil {
		return VerificationResult{}, err
	}
	manifestSchema := ManifestSchema
	var targetLock TargetLock
	switch targetOS {
	case "linux":
		targetLock, err = policy.Select(strings.TrimSpace(arch))
	case "windows":
		targetLock, policyDigest, err = selectWindowsTarget(strings.TrimSpace(arch))
		manifestSchema = WindowsManifestSchema
	case "darwin":
		targetLock, policyDigest, err = selectDarwinTarget(strings.TrimSpace(arch))
		manifestSchema = DarwinManifestSchema
	default:
		err = fmt.Errorf("unsupported source-built runtime target %s/%s", targetOS, arch)
	}
	if err != nil {
		return VerificationResult{}, err
	}
	absolute, rootInfo, err := inspectRealDirectory(rootPath, "observer staging directory")
	if err != nil {
		return VerificationResult{}, err
	}
	if rootInfo.Mode().Perm() != 0o555 {
		return VerificationResult{}, errors.New("observer staging directory mode must be 0555")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("anchor observer staging directory: %w", err)
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil || !stableFileInfo(rootInfo, openedRoot) {
		return VerificationResult{}, errors.New("observer staging directory changed while opening")
	}
	directory, err := root.Open(".")
	if err != nil {
		return VerificationResult{}, fmt.Errorf("open observer staging directory: %w", err)
	}
	children, err := directory.ReadDir(-1)
	closeDirectoryErr := directory.Close()
	if err != nil {
		return VerificationResult{}, fmt.Errorf("list observer staging directory: %w", err)
	}
	if closeDirectoryErr != nil {
		return VerificationResult{}, fmt.Errorf("close observer staging directory: %w", closeDirectoryErr)
	}
	names := make([]string, len(children))
	for index, child := range children {
		names[index] = child.Name()
	}
	sort.Strings(names)
	expectedNames := []string{manifestName}
	for _, entry := range targetLock.Entries {
		expectedNames = append(expectedNames, entry.Name)
	}
	sort.Strings(expectedNames)
	if !equalStrings(names, expectedNames) {
		return VerificationResult{}, fmt.Errorf("observer staging directory contains %v, want exactly %v", names, expectedNames)
	}
	manifestBytes, err := readRootedStableRegular(root, manifestName, manifestMode, maximumManifestSize)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("verify %s: %w", manifestName, err)
	}
	manifest, err := parseManifest(manifestBytes)
	if err != nil {
		return VerificationResult{}, err
	}
	target := Target{OS: targetOS, Arch: targetLock.Arch}
	if manifest.Schema != manifestSchema || manifest.PolicySHA256 != policyDigest || manifest.Target != target ||
		manifest.GoVersion != policy.Toolchain || !equalEntries(manifest.Entries, targetLock.Entries) {
		return VerificationResult{}, errors.New("observer stage manifest differs from the embedded build policy")
	}
	total := int64(len(manifestBytes))
	for _, entry := range targetLock.Entries {
		content, err := readRootedStableRegular(root, entry.Name, entry.Mode, maximumBinarySize)
		if err != nil {
			return VerificationResult{}, fmt.Errorf("verify observer entry %q: %w", entry.Name, err)
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return VerificationResult{}, fmt.Errorf("observer entry %q bytes differ from the build lock", entry.Name)
		}
		if err := verifyBinary(content, entry, target, policy); err != nil {
			return VerificationResult{}, fmt.Errorf("verify observer entry %q: %w", entry.Name, err)
		}
		total += int64(len(content))
	}
	afterRoot, rootErr := root.Stat(".")
	afterPath, pathErr := os.Lstat(absolute)
	if rootErr != nil || pathErr != nil || !stableFileInfo(openedRoot, afterRoot) || !stableFileInfo(openedRoot, afterPath) {
		return VerificationResult{}, errors.New("observer staging directory changed during verification")
	}
	return VerificationResult{
		OutputDir: absolute, Target: target, Identity: policy.identity(policyDigest), Manifest: manifest,
		FileCount: len(expectedNames), TotalBytes: total,
	}, nil
}

func readStableRegular(path string, mode uint32, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || hasSpecialMode(before.Mode()) ||
		before.Mode().Perm() != os.FileMode(mode) || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("entry is not a bounded regular file with its locked mode")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !stableFileInfo(before, opened) {
		_ = file.Close()
		return nil, errors.New("entry changed while opening")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	afterOpen, statErr := file.Stat()
	closeErr := file.Close()
	afterPath, lstatErr := os.Lstat(path)
	if readErr != nil || int64(len(content)) != before.Size() || statErr != nil || closeErr != nil || lstatErr != nil ||
		!stableFileInfo(before, afterOpen) || !stableFileInfo(before, afterPath) {
		return nil, errors.New("entry changed during verification")
	}
	return content, nil
}

func readRootedStableRegular(root *os.Root, name string, mode uint32, maximum int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || hasSpecialMode(before.Mode()) ||
		before.Mode().Perm() != os.FileMode(mode) || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("entry is not a bounded regular file with its locked mode")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !stableFileInfo(before, opened) {
		_ = file.Close()
		return nil, errors.New("entry changed while opening")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	afterOpen, statErr := file.Stat()
	closeErr := file.Close()
	afterPath, lstatErr := root.Lstat(name)
	if readErr != nil || int64(len(content)) != before.Size() || statErr != nil || closeErr != nil || lstatErr != nil ||
		!stableFileInfo(before, afterOpen) || !stableFileInfo(before, afterPath) {
		return nil, errors.New("entry changed during verification")
	}
	return content, nil
}

func equalEntries(left, right []EntryLock) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
