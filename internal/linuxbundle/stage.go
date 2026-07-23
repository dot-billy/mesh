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
)

type stagedFile struct {
	path string
	mode uint32
	file *os.File
}

type stagedDirectory struct {
	path string
	file *os.File
}

// StageAuthenticated consumes an already-authenticated open archive descriptor
// and writes only the fixed package tree beneath an empty anchored root. It
// never reopens the archive pathname and does not publish, install, or start
// anything.
func StageAuthenticated(archive *os.File, root *os.Root, expected Expected, artifact ArtifactIdentity) (StageResult, error) {
	policy, err := productionPolicy(expected.Arch)
	if err != nil {
		return StageResult{}, err
	}
	return stageWithPolicy(archive, root, expected, artifact, policy)
}

func stageWithPolicy(archive *os.File, root *os.Root, expected Expected, artifact ArtifactIdentity, policy bundlePolicy) (result StageResult, returnErr error) {
	if archive == nil || root == nil {
		return result, errors.New("authenticated archive and staging root are required")
	}
	if err := validateExpectedInput(expected); err != nil {
		return result, err
	}
	if expected.Arch != policy.arch {
		return result, errors.New("expected architecture does not match the compiled bundle policy")
	}
	before, err := archive.Stat()
	if err != nil {
		return result, fmt.Errorf("inspect authenticated archive: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > MaxArchiveSize {
		return result, errors.New("authenticated archive must be a bounded non-empty regular file")
	}
	if artifact.Size != before.Size() || artifact.Size <= 0 || artifact.Size > MaxArchiveSize || !digestPattern.MatchString(artifact.SHA256) {
		return result, errors.New("threshold-authenticated artifact identity does not match the open archive size")
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !exactDirectoryMode(rootInfo, 0o700) {
		return result, errors.New("staging root must be an anchored real 0700 directory")
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return result, fmt.Errorf("inspect staging root: %w", err)
	}
	if len(entries) != 0 {
		return result, errors.New("staging root must be empty")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind authenticated archive: %w", err)
	}
	archiveHasher := sha256.New()
	reader := io.TeeReader(archive, archiveHasher)
	packageHeaderBlock := make([]byte, tarBlockSize)
	if err := readExact(reader, packageHeaderBlock, "package.json header"); err != nil {
		return result, err
	}
	if allZero(packageHeaderBlock) {
		return result, errors.New("archive begins with an end marker instead of package.json")
	}
	packageHeader, err := parseHeaderBlock(packageHeaderBlock)
	if err != nil {
		return result, err
	}
	if packageHeader.Name != packageJSONPath || packageHeader.Size <= 0 || packageHeader.Size > maxPackageJSONSize {
		return result, errors.New("first archive member must be bounded package.json")
	}
	packageJSON := make([]byte, packageHeader.Size)
	if err := readExact(reader, packageJSON, "package.json payload"); err != nil {
		return result, err
	}
	if err := readZeroPadding(reader, packageHeader.Size, packageJSONPath); err != nil {
		return result, err
	}
	metadata, err := parsePackage(packageJSON)
	if err != nil {
		return result, err
	}
	buildTime, _ := parseCanonicalTime(metadata.BuildTime)
	expectedPackageHeader, err := canonicalHeaderBlock(packageJSONPath, packageJSONMode, int64(len(packageJSON)), buildTime)
	if err != nil || !bytes.Equal(packageHeaderBlock, expectedPackageHeader) {
		return result, errors.New("package.json header is not canonical USTAR")
	}
	if err := validateExpected(expected, metadata); err != nil {
		return result, err
	}
	if err := policy.validateMetadata(metadata); err != nil {
		return result, err
	}
	wantArchiveSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil {
		return result, err
	}
	if before.Size() != wantArchiveSize {
		return result, fmt.Errorf("archive size is %d bytes, canonical size is %d", before.Size(), wantArchiveSize)
	}

	directories, err := createStageDirectories(root)
	if err != nil {
		return result, err
	}
	files := make([]stagedFile, 0, len(payloadSpecs)+1)
	cleanup := true
	defer func() {
		for index := range files {
			if files[index].file != nil {
				_ = files[index].file.Close()
			}
		}
		for index := range directories {
			if directories[index].file != nil {
				if cleanup {
					_ = directories[index].file.Chmod(0o700)
				}
				_ = directories[index].file.Close()
			}
		}
		if cleanup {
			_ = root.Chmod(".", 0o700)
			for _, directory := range directoryPaths {
				_ = root.Chmod(directory, 0o700)
			}
			_ = root.Remove(packageJSONPath)
			for _, top := range []string{"bin", "lib", "share"} {
				_ = root.RemoveAll(top)
			}
		}
	}()
	packageFile, err := createStagedFile(root, packageJSONPath, packageJSON)
	if err != nil {
		return result, err
	}
	files = append(files, stagedFile{path: packageJSONPath, mode: packageJSONMode, file: packageFile})

	for index, entry := range metadata.Entries {
		headerBlock := make([]byte, tarBlockSize)
		if err := readExact(reader, headerBlock, fmt.Sprintf("header for payload %d", index)); err != nil {
			return result, err
		}
		if allZero(headerBlock) {
			return result, fmt.Errorf("archive ended before payload %q", entry.Path)
		}
		header, err := parseHeaderBlock(headerBlock)
		if err != nil {
			return result, fmt.Errorf("payload %q: %w", entry.Path, err)
		}
		canonical, err := canonicalHeaderBlock(entry.Path, entry.Mode, entry.Size, buildTime)
		if err != nil || !bytes.Equal(headerBlock, canonical) || header.Name != entry.Path || header.Size != entry.Size {
			return result, fmt.Errorf("payload %q header is not canonical USTAR", entry.Path)
		}
		content := make([]byte, entry.Size)
		if err := readExact(reader, content, "payload "+entry.Path); err != nil {
			return result, err
		}
		if err := readZeroPadding(reader, entry.Size, entry.Path); err != nil {
			return result, err
		}
		if err := policy.validateContent(entry.Path, content, metadata); err != nil {
			return result, err
		}
		file, err := createStagedFile(root, entry.Path, content)
		if err != nil {
			return result, err
		}
		files = append(files, stagedFile{path: entry.Path, mode: entry.Mode, file: file})
		result.TotalBytes += entry.Size
	}
	var trailer [2 * tarBlockSize]byte
	if err := readExact(reader, trailer[:], "exact two-block USTAR trailer"); err != nil {
		return result, err
	}
	if !allZero(trailer[:]) {
		return result, errors.New("USTAR trailer must contain exactly two zero blocks")
	}
	var trailing [1]byte
	if count, err := reader.Read(trailing[:]); err != io.EOF || count != 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			return result, fmt.Errorf("inspect trailing archive bytes: %w", err)
		}
		return result, errors.New("archive contains data after the exact two-block USTAR trailer")
	}
	after, err := archive.Stat()
	position, seekErr := archive.Seek(0, io.SeekCurrent)
	if err != nil || seekErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() || after.Mode() != before.Mode() || position != before.Size() {
		return result, errors.New("authenticated archive identity, metadata, or length changed while staging")
	}
	if hex.EncodeToString(archiveHasher.Sum(nil)) != artifact.SHA256 {
		return result, errors.New("open archive SHA-256 does not match the threshold-authenticated artifact")
	}
	for index := range files {
		if err := files[index].file.Chmod(os.FileMode(files[index].mode)); err != nil {
			return result, fmt.Errorf("set final mode for %s: %w", files[index].path, err)
		}
		if err := files[index].file.Sync(); err != nil {
			return result, fmt.Errorf("sync final staged file %s: %w", files[index].path, err)
		}
		opened, statErr := files[index].file.Stat()
		visible, pathErr := root.Lstat(files[index].path)
		if statErr != nil || pathErr != nil || !stableRegularInfo(opened, visible) ||
			!exactRegularMode(visible, files[index].mode) {
			return result, fmt.Errorf("final staged file %s changed before publication", files[index].path)
		}
		if err := files[index].file.Close(); err != nil {
			return result, fmt.Errorf("close staged file %s: %w", files[index].path, err)
		}
		files[index].file = nil
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := directories[index].file.Chmod(directoryMode); err != nil {
			return result, fmt.Errorf("set final mode for directory %s: %w", directories[index].path, err)
		}
		if err := directories[index].file.Sync(); err != nil {
			return result, fmt.Errorf("sync staged directory %s: %w", directories[index].path, err)
		}
		opened, statErr := directories[index].file.Stat()
		visible, pathErr := root.Lstat(directories[index].path)
		if statErr != nil || pathErr != nil || !stableDirectoryInfo(opened, visible, directoryMode) {
			return result, fmt.Errorf("final staged directory %s changed before publication", directories[index].path)
		}
		if err := directories[index].file.Close(); err != nil {
			return result, fmt.Errorf("close staged directory %s: %w", directories[index].path, err)
		}
		directories[index].file = nil
	}
	rootDirectory, err := root.Open(".")
	if err != nil {
		return result, fmt.Errorf("open staging root for sync: %w", err)
	}
	if err := rootDirectory.Chmod(directoryMode); err != nil {
		_ = rootDirectory.Close()
		return result, fmt.Errorf("set final staging root mode: %w", err)
	}
	if err := rootDirectory.Sync(); err != nil {
		_ = rootDirectory.Chmod(0o700)
		_ = rootDirectory.Close()
		return result, fmt.Errorf("sync staging root: %w", err)
	}
	openedRoot, statErr := rootDirectory.Stat()
	visibleRoot, pathErr := root.Stat(".")
	if statErr != nil || pathErr != nil || !stableDirectoryInfo(openedRoot, visibleRoot, directoryMode) {
		_ = rootDirectory.Chmod(0o700)
		_ = rootDirectory.Close()
		return result, errors.New("final staging root changed before publication")
	}
	if err := rootDirectory.Close(); err != nil {
		_ = root.Chmod(".", 0o700)
		return result, fmt.Errorf("close staging root: %w", err)
	}
	finalRoot, err := root.Stat(".")
	if err != nil {
		return result, fmt.Errorf("inspect finalized staging root: %w", err)
	}
	proof, err := verifyDirectoryWithPolicy(root, finalRoot, expected, metadata, packageJSON, policy)
	if err != nil {
		return result, fmt.Errorf("verify finalized staged tree: %w", err)
	}
	cleanup = false
	return proof, nil
}

func validateExpectedInput(expected Expected) error {
	if err := validateVersion(expected.Version); err != nil {
		return fmt.Errorf("expected release version: %w", err)
	}
	if expected.OS != "linux" || !supportedArch(expected.Arch) {
		return errors.New("expected platform must be linux/amd64 or linux/arm64")
	}
	if expected.MinimumSecurityFloor == 0 {
		return errors.New("expected minimum security floor must be positive")
	}
	if expected.InstallerStateSchemaVersion == 0 {
		return errors.New("expected installer-state schema version must be positive")
	}
	if !digestPattern.MatchString(expected.InstallerBootstrapRootSHA256) {
		return errors.New("expected installer bootstrap-root SHA-256 is not canonical")
	}
	return nil
}

func createStageDirectories(root *os.Root) ([]stagedDirectory, error) {
	directories := make([]stagedDirectory, 0, len(directoryPaths))
	cleanup := func() {
		for index := len(directories) - 1; index >= 0; index-- {
			_ = directories[index].file.Close()
			_ = root.Remove(directories[index].path)
		}
	}
	for _, path := range directoryPaths {
		if err := root.Mkdir(path, 0o700); err != nil {
			cleanup()
			return nil, fmt.Errorf("create staged directory %s: %w", path, err)
		}
		file, err := root.Open(path)
		if err != nil {
			_ = root.Remove(path)
			cleanup()
			return nil, fmt.Errorf("anchor staged directory %s: %w", path, err)
		}
		info, err := file.Stat()
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = file.Close()
			_ = root.Remove(path)
			cleanup()
			return nil, fmt.Errorf("staged directory %s is not a real directory", path)
		}
		directories = append(directories, stagedDirectory{path: path, file: file})
	}
	return directories, nil
}

func createStagedFile(root *os.Root, path string, content []byte) (*os.File, error) {
	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create private staged file %s: %w", path, err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write private staged file %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync private staged file %s: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil || !singleLink(info) {
		_ = file.Close()
		return nil, fmt.Errorf("private staged file %s does not have exactly one link", path)
	}
	return file, nil
}

func readZeroPadding(reader io.Reader, size int64, name string) error {
	paddingSize := paddedSize(size) - size
	if paddingSize == 0 {
		return nil
	}
	padding := make([]byte, paddingSize)
	if err := readExact(reader, padding, "padding for "+name); err != nil {
		return err
	}
	if !allZero(padding) {
		return fmt.Errorf("payload %q has nonzero USTAR padding", name)
	}
	return nil
}
