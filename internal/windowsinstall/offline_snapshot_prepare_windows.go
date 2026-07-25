//go:build windows

package windowsinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"mesh/internal/onlinerelease"
	"mesh/internal/windowsbundle"
	"mesh/internal/windowssecurity"
)

type WindowsSnapshotPreparationResult struct {
	Directory         string `json:"directory"`
	Architecture      string `json:"architecture"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	ArtifactSize      int64  `json:"artifact_size"`
	PackageJSONSHA256 string `json:"package_json_sha256"`
}

type windowsSnapshotSource struct {
	root *os.Root
	file *os.File
	name string
	info os.FileInfo
}

// PrepareProductionWindowsSnapshot converts untrusted removable-media inputs
// into the exact LocalSystem-private three-file snapshot accepted by install.
// Structural bundle inspection here is defense in depth only; threshold
// metadata remains the authority when the snapshot is imported.
func PrepareProductionWindowsSnapshot(ctx context.Context, bundlePath, artifactPath, destination string) (result WindowsSnapshotPreparationResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows snapshot preparation requires a context")
	}
	for label, value := range map[string]string{"bundle": bundlePath, "artifact": artifactPath, "destination": destination} {
		if !cleanWindowsAbsolutePath(value) || filepath.Clean(value) != value || filepath.Dir(value) == value {
			return result, fmt.Errorf("Windows snapshot %s path must be clean, absolute, and non-root", label)
		}
	}
	if strings.EqualFold(bundlePath, artifactPath) || strings.EqualFold(destination, bundlePath) || strings.EqualFold(destination, artifactPath) {
		return result, errors.New("Windows snapshot source and destination paths must be distinct")
	}
	bundleSource, err := openWindowsSnapshotSource(bundlePath, onlinerelease.MaxEncodedBundleSize)
	if err != nil {
		return result, fmt.Errorf("open Windows snapshot bundle input: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, bundleSource.Close()) }()
	bundleRaw, err := io.ReadAll(io.LimitReader(bundleSource.file, onlinerelease.MaxEncodedBundleSize+1))
	if err != nil || len(bundleRaw) > onlinerelease.MaxEncodedBundleSize {
		return result, errors.Join(err, errors.New("Windows snapshot bundle input is oversized"))
	}
	bundle, err := onlinerelease.Parse(bundleRaw)
	if err != nil {
		return result, err
	}
	canonicalBundle, err := onlinerelease.Encode(bundle)
	if err != nil || !bytes.Equal(canonicalBundle, bundleRaw) {
		return result, errors.Join(err, errors.New("Windows snapshot bundle input is not canonical"))
	}
	if err := bundleSource.Validate(); err != nil {
		return result, err
	}

	artifactSource, err := openWindowsSnapshotSource(artifactPath, int(windowsbundle.MaxArchiveSize))
	if err != nil {
		return result, fmt.Errorf("open Windows snapshot artifact input: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, artifactSource.Close()) }()
	if artifactSource.info.Size() < 1 || artifactSource.info.Size() > windowsbundle.MaxArchiveSize {
		return result, errors.New("Windows snapshot artifact input is empty or oversized")
	}

	parent, _, err := openNoReparseRoot(filepath.Dir(destination))
	if err != nil {
		return result, fmt.Errorf("anchor Windows snapshot destination parent: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, parent.Close()) }()
	destinationName := filepath.Base(destination)
	if _, err := parent.Lstat(destinationName); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return result, errors.New("Windows snapshot destination already exists")
		}
		return result, err
	}
	if err := parent.Mkdir(destinationName, 0o700); err != nil {
		return result, err
	}
	created := true
	var destinationRoot *os.Root
	defer func() {
		if returnErr == nil || !created {
			return
		}
		if destinationRoot != nil {
			for _, name := range []string{WindowsInstallSnapshotFile, WindowsInstallSnapshotBundleFile, WindowsInstallSnapshotArtifact} {
				_ = destinationRoot.Remove(name)
			}
			entries, readErr := fs.ReadDir(destinationRoot.FS(), ".")
			_ = destinationRoot.Close()
			destinationRoot = nil
			if readErr != nil || len(entries) != 0 {
				return
			}
		}
		_ = parent.Remove(destinationName)
	}()
	visible, err := parent.Lstat(destinationName)
	if err != nil || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
		return result, errors.Join(err, errors.New("created Windows snapshot destination is not a real directory"))
	}
	directory, err := parent.Open(destinationName)
	if err != nil {
		return result, err
	}
	opened, statErr := directory.Stat()
	protectErr := windowssecurity.ProtectPrivateFileForActor(directory, windowssecurity.Directory, windowssecurity.LocalSystemSID)
	closeErr := directory.Close()
	if statErr != nil || !sameStableWindowsFile(visible, opened) || protectErr != nil || closeErr != nil {
		return result, errors.Join(statErr, protectErr, closeErr, errors.New("protect Windows snapshot destination"))
	}
	destinationRoot, visible, err = openNoReparseRoot(destination)
	if err != nil {
		return result, err
	}
	defer func() {
		if destinationRoot != nil {
			if returnErr == nil {
				returnErr = errors.Join(returnErr, destinationRoot.Close())
				destinationRoot = nil
			}
		}
	}()
	if err := inspectRootDirectory(destinationRoot, visible, windowssecurity.LocalSystemSID); err != nil {
		return result, err
	}
	descriptor, err := EncodeWindowsInstallSnapshotDescriptor(WindowsInstallSnapshotDescriptor{
		Schema: WindowsInstallSnapshotSchema, OnlineBundle: WindowsInstallSnapshotBundleFile, Artifact: WindowsInstallSnapshotArtifact,
	})
	if err != nil {
		return result, err
	}
	if err := writePreparedWindowsSnapshotFile(ctx, destinationRoot, WindowsInstallSnapshotFile, bytes.NewReader(descriptor), int64(len(descriptor))); err != nil {
		return result, err
	}
	if err := writePreparedWindowsSnapshotFile(ctx, destinationRoot, WindowsInstallSnapshotBundleFile, bytes.NewReader(canonicalBundle), int64(len(canonicalBundle))); err != nil {
		return result, err
	}
	if _, err := artifactSource.file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	if err := writePreparedWindowsSnapshotFile(ctx, destinationRoot, WindowsInstallSnapshotArtifact, artifactSource.file, artifactSource.info.Size()); err != nil {
		return result, err
	}
	if err := artifactSource.Validate(); err != nil {
		return result, err
	}
	artifactRaw, err := readAuthenticatedWindowsCandidate(filepath.Join(destination, WindowsInstallSnapshotArtifact), windowssecurity.LocalSystemSID)
	if err != nil {
		return result, err
	}
	expanded, err := windowsbundle.InspectCandidateArchive(artifactRaw)
	if err != nil {
		return result, fmt.Errorf("inspect prepared Windows snapshot artifact: %w", err)
	}
	if expanded.Inspection.Package.Target.OS != "windows" || expanded.Inspection.Package.Target.Arch != runtime.GOARCH {
		return result, fmt.Errorf("Windows snapshot artifact targets %s/%s, want windows/%s", expanded.Inspection.Package.Target.OS, expanded.Inspection.Package.Target.Arch, runtime.GOARCH)
	}
	if err := validatePreparedWindowsSnapshot(destinationRoot, visible); err != nil {
		return result, err
	}
	preparedSnapshot, err := openWindowsOfflineSnapshot(destination)
	if err != nil {
		return result, fmt.Errorf("reopen prepared Windows snapshot through install boundary: %w", err)
	}
	if err := preparedSnapshot.Close(); err != nil {
		return result, err
	}
	created = false
	return WindowsSnapshotPreparationResult{
		Directory: destination, Architecture: expanded.Inspection.Package.Target.Arch,
		ArtifactSHA256: expanded.Inspection.ArtifactSHA256, ArtifactSize: expanded.Inspection.ArtifactSize,
		PackageJSONSHA256: expanded.Inspection.PackageJSONSHA256,
	}, nil
}

func openWindowsSnapshotSource(path string, maximum int) (*windowsSnapshotSource, error) {
	if maximum < 1 {
		return nil, errors.New("Windows snapshot source bound is invalid")
	}
	root, _, err := openNoReparseRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > int64(maximum) {
		root.Close()
		return nil, errors.Join(err, errors.New("Windows snapshot source is not one bounded real regular file"))
	}
	file, err := root.Open(name)
	if err != nil {
		root.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		file.Close()
		root.Close()
		return nil, errors.Join(err, errors.New("Windows snapshot source changed while opening"))
	}
	return &windowsSnapshotSource{root: root, file: file, name: name, info: opened}, nil
}

func (source *windowsSnapshotSource) Validate() error {
	if source == nil || source.root == nil || source.file == nil {
		return errors.New("Windows snapshot source is closed")
	}
	opened, statErr := source.file.Stat()
	visible, pathErr := source.root.Lstat(source.name)
	if statErr != nil || pathErr != nil || !sameStableWindowsFile(source.info, opened) || !sameStableWindowsFile(source.info, visible) {
		return errors.Join(statErr, pathErr, errors.New("Windows snapshot source changed while reading"))
	}
	return nil
}

func (source *windowsSnapshotSource) Close() error {
	if source == nil {
		return nil
	}
	var err error
	if source.file != nil {
		err = errors.Join(err, source.file.Close())
		source.file = nil
	}
	if source.root != nil {
		err = errors.Join(err, source.root.Close())
		source.root = nil
	}
	return err
}

func writePreparedWindowsSnapshotFile(ctx context.Context, root *os.Root, name string, source io.Reader, expectedSize int64) error {
	if ctx == nil || root == nil || source == nil || expectedSize < 1 || expectedSize > windowsbundle.MaxArchiveSize ||
		name != WindowsInstallSnapshotFile && name != WindowsInstallSnapshotBundleFile && name != WindowsInstallSnapshotArtifact {
		return errors.New("prepared Windows snapshot file request is invalid")
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		file.Close()
		return err
	}
	written, copyErr := io.CopyBuffer(file, io.LimitReader(windowsContextReader{ctx: ctx, reader: source}, expectedSize+1), make([]byte, windowsOfflineArtifactCopyBufferSize))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || written != expectedSize || syncErr != nil || closeErr != nil {
		return errors.Join(copyErr, syncErr, closeErr, fmt.Errorf("wrote %d of %d prepared Windows snapshot bytes", written, expectedSize))
	}
	return nil
}

type windowsContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader windowsContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func validatePreparedWindowsSnapshot(root *os.Root, identity os.FileInfo) error {
	if root == nil || identity == nil {
		return errors.New("prepared Windows snapshot root is required")
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != 3 {
		return errors.Join(err, errors.New("prepared Windows snapshot must contain exactly three entries"))
	}
	for index, want := range []string{WindowsInstallSnapshotBundleFile, WindowsInstallSnapshotFile, WindowsInstallSnapshotArtifact} {
		if entries[index].Name() != want || entries[index].IsDir() || entries[index].Type()&os.ModeSymlink != 0 {
			return errors.New("prepared Windows snapshot entry set is not exact")
		}
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(identity, opened) {
		return errors.Join(err, errors.New("prepared Windows snapshot directory changed during assembly"))
	}
	return inspectRootDirectory(root, opened, windowssecurity.LocalSystemSID)
}
