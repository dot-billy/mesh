//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowsbundle"
	"mesh/internal/windowssecurity"
)

type windowsOfflineSnapshot struct {
	path         string
	root         *os.Root
	rootIdentity os.FileInfo
	bundle       onlinerelease.Bundle
	artifact     *os.File
	artifactInfo os.FileInfo
	closed       bool
}

// ImportProductionWindowsSnapshot authenticates an exact LocalSystem-private
// three-file directory, verifies its signed metadata with compiled trust, and
// copies the local artifact through the same immutable capture used online.
func (store *ActivationJournalStore) ImportProductionWindowsSnapshot(ctx context.Context, sourceDirectory string, now time.Time) (intake VerifiedWindowsIntake, capturePath string, returnErr error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return intake, "", fmt.Errorf("load compiled Windows installer trust: %w", err)
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return intake, "", fmt.Errorf("load compiled Windows installer identity: %w", err)
	}
	return store.importWindowsSnapshotUsing(ctx, sourceDirectory, now, bootstrap, build)
}

func (store *ActivationJournalStore) importWindowsSnapshotUsing(ctx context.Context, sourceDirectory string, now time.Time, bootstrap installtrust.Bootstrap, build buildinfo.Info) (intake VerifiedWindowsIntake, capturePath string, returnErr error) {
	if ctx == nil {
		return intake, "", errors.New("Windows offline snapshot import requires a context")
	}
	if err := validateWindowsProductionInputs(bootstrap, build, now); err != nil {
		return intake, "", err
	}
	snapshot, err := openWindowsOfflineSnapshot(sourceDirectory)
	if err != nil {
		return intake, "", err
	}
	defer func() { returnErr = errors.Join(returnErr, snapshot.Close()) }()
	intake, err = store.authenticateWindowsCandidateUsing(snapshot.bundle, now, bootstrap, build)
	if err != nil {
		return VerifiedWindowsIntake{}, "", fmt.Errorf("authenticate Windows offline snapshot metadata: %w", err)
	}
	if snapshot.artifactInfo.Size() != intake.Candidate.Artifact.Size {
		return VerifiedWindowsIntake{}, "", errors.New("Windows offline artifact size differs from the threshold-authenticated release")
	}
	if err := snapshot.copyArtifact(ctx, io.Discard, intake.Candidate.Artifact); err != nil {
		return VerifiedWindowsIntake{}, "", err
	}
	capturePath, err = store.fetchWindowsArtifactUsing(ctx, intake, snapshot)
	if err != nil {
		return VerifiedWindowsIntake{}, "", err
	}
	return intake, capturePath, nil
}

func openWindowsOfflineSnapshot(path string) (*windowsOfflineSnapshot, error) {
	if !cleanWindowsAbsolutePath(path) || filepath.Dir(path) == path || filepath.Clean(path) != path {
		return nil, errors.New("Windows offline snapshot directory must be a clean absolute local non-root path")
	}
	root, identity, err := openNoReparseRoot(path)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			root.Close()
		}
	}()
	if err := inspectRootDirectory(root, identity, windowssecurity.LocalSystemSID); err != nil {
		return nil, fmt.Errorf("authenticate Windows offline snapshot directory: %w", err)
	}
	descriptorRaw, err := readWindowsOfflineSnapshotFile(root, WindowsInstallSnapshotFile, maximumWindowsInstallSnapshotDescriptorSize)
	if err != nil {
		return nil, fmt.Errorf("read Windows offline snapshot descriptor: %w", err)
	}
	if _, err := ParseWindowsInstallSnapshotDescriptor(descriptorRaw); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("Windows offline snapshot entries must all be real regular files")
		}
		names[index] = entry.Name()
	}
	sort.Strings(names)
	wantNames := []string{WindowsInstallSnapshotBundleFile, WindowsInstallSnapshotFile, WindowsInstallSnapshotArtifact}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		return nil, fmt.Errorf("Windows offline snapshot entries %v differ from exact contract %v", names, wantNames)
	}
	bundleRaw, err := readWindowsOfflineSnapshotFile(root, WindowsInstallSnapshotBundleFile, onlinerelease.MaxEncodedBundleSize)
	if err != nil {
		return nil, err
	}
	bundle, err := onlinerelease.Parse(bundleRaw)
	if err != nil {
		return nil, err
	}
	artifact, artifactInfo, err := openWindowsOfflineSnapshotFile(root, WindowsInstallSnapshotArtifact, windowsbundle.MaxArchiveSize)
	if err != nil {
		return nil, err
	}
	snapshot := &windowsOfflineSnapshot{
		path: path, root: root, rootIdentity: identity, bundle: bundle,
		artifact: artifact, artifactInfo: artifactInfo,
	}
	if err := snapshot.validateDirectory(); err != nil {
		artifact.Close()
		return nil, err
	}
	owned = false
	return snapshot, nil
}

func readWindowsOfflineSnapshotFile(root *os.Root, name string, maximum int64) ([]byte, error) {
	file, identity, err := openWindowsOfflineSnapshotFile(root, name, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != identity.Size() {
		return nil, errors.Join(err, errors.New("Windows offline snapshot file changed while reading"))
	}
	if err := validateWindowsOfflineSnapshotFile(root, name, file, identity, maximum); err != nil {
		return nil, err
	}
	return raw, nil
}

func openWindowsOfflineSnapshotFile(root *os.Root, name string, maximum int64) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || maximum < 1 || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, nil, errors.Join(err, fmt.Errorf("Windows offline snapshot file %q is not one bounded real regular file", name))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		file.Close()
		return nil, nil, errors.New("Windows offline snapshot file changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		file.Close()
		return nil, nil, err
	}
	return file, opened, nil
}

func validateWindowsOfflineSnapshotFile(root *os.Root, name string, file *os.File, expected os.FileInfo, maximum int64) error {
	opened, statErr := file.Stat()
	visible, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || opened.Size() < 1 || opened.Size() > maximum ||
		!sameStableWindowsFile(expected, opened) || !sameStableWindowsFile(expected, visible) {
		return errors.Join(statErr, pathErr, errors.New("Windows offline snapshot file changed while in use"))
	}
	return windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID)
}

func (snapshot *windowsOfflineSnapshot) FetchArtifact(ctx context.Context, expected releasetrust.Artifact, destination *os.File) error {
	if destination == nil {
		return errors.New("Windows offline artifact destination is required")
	}
	if err := snapshot.copyArtifact(ctx, destination, expected); err != nil {
		return err
	}
	return destination.Sync()
}

func (snapshot *windowsOfflineSnapshot) copyArtifact(ctx context.Context, destination io.Writer, expected releasetrust.Artifact) error {
	if snapshot == nil || snapshot.closed || snapshot.artifact == nil {
		return errors.New("Windows offline snapshot is closed")
	}
	if snapshot.artifactInfo.Size() != expected.Size {
		return errors.New("Windows offline artifact size differs from authenticated metadata")
	}
	if err := validateWindowsOfflineSnapshotFile(snapshot.root, WindowsInstallSnapshotArtifact, snapshot.artifact, snapshot.artifactInfo, expected.Size); err != nil {
		return err
	}
	if _, err := snapshot.artifact.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyExactWindowsOfflineArtifact(ctx, snapshot.artifact, destination, expected); err != nil {
		return err
	}
	if err := validateWindowsOfflineSnapshotFile(snapshot.root, WindowsInstallSnapshotArtifact, snapshot.artifact, snapshot.artifactInfo, expected.Size); err != nil {
		return err
	}
	return snapshot.validateDirectory()
}

func (snapshot *windowsOfflineSnapshot) validateDirectory() error {
	if snapshot == nil || snapshot.closed || snapshot.root == nil {
		return errors.New("Windows offline snapshot is closed")
	}
	opened, err := snapshot.root.Stat(".")
	if err != nil || !sameStableWindowsFile(snapshot.rootIdentity, opened) {
		return errors.Join(err, errors.New("Windows offline snapshot directory changed while in use"))
	}
	return inspectRootDirectory(snapshot.root, opened, windowssecurity.LocalSystemSID)
}

func (snapshot *windowsOfflineSnapshot) Close() error {
	if snapshot == nil || snapshot.closed {
		return nil
	}
	snapshot.closed = true
	var err error
	if snapshot.artifact != nil {
		err = errors.Join(err, snapshot.artifact.Close())
		snapshot.artifact = nil
	}
	if snapshot.root != nil {
		err = errors.Join(err, snapshot.root.Close())
		snapshot.root = nil
	}
	return err
}
