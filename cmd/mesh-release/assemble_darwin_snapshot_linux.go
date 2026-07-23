//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mesh/internal/darwinbundle"
	"mesh/internal/darwininstall"
	"mesh/internal/onlinerelease"
)

type darwinSnapshotAssemblyOptions struct {
	outputPath   string
	bundlePath   string
	artifactPath string
}

func assembleDarwinSnapshot(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("assemble-darwin-snapshot", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("output", "", "new private Darwin snapshot directory (created 0700, never overwritten)")
	bundlePath := flags.String("online-bundle", "", "exact canonical signed release bundle")
	artifactPath := flags.String("artifact", "", "exact Darwin bundle artifact")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("assemble-darwin-snapshot does not accept positional arguments")
	}
	path, err := assembleDarwinSnapshotUsing(darwinSnapshotAssemblyOptions{
		outputPath: *outputPath, bundlePath: *bundlePath, artifactPath: *artifactPath,
	}, snapshotAssemblyHooks{})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Assembled private Darwin install snapshot %s. No metadata was trusted and no software was installed or started.\n", path)
	return err
}

func assembleDarwinSnapshotUsing(options darwinSnapshotAssemblyOptions, hooks snapshotAssemblyHooks) (string, error) {
	for _, required := range []struct{ name, value string }{
		{"--output", options.outputPath}, {"--online-bundle", options.bundlePath}, {"--artifact", options.artifactPath},
	} {
		if strings.TrimSpace(required.value) == "" {
			return "", fmt.Errorf("%s is required", required.name)
		}
	}
	parentPath, targetName, targetPath, err := resolveSnapshotTarget(options.outputPath)
	if err != nil {
		return "", err
	}
	parent, err := openStableSnapshotParent(parentPath)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if err := requireSnapshotTargetAbsent(targetPath); err != nil {
		return "", err
	}
	inputs, err := openSnapshotInputs([]snapshotInputSpec{
		{role: "Darwin online release bundle", path: options.bundlePath, limit: onlinerelease.MaxEncodedBundleSize},
		{role: "Darwin bundle artifact", path: options.artifactPath, limit: darwinbundle.MaxArchiveSize},
	})
	if err != nil {
		return "", err
	}
	defer closeSnapshotInputs(inputs)
	bundleInput := findSnapshotInput(inputs, "Darwin online release bundle")
	artifactInput := findSnapshotInput(inputs, "Darwin bundle artifact")
	if bundleInput == nil || artifactInput == nil {
		return "", errors.New("internal Darwin snapshot input classification failure")
	}
	bundleInput.raw, err = readStableSnapshotInput(bundleInput, hooks)
	if err != nil {
		return "", fmt.Errorf("read Darwin online release bundle: %w", err)
	}
	if _, err := onlinerelease.Parse(bundleInput.raw); err != nil {
		return "", fmt.Errorf("parse canonical Darwin online release bundle: %w", err)
	}

	temporaryPath, err := os.MkdirTemp(parentPath, ".mesh-darwin-install-snapshot-")
	if err != nil {
		return "", fmt.Errorf("create private Darwin snapshot staging directory: %w", err)
	}
	temporaryName := filepath.Base(temporaryPath)
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporaryPath)
			_ = parent.Sync()
		}
	}()
	if err := os.Chmod(temporaryPath, snapshotDirectoryMode); err != nil {
		return "", fmt.Errorf("set Darwin snapshot staging directory mode: %w", err)
	}
	stagedInfo, err := validateSnapshotOutputDirectory(temporaryPath)
	if err != nil {
		return "", err
	}
	if err := writeSnapshotBytes(temporaryPath, darwininstall.DarwinInstallSnapshotBundleFile, bundleInput.raw); err != nil {
		return "", err
	}
	artifactHasher := sha256.New()
	if err := writeSnapshotReader(
		temporaryPath,
		darwininstall.DarwinInstallSnapshotArtifact,
		io.TeeReader(artifactInput.file, artifactHasher),
		artifactInput.identity.size,
	); err != nil {
		return "", fmt.Errorf("copy Darwin bundle artifact: %w", err)
	}
	if hooks.afterInputRead != nil {
		hooks.afterInputRead(artifactInput.path)
	}
	if err := validateOpenedSnapshotInput(artifactInput); err != nil {
		return "", fmt.Errorf("Darwin bundle artifact changed while copying: %w", err)
	}
	descriptorRaw, err := darwininstall.EncodeDarwinInstallSnapshotDescriptor(darwininstall.DarwinInstallSnapshotDescriptor{
		Schema:       darwininstall.DarwinInstallSnapshotSchema,
		OnlineBundle: darwininstall.DarwinInstallSnapshotBundleFile,
		Artifact:     darwininstall.DarwinInstallSnapshotArtifact,
	})
	if err != nil {
		return "", err
	}
	if err := writeSnapshotBytes(temporaryPath, darwininstall.DarwinInstallSnapshotFile, descriptorRaw); err != nil {
		return "", err
	}
	if err := validateAllSnapshotInputs(inputs); err != nil {
		return "", err
	}
	if err := syncSnapshotDirectory(temporaryPath); err != nil {
		return "", err
	}
	var sourceArtifactDigest [sha256.Size]byte
	copy(sourceArtifactDigest[:], artifactHasher.Sum(nil))
	if err := validateAssembledDarwinSnapshot(temporaryPath, bundleInput.raw, artifactInput.identity.size, sourceArtifactDigest); err != nil {
		return "", err
	}
	if err := validateStableSnapshotParent(parentPath, parent); err != nil {
		return "", err
	}
	if hooks.beforePublish != nil {
		hooks.beforePublish()
	}
	if err := renameSnapshotNoReplace(int(parent.Fd()), temporaryName, targetName); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("refusing to overwrite existing snapshot directory %s", targetPath)
		}
		return "", fmt.Errorf("atomically publish Darwin snapshot: %w", err)
	}
	removeTemporary = false
	finalInfo, err := os.Lstat(targetPath)
	if err != nil || !os.SameFile(stagedInfo, finalInfo) || !finalInfo.IsDir() || finalInfo.Mode().Perm() != snapshotDirectoryMode || hasSnapshotSpecialMode(finalInfo.Mode()) {
		return "", errors.New("published Darwin snapshot directory identity or mode changed unexpectedly")
	}
	if err := parent.Sync(); err != nil {
		return "", fmt.Errorf("fsync Darwin snapshot parent directory after publication: %w", err)
	}
	return targetPath, nil
}

func validateAssembledDarwinSnapshot(directory string, wantBundle []byte, wantArtifactSize int64, wantArtifactDigest [sha256.Size]byte) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("list assembled Darwin snapshot: %w", err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	wantNames := []string{
		darwininstall.DarwinInstallSnapshotArtifact,
		darwininstall.DarwinInstallSnapshotBundleFile,
		darwininstall.DarwinInstallSnapshotFile,
	}
	sort.Strings(wantNames)
	if fmt.Sprint(names) != fmt.Sprint(wantNames) {
		return fmt.Errorf("assembled Darwin snapshot entries %v differ from %v", names, wantNames)
	}
	descriptor, err := readDarwinSnapshotAssemblyFile(filepath.Join(directory, darwininstall.DarwinInstallSnapshotFile), 4096)
	if err != nil {
		return err
	}
	if _, err := darwininstall.ParseDarwinInstallSnapshotDescriptor(descriptor); err != nil {
		return fmt.Errorf("parse assembled Darwin snapshot descriptor: %w", err)
	}
	bundle, err := readDarwinSnapshotAssemblyFile(filepath.Join(directory, darwininstall.DarwinInstallSnapshotBundleFile), onlinerelease.MaxEncodedBundleSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(bundle, wantBundle) {
		return errors.New("assembled Darwin snapshot changed exact online bundle bytes")
	}
	if _, err := onlinerelease.Parse(bundle); err != nil {
		return fmt.Errorf("parse assembled Darwin snapshot bundle: %w", err)
	}
	artifactInput, err := openSnapshotInput(snapshotInputSpec{
		role: "assembled Darwin artifact", path: filepath.Join(directory, darwininstall.DarwinInstallSnapshotArtifact), limit: darwinbundle.MaxArchiveSize,
	})
	if err != nil {
		return err
	}
	defer artifactInput.file.Close()
	if os.FileMode(artifactInput.identity.mode).Perm() != snapshotFileMode || artifactInput.identity.ownerUID != uint32(os.Geteuid()) || artifactInput.identity.size != wantArtifactSize {
		return errors.New("assembled Darwin artifact metadata differs from its exact private snapshot contract")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(artifactInput.file, wantArtifactSize+1))
	if err != nil || written != wantArtifactSize {
		return errors.Join(err, errors.New("assembled Darwin artifact size changed during readback"))
	}
	if err := validateOpenedSnapshotInput(artifactInput); err != nil {
		return err
	}
	if !bytes.Equal(hasher.Sum(nil), wantArtifactDigest[:]) {
		return errors.New("assembled Darwin artifact digest differs after readback")
	}
	return nil
}

func readDarwinSnapshotAssemblyFile(path string, limit int64) ([]byte, error) {
	input, err := openSnapshotInput(snapshotInputSpec{role: "assembled Darwin snapshot file", path: path, limit: limit})
	if err != nil {
		return nil, err
	}
	defer input.file.Close()
	if os.FileMode(input.identity.mode).Perm() != snapshotFileMode || input.identity.ownerUID != uint32(os.Geteuid()) {
		return nil, errors.New("assembled Darwin snapshot file is not effective-user-owned mode-0400")
	}
	return readStableSnapshotInput(input, snapshotAssemblyHooks{})
}
