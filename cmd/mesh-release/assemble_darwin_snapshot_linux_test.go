//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/darwininstall"
)

func TestAssembleDarwinSnapshotIsDeterministicPrivateAndExact(t *testing.T) {
	root := t.TempDir()
	inputs := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	bundlePath := filepath.Join(root, "online-bundle.json")
	if err := assembleOnlineBundleUsing(onlineBundleAssemblyOptions{
		outputPath: bundlePath, channelManifestPath: inputs.channelManifestPath,
		channelSignaturePaths: inputs.channelSignaturePaths, releaseManifestPath: inputs.releaseManifestPath,
		releaseSignaturePaths: inputs.releaseSignaturePaths,
	}, onlineBundleAssemblyHooks{}); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "darwin-snapshot-first")
	options := darwinSnapshotAssemblyOptions{outputPath: first, bundlePath: bundlePath, artifactPath: inputs.artifactPath}
	var output bytes.Buffer
	if err := assembleDarwinSnapshot([]string{
		"--output", first, "--online-bundle", bundlePath, "--artifact", inputs.artifactPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), first) || !strings.Contains(output.String(), "No metadata was trusted") {
		t.Fatalf("unexpected assembler output %q", output.String())
	}
	secondOptions := options
	secondOptions.outputPath = filepath.Join(root, "darwin-snapshot-second")
	second, err := assembleDarwinSnapshotUsing(secondOptions, snapshotAssemblyHooks{})
	if err != nil {
		t.Fatal(err)
	}
	firstTree := readSnapshotTree(t, first)
	secondTree := readSnapshotTree(t, second)
	if len(firstTree) != 3 || len(secondTree) != 3 {
		t.Fatalf("snapshot tree sizes = %d and %d", len(firstTree), len(secondTree))
	}
	for name, raw := range firstTree {
		if !bytes.Equal(raw, secondTree[name]) {
			t.Fatalf("deterministic Darwin snapshot entry %q differs", name)
		}
	}
	descriptor, err := darwininstall.ParseDarwinInstallSnapshotDescriptor(firstTree[darwininstall.DarwinInstallSnapshotFile])
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.OnlineBundle != darwininstall.DarwinInstallSnapshotBundleFile || descriptor.Artifact != darwininstall.DarwinInstallSnapshotArtifact {
		t.Fatalf("unexpected descriptor %#v", descriptor)
	}
	if !bytes.Equal(firstTree[darwininstall.DarwinInstallSnapshotBundleFile], mustReadFile(t, bundlePath)) ||
		!bytes.Equal(firstTree[darwininstall.DarwinInstallSnapshotArtifact], mustReadFile(t, inputs.artifactPath)) {
		t.Fatal("Darwin snapshot did not preserve exact input bytes")
	}
	assertSnapshotModes(t, first)
	assertSnapshotModes(t, second)
	if _, err := assembleDarwinSnapshotUsing(options, snapshotAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("existing Darwin snapshot returned %v", err)
	}
}

func TestAssembleDarwinSnapshotRejectsInputMutation(t *testing.T) {
	root := t.TempDir()
	inputs := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	bundlePath := filepath.Join(root, "online-bundle.json")
	if err := assembleOnlineBundleUsing(onlineBundleAssemblyOptions{
		outputPath: bundlePath, channelManifestPath: inputs.channelManifestPath,
		channelSignaturePaths: inputs.channelSignaturePaths, releaseManifestPath: inputs.releaseManifestPath,
		releaseSignaturePaths: inputs.releaseSignaturePaths,
	}, onlineBundleAssemblyHooks{}); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(root, "mutated-snapshot")
	mutated := false
	_, err := assembleDarwinSnapshotUsing(darwinSnapshotAssemblyOptions{
		outputPath: outputPath, bundlePath: bundlePath, artifactPath: inputs.artifactPath,
	}, snapshotAssemblyHooks{afterInputRead: func(path string) {
		if path == inputs.artifactPath && !mutated {
			mutated = true
			if chmodErr := os.Chmod(path, 0o644); chmodErr != nil {
				t.Errorf("mutate artifact mode: %v", chmodErr)
			}
		}
	}})
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("mutated Darwin snapshot input returned %v", err)
	}
	if _, statErr := os.Lstat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed assembly published output: %v", statErr)
	}
}
