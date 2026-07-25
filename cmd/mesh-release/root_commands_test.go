//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	releasetrust "mesh/internal/release"
)

func TestRootCommandWorkflowIsCanonicalCreateOnlyAndDualThresholdVerified(t *testing.T) {
	directory := t.TempDir()
	privatePaths := make([]string, 4)
	publicPaths := make([]string, 4)
	for index := range privatePaths {
		privatePaths[index] = filepath.Join(directory, "key-"+string(rune('a'+index))+".private.json")
		publicPaths[index] = filepath.Join(directory, "key-"+string(rune('a'+index))+".public.json")
		if err := generateKey([]string{"--private", privatePaths[index]}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if err := exportPublic([]string{"--private", privatePaths[index], "--public", publicPaths[index]}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	rootOnePath := filepath.Join(directory, "1.root.json")
	initialArgs := []string{
		"--output", rootOnePath, "--channel", "stable", "--release-epoch", "1",
		"--minimum-release-sequence", "1", "--minimum-security-floor", "1",
		"--issued", "2026-07-20T12:00:00Z", "--expires", "2027-07-20T12:00:00Z",
		"--root-threshold", "2", "--release-threshold", "2",
		"--root-public", publicPaths[1], "--root-public", publicPaths[0],
		"--release-public", publicPaths[3], "--release-public", publicPaths[2],
	}
	var output bytes.Buffer
	if err := createRoot(initialArgs, &output); err != nil {
		t.Fatal(err)
	}
	rootOneRaw, err := os.ReadFile(rootOnePath)
	if err != nil {
		t.Fatal(err)
	}
	rootOne, err := releasetrust.ParseRoot(rootOneRaw)
	if err != nil {
		t.Fatal(err)
	}
	if rootOne.Document.Version != 1 || rootOne.Document.ReleaseEpoch != 1 || !strings.Contains(output.String(), rootOne.SHA256) {
		t.Fatalf("unexpected initial root/output: %+v, %q", rootOne, output.String())
	}
	if err := createRoot(initialArgs, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("root overwrite returned %v", err)
	}

	rootTwoPath := filepath.Join(directory, "2.root.json")
	successorArgs := []string{
		"--output", rootTwoPath, "--previous-root", rootOnePath,
		"--issued", "2026-07-21T12:00:00Z", "--expires", "2027-07-21T12:00:00Z",
		"--root-threshold", "2", "--release-threshold", "2",
		"--root-public", publicPaths[0], "--root-public", publicPaths[1],
		"--release-public", publicPaths[2], "--release-public", publicPaths[3],
	}
	if err := createRoot(successorArgs, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	rootTwoRaw, err := os.ReadFile(rootTwoPath)
	if err != nil {
		t.Fatal(err)
	}
	rootTwo, err := releasetrust.ParseRoot(rootTwoRaw)
	if err != nil || rootTwo.Document.Version != 2 || rootTwo.Document.ReleaseEpoch != 1 {
		t.Fatalf("successor root: %+v, %v", rootTwo, err)
	}

	signaturePaths := []string{filepath.Join(directory, "2.root.a.sig.json"), filepath.Join(directory, "2.root.b.sig.json")}
	for index, signaturePath := range signaturePaths {
		if err := sign([]string{"--private", privatePaths[index], "--manifest", rootTwoPath, "--signature", signaturePath}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	updatePath := filepath.Join(directory, "2.root-update.json")
	if err := assembleRootUpdate([]string{
		"--output", updatePath, "--previous-root", rootOnePath, "--root", rootTwoPath,
		"--signature", signaturePaths[1], "--signature", signaturePaths[0],
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	updateRaw, err := os.ReadFile(updatePath)
	if err != nil {
		t.Fatal(err)
	}
	update, err := releasetrust.ParseRootUpdate(updateRaw)
	if err != nil || !bytes.Equal(update.RootManifest, rootTwoRaw) || len(update.Signatures) != 2 {
		t.Fatalf("assembled root update: %+v, %v", update, err)
	}
	if err := assembleRootUpdate([]string{
		"--output", updatePath, "--previous-root", rootOnePath, "--root", rootTwoPath,
		"--signature", signaturePaths[0], "--signature", signaturePaths[1],
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("root update overwrite returned %v", err)
	}

	output.Reset()
	if err := inspectRoot([]string{"--root", rootTwoPath}, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version 2", "release epoch 1", rootTwo.SHA256} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("inspect output %q omits %q", output.String(), want)
		}
	}
}

func TestRootCommandUsageAndArgumentsFailClosed(t *testing.T) {
	for _, command := range []string{"create-root", "inspect-root", "assemble-root-update"} {
		if !strings.Contains(releaseUsage, command) {
			t.Fatalf("release usage omits %s: %q", command, releaseUsage)
		}
	}
	if err := createRoot(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty create-root accepted")
	}
	if err := inspectRoot(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty inspect-root accepted")
	}
	if err := assembleRootUpdate(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty assemble-root-update accepted")
	}
}
