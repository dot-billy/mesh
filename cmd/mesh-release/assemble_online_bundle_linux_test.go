//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

func TestAssembleOnlineBundleIsDeterministicCreateOnlyAndExact(t *testing.T) {
	root := t.TempDir()
	inputs := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	wantChannel := mustReadFile(t, inputs.channelManifestPath)
	wantRelease := mustReadFile(t, inputs.releaseManifestPath)
	first := filepath.Join(root, "bundle-one.json")
	second := filepath.Join(root, "bundle-two.json")
	options := onlineBundleAssemblyOptions{
		outputPath:            first,
		channelManifestPath:   inputs.channelManifestPath,
		channelSignaturePaths: reverseStrings(inputs.channelSignaturePaths),
		releaseManifestPath:   inputs.releaseManifestPath,
		releaseSignaturePaths: reverseStrings(inputs.releaseSignaturePaths),
	}

	var output bytes.Buffer
	args := []string{
		"--output", first,
		"--channel-manifest", options.channelManifestPath,
		"--channel-signature", options.channelSignaturePaths[0],
		"--channel-signature", options.channelSignaturePaths[1],
		"--release-manifest", options.releaseManifestPath,
		"--release-signature", options.releaseSignaturePaths[0],
		"--release-signature", options.releaseSignaturePaths[1],
	}
	if err := assembleOnlineBundle(args, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), first) || !strings.Contains(output.String(), "No metadata was trusted") {
		t.Fatalf("unexpected operator output %q", output.String())
	}

	options.outputPath = second
	options.channelSignaturePaths = reverseStrings(options.channelSignaturePaths)
	options.releaseSignaturePaths = reverseStrings(options.releaseSignaturePaths)
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err != nil {
		t.Fatal(err)
	}
	one := mustReadFile(t, first)
	two := mustReadFile(t, second)
	if !bytes.Equal(one, two) {
		t.Fatal("flag order changed online bundle bytes")
	}
	parsed, err := onlinerelease.Parse(one)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.ChannelManifest, wantChannel) || !bytes.Equal(parsed.ReleaseManifest, wantRelease) {
		t.Fatal("publisher changed exact manifest bytes")
	}
	assertOnlineSignaturesSorted(t, parsed.ChannelSignatures, inputs.channelSignaturePaths)
	assertOnlineSignaturesSorted(t, parsed.ReleaseSignatures, inputs.releaseSignaturePaths)
	info, err := os.Lstat(first)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("output metadata = %v, %v", info, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatalf("output link metadata = %+v", stat)
	}
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("overwrite returned %v", err)
	}
	if got := mustReadFile(t, second); !bytes.Equal(got, two) {
		t.Fatal("overwrite attempt changed existing output")
	}
}

func TestAssembleOnlineBundleSortsAndCarriesContiguousRootUpdates(t *testing.T) {
	root := t.TempDir()
	inputs := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
	updates := writeSnapshotRootUpdates(t, filepath.Join(root, "root-updates"), 3)
	options := onlineBundleOptionsFromSnapshot(inputs, filepath.Join(root, "bundle.json"))
	options.rootUpdatePaths = []string{updates[2], updates[0], updates[1]}
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err != nil {
		t.Fatal(err)
	}
	parsed, err := onlinerelease.Parse(mustReadFile(t, options.outputPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.RootUpdates) != len(updates) {
		t.Fatalf("root update count = %d, want %d", len(parsed.RootUpdates), len(updates))
	}
	for index, path := range updates {
		if !bytes.Equal(parsed.RootUpdates[index], mustReadFile(t, path)) {
			t.Fatalf("root update %d was not sorted by decoded version", index)
		}
	}

	duplicate := options
	duplicate.outputPath = filepath.Join(root, "duplicate.json")
	duplicatePath := filepath.Join(root, "duplicate-version.json")
	if err := os.WriteFile(duplicatePath, mustReadFile(t, updates[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	duplicate.rootUpdatePaths = []string{updates[0], duplicatePath}
	assertOnlineAssemblyFailure(t, duplicate, onlineBundleAssemblyHooks{}, "duplicate root update version")

	gap := options
	gap.outputPath = filepath.Join(root, "gap.json")
	gap.rootUpdatePaths = []string{updates[0], updates[2]}
	assertOnlineAssemblyFailure(t, gap, onlineBundleAssemblyHooks{}, "does not continue")
}

func TestAssembleOnlineBundleRejectsUnsafeInputs(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		link := filepath.Join(root, "channel-link.json")
		if err := os.Symlink(options.channelManifestPath, link); err != nil {
			t.Fatal(err)
		}
		options.channelManifestPath = link
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "symlink")
	})

	for _, test := range []struct {
		name string
		make func(*testing.T, string)
	}{
		{name: "directory", make: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "FIFO", make: func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
			unsafe := filepath.Join(root, "unsafe-input")
			test.make(t, unsafe)
			options.channelManifestPath = unsafe
			assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "regular file")
		})
	}

	t.Run("hard link count", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		if err := os.Link(options.channelManifestPath, filepath.Join(root, "extra-link.json")); err != nil {
			t.Fatal(err)
		}
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "link count")
	})

	t.Run("same inode in two roles", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		options.releaseManifestPath = options.channelManifestPath
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "collision")
	})

	t.Run("byte-identical signature envelopes", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		if err := os.WriteFile(options.releaseSignaturePaths[0], mustReadFile(t, options.channelSignaturePaths[0]), 0o600); err != nil {
			t.Fatal(err)
		}
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "byte-identical")
	})
}

func TestAssembleOnlineBundleRejectsConcurrentInputChanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "in-place mutation", mutate: func(t *testing.T, path string) {
			raw := mustReadFile(t, path)
			raw[0] ^= 1
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "replacement", mutate: func(t *testing.T, path string) {
			replaced := path + ".replaced"
			if err := os.Rename(path, replaced); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mustReadFile(t, replaced), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "truncation", mutate: func(t *testing.T, path string) {
			if err := os.Truncate(path, 1); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "growth", mutate: func(t *testing.T, path string) {
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("growth"); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
			target := options.channelManifestPath
			mutated := false
			hooks := onlineBundleAssemblyHooks{afterInputRead: func(path string) {
				if path == target && !mutated {
					mutated = true
					test.mutate(t, path)
				}
			}}
			assertOnlineAssemblyFailure(t, options, hooks, "changed")
		})
	}
}

func TestAssembleOnlineBundleNeverOverwritesPublicationCollision(t *testing.T) {
	root := t.TempDir()
	options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
	want := []byte("operator-owned\n")
	hooks := onlineBundleAssemblyHooks{beforePublish: func() {
		if err := os.WriteFile(options.outputPath, want, 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	err := assembleOnlineBundleUsing(options, hooks)
	if err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("publication collision returned %v", err)
	}
	if got := mustReadFile(t, options.outputPath); !bytes.Equal(got, want) {
		t.Fatalf("publication collision changed to %q", got)
	}
}

func TestAssembleOnlineBundleEnforcesBoundsAndArguments(t *testing.T) {
	t.Run("required options", func(t *testing.T) {
		if err := assembleOnlineBundle(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--output") {
			t.Fatalf("empty options returned %v", err)
		}
	})

	t.Run("no positional or trust inputs", func(t *testing.T) {
		if err := assembleOnlineBundle([]string{"positional"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "positional") {
			t.Fatalf("positional argument returned %v", err)
		}
		for _, flagName := range []string{"--private", "--public", "--threshold", "--channel"} {
			if err := assembleOnlineBundle([]string{flagName, "value"}, &bytes.Buffer{}); err == nil {
				t.Fatalf("trust-bearing flag %s accepted", flagName)
			}
		}
	})

	t.Run("empty manifest", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		if err := os.WriteFile(options.channelManifestPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "size")
	})

	t.Run("oversize manifest", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		if err := os.Truncate(options.channelManifestPath, releasetrust.MaxManifestSize+1); err != nil {
			t.Fatal(err)
		}
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "size")
	})

	t.Run("signature counts", func(t *testing.T) {
		root := t.TempDir()
		options := onlineBundleOptionsFromSnapshot(writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs")), filepath.Join(root, "bundle.json"))
		options.channelSignaturePaths = nil
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "count")
		options.channelSignaturePaths = make([]string, releasetrust.MaxSignatureEnvelopes+1)
		for index := range options.channelSignaturePaths {
			options.channelSignaturePaths[index] = fmt.Sprintf("unopened-%d", index)
		}
		assertOnlineAssemblyFailure(t, options, onlineBundleAssemblyHooks{}, "count")
	})

	t.Run("maximum signature count", func(t *testing.T) {
		root := t.TempDir()
		inputs := writeSnapshotAssemblyInputs(t, filepath.Join(root, "inputs"))
		options := onlineBundleOptionsFromSnapshot(inputs, filepath.Join(root, "bundle.json"))
		options.channelSignaturePaths = make([]string, releasetrust.MaxSignatureEnvelopes)
		for index := range options.channelSignaturePaths {
			path := filepath.Join(root, "inputs", fmt.Sprintf("max-channel-%03d.json", index))
			if err := os.WriteFile(path, []byte(fmt.Sprintf("unique channel signature %03d\n", index)), 0o600); err != nil {
				t.Fatal(err)
			}
			options.channelSignaturePaths[index] = path
		}
		if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err != nil {
			t.Fatal(err)
		}
		parsed, err := onlinerelease.Parse(mustReadFile(t, options.outputPath))
		if err != nil || len(parsed.ChannelSignatures) != releasetrust.MaxSignatureEnvelopes {
			t.Fatalf("maximum signature result = %d, %v", len(parsed.ChannelSignatures), err)
		}
	})
}

func onlineBundleOptionsFromSnapshot(options snapshotAssemblyOptions, output string) onlineBundleAssemblyOptions {
	return onlineBundleAssemblyOptions{
		outputPath:            output,
		rootUpdatePaths:       append([]string(nil), options.rootUpdatePaths...),
		channelManifestPath:   options.channelManifestPath,
		channelSignaturePaths: append([]string(nil), options.channelSignaturePaths...),
		releaseManifestPath:   options.releaseManifestPath,
		releaseSignaturePaths: append([]string(nil), options.releaseSignaturePaths...),
	}
}

func assertOnlineAssemblyFailure(t *testing.T, options onlineBundleAssemblyOptions, hooks onlineBundleAssemblyHooks, message string) {
	t.Helper()
	err := assembleOnlineBundleUsing(options, hooks)
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("assembly error = %v, want substring %q", err, message)
	}
	if _, statErr := os.Lstat(options.outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed assembly left output %q: %v", options.outputPath, statErr)
	}
}

func assertOnlineSignaturesSorted(t *testing.T, got [][]byte, sourcePaths []string) {
	t.Helper()
	want := make([][]byte, len(sourcePaths))
	for index, path := range sourcePaths {
		want[index] = mustReadFile(t, path)
	}
	sort.Slice(want, func(left, right int) bool {
		leftDigest := sha256.Sum256(want[left])
		rightDigest := sha256.Sum256(want[right])
		if compared := bytes.Compare(leftDigest[:], rightDigest[:]); compared != 0 {
			return compared < 0
		}
		return bytes.Compare(want[left], want[right]) < 0
	})
	if len(got) != len(want) {
		t.Fatalf("signature count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if !bytes.Equal(got[index], want[index]) {
			t.Fatalf("signature %d was not deterministically sorted", index)
		}
	}
}
