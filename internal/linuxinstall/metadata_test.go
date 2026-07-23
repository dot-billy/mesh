//go:build linux

package linuxinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
)

func TestOpenMetadataSnapshotReturnsStableVerifierInputAndArtifactIdentity(t *testing.T) {
	directory, descriptor, metadata, policy, now := writeMetadataSnapshotFixture(t)

	snapshot, err := OpenMetadataSnapshot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot.Metadata.ChannelManifest, metadata.ChannelManifest) ||
		!bytes.Equal(snapshot.Metadata.ReleaseManifest, metadata.ReleaseManifest) ||
		!reflect.DeepEqual(snapshot.Metadata.ChannelSignatures, metadata.ChannelSignatures) ||
		!reflect.DeepEqual(snapshot.Metadata.ReleaseSignatures, metadata.ReleaseSignatures) {
		t.Fatal("snapshot bytes differ from the exact signed source bytes")
	}
	if snapshot.Artifact.Path != filepath.Join(directory, descriptor.Artifact) ||
		snapshot.Artifact.Identity.Size != 1024 ||
		snapshot.Artifact.Identity.OwnerUID != uint32(os.Geteuid()) ||
		snapshot.Artifact.Identity.LinkCount != 1 || snapshot.Artifact.Identity.Inode == 0 {
		t.Fatalf("unexpected artifact source: %+v", snapshot.Artifact)
	}
	verified, err := verifySignedCandidateWithPolicy(snapshot.Metadata, policy, nil, now, 3)
	if err != nil {
		t.Fatalf("snapshot was not directly compatible with candidate verifier: %v", err)
	}
	if verified.Artifact.Size != 1024 || verified.Artifact.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("threshold-authenticated artifact did not remain authoritative: %+v", verified.Artifact)
	}
}

func TestOpenMetadataSnapshotCarriesExactContiguousRootUpdates(t *testing.T) {
	directory, descriptor, _, _, _ := writeMetadataSnapshotFixture(t)
	_, updates := rootStoreFixture(t, 2)
	descriptor.RootUpdates = []string{"root-update-000.json", "root-update-001.json"}
	for index, name := range descriptor.RootUpdates {
		writeSnapshotSource(t, filepath.Join(directory, name), updates[index])
	}
	rawDescriptor, err := EncodeInstallSnapshotDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, InstallSnapshotFile), rawDescriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := OpenMetadataSnapshot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.RootUpdates, updates) {
		t.Fatal("snapshot changed exact root-update bytes")
	}
	snapshot.RootUpdates[0][0] ^= 1
	again, err := OpenMetadataSnapshot(directory)
	if err != nil || !bytes.Equal(again.RootUpdates[0], updates[0]) {
		t.Fatalf("caller mutation poisoned snapshot reread: %v", err)
	}

	if err := os.WriteFile(filepath.Join(directory, descriptor.RootUpdates[0]), updates[1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMetadataSnapshot(directory); err == nil || !strings.Contains(err.Error(), "continue") {
		t.Fatalf("noncontiguous root updates returned %v", err)
	}
}

func TestInstallSnapshotDescriptorRequiresOneCanonicalForm(t *testing.T) {
	descriptor := validInstallSnapshotDescriptor()
	raw, err := EncodeInstallSnapshotDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Contains(raw[:len(raw)-1], []byte("\n")) {
		t.Fatalf("encoder did not emit compact JSON with one LF: %q", raw)
	}
	if parsed, err := parseInstallSnapshotDescriptor(raw); err != nil || !reflect.DeepEqual(parsed, descriptor) {
		t.Fatalf("canonical descriptor did not round trip: parsed=%+v err=%v", parsed, err)
	}
	legacy := cloneInstallSnapshotDescriptor(descriptor)
	legacy.Schema = InstallSnapshotSchemaV1
	legacy.RootUpdates = nil
	legacyRaw, err := EncodeInstallSnapshotDescriptor(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacyRaw, []byte("root_updates")) {
		t.Fatalf("v1 descriptor unexpectedly carries root updates: %s", legacyRaw)
	}
	if parsed, err := parseInstallSnapshotDescriptor(legacyRaw); err != nil || !reflect.DeepEqual(parsed, legacy) {
		t.Fatalf("legacy descriptor did not round trip: parsed=%+v err=%v", parsed, err)
	}

	withoutLF := append([]byte(nil), raw[:len(raw)-1]...)
	withTwoLF := append(append([]byte(nil), raw...), '\n')
	indented, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	indented = append(indented, '\n')
	unknown := append([]byte(nil), raw[:len(raw)-2]...)
	unknown = append(unknown, []byte(`,"minimum_sequence":1}`)...)
	unknown = append(unknown, '\n')
	duplicateField := append([]byte(nil), raw[:len(raw)-2]...)
	duplicateField = append(duplicateField, []byte(`,"artifact":"bundle.tar"}`)...)
	duplicateField = append(duplicateField, '\n')
	for name, candidate := range map[string][]byte{
		"missing LF": withoutLF, "two LF": withTwoLF, "indented": indented,
		"unknown field": unknown, "duplicate field": duplicateField,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInstallSnapshotDescriptor(candidate); err == nil {
				t.Fatal("noncanonical descriptor accepted")
			}
		})
	}
}

func TestInstallSnapshotDescriptorRejectsUnsafeAndAmbiguousNames(t *testing.T) {
	base := validInstallSnapshotDescriptor()
	tests := []struct {
		name   string
		change func(*InstallSnapshotDescriptor)
	}{
		{name: "path traversal", change: func(value *InstallSnapshotDescriptor) { value.Artifact = "../bundle.tar" }},
		{name: "uppercase", change: func(value *InstallSnapshotDescriptor) { value.Artifact = "Bundle.tar" }},
		{name: "descriptor reuse", change: func(value *InstallSnapshotDescriptor) { value.Artifact = InstallSnapshotFile }},
		{name: "cross-role duplicate", change: func(value *InstallSnapshotDescriptor) { value.ReleaseManifest = value.ChannelManifest }},
		{name: "root update wrong name", change: func(value *InstallSnapshotDescriptor) { value.RootUpdates = []string{"update.json"} }},
		{name: "root update collision", change: func(value *InstallSnapshotDescriptor) { value.RootUpdates = []string{value.ChannelManifest} }},
		{name: "missing v2 root updates", change: func(value *InstallSnapshotDescriptor) { value.RootUpdates = nil }},
		{name: "too many root updates", change: func(value *InstallSnapshotDescriptor) {
			value.RootUpdates = make([]string, releasetrust.MaxRootUpdatesPerInput+1)
		}},
		{name: "unsorted signatures", change: func(value *InstallSnapshotDescriptor) {
			value.ChannelSignatures[0], value.ChannelSignatures[1] = value.ChannelSignatures[1], value.ChannelSignatures[0]
		}},
		{name: "duplicate signature", change: func(value *InstallSnapshotDescriptor) { value.ReleaseSignatures[1] = value.ReleaseSignatures[0] }},
		{name: "empty channel signatures", change: func(value *InstallSnapshotDescriptor) { value.ChannelSignatures = nil }},
		{name: "too many release signatures", change: func(value *InstallSnapshotDescriptor) {
			value.ReleaseSignatures = make([]string, releasetrust.MaxSignatureEnvelopes+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneInstallSnapshotDescriptor(base)
			test.change(&candidate)
			if _, err := EncodeInstallSnapshotDescriptor(candidate); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
}

func TestOpenMetadataSnapshotRejectsUnsafeRootsAndSourceFiles(t *testing.T) {
	t.Run("directory mode", func(t *testing.T) {
		directory, _, _, _, _ := writeMetadataSnapshotFixture(t)
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMetadataSnapshot(directory); err == nil {
			t.Fatal("nonprivate source directory accepted")
		}
	})

	t.Run("directory symlink", func(t *testing.T) {
		directory, _, _, _, _ := writeMetadataSnapshotFixture(t)
		link := filepath.Join(t.TempDir(), "snapshot")
		if err := os.Symlink(directory, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMetadataSnapshot(link); err == nil {
			t.Fatal("symlinked source directory accepted")
		}
	})

	t.Run("file symlink", func(t *testing.T) {
		directory, descriptor, _, _, _ := writeMetadataSnapshotFixture(t)
		path := filepath.Join(directory, descriptor.ChannelManifest)
		target := filepath.Join(directory, "replacement.json")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(target), path); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMetadataSnapshot(directory); err == nil {
			t.Fatal("symlinked source file accepted")
		}
	})

	t.Run("hard linked file", func(t *testing.T) {
		directory, descriptor, _, _, _ := writeMetadataSnapshotFixture(t)
		if err := os.Link(filepath.Join(directory, descriptor.ReleaseManifest), filepath.Join(directory, "second-link.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMetadataSnapshot(directory); err == nil {
			t.Fatal("multiply linked source file accepted")
		}
	})

	t.Run("writable by other users", func(t *testing.T) {
		directory, descriptor, _, _, _ := writeMetadataSnapshotFixture(t)
		if err := os.Chmod(filepath.Join(directory, descriptor.Artifact), 0o662); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMetadataSnapshot(directory); err == nil {
			t.Fatal("group/world-writable source accepted")
		}
	})

	t.Run("oversized signature", func(t *testing.T) {
		directory, descriptor, _, _, _ := writeMetadataSnapshotFixture(t)
		if err := os.WriteFile(filepath.Join(directory, descriptor.ChannelSignatures[0]), make([]byte, releasetrust.MaxEnvelopeSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMetadataSnapshot(directory); err == nil {
			t.Fatal("oversized signature accepted")
		}
	})

	t.Run("wrong expected owner", func(t *testing.T) {
		directory, _, _, _, _ := writeMetadataSnapshotFixture(t)
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := openMetadataSnapshotAtRoot(root, uint32(os.Geteuid()+1), metadataSnapshotHooks{}); err == nil {
			t.Fatal("source owned by a different expected UID was accepted")
		}
	})
}

func TestOpenMetadataSnapshotRejectsMutationReplacementAndTruncation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, directory string, descriptor InstallSnapshotDescriptor) metadataSnapshotHooks
	}{
		{
			name: "truncate current file after read",
			mutate: func(t *testing.T, directory string, descriptor InstallSnapshotDescriptor) metadataSnapshotHooks {
				return oneShotSnapshotHook(descriptor.ChannelManifest, func() {
					if err := os.Truncate(filepath.Join(directory, descriptor.ChannelManifest), 1); err != nil {
						t.Error(err)
					}
				})
			},
		},
		{
			name: "replace current pathname after read",
			mutate: func(t *testing.T, directory string, descriptor InstallSnapshotDescriptor) metadataSnapshotHooks {
				return oneShotSnapshotHook(descriptor.ReleaseManifest, func() {
					path := filepath.Join(directory, descriptor.ReleaseManifest)
					if err := os.Rename(path, path+".old"); err != nil {
						t.Error(err)
						return
					}
					if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
						t.Error(err)
					}
				})
			},
		},
		{
			name: "mutate previously read file",
			mutate: func(t *testing.T, directory string, descriptor InstallSnapshotDescriptor) metadataSnapshotHooks {
				return oneShotSnapshotHook(descriptor.ReleaseManifest, func() {
					path := filepath.Join(directory, descriptor.ChannelManifest)
					file, err := os.OpenFile(path, os.O_WRONLY, 0)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := file.WriteAt([]byte("X"), 0); err != nil {
						t.Error(err)
					}
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
			},
		},
		{
			name: "append artifact after identity",
			mutate: func(t *testing.T, directory string, descriptor InstallSnapshotDescriptor) metadataSnapshotHooks {
				return oneShotSnapshotHook(descriptor.Artifact, func() {
					file, err := os.OpenFile(filepath.Join(directory, descriptor.Artifact), os.O_APPEND|os.O_WRONLY, 0)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := file.Write([]byte("changed")); err != nil {
						t.Error(err)
					}
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory, descriptor, _, _, _ := writeMetadataSnapshotFixture(t)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err := openMetadataSnapshotAtRoot(root, uint32(os.Geteuid()), test.mutate(t, directory, descriptor)); err == nil {
				t.Fatal("concurrently changed source accepted")
			}
		})
	}
}

func oneShotSnapshotHook(target string, action func()) metadataSnapshotHooks {
	done := false
	return metadataSnapshotHooks{afterRead: func(name string) {
		if !done && name == target {
			done = true
			action()
		}
	}}
}

func writeMetadataSnapshotFixture(t *testing.T) (string, InstallSnapshotDescriptor, SignedMetadata, installtrust.Policy, time.Time) {
	t.Helper()
	policy, privateKeys := candidateTrust(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	metadata := candidateMetadata(t, policy, privateKeys, 8, now.Add(-time.Minute), now.Add(time.Hour), "a")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor := validInstallSnapshotDescriptor()
	writeSnapshotSource(t, filepath.Join(directory, descriptor.ChannelManifest), metadata.ChannelManifest)
	writeSnapshotSource(t, filepath.Join(directory, descriptor.ReleaseManifest), metadata.ReleaseManifest)
	for index, name := range descriptor.ChannelSignatures {
		writeSnapshotSource(t, filepath.Join(directory, name), metadata.ChannelSignatures[index])
	}
	for index, name := range descriptor.ReleaseSignatures {
		writeSnapshotSource(t, filepath.Join(directory, name), metadata.ReleaseSignatures[index])
	}
	writeSnapshotSource(t, filepath.Join(directory, descriptor.Artifact), bytes.Repeat([]byte("b"), 1024))
	rawDescriptor, err := EncodeInstallSnapshotDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	writeSnapshotSource(t, filepath.Join(directory, InstallSnapshotFile), rawDescriptor)
	return directory, descriptor, metadata, policy, now
}

func validInstallSnapshotDescriptor() InstallSnapshotDescriptor {
	return InstallSnapshotDescriptor{
		Schema: InstallSnapshotSchema, RootUpdates: []string{}, ChannelManifest: "channel.json",
		ChannelSignatures: []string{"channel-a.sig.json", "channel-b.sig.json"},
		ReleaseManifest:   "release.json",
		ReleaseSignatures: []string{"release-a.sig.json", "release-b.sig.json"},
		Artifact:          "bundle.tar",
	}
}

func cloneInstallSnapshotDescriptor(source InstallSnapshotDescriptor) InstallSnapshotDescriptor {
	clone := source
	if source.RootUpdates != nil {
		clone.RootUpdates = append([]string{}, source.RootUpdates...)
	}
	clone.ChannelSignatures = append([]string(nil), source.ChannelSignatures...)
	clone.ReleaseSignatures = append([]string(nil), source.ReleaseSignatures...)
	return clone
}

func writeSnapshotSource(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
