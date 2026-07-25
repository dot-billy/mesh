package nebulaartifact

import (
	"bytes"
	"strings"
	"testing"

	nebulalock "mesh/third_party/nebula"
)

func TestEmbeddedLockTargetsAndIdentity(t *testing.T) {
	lock, err := EmbeddedLock()
	if err != nil {
		t.Fatal(err)
	}
	if lock.ReleaseID != 283875123 || lock.TagObject != "afe3e8c52cd4b91e8c5f946bf2e624df6d311c13" || lock.Commit != lockedRevision || len(lock.Artifacts) != 5 {
		t.Fatalf("unexpected release identity: %+v", lock)
	}
	for _, target := range []Target{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}} {
		artifact, err := lock.Select(target.OS, target.Arch)
		if err != nil {
			t.Fatalf("select %v: %v", target, err)
		}
		if artifact.AssetID <= 0 || len(artifact.Entries) < 2 {
			t.Fatalf("incomplete artifact for %v", target)
		}
	}
	if _, err := lock.Select("linux", "386"); err == nil {
		t.Fatal("unsupported target selected")
	}
}

func TestEmbeddedLockReturnsDeepCopies(t *testing.T) {
	first, err := EmbeddedLock()
	if err != nil {
		t.Fatal(err)
	}
	want := first.Artifacts[0].Entries[0].Name
	first.Artifacts[0].Entries[0].Name = "poisoned"
	first.Artifacts[0].Targets[0].OS = "poisoned"
	first.Artifacts[0].Entries[0].Binary.Targets[0].Arch = "poisoned"
	second, err := EmbeddedLock()
	if err != nil {
		t.Fatal(err)
	}
	if second.Artifacts[0].Entries[0].Name != want || second.Artifacts[0].Targets[0].OS == "poisoned" || second.Artifacts[0].Entries[0].Binary.Targets[0].Arch == "poisoned" {
		t.Fatal("caller mutation poisoned embedded trust state")
	}
	selected, err := second.Select("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	selected.Entries[0].Name = "poisoned-again"
	selectedAgain, _ := second.Select("linux", "amd64")
	if selectedAgain.Entries[0].Name == "poisoned-again" {
		t.Fatal("Select returned lock-backed mutable slices")
	}
}

func TestParseLockStrictJSON(t *testing.T) {
	raw := nebulalock.V1103Lock()
	tests := map[string][]byte{
		"duplicate":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		"unknown":     bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"trailing":    append(append([]byte(nil), raw...), []byte(` {}`)...),
		"invalid-utf": append(append([]byte(nil), raw...), 0xff),
		"surrogate":   bytes.Replace(raw, []byte(`"repository": "https://github.com/slackhq/nebula"`), []byte(`"repository": "\ud800"`), 1),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLock(candidate); err == nil {
				t.Fatal("malformed lock accepted")
			}
		})
	}
}

func TestParseLockPinsTagObjectAndBinaryShapes(t *testing.T) {
	raw := nebulalock.V1103Lock()
	t.Run("tag-object", func(t *testing.T) {
		candidate := bytes.Replace(raw, []byte("afe3e8c52cd4b91e8c5f946bf2e624df6d311c13"), []byte(strings.Repeat("0", 40)), 1)
		if _, err := ParseLock(candidate); err == nil {
			t.Fatal("alternate tag object accepted")
		}
	})
	t.Run("format-target", func(t *testing.T) {
		candidate := bytes.Replace(raw, []byte(`"format": "elf"`), []byte(`"format": "pe"`), 1)
		if _, err := ParseLock(candidate); err == nil {
			t.Fatal("PE expectation for Linux accepted")
		}
	})
	t.Run("missing-role", func(t *testing.T) {
		candidate := bytes.Replace(raw, []byte("github.com/slackhq/nebula/cmd/nebula-cert"), []byte("github.com/slackhq/nebula/cmd/nebula_____"), 1)
		if _, err := ParseLock(candidate); err == nil {
			t.Fatal("artifact without nebula-cert role accepted")
		}
	})
}

func TestWindowsLockEnumeratesCompleteWintunTree(t *testing.T) {
	lock, err := EmbeddedLock()
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		artifact, err := lock.Select("windows", arch)
		if err != nil {
			t.Fatal(err)
		}
		seen := make(map[string]struct{})
		for _, entry := range artifact.Entries {
			seen[entry.Name] = struct{}{}
		}
		for _, name := range []string{"dist/", "dist/windows/wintun/", "dist/windows/wintun/LICENSE.txt", "dist/windows/wintun/README.md", "dist/windows/wintun/bin/amd64/wintun.dll", "dist/windows/wintun/bin/arm/wintun.dll", "dist/windows/wintun/bin/arm64/wintun.dll", "dist/windows/wintun/bin/x86/wintun.dll", "dist/windows/wintun/include/wintun.h"} {
			if _, ok := seen[name]; !ok {
				t.Fatalf("%s lock missing %q", arch, name)
			}
		}
		if len(artifact.Entries) != 18 {
			t.Fatalf("%s lock has %d entries, want 18", arch, len(artifact.Entries))
		}
	}
}
