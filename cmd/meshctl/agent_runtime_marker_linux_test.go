//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeReadinessMarkerIsClosedWhenRuntimeDirectoryIsAbsent(t *testing.T) {
	marker := mustRuntimeReadinessMarker(t, filepath.Join(t.TempDir(), "not-created"), false)
	open, err := marker.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("absent systemd RuntimeDirectory was treated as authorized")
	}
	if err := marker.Close(); err != nil {
		t.Fatalf("closing an absent marker: %v", err)
	}
	if err := marker.Open(); err == nil {
		t.Fatal("marker publication succeeded without systemd RuntimeDirectory")
	}
}

func TestRuntimeReadinessMarkerExactLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "mesh-agent")
	marker := mustRuntimeReadinessMarker(t, directory, true)
	if err := marker.Open(); err != nil {
		t.Fatal(err)
	}
	if err := marker.Open(); err != nil {
		t.Fatalf("idempotent publication: %v", err)
	}
	open, err := marker.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if !open {
		t.Fatal("exact readiness publication was not observed")
	}
	content, err := os.ReadFile(filepath.Join(directory, runtimeReadinessMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, runtimeReadinessMarkerContent) {
		t.Fatalf("marker content = %q", content)
	}
	info, err := os.Lstat(filepath.Join(directory, runtimeReadinessMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != runtimeReadinessMarkerMode {
		t.Fatalf("marker mode = %o", info.Mode().Perm())
	}
	if _, err := os.Lstat(filepath.Join(directory, runtimeReadinessRecoveryName)); !os.IsNotExist(err) {
		t.Fatalf("recovery name remained after publication: %v", err)
	}
	if err := marker.Close(); err != nil {
		t.Fatal(err)
	}
	open, err = marker.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("closed readiness marker remained open")
	}
}

func TestRuntimeReadinessMarkerRecoversInterruptedPublication(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "complete recovery file",
			setup: func(t *testing.T, directory string) {
				writeReadinessTestFile(t, filepath.Join(directory, runtimeReadinessRecoveryName), runtimeReadinessMarkerContent)
			},
		},
		{
			name: "linked live and recovery names",
			setup: func(t *testing.T, directory string) {
				recovery := filepath.Join(directory, runtimeReadinessRecoveryName)
				writeReadinessTestFile(t, recovery, runtimeReadinessMarkerContent)
				if err := os.Link(recovery, filepath.Join(directory, runtimeReadinessMarkerName)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncated recovery file",
			setup: func(t *testing.T, directory string) {
				writeReadinessTestFile(t, filepath.Join(directory, runtimeReadinessRecoveryName), runtimeReadinessMarkerContent[:7])
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "mesh-agent")
			marker := mustRuntimeReadinessMarker(t, directory, true)
			test.setup(t, directory)
			if err := marker.Open(); err != nil {
				t.Fatal(err)
			}
			open, err := marker.Inspect()
			if err != nil {
				t.Fatal(err)
			}
			if !open {
				t.Fatal("recovered marker is not open")
			}
			if _, err := os.Lstat(filepath.Join(directory, runtimeReadinessRecoveryName)); !os.IsNotExist(err) {
				t.Fatalf("recovery name remains: %v", err)
			}
		})
	}
}

func TestRuntimeReadinessMarkerRejectsInexactPublicationButClosesIt(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
		check func(*testing.T, string)
	}{
		{
			name: "wrong content",
			setup: func(t *testing.T, directory string) {
				writeReadinessTestFile(t, filepath.Join(directory, runtimeReadinessMarkerName), []byte("not-authorized\n"))
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, directory string) {
				target := filepath.Join(directory, "target")
				writeReadinessTestFile(t, target, runtimeReadinessMarkerContent)
				if err := os.Symlink(target, filepath.Join(directory, runtimeReadinessMarkerName)); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, directory string) {
				if _, err := os.Lstat(filepath.Join(directory, "target")); err != nil {
					t.Fatalf("symlink target was damaged: %v", err)
				}
			},
		},
		{
			name: "unknown hard link",
			setup: func(t *testing.T, directory string) {
				outside := filepath.Join(directory, "outside")
				writeReadinessTestFile(t, outside, runtimeReadinessMarkerContent)
				if err := os.Link(outside, filepath.Join(directory, runtimeReadinessMarkerName)); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, directory string) {
				if _, err := os.Lstat(filepath.Join(directory, "outside")); err != nil {
					t.Fatalf("unrelated hard link was damaged: %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "mesh-agent")
			marker := mustRuntimeReadinessMarker(t, directory, true)
			test.setup(t, directory)
			if open, err := marker.Inspect(); err == nil || open {
				t.Fatalf("inexact marker inspection = (%v, %v), want closed error", open, err)
			}
			if err := marker.Open(); err == nil {
				t.Fatal("inexact marker was accepted for publication")
			}
			if err := marker.Close(); err != nil {
				t.Fatalf("fail-closed removal: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, runtimeReadinessMarkerName)); !os.IsNotExist(err) {
				t.Fatalf("inexact live name remained: %v", err)
			}
			if test.check != nil {
				test.check(t, directory)
			}
		})
	}
}

func mustRuntimeReadinessMarker(t *testing.T, directory string, create bool) *filesystemRuntimeReadinessMarker {
	t.Helper()
	if create {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker, err := newFilesystemRuntimeReadinessMarker(directory)
	if err != nil {
		t.Fatal(err)
	}
	return marker
}

func writeReadinessTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, runtimeReadinessMarkerMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, runtimeReadinessMarkerMode); err != nil {
		t.Fatal(err)
	}
}
