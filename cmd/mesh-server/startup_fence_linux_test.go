//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"mesh/internal/backupio"
	"mesh/internal/control"
)

func TestOpenFencedControlStoreRefusesHeldParentFence(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "data")
	fence, err := backupio.AcquireStartupFence(target)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	if _, err := openFencedControlStore(target); !errors.Is(err, backupio.ErrStartupFenceBusy) {
		t.Fatalf("server startup was not refused while restore fence was held: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused startup created its target: %v", err)
	}
}

func TestOpenFencedControlStoreRefusesMarkerBeforeCreatingTarget(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "data")
	marker, err := backupio.RestoreMarkerPath(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("interrupted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openFencedControlStore(target); !errors.Is(err, backupio.ErrIncompleteRestore) {
		t.Fatalf("server startup was not refused by marker: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker-refused startup created its target: %v", err)
	}
}

func TestOpenFencedControlStoreReturnsLockedStore(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "data")
	store, err := openFencedControlStore(target)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if competing, err := control.OpenStore(filepath.Join(target, backupio.ControlStateName)); err == nil {
		_ = competing.Close()
		t.Fatal("fenced startup returned without retaining the control store lock")
	}
}
