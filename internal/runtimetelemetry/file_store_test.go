//go:build !windows

package runtimetelemetry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFileStoreDurablyMigratesCanonicalV1State(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[]}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("OpenFileStore legacy v1: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, legacy) || string(current) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy state was not durably migrated: %s", current)
	}
}

func TestFileStorePersistsExactObservationAndDeletion(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	if _, changed, err := store.Put("node_a", 9, now, validObservation(), UnsupportedActiveProbe()); err != nil || !changed {
		t.Fatalf("put changed=%t err=%v", changed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatalf("state metadata=%v err=%v", info, err)
	}
	store, err = OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record, found, err := store.Get("node_a")
	if err != nil || !found || record.HeartbeatSequence != 9 || record.Observation.State != StateObserved {
		t.Fatalf("reopened record=%+v found=%t err=%v", record, found, err)
	}
	if deleted, err := store.Delete("node_a"); err != nil || !deleted {
		t.Fatalf("delete=%t err=%v", deleted, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if records, err := store.List(); err != nil || len(records) != 0 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestFileStorePersistsConfigBoundProbeRecovery(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 21, 19, 0, 0, 0, time.UTC)
	digest := string(bytes.Repeat([]byte{'e'}, 64))
	observation := validObservation()
	if _, _, err := store.PutWithConfig("node_a", 1, now, observation, transitionProbe(2, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest); err != nil {
		t.Fatal(err)
	}
	observation = nextTransitionObservation(observation)
	recovered, changed, err := store.PutWithConfig("node_a", 2, now.Add(time.Second), observation, transitionProbe(2, 2), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest)
	if err != nil || !changed || recovered.ProbeTransition != ProbeTransitionRecovered {
		t.Fatalf("recovered=%#v changed=%t err=%v", recovered, changed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reopened, found, err := store.Get("node_a")
	if err != nil || !found || reopened.AppliedConfigSHA256 != digest || reopened.ProbeTransition != ProbeTransitionRecovered {
		t.Fatalf("reopened=%#v found=%t err=%v", reopened, found, err)
	}
}

func TestFileStorePersistsContinuityAndRejectsRollbackWithoutWriting(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	if record, changed, err := store.Put("node_a", 1, now, validObservation(), UnsupportedActiveProbe()); err != nil || !changed || record.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("first put=%+v changed=%t err=%v", record, changed, err)
	}
	continuous := validObservation()
	continuous.Snapshot.SampleSequence++
	continuous.Snapshot.ProcessUptimeMS++
	accepted, changed, err := store.Put("node_a", 2, now.Add(time.Minute), continuous, UnsupportedActiveProbe())
	if err != nil || !changed || accepted.ProcessContinuity != ContinuityContinuous {
		t.Fatalf("continuous put=%+v changed=%t err=%v", accepted, changed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reopened, found, err := store.Get("node_a")
	if err != nil || !found || reopened.ProcessContinuity != ContinuityContinuous {
		t.Fatalf("reopened=%+v found=%t err=%v", reopened, found, err)
	}
	if _, _, err := store.Put("node_a", 3, now.Add(2*time.Minute), validObservation(), UnsupportedActiveProbe()); !errors.Is(err, ErrReplay) {
		t.Fatalf("same-process rollback returned %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("rejected rollback rewrote state:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestFileStoreDurablyMigratesCanonicalV2State(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v2","records":[]}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("OpenFileStore legacy v2: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, legacy) || string(current) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy v2 state was not durably migrated: %s", current)
	}
}

func TestFileStoreDurablyMigratesCanonicalV4State(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v4","records":[]}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("OpenFileStore legacy v4: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, legacy) || string(current) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy v4 state was not durably migrated: %s", current)
	}
}

func TestFileStoreDurablyMigratesCanonicalV6State(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v6","records":[]}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("OpenFileStore legacy v6: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, legacy) || string(current) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy v6 state was not durably migrated: %s", current)
	}
}

func TestFileStoreRejectsConcurrentOpenAndCorruptState(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-telemetry.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("concurrent runtime telemetry store open succeeded")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[],"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt state returned %v", err)
	}
}

func TestFileStoreRejectsUnsafeDirectoryAndStateMetadata(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime-telemetry.json")
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("mode-0755 telemetry directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("symlink telemetry state was accepted")
	}
}
