//go:build linux

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRootStoreRejectsUnsafeHistoryFileTypesAndIdentities(t *testing.T) {
	initial, updates := rootStoreFixture(t, 1)
	mutations := map[string]func(*testing.T, string, []byte){
		"symlink": func(t *testing.T, path string, raw []byte) {
			target := filepath.Join(filepath.Dir(filepath.Dir(path)), "symlink-target")
			mustWriteRootHistoryFixture(t, target, raw, 0o400)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path string, _ []byte) {
			if err := os.Mkdir(path, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, path string, _ []byte) {
			if err := syscall.Mkfifo(path, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, path string, raw []byte) {
			target := filepath.Join(filepath.Dir(filepath.Dir(path)), "hardlink-target")
			mustWriteRootHistoryFixture(t, target, raw, 0o400)
			if err := os.Link(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"writable mode": func(t *testing.T, path string, raw []byte) {
			mustWriteRootHistoryFixture(t, path, raw, 0o600)
		},
		"special bit": func(t *testing.T, path string, raw []byte) {
			mustWriteRootHistoryFixture(t, path, raw, 0o400)
			if err := os.Chmod(path, os.FileMode(0o400)|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		},
		"truncated": func(t *testing.T, path string, raw []byte) {
			mustWriteRootHistoryFixture(t, path, raw[:len(raw)/2], 0o400)
		},
		"grown": func(t *testing.T, path string, raw []byte) {
			mustWriteRootHistoryFixture(t, path, append(append([]byte(nil), raw...), 'x'), 0o400)
		},
	}
	if os.Geteuid() == 0 {
		mutations["device"] = func(t *testing.T, path string, _ []byte) {
			if err := syscall.Mknod(path, syscall.S_IFCHR|0o400, 0x103); err != nil {
				if errors.Is(err, syscall.EPERM) {
					t.Skip("test environment does not permit device creation")
				}
				t.Fatal(err)
			}
		}
		mutations["wrong owner"] = func(t *testing.T, path string, raw []byte) {
			mustWriteRootHistoryFixture(t, path, raw, 0o400)
			if err := os.Chown(path, 1, 1); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trust")
			store := mustRootStore(t, path, initial)
			lock, err := store.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			mutate(t, filepath.Join(path, rootHistoryDirectoryName, rootHistoryName(2)), updates[0])
			if lock, err := store.Acquire(); err == nil {
				_ = lock.Close()
				t.Fatal("unsafe root history entry was accepted")
			}
		})
	}
}

func TestRootStoreDetectsHistoryReplacementDuringRead(t *testing.T) {
	initial, updates := rootStoreFixture(t, 1)
	path := filepath.Join(t.TempDir(), "trust")
	store := mustRootStore(t, path, initial)
	lock, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if _, err := lock.ApplyChain(updates, now, 0); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	name := rootHistoryName(2)
	store.hooks.afterHistoryRead = func(got string) {
		if got != name {
			return
		}
		store.hooks.afterHistoryRead = nil
		target := filepath.Join(path, rootHistoryDirectoryName, name)
		replacement := target + ".replacement"
		mustWriteRootHistoryFixture(t, replacement, updates[0], 0o400)
		if err := os.Rename(replacement, target); err != nil {
			t.Fatal(err)
		}
	}
	if lock, err := store.Acquire(); err == nil {
		_ = lock.Close()
		t.Fatal("history replacement during read was accepted")
	}
}

func TestRootStorePublicationFailurePointsLeaveReplayableHistory(t *testing.T) {
	initial, updates := rootStoreFixture(t, 1)
	injected := errors.New("injected root publication failure")
	tests := map[string]struct {
		hooks       rootStoreHooks
		wantVersion uint64
	}{
		"write": {
			hooks: rootStoreHooks{write: func(*os.File, []byte) (int, error) { return 0, injected }}, wantVersion: 1,
		},
		"file sync": {
			hooks: rootStoreHooks{beforeFileSync: func() error { return injected }}, wantVersion: 1,
		},
		"readback": {
			hooks: rootStoreHooks{beforeReadback: func(string) error { return injected }}, wantVersion: 1,
		},
		"rename": {
			hooks: rootStoreHooks{beforeRename: func() error { return injected }}, wantVersion: 1,
		},
		"directory sync": {
			hooks: rootStoreHooks{beforeDirectorySync: func() error { return injected }}, wantVersion: 2,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trust")
			store := mustRootStore(t, path, initial)
			store.hooks = test.hooks
			lock, err := store.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			_, err = lock.ApplyChain(updates, time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC), 0)
			if !errors.Is(err, injected) && (err == nil || !strings.Contains(err.Error(), injected.Error())) {
				t.Fatalf("publication failure returned %v", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			store.hooks = rootStoreHooks{}
			reopened, err := store.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if got := reopened.Current().Document.Version; got != test.wantVersion {
				t.Fatalf("replayed version = %d, want %d", got, test.wantVersion)
			}
		})
	}
}

func TestRootStoreConcurrentWritersConvergeOnOneContiguousChain(t *testing.T) {
	initial, updates := rootStoreFixture(t, 3)
	store := mustRootStore(t, filepath.Join(t.TempDir(), "trust"), initial)
	const writers = 8
	start := make(chan struct{})
	errorsByWriter := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for attempt := 0; attempt < 10000; attempt++ {
				lock, err := store.Acquire()
				if err != nil {
					if strings.Contains(err.Error(), "holds the trust lock") {
						runtime.Gosched()
						continue
					}
					errorsByWriter <- err
					return
				}
				_, applyErr := lock.ApplyChain(updates, time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC), 0)
				closeErr := lock.Close()
				errorsByWriter <- errors.Join(applyErr, closeErr)
				return
			}
			errorsByWriter <- errors.New("writer did not acquire root lock")
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	lock, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if got := lock.Current().Document.Version; got != 4 {
		t.Fatalf("concurrent root history ended at version %d, want 4", got)
	}
}

func mustWriteRootHistoryFixture(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
