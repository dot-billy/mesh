//go:build linux

package linuxinstall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestStateStoreRoundTripAndStrictPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	store, err := NewStateStore(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, found, err := lock.Load(); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("new state store unexpectedly exists")
	}
	state := preparedInitialState()
	if err := lock.Commit(state); err != nil {
		t.Fatal(err)
	}
	state = stateAtPhase(state, PhaseServicesStopped)
	if err := lock.Commit(state); err != nil {
		t.Fatal(err)
	}
	state = stateAtPhase(state, PhaseCurrentSwitched)
	if err := lock.Commit(state); err != nil {
		t.Fatal(err)
	}
	state = successfulState(state)
	if err := lock.Commit(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.HighWater.InstalledID != state.HighWater.InstalledID || loaded.TrustPolicySHA256 != state.TrustPolicySHA256 ||
		loaded.HighWater.AgentStateReadMin != state.HighWater.AgentStateReadMin || loaded.HighWater.AgentStateReadMax != state.HighWater.AgentStateReadMax ||
		loaded.HighWater.AgentStateWriteVersion != state.HighWater.AgentStateWriteVersion {
		t.Fatalf("round trip changed state: %+v", loaded)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %04o", info.Mode().Perm())
	}
}

func TestWriteStateAtomicCreateOnlyPublishesSingleLink(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := marshalState(preparedInitialState())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStateAtomic(root, "state.json", raw, true); err != nil {
		t.Fatal(err)
	}
	info, err := root.Lstat("state.json")
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("first installer state has no Linux stat identity")
	}
	if stat.Nlink != 1 {
		t.Fatalf("first installer state link count = %d, want 1", stat.Nlink)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".state-") {
			t.Fatalf("first installer state retained publication name %q", entry.Name())
		}
	}
	if got, err := root.ReadFile("state.json"); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("published installer state differs: err=%v", err)
	}
}

func TestWriteStateAtomicCreateOnlyUsesRenamePublication(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	watch, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		t.Skipf("inotify is unavailable: %v", err)
	}
	defer syscall.Close(watch)
	if _, err := syscall.InotifyAddWatch(watch, directory, syscall.IN_CREATE|syscall.IN_MOVED_TO); err != nil {
		t.Skipf("cannot watch installer state directory: %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := marshalState(preparedInitialState())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStateAtomic(root, "state.json", raw, true); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	count, err := syscall.Read(watch, buffer)
	if err != nil {
		t.Fatal(err)
	}
	var createdFinal, movedFinal bool
	for offset := 0; offset+syscall.SizeofInotifyEvent <= count; {
		event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
		nameStart := offset + syscall.SizeofInotifyEvent
		nameEnd := nameStart + int(event.Len)
		if nameEnd > count {
			t.Fatal("truncated inotify event while observing installer state publication")
		}
		name := string(bytes.TrimRight(buffer[nameStart:nameEnd], "\x00"))
		if name == "state.json" {
			createdFinal = createdFinal || event.Mask&syscall.IN_CREATE != 0
			movedFinal = movedFinal || event.Mask&syscall.IN_MOVED_TO != 0
		}
		offset = nameEnd
	}
	if createdFinal || !movedFinal {
		t.Fatalf("first installer state events: create=%v moved-to=%v; want atomic rename publication", createdFinal, movedFinal)
	}
}

func TestRenameNoReplacePreservesExistingDestination(t *testing.T) {
	directory := t.TempDir()
	parent, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	oldPath := filepath.Join(directory, "temporary")
	newPath := filepath.Join(directory, "state.json")
	if err := os.WriteFile(oldPath, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(parent, filepath.Base(oldPath), filepath.Base(newPath)); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("no-replace collision error = %v, want EEXIST", err)
	}
	if content, err := os.ReadFile(oldPath); err != nil || string(content) != "candidate" {
		t.Fatalf("collision changed source: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(newPath); err != nil || string(content) != "existing" {
		t.Fatalf("collision replaced destination: content=%q err=%v", content, err)
	}
}

func TestStateStoreRejectsSymlinkAndLooseMode(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	store, _ := NewStateStore(filepath.Join(directory, "state.json"))
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("symlink state accepted")
	}
	if err := os.Remove(store.Path()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path(), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("loosely permissioned state accepted")
	}
}

func TestStateStoreRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	store, _ := NewStateStore(filepath.Join(directory, "state.json"))
	writeStateFile(t, store.Path(), validState())
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"duplicate":    bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"other","schema":`), 1),
		"unknown":      bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"trailing":     append(append([]byte(nil), raw...), []byte(` {}`)...),
		"noncanonical": bytes.Replace(raw, []byte(`{"schema"`), []byte(`{ "schema"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(store.Path(), candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("malformed state accepted")
			}
		})
	}
}

func TestStateStoreLockExcludesConcurrentInstaller(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	store, _ := NewStateStore(filepath.Join(directory, "state.json"))
	first, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := store.AcquireLock(); err == nil {
		t.Fatal("concurrent installer lock acquired")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreLockRequiresLoadAndCreateOnlyPreparedState(t *testing.T) {
	store := newTestStateStore(t)
	lock, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lock.Commit(preparedInitialState()); err == nil {
		t.Fatal("commit without locked load succeeded")
	}
	if _, found, err := lock.Load(); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("new installer state unexpectedly exists")
	}
	if err := lock.Commit(validState()); err == nil {
		t.Fatal("first commit created a completed state without a prepared journal")
	}
	if err := lock.Commit(preparedInitialState()); err != nil {
		t.Fatalf("prepared first commit failed: %v", err)
	}
}

func TestStoreLockRejectsStaleSnapshot(t *testing.T) {
	t.Run("existing-state-rewritten", func(t *testing.T) {
		store := newTestStateStore(t)
		original := validState()
		writeStateFile(t, store.Path(), original)
		lock, err := store.AcquireLock()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if _, found, err := lock.Load(); err != nil || !found {
			t.Fatalf("load found=%v err=%v", found, err)
		}
		changed := original
		changed.TrustPolicySHA256 = strings.Repeat("e", 64)
		writeStateFile(t, store.Path(), changed)
		if err := lock.Commit(original); err == nil {
			t.Fatal("commit accepted an externally rewritten state")
		}
	})

	t.Run("missing-state-created", func(t *testing.T) {
		store := newTestStateStore(t)
		lock, err := store.AcquireLock()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if _, found, err := lock.Load(); err != nil || found {
			t.Fatalf("load found=%v err=%v", found, err)
		}
		prepared := preparedInitialState()
		writeStateFile(t, store.Path(), prepared)
		if err := lock.Commit(prepared); err == nil {
			t.Fatal("create-only commit overwrote an externally created state")
		}
	})
}

func TestStoreCommitRejectsRollbackPolicyDriftAndUnjournaledAdvance(t *testing.T) {
	active := testRelease(5, "1", "2", 1)
	accepted := testRelease(7, "a", "b", 2)
	old := validState()
	old.HighWater = accepted
	old.Active = &active

	tests := map[string]func(State) State{
		"lower-sequence": func(state State) State {
			return beginPreparedTransaction(state, testRelease(6, "3", "4", 2))
		},
		"lower-floor": func(state State) State {
			return beginPreparedTransaction(state, testRelease(8, "3", "4", 1))
		},
		"same-sequence-equivocation": func(state State) State {
			return beginPreparedTransaction(state, testRelease(7, "3", "4", 2))
		},
		"same-sequence-agent-state-range-drift": func(state State) State {
			candidate := state.HighWater
			candidate.AgentStateReadMax++
			return beginPreparedTransaction(state, candidate)
		},
		"same-sequence-agent-state-writer-drift": func(state State) State {
			candidate := state.HighWater
			candidate.AgentStateReadMax++
			candidate.AgentStateWriteVersion++
			return beginPreparedTransaction(state, candidate)
		},
		"policy-drift": func(state State) State {
			state.TrustPolicySHA256 = strings.Repeat("e", 64)
			return state
		},
		"unjournaled-advance": func(state State) State {
			state.HighWater = testRelease(8, "3", "4", 2)
			return state
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := newTestStateStore(t)
			writeStateFile(t, store.Path(), old)
			lock, err := store.AcquireLock()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			loaded, found, err := lock.Load()
			if err != nil || !found {
				t.Fatalf("load found=%v err=%v", found, err)
			}
			if err := lock.Commit(mutate(loaded)); err == nil {
				t.Fatal("forbidden installer state transition committed")
			}
		})
	}
}

func TestStoreCommitPreservesPendingJournal(t *testing.T) {
	old := beginPreparedTransaction(validState(), testRelease(8, "3", "4", 2))
	old = stateAtPhase(old, PhaseServicesStopped)
	store := newTestStateStore(t)
	writeStateFile(t, store.Path(), old)
	lock, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	loaded, found, err := lock.Load()
	if err != nil || !found {
		t.Fatalf("load found=%v err=%v", found, err)
	}
	changedJournal := stateAtPhase(loaded, PhaseCurrentSwitched)
	changedJournal.Pending.StartedAt = "2026-07-19T12:00:01Z"
	if err := lock.Commit(changedJournal); err == nil {
		t.Fatal("pending journal mutation committed")
	}
	changedJournal = stateAtPhase(loaded, PhaseCurrentSwitched)
	changedJournal.Pending.NebulaWasActive = !loaded.Pending.NebulaWasActive
	if err := lock.Commit(changedJournal); err == nil {
		t.Fatal("pending Nebula runtime snapshot mutation committed")
	}
	changedJournal = stateAtPhase(loaded, PhaseCurrentSwitched)
	changedJournal.Pending.RuntimeGateWasOpen = !loaded.Pending.RuntimeGateWasOpen
	if err := lock.Commit(changedJournal); err == nil {
		t.Fatal("pending runtime-gate snapshot mutation committed")
	}
	wrongClear := successfulState(loaded)
	if err := lock.Commit(wrongClear); err == nil {
		t.Fatal("services-stopped transaction cleared as a successful switch")
	}
}

func TestPendingEqualityAndDeepCopyBindRuntimeSnapshot(t *testing.T) {
	state := beginPreparedTransaction(validState(), testRelease(8, "3", "4", 2))
	state.Pending.NebulaWasActive = true
	state.Pending.RuntimeGateWasOpen = true
	copy := deepCopyState(state)
	if copy.Pending == state.Pending || !copy.Pending.NebulaWasActive || !copy.Pending.RuntimeGateWasOpen || !sameStateExact(state, copy) {
		t.Fatalf("deep copy did not preserve an independent exact pending journal: original=%+v copy=%+v", state.Pending, copy.Pending)
	}
	copy.Pending.RuntimeGateWasOpen = false
	if !state.Pending.NebulaWasActive {
		t.Fatal("mutating the copied pending journal changed the source")
	}
	if samePendingPointerExact(state.Pending, copy.Pending) || samePendingJournalExceptPhase(*state.Pending, *copy.Pending) || sameStateExact(state, copy) {
		t.Fatal("pending equality ignored the runtime-gate snapshot")
	}
}

func TestStoreLockLoadReturnsIndependentMutableState(t *testing.T) {
	prepared := beginPreparedTransaction(validState(), testRelease(8, "3", "4", 2))
	store := newTestStateStore(t)
	writeStateFile(t, store.Path(), prepared)
	lock, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	loaded, found, err := lock.Load()
	if err != nil || !found {
		t.Fatalf("load found=%v err=%v", found, err)
	}
	loaded.Pending.Phase = PhaseServicesStopped
	if err := lock.Commit(loaded); err != nil {
		t.Fatalf("natural in-place update of loaded state failed: %v", err)
	}
}

func TestCommittedActivationSuccessAndFailureRestoreExactSources(t *testing.T) {
	base := validState()
	previous := testRelease(6, "1", "2", 1)
	base.Previous = &previous
	candidate := testRelease(8, "3", "4", 2)
	prepared := beginPreparedTransaction(base, candidate)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: base}, prepared); err != nil {
		t.Fatalf("prepare activation: %v", err)
	}

	switched := stateAtPhase(stateAtPhase(prepared, PhaseServicesStopped), PhaseCurrentSwitched)
	committed := successfulState(switched)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: switched}, committed); err != nil {
		t.Fatalf("commit activation: %v", err)
	}
	if committed.Active == nil || *committed.Active != candidate || committed.Previous == nil || *committed.Previous != *base.Active {
		t.Fatalf("activation committed wrong releases: %+v", committed)
	}
	if committed.HighWater != candidate {
		t.Fatal("activation did not retain advanced high-water identity")
	}

	rollingBack := stateAtPhase(stateAtPhase(prepared, PhaseServicesStopped), PhaseRollingBack)
	restored := clearPending(rollingBack)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: rollingBack}, restored); err != nil {
		t.Fatalf("complete failed-activation rollback: %v", err)
	}
	if !sameReleasePointerExact(restored.Active, base.Active) || !sameReleasePointerExact(restored.Previous, base.Previous) {
		t.Fatalf("failed activation did not restore exact source state: %+v", restored)
	}
	if restored.HighWater != candidate {
		t.Fatal("failed activation lowered the accepted high-water identity")
	}
}

func TestCommittedExplicitRollbackSuccessAndFailure(t *testing.T) {
	base := validState()
	previous := testRelease(6, "1", "2", 1)
	base.Previous = &previous
	prepared := beginRollbackTransaction(base)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: base}, prepared); err != nil {
		t.Fatalf("prepare explicit rollback: %v", err)
	}

	switched := stateAtPhase(stateAtPhase(prepared, PhaseServicesStopped), PhaseCurrentSwitched)
	committed := successfulState(switched)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: switched}, committed); err != nil {
		t.Fatalf("commit explicit rollback: %v", err)
	}
	if committed.Active == nil || *committed.Active != previous || committed.Previous == nil || *committed.Previous != *base.Active {
		t.Fatalf("explicit rollback committed wrong releases: %+v", committed)
	}
	if committed.HighWater != base.HighWater {
		t.Fatal("explicit rollback changed the accepted high-water identity")
	}

	rollingBack := stateAtPhase(prepared, PhaseRollingBack)
	restored := clearPending(rollingBack)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: rollingBack}, restored); err != nil {
		t.Fatalf("abort explicit rollback: %v", err)
	}
	if !sameReleasePointerExact(restored.Active, base.Active) || !sameReleasePointerExact(restored.Previous, base.Previous) || restored.HighWater != base.HighWater {
		t.Fatalf("failed explicit rollback did not restore exact source state: %+v", restored)
	}
}

func TestCommittedExplicitRollbackCannotAdvanceHighWater(t *testing.T) {
	base := validState()
	previous := testRelease(6, "1", "2", 1)
	base.Previous = &previous
	next := beginRollbackTransaction(base)
	next.HighWater = testRelease(8, "3", "4", 2)
	next.Pending.Candidate = next.HighWater
	if err := validateCommittedTransition(stateSnapshot{found: true, state: base}, next); err == nil {
		t.Fatal("explicit rollback advanced high-water identity")
	}
}

func TestCommittedTransitionPhaseMatrix(t *testing.T) {
	prepared := beginPreparedTransaction(validState(), testRelease(8, "3", "4", 2))
	phases := []TransactionPhase{PhasePrepared, PhaseServicesStopped, PhaseCurrentSwitched, PhaseRollingBack}
	allowed := map[[2]TransactionPhase]bool{
		{PhasePrepared, PhasePrepared}:               true,
		{PhasePrepared, PhaseServicesStopped}:        true,
		{PhasePrepared, PhaseRollingBack}:            true,
		{PhaseServicesStopped, PhaseServicesStopped}: true,
		{PhaseServicesStopped, PhaseCurrentSwitched}: true,
		{PhaseServicesStopped, PhaseRollingBack}:     true,
		{PhaseCurrentSwitched, PhaseCurrentSwitched}: true,
		{PhaseCurrentSwitched, PhaseRollingBack}:     true,
		{PhaseRollingBack, PhaseRollingBack}:         true,
	}
	for _, from := range phases {
		for _, to := range phases {
			old := stateAtPhase(prepared, from)
			next := stateAtPhase(old, to)
			err := validateCommittedTransition(stateSnapshot{found: true, state: old}, next)
			if allowed[[2]TransactionPhase{from, to}] && err != nil {
				t.Fatalf("allowed phase transition %s -> %s failed: %v", from, to, err)
			}
			if !allowed[[2]TransactionPhase{from, to}] && err == nil {
				t.Fatalf("forbidden phase transition %s -> %s succeeded", from, to)
			}
		}
	}

	preparedAbort := clearPending(stateAtPhase(prepared, PhasePrepared))
	if err := validateCommittedTransition(stateSnapshot{found: true, state: stateAtPhase(prepared, PhasePrepared)}, preparedAbort); err != nil {
		t.Fatalf("prepared abort failed: %v", err)
	}
	servicesStopped := stateAtPhase(prepared, PhaseServicesStopped)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: servicesStopped}, clearPending(servicesStopped)); err == nil {
		t.Fatal("services-stopped transaction cleared without recording rolling_back")
	}
	rollingBack := stateAtPhase(prepared, PhaseRollingBack)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: rollingBack}, clearPending(rollingBack)); err != nil {
		t.Fatalf("completed rollback failed: %v", err)
	}
	switched := stateAtPhase(prepared, PhaseCurrentSwitched)
	if err := validateCommittedTransition(stateSnapshot{found: true, state: switched}, successfulState(switched)); err != nil {
		t.Fatalf("successful switch completion failed: %v", err)
	}
}

func TestStateStoreRejectsSymlinkOrNonemptyLock(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		store := newTestStateStore(t)
		target := filepath.Join(filepath.Dir(store.Path()), "lock-target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(target), store.Path()+".lock"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcquireLock(); err == nil {
			t.Fatal("symlink installer lock accepted")
		}
	})
	t.Run("nonempty", func(t *testing.T) {
		store := newTestStateStore(t)
		if err := os.WriteFile(store.Path()+".lock", []byte("not empty"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcquireLock(); err == nil {
			t.Fatal("nonempty installer lock accepted")
		}
	})
}

func TestStateDirectoryRejectsWritableAncestor(t *testing.T) {
	base := t.TempDir()
	insecure := filepath.Join(base, "insecure")
	if err := os.Mkdir(insecure, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o777); err != nil {
		t.Fatal(err)
	}
	err := EnsureStateDirectory(filepath.Join(insecure, "state"))
	if err == nil {
		t.Fatal("state directory below writable ancestor accepted")
	}
}

func TestStateDirectoryRejectsWritableImmediateParent(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateDirectory(filepath.Join(base, "state")); err == nil {
		t.Fatal("state directory below writable immediate parent accepted")
	}
}

func validState() State {
	high := testRelease(7, "a", "b", 1)
	return State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64),
		Channel: "stable", HighWater: high, Active: &high,
	}
}

func newTestStateStore(t *testing.T) *StateStore {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	store, err := NewStateStore(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func writeStateFile(t *testing.T, path string, state State) {
	t.Helper()
	raw, err := marshalState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func preparedInitialState() State {
	high := testRelease(7, "a", "b", 1)
	return State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable", HighWater: high,
		Pending: &PendingTransaction{
			Operation: OperationActivate, Candidate: high, TargetActive: high,
			Phase: PhasePrepared, AgentWasEnabled: false, AgentWasActive: false,
			StartedAt: "2026-07-19T12:00:00Z",
		},
	}
}

func beginPreparedTransaction(previous State, candidate ReleaseIdentity) State {
	next := cloneState(previous)
	next.HighWater = candidate
	next.Pending = &PendingTransaction{
		Operation: OperationActivate, Candidate: candidate,
		SourceActive: cloneReleasePointer(previous.Active), SourcePrevious: cloneReleasePointer(previous.Previous),
		TargetActive: candidate, Phase: PhasePrepared,
		AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true, StartedAt: "2026-07-19T12:00:00Z",
	}
	return next
}

func beginRollbackTransaction(previous State) State {
	next := cloneState(previous)
	target := ReleaseIdentity{}
	if previous.Previous != nil {
		target = *previous.Previous
	}
	next.Pending = &PendingTransaction{
		Operation: OperationRollback, Candidate: previous.HighWater,
		SourceActive: cloneReleasePointer(previous.Active), SourcePrevious: cloneReleasePointer(previous.Previous),
		TargetActive: target, Phase: PhasePrepared,
		AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true, StartedAt: "2026-07-19T12:00:00Z",
	}
	return next
}

func stateAtPhase(state State, phase TransactionPhase) State {
	next := cloneState(state)
	if next.Pending != nil {
		next.Pending.Phase = phase
	}
	return next
}

func successfulState(state State) State {
	next := cloneState(state)
	if next.Pending == nil {
		return next
	}
	target := next.Pending.TargetActive
	next.Active = &target
	next.Previous = cloneReleasePointer(next.Pending.SourceActive)
	next.Pending = nil
	return next
}

func clearPending(state State) State {
	next := cloneState(state)
	next.Pending = nil
	return next
}

func cloneState(state State) State {
	clone := state
	clone.Active = cloneReleasePointer(state.Active)
	clone.Previous = cloneReleasePointer(state.Previous)
	if state.Pending != nil {
		pending := *state.Pending
		pending.SourceActive = cloneReleasePointer(state.Pending.SourceActive)
		pending.SourcePrevious = cloneReleasePointer(state.Pending.SourcePrevious)
		clone.Pending = &pending
	}
	return clone
}

func cloneReleasePointer(identity *ReleaseIdentity) *ReleaseIdentity {
	if identity == nil {
		return nil
	}
	clone := *identity
	return &clone
}
