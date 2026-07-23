//go:build linux

package linuxinstall

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"mesh/internal/installtrust"
)

const maxStateSize = 128 << 10

type StateStore struct {
	path   string
	parent string
	name   string
}

func NewStateStore(path string) (*StateStore, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	parent, name := filepath.Split(abs)
	parent = filepath.Clean(parent)
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return nil, errors.New("installer state path must name a file")
	}
	return &StateStore{path: abs, parent: parent, name: name}, nil
}

func EnsureStateDirectory(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	parent := filepath.Dir(abs)
	if err := validateSecureAncestorChain(parent, false); err != nil {
		return err
	}
	if err := os.Mkdir(abs, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create installer state directory: %w", err)
	}
	if err := validatePrivateDirectory(abs); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func (store *StateStore) Path() string { return store.path }

func (store *StateStore) Load() (State, error) {
	if err := store.validateParent(); err != nil {
		return State{}, err
	}
	root, err := os.OpenRoot(store.parent)
	if err != nil {
		return State{}, err
	}
	defer root.Close()
	snapshot, err := readStateSnapshot(root, store.name)
	if err != nil {
		return State{}, err
	}
	if !snapshot.found {
		return State{}, &os.PathError{Op: "open", Path: store.path, Err: os.ErrNotExist}
	}
	return snapshot.state, nil
}

func (store *StateStore) validateParent() error {
	return validatePrivateDirectory(store.parent)
}

type stateFileIdentity struct {
	device, inode, links uint64
	mode                 uint32
	uid, gid             uint32
	size                 int64
	mtimeSeconds         int64
	mtimeNanoseconds     int64
	ctimeSeconds         int64
	ctimeNanoseconds     int64
}

type stateSnapshot struct {
	found    bool
	raw      []byte
	state    State
	identity stateFileIdentity
}

type StoreLock struct {
	store    *StateStore
	root     *os.Root
	file     *os.File
	loaded   bool
	snapshot stateSnapshot
}

func (store *StateStore) AcquireLock() (*StoreLock, error) {
	if err := store.validateParent(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(store.parent)
	if err != nil {
		return nil, err
	}
	name := store.name + ".lock"
	file, err := openStoreLockFile(root, name)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		_ = root.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("another installer transaction holds the state lock")
		}
		return nil, err
	}
	lock := &StoreLock{store: store, root: root, file: file}
	if err := lock.validateHeldLock(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

// Load snapshots the exact state protected by the lock. It must be called once
// before Commit. A missing state is represented by found=false so the first
// Commit can use create-only publication rather than overwrite another writer.
func (lock *StoreLock) Load() (state State, found bool, err error) {
	if err := lock.validateHeldLock(); err != nil {
		return State{}, false, err
	}
	if lock.loaded {
		return State{}, false, errors.New("installer state lock already loaded a snapshot")
	}
	snapshot, err := readStateSnapshot(lock.root, lock.store.name)
	if err != nil {
		return State{}, false, err
	}
	lock.loaded = true
	lock.snapshot = snapshot
	return deepCopyState(snapshot.state), snapshot.found, nil
}

// Commit is the only state mutation path. It re-reads the exact file and inode
// remembered by Load, rejects stale or externally replaced state, validates the
// complete install transaction transition, and publishes through an fsynced
// atomic replacement. Successful commits advance the remembered snapshot so a
// caller holding the lock can durably journal subsequent phases.
func (lock *StoreLock) Commit(next State) error {
	if err := lock.validateHeldLock(); err != nil {
		return err
	}
	if !lock.loaded {
		return errors.New("installer state must be loaded under the lock before commit")
	}
	current, err := readStateSnapshot(lock.root, lock.store.name)
	if err != nil {
		return err
	}
	if !sameStateSnapshot(lock.snapshot, current) {
		return errors.New("installer state changed after the locked snapshot was loaded")
	}
	if err := validateCommittedTransition(current, next); err != nil {
		return err
	}
	expectedRaw, err := marshalState(next)
	if err != nil {
		return err
	}
	if err := writeStateAtomic(lock.root, lock.store.name, expectedRaw, !current.found); err != nil {
		return err
	}
	committed, err := readStateSnapshot(lock.root, lock.store.name)
	if err != nil {
		return fmt.Errorf("read committed installer state: %w", err)
	}
	if !committed.found || !bytes.Equal(committed.raw, expectedRaw) {
		return errors.New("committed installer state bytes do not match the requested transition")
	}
	lock.snapshot = committed
	return nil
}

// MigrateV2 is the sole schema-changing state mutation. It computes the exact
// v3 mapping under the already-held state lock and publishes it through the
// same fsynced atomic replacement and readback used by transaction commits.
func (lock *StoreLock) MigrateV2(bootstrap installtrust.Bootstrap, rootHistoryEmpty bool) (State, error) {
	if err := lock.validateHeldLock(); err != nil {
		return State{}, err
	}
	if !lock.loaded {
		return State{}, errors.New("installer state must be loaded under the lock before migration")
	}
	current, err := readStateSnapshot(lock.root, lock.store.name)
	if err != nil {
		return State{}, err
	}
	if !sameStateSnapshot(lock.snapshot, current) {
		return State{}, errors.New("installer state changed after the locked snapshot was loaded")
	}
	if !current.found {
		return State{}, errors.New("legacy installer state does not exist")
	}
	next, err := MigrateStateV2(current.state, bootstrap, rootHistoryEmpty)
	if err != nil {
		return State{}, err
	}
	expectedRaw, err := marshalState(next)
	if err != nil {
		return State{}, err
	}
	if err := writeStateAtomic(lock.root, lock.store.name, expectedRaw, false); err != nil {
		return State{}, err
	}
	committed, err := readStateSnapshot(lock.root, lock.store.name)
	if err != nil {
		return State{}, fmt.Errorf("read migrated installer state: %w", err)
	}
	if !committed.found || !bytes.Equal(committed.raw, expectedRaw) || !sameStateExact(committed.state, next) {
		return State{}, errors.New("migrated installer state bytes do not match the requested mapping")
	}
	lock.snapshot = committed
	return deepCopyState(committed.state), nil
}

func (lock *StoreLock) Close() error {
	if lock == nil {
		return nil
	}
	var unlockErr, fileCloseErr, rootCloseErr error
	if lock.file != nil {
		unlockErr = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		fileCloseErr = lock.file.Close()
	}
	if lock.root != nil {
		rootCloseErr = lock.root.Close()
	}
	lock.store = nil
	lock.root = nil
	lock.file = nil
	lock.loaded = false
	lock.snapshot = stateSnapshot{}
	return errors.Join(unlockErr, fileCloseErr, rootCloseErr)
}

func openStoreLockFile(root *os.Root, name string) (file *os.File, returnErr error) {
	before, err := root.Lstat(name)
	created := false
	switch {
	case err == nil:
		if err := validatePrivateRegular(before, 0o600, 0); err != nil {
			return nil, fmt.Errorf("installer state lock: %w", err)
		}
		file, err = root.OpenFile(name, os.O_RDWR, 0)
	case errors.Is(err, os.ErrNotExist):
		file, err = root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		created = err == nil
	default:
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr == nil {
			return
		}
		_ = file.Close()
		if created {
			_ = root.Remove(name)
		}
	}()
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validatePrivateRegular(opened, 0o600, 0); err != nil {
		return nil, fmt.Errorf("installer state lock: %w", err)
	}
	if !created && !os.SameFile(before, opened) {
		return nil, errors.New("installer state lock changed while opening")
	}
	current, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateRegular(current, 0o600, 0); err != nil || !os.SameFile(opened, current) {
		return nil, errors.New("installer state lock path is not the opened private empty regular file")
	}
	if created {
		if err := syncRootDirectory(root); err != nil {
			return nil, fmt.Errorf("sync installer state lock creation: %w", err)
		}
	}
	return file, nil
}

func (lock *StoreLock) validateHeldLock() error {
	if lock == nil || lock.store == nil || lock.root == nil || lock.file == nil {
		return errors.New("installer state lock is closed")
	}
	if err := lock.store.validateParent(); err != nil {
		return err
	}
	pathDirectory, err := os.Lstat(lock.store.parent)
	if err != nil {
		return err
	}
	rootDirectory, err := lock.root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(pathDirectory, rootDirectory) {
		return errors.New("installer state directory changed after acquiring the lock")
	}
	held, err := lock.file.Stat()
	if err != nil {
		return err
	}
	if err := validatePrivateRegular(held, 0o600, 0); err != nil {
		return fmt.Errorf("held installer state lock: %w", err)
	}
	current, err := lock.root.Lstat(lock.store.name + ".lock")
	if err != nil {
		return err
	}
	if err := validatePrivateRegular(current, 0o600, 0); err != nil || !os.SameFile(held, current) {
		return errors.New("installer state lock path changed after locking")
	}
	return nil
}

func readStateSnapshot(root *os.Root, name string) (stateSnapshot, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return stateSnapshot{}, nil
	}
	if err != nil {
		return stateSnapshot{}, err
	}
	if err := validatePrivateRegular(before, 0o600, maxStateSize); err != nil {
		return stateSnapshot{}, fmt.Errorf("installer state: %w", err)
	}
	file, err := root.Open(name)
	if err != nil {
		return stateSnapshot{}, err
	}
	openedBefore, err := file.Stat()
	if err != nil || !os.SameFile(before, openedBefore) {
		_ = file.Close()
		return stateSnapshot{}, errors.New("installer state changed while opening")
	}
	beforeIdentity, err := stateIdentity(openedBefore)
	if err != nil {
		_ = file.Close()
		return stateSnapshot{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxStateSize+1))
	openedAfter, statErr := file.Stat()
	current, pathErr := root.Lstat(name)
	closeErr := file.Close()
	if readErr != nil {
		return stateSnapshot{}, readErr
	}
	if statErr != nil {
		return stateSnapshot{}, statErr
	}
	if pathErr != nil {
		return stateSnapshot{}, pathErr
	}
	if closeErr != nil {
		return stateSnapshot{}, closeErr
	}
	if err := validatePrivateRegular(openedAfter, 0o600, maxStateSize); err != nil {
		return stateSnapshot{}, fmt.Errorf("opened installer state: %w", err)
	}
	if err := validatePrivateRegular(current, 0o600, maxStateSize); err != nil || !os.SameFile(openedAfter, current) {
		return stateSnapshot{}, errors.New("installer state path changed while reading")
	}
	afterIdentity, err := stateIdentity(openedAfter)
	if err != nil {
		return stateSnapshot{}, err
	}
	currentIdentity, err := stateIdentity(current)
	if err != nil {
		return stateSnapshot{}, err
	}
	if beforeIdentity != afterIdentity || afterIdentity != currentIdentity {
		return stateSnapshot{}, errors.New("installer state metadata changed while reading")
	}
	if len(raw) == 0 || len(raw) > maxStateSize || int64(len(raw)) != openedAfter.Size() {
		return stateSnapshot{}, fmt.Errorf("installer state size must be between 1 and %d bytes and match the opened file", maxStateSize)
	}
	var state State
	if err := decodeStrictStateJSON(raw, &state); err != nil {
		return stateSnapshot{}, fmt.Errorf("decode installer state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return stateSnapshot{}, fmt.Errorf("validate installer state: %w", err)
	}
	canonical, err := marshalState(state)
	if err != nil {
		return stateSnapshot{}, fmt.Errorf("canonicalize installer state: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return stateSnapshot{}, errors.New("installer state bytes are not in exact canonical form")
	}
	return stateSnapshot{found: true, raw: append([]byte(nil), raw...), state: state, identity: currentIdentity}, nil
}

func stateIdentity(info os.FileInfo) (stateFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return stateFileIdentity{}, errors.New("installer state file has no Linux stat identity")
	}
	return stateFileIdentity{
		device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink),
		mode: uint32(stat.Mode), uid: uint32(stat.Uid), gid: uint32(stat.Gid), size: info.Size(),
		mtimeSeconds: int64(stat.Mtim.Sec), mtimeNanoseconds: int64(stat.Mtim.Nsec),
		ctimeSeconds: int64(stat.Ctim.Sec), ctimeNanoseconds: int64(stat.Ctim.Nsec),
	}, nil
}

func sameStateSnapshot(left, right stateSnapshot) bool {
	if left.found != right.found {
		return false
	}
	if !left.found {
		return true
	}
	return left.identity == right.identity && bytes.Equal(left.raw, right.raw) && sameStateExact(left.state, right.state)
}

func marshalState(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > maxStateSize {
		return nil, fmt.Errorf("installer state exceeds %d bytes", maxStateSize)
	}
	return raw, nil
}

func writeStateAtomic(root *os.Root, name string, raw []byte, createOnly bool) (returnErr error) {
	temporaryName, err := randomStateName()
	if err != nil {
		return err
	}
	temporary, err := root.OpenFile(temporaryName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	temporaryOpen := true
	temporaryNamed := true
	defer func() {
		if temporaryOpen {
			if err := temporary.Close(); err != nil && returnErr == nil {
				returnErr = err
			}
		}
		if temporaryNamed {
			_ = root.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if written, err := temporary.Write(raw); err != nil {
		return err
	} else if written != len(raw) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	info, err := temporary.Stat()
	if err != nil {
		return err
	}
	if err := validatePrivateRegular(info, 0o600, maxStateSize); err != nil || info.Size() != int64(len(raw)) {
		return errors.New("installer state temporary file is invalid")
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporaryOpen = false
	if createOnly {
		directory, err := root.Open(".")
		if err != nil {
			return fmt.Errorf("open installer state directory for publication: %w", err)
		}
		rootInfo, rootErr := root.Stat(".")
		directoryInfo, directoryErr := directory.Stat()
		if rootErr != nil || directoryErr != nil || !sameDirectoryObject(rootInfo, directoryInfo) {
			_ = directory.Close()
			return errors.New("installer state directory changed while preparing publication")
		}
		if err := renameNoReplace(directory, temporaryName, name); err != nil {
			_ = directory.Close()
			return fmt.Errorf("create installer state without replacement: %w", err)
		}
		temporaryNamed = false
		if err := directory.Close(); err != nil {
			return fmt.Errorf("close installer state publication directory: %w", err)
		}
		published, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if err := validatePrivateRegular(published, 0o600, maxStateSize); err != nil || published.Size() != int64(len(raw)) {
			return errors.New("new installer state publication is invalid")
		}
	} else {
		if err := root.Rename(temporaryName, name); err != nil {
			return err
		}
		temporaryNamed = false
	}
	if err := syncRootDirectory(root); err != nil {
		return fmt.Errorf("sync installer state directory: %w", err)
	}
	return nil
}

func validateCommittedTransition(current stateSnapshot, next State) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if !current.found {
		if next.Active != nil || next.Previous != nil || next.Pending == nil || next.Pending.Phase != PhasePrepared ||
			next.Pending.Operation != OperationActivate || next.Pending.SourceActive != nil || next.Pending.SourcePrevious != nil ||
			next.Pending.Candidate != next.HighWater || next.Pending.TargetActive != next.Pending.Candidate {
			return errors.New("first installer state must create a prepared transaction with no prior release")
		}
		return nil
	}
	previous := current.state
	if next.Schema != previous.Schema || next.TrustPolicySHA256 != previous.TrustPolicySHA256 ||
		next.BootstrapTrustSHA256 != previous.BootstrapTrustSHA256 || next.Channel != previous.Channel {
		return errors.New("installer state schema, trust identity, and channel are immutable")
	}
	if previous.Pending == nil {
		if next.Pending == nil {
			if !sameStateExact(previous, next) {
				return errors.New("installer state cannot change without a prepared transaction")
			}
			return nil
		}
		switch next.Pending.Operation {
		case OperationActivate:
			if err := validateHighWaterAdvance(previous.HighWater, next.HighWater); err != nil {
				return err
			}
		case OperationRollback:
			if next.HighWater != previous.HighWater {
				return errors.New("explicit rollback must retain the exact accepted high-water release")
			}
		default:
			return fmt.Errorf("unsupported installer transaction operation %q", next.Pending.Operation)
		}
		if next.Pending.Phase != PhasePrepared || next.Pending.Candidate != next.HighWater ||
			!sameReleasePointerExact(next.Pending.SourceActive, previous.Active) ||
			!sameReleasePointerExact(next.Pending.SourcePrevious, previous.Previous) ||
			!sameReleasePointerExact(next.Active, previous.Active) || !sameReleasePointerExact(next.Previous, previous.Previous) {
			return errors.New("new installer transaction must bind its exact source state and high-water candidate without changing active releases")
		}
		return nil
	}
	if next.HighWater != previous.HighWater {
		return errors.New("an existing installer transaction cannot change its accepted high-water release")
	}
	if next.Pending != nil {
		if !sameReleasePointerExact(next.Active, previous.Active) || !sameReleasePointerExact(next.Previous, previous.Previous) {
			return errors.New("active releases cannot change while an installer transaction remains pending")
		}
		if !samePendingJournalExceptPhase(*previous.Pending, *next.Pending) {
			return errors.New("pending installer journal fields other than phase are immutable")
		}
		if !allowedPendingPhaseTransition(previous.Pending.Phase, next.Pending.Phase) {
			return fmt.Errorf("invalid installer transaction phase transition %q to %q", previous.Pending.Phase, next.Pending.Phase)
		}
		return nil
	}
	switch previous.Pending.Phase {
	case PhasePrepared, PhaseRollingBack:
		if !sameReleasePointerExact(next.Active, previous.Pending.SourceActive) || !sameReleasePointerExact(next.Previous, previous.Pending.SourcePrevious) {
			return errors.New("aborted or rolled-back transaction must restore its exact source releases")
		}
	case PhaseCurrentSwitched:
		target := previous.Pending.TargetActive
		if !sameReleasePointerExact(next.Active, &target) || !sameReleasePointerExact(next.Previous, previous.Pending.SourceActive) {
			return errors.New("successful transaction must activate target_active and retain source_active as previous")
		}
	case PhaseServicesStopped:
		return errors.New("services-stopped transaction must record rolling_back before it can be cleared")
	default:
		return fmt.Errorf("unsupported installer transaction phase %q", previous.Pending.Phase)
	}
	return nil
}

func validateHighWaterAdvance(previous, next ReleaseIdentity) error {
	position := compareReleasePosition(next, previous)
	if position < 0 {
		return fmt.Errorf("installer high-water position (%d,%d) cannot decrease below (%d,%d)", next.ReleaseEpoch, next.Sequence, previous.ReleaseEpoch, previous.Sequence)
	}
	if next.MinimumSecurityFloor < previous.MinimumSecurityFloor {
		return fmt.Errorf("installer security floor %d cannot decrease below %d", next.MinimumSecurityFloor, previous.MinimumSecurityFloor)
	}
	if position == 0 && next != previous {
		return errors.New("same-position installer high-water identity must remain exact")
	}
	return nil
}

func sameStateExact(left, right State) bool {
	return left.Schema == right.Schema && left.TrustPolicySHA256 == right.TrustPolicySHA256 &&
		left.BootstrapTrustSHA256 == right.BootstrapTrustSHA256 && left.Channel == right.Channel &&
		left.HighWater == right.HighWater && sameReleasePointerExact(left.Active, right.Active) &&
		sameReleasePointerExact(left.Previous, right.Previous) && samePendingPointerExact(left.Pending, right.Pending)
}

func deepCopyState(state State) State {
	copy := state
	copy.Active = deepCopyReleasePointer(state.Active)
	copy.Previous = deepCopyReleasePointer(state.Previous)
	if state.Pending != nil {
		pending := *state.Pending
		pending.SourceActive = deepCopyReleasePointer(state.Pending.SourceActive)
		pending.SourcePrevious = deepCopyReleasePointer(state.Pending.SourcePrevious)
		copy.Pending = &pending
	}
	return copy
}

func deepCopyReleasePointer(identity *ReleaseIdentity) *ReleaseIdentity {
	if identity == nil {
		return nil
	}
	copy := *identity
	return &copy
}

func sameReleasePointerExact(left, right *ReleaseIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func samePendingPointerExact(left, right *PendingTransaction) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Operation == right.Operation && left.Candidate == right.Candidate &&
		sameReleasePointerExact(left.SourceActive, right.SourceActive) && sameReleasePointerExact(left.SourcePrevious, right.SourcePrevious) &&
		left.TargetActive == right.TargetActive &&
		left.Phase == right.Phase && left.AgentWasEnabled == right.AgentWasEnabled &&
		left.AgentWasActive == right.AgentWasActive && left.NebulaWasActive == right.NebulaWasActive &&
		left.RuntimeGateWasOpen == right.RuntimeGateWasOpen &&
		left.StartedAt == right.StartedAt
}

func samePendingJournalExceptPhase(left, right PendingTransaction) bool {
	return left.Operation == right.Operation && left.Candidate == right.Candidate &&
		sameReleasePointerExact(left.SourceActive, right.SourceActive) && sameReleasePointerExact(left.SourcePrevious, right.SourcePrevious) &&
		left.TargetActive == right.TargetActive &&
		left.AgentWasEnabled == right.AgentWasEnabled && left.AgentWasActive == right.AgentWasActive &&
		left.NebulaWasActive == right.NebulaWasActive && left.RuntimeGateWasOpen == right.RuntimeGateWasOpen &&
		left.StartedAt == right.StartedAt
}

func allowedPendingPhaseTransition(previous, next TransactionPhase) bool {
	if previous == next {
		return true
	}
	switch previous {
	case PhasePrepared:
		return next == PhaseServicesStopped || next == PhaseRollingBack
	case PhaseServicesStopped:
		return next == PhaseCurrentSwitched || next == PhaseRollingBack
	case PhaseCurrentSwitched:
		return next == PhaseRollingBack
	default:
		return false
	}
}

func validatePrivateDirectory(path string) error {
	if err := validateSecureAncestorChain(path, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("installer state directory must be a real effective-user-owned mode-0700 directory without special bits")
	}
	return nil
}

func validateSecureAncestorChain(path string, _ bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	current := string(filepath.Separator)
	previous, err := os.Lstat(current)
	if err != nil {
		return err
	}
	rootStat, ok := previous.Sys().(*syscall.Stat_t)
	if !ok || previous.Mode()&os.ModeSymlink != 0 || !previous.IsDir() || rootStat.Uid != 0 && rootStat.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe filesystem root for installer state")
	}
	if err := rejectPOSIXACL(current); err != nil {
		return err
	}
	components := strings.Split(strings.TrimPrefix(abs, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("unsafe installer state ancestor %q", current)
		}
		if previous.Mode().Perm()&0o022 != 0 && previous.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("installer state ancestor parent of %q is writable without sticky protection", current)
		}
		if err := rejectPOSIXACL(current); err != nil {
			return err
		}
		previous = info
	}
	if previous.Mode().Perm()&0o022 != 0 && previous.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("installer state ancestor %q is writable without sticky protection", abs)
	}
	return nil
}

func rejectPOSIXACL(path string) error {
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		size, err := syscall.Getxattr(path, attribute, nil)
		if err == nil && size > 0 {
			return fmt.Errorf("installer state ancestor %q has extended POSIX ACL %q", path, attribute)
		}
		if err != nil && !errors.Is(err, syscall.ENODATA) && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.EOPNOTSUPP) {
			return err
		}
	}
	return nil
}

func validatePrivateRegular(info os.FileInfo, mode os.FileMode, maxSize int64) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		!info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() < 0 || info.Size() > maxSize {
		return errors.New("must be a bounded private regular file with exact mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("private file must be effective-user-owned with one link")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func randomStateName() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return ".state-" + hex.EncodeToString(value[:]), nil
}

func decodeStrictStateJSON(raw []byte, output any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeStateJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func consumeStateJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeStateJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := consumeStateJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
