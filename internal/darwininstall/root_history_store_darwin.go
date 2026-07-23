//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mesh/internal/nodeagent"
	releasetrust "mesh/internal/release"

	"golang.org/x/sys/unix"
)

const darwinRootHistoryFileMode = uint16(0o400)

type darwinRootHistoryLockState struct {
	loaded  bool
	initial releasetrust.ParsedRoot
	current releasetrust.ParsedRoot
}

type darwinRootHistorySnapshot struct {
	found    bool
	raw      []byte
	identity darwinInstallStatSnapshot
}

// LoadTrustedRoot replays the compiled root plus every authenticated,
// create-only successor while holding the installer transaction lock.
func (store *InstallerJournalStore) LoadTrustedRoot(initial releasetrust.ParsedRoot) (root releasetrust.ParsedRoot, returnErr error) {
	lock, err := store.AcquireLock()
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	return lock.LoadTrustedRoot(initial)
}

// ApplyTrustedRootUpdates is the quiescent mutation path. Root history cannot
// advance outside the transaction lock or while an activation journal is live.
func (store *InstallerJournalStore) ApplyTrustedRootUpdates(initial releasetrust.ParsedRoot, rawUpdates [][]byte, now time.Time, clockSkew time.Duration) (result releasetrust.RootChainResult, returnErr error) {
	lock, err := store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Darwin trusted-root history cannot advance during an active installer transaction")
	}
	if _, found, err := lock.LoadIntakeRecord(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Darwin trusted-root history cannot advance while an accepted intake is active")
	}
	if _, err := lock.LoadTrustedRoot(initial); err != nil {
		return result, err
	}
	return lock.ApplyTrustedRootUpdates(rawUpdates, now, clockSkew)
}

// LoadTrustedRoot may be called once on an acquired installer lock. It first
// finishes the sole authenticated pending successor, then replays the complete
// contiguous history from the caller's compiled bootstrap root.
func (lock *InstallerJournalLock) LoadTrustedRoot(initial releasetrust.ParsedRoot) (releasetrust.ParsedRoot, error) {
	if err := lock.validateHeld(); err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	if lock.rootHistory.loaded {
		return releasetrust.ParsedRoot{}, errors.New("Darwin installer lock already loaded trusted-root history")
	}
	canonical, err := canonicalDarwinRoot(initial)
	if err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("compiled Darwin release root: %w", err)
	}
	lock.rootHistory.initial = canonical
	if err := lock.reconcileDarwinRootPending(); err != nil {
		lock.rootHistory = darwinRootHistoryLockState{}
		return releasetrust.ParsedRoot{}, err
	}
	current, _, err := lock.replayDarwinRootHistory()
	if err != nil {
		lock.rootHistory = darwinRootHistoryLockState{}
		return releasetrust.ParsedRoot{}, err
	}
	lock.rootHistory.loaded = true
	lock.rootHistory.current = current
	return cloneDarwinTrustedRoot(current), nil
}

// TrustedRootVersion returns an exact historical authority only after a fresh
// full-chain replay proves that history did not change while the lock was held.
func (lock *InstallerJournalLock) TrustedRootVersion(version uint64) (releasetrust.ParsedRoot, error) {
	if err := lock.validateDarwinRootHistoryHeld(); err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	current, versions, err := lock.replayDarwinRootHistory()
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	if !sameDarwinTrustedRoot(current, lock.rootHistory.current) {
		return releasetrust.ParsedRoot{}, errors.New("Darwin trusted-root history changed while the installer lock was held")
	}
	root, found := versions[version]
	if !found {
		return releasetrust.ParsedRoot{}, fmt.Errorf("trusted Darwin root version %d is not in persisted history", version)
	}
	return cloneDarwinTrustedRoot(root), nil
}

// ApplyTrustedRootUpdates verifies the complete proposed chain before
// publishing any bytes, then appends each successor with file-sync,
// create-only rename, directory-sync, and complete-chain readback.
func (lock *InstallerJournalLock) ApplyTrustedRootUpdates(rawUpdates [][]byte, now time.Time, clockSkew time.Duration) (releasetrust.RootChainResult, error) {
	if err := lock.validateDarwinRootHistoryHeld(); err != nil {
		return releasetrust.RootChainResult{}, err
	}
	current, _, err := lock.replayDarwinRootHistory()
	if err != nil {
		return releasetrust.RootChainResult{}, err
	}
	if !sameDarwinTrustedRoot(current, lock.rootHistory.current) {
		return releasetrust.RootChainResult{}, errors.New("Darwin trusted-root history changed while the installer lock was held")
	}
	result, err := releasetrust.EvaluateRootChain(current, rawUpdates, now, clockSkew)
	if err != nil {
		return result, err
	}
	for _, applied := range result.Applied {
		version := applied.Transition.Root.Document.Version
		if err := lock.publishDarwinRootUpdate(version, applied.Raw); err != nil {
			return result, fmt.Errorf("persist Darwin trusted-root version %d: %w", version, err)
		}
		persisted, _, err := lock.replayDarwinRootHistory()
		if err != nil {
			return result, err
		}
		if !sameDarwinTrustedRoot(persisted, applied.Transition.Root) {
			return result, fmt.Errorf("persisted Darwin trusted-root version %d differs after replay", version)
		}
		lock.rootHistory.current = persisted
	}
	if !sameDarwinTrustedRoot(lock.rootHistory.current, result.Root) {
		return result, errors.New("final Darwin trusted-root history differs from the verified chain")
	}
	return cloneDarwinRootChainResult(result), nil
}

func (lock *InstallerJournalLock) validateDarwinRootHistoryHeld() error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if !lock.rootHistory.loaded {
		return errors.New("Darwin trusted-root history must be loaded first")
	}
	return nil
}

func (lock *InstallerJournalLock) replayDarwinRootHistory() (releasetrust.ParsedRoot, map[uint64]releasetrust.ParsedRoot, error) {
	live, pending, err := lock.listDarwinRootHistory()
	if err != nil {
		return releasetrust.ParsedRoot{}, nil, err
	}
	if len(pending) != 0 {
		return releasetrust.ParsedRoot{}, nil, errors.New("pending Darwin trusted-root publication was not reconciled")
	}
	return lock.replayDarwinRootNames(live)
}

func (lock *InstallerJournalLock) replayDarwinRootNames(names []string) (releasetrust.ParsedRoot, map[uint64]releasetrust.ParsedRoot, error) {
	current := cloneDarwinTrustedRoot(lock.rootHistory.initial)
	versions := map[uint64]releasetrust.ParsedRoot{current.Document.Version: current}
	for _, name := range names {
		version, err := darwinRootHistoryVersion(name)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, err
		}
		if current.Document.Version == ^uint64(0) || version != current.Document.Version+1 {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("Darwin trusted-root history gap: version %d does not follow %d", version, current.Document.Version)
		}
		raw, err := lock.readDarwinRootUpdate(name)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, err
		}
		update, err := releasetrust.ParseRootUpdate(raw)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("parse Darwin trusted-root history %q: %w", name, err)
		}
		candidate, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil || candidate.Document.Version != version {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("Darwin trusted-root history %q manifest version differs from its filename", name)
		}
		transition, err := releasetrust.VerifyRootTransition(current, update.RootManifest, update.Signatures)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("verify Darwin trusted-root history %q: %w", name, err)
		}
		current = transition.Root
		versions[version] = current
	}
	return cloneDarwinTrustedRoot(current), versions, nil
}

func (lock *InstallerJournalLock) reconcileDarwinRootPending() error {
	live, pending, err := lock.listDarwinRootHistory()
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	if len(pending) != 1 {
		return errors.New("multiple pending Darwin trusted-root publications exist")
	}
	current, _, err := lock.replayDarwinRootNames(live)
	if err != nil {
		return err
	}
	name := pending[0]
	version, err := darwinRootPendingVersion(name)
	if err != nil {
		return err
	}
	if current.Document.Version == ^uint64(0) || version != current.Document.Version+1 {
		return fmt.Errorf("pending Darwin trusted-root version %d does not follow %d", version, current.Document.Version)
	}
	snapshot, err := lock.readDarwinRootUpdateRaw(name)
	if err != nil {
		return err
	}
	update, err := releasetrust.ParseRootUpdate(snapshot.raw)
	if err != nil {
		return fmt.Errorf("parse pending Darwin trusted-root version %d: %w", version, err)
	}
	candidate, err := releasetrust.ParseRoot(update.RootManifest)
	if err != nil || candidate.Document.Version != version {
		return fmt.Errorf("pending Darwin trusted-root version %d differs from its filename", version)
	}
	transition, err := releasetrust.VerifyRootTransition(current, update.RootManifest, update.Signatures)
	if err != nil {
		return fmt.Errorf("verify pending Darwin trusted-root version %d: %w", version, err)
	}
	liveAgain, pendingAgain, err := lock.listDarwinRootHistory()
	if err != nil {
		return err
	}
	stable, err := lock.readDarwinRootUpdateRaw(name)
	if err != nil {
		return err
	}
	if !equalDarwinRootNames(live, liveAgain) || !equalDarwinRootNames(pending, pendingAgain) || !sameDarwinRootHistorySnapshot(snapshot, stable) {
		return errors.New("Darwin trusted-root history changed while reconciling pending bytes")
	}
	if err := unix.RenameatxNp(lock.directory.fd, name, lock.directory.fd, darwinRootHistoryName(version), unix.RENAME_EXCL); err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	replayed, _, err := lock.replayDarwinRootHistory()
	if err != nil {
		return err
	}
	if !sameDarwinTrustedRoot(replayed, transition.Root) {
		return errors.New("recovered Darwin trusted-root publication differs after replay")
	}
	return nil
}

func (lock *InstallerJournalLock) publishDarwinRootUpdate(version uint64, raw []byte) (returnErr error) {
	name := darwinRootHistoryName(version)
	if existing, err := lock.readDarwinRootUpdateRaw(name); err != nil {
		return err
	} else if existing.found {
		if bytes.Equal(existing.raw, raw) {
			return nil
		}
		return fmt.Errorf("Darwin trusted-root equivocation at version %d", version)
	}
	pendingName := darwinRootPendingName(version)
	if pending, err := lock.readDarwinRootUpdateRaw(pendingName); err != nil {
		return err
	} else if pending.found {
		return errors.New("pending Darwin trusted-root publication was not reconciled before commit")
	}
	fd, err := unix.Openat(lock.directory.fd, pendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(darwinRootHistoryFileMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(lock.store.directory, pendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin trusted-root pending descriptor")
	}
	open := true
	defer func() {
		if open {
			returnErr = errors.Join(returnErr, file.Close())
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, uint32(darwinRootHistoryFileMode)); err != nil {
		return err
	}
	written, writeErr := file.Write(raw)
	if writeErr != nil || written != len(raw) {
		return errors.Join(writeErr, shortWriteError(written, len(raw)))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		open = false
		return err
	}
	open = false
	readback, err := lock.readDarwinRootUpdateRaw(pendingName)
	if err != nil {
		return err
	}
	if !readback.found || !bytes.Equal(readback.raw, raw) {
		return errors.New("pending Darwin trusted-root bytes differ after write and sync")
	}
	if err := unix.RenameatxNp(lock.directory.fd, pendingName, lock.directory.fd, name, unix.RENAME_EXCL); err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	committed, err := lock.readDarwinRootUpdateRaw(name)
	if err != nil {
		return err
	}
	if !committed.found || !bytes.Equal(committed.raw, raw) {
		return errors.New("published Darwin trusted-root bytes differ after directory sync")
	}
	return nil
}

func (lock *InstallerJournalLock) listDarwinRootHistory() (live, pending []string, returnErr error) {
	if err := lock.validateHeld(); err != nil {
		return nil, nil, err
	}
	var anchoredBefore unix.Stat_t
	if err := unix.Fstat(lock.directory.fd, &anchoredBefore); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Openat(lock.directory.fd, ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, nil, err
	}
	directory := os.NewFile(uintptr(fd), lock.store.directory)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("adopt Darwin trusted-root directory descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close()) }()
	var listedBefore unix.Stat_t
	if err := unix.Fstat(fd, &listedBefore); err != nil {
		return nil, nil, err
	}
	if err := validateDarwinInstallerDirectoryStat(listedBefore); err != nil {
		return nil, nil, err
	}
	if snapshotDarwinInstallStat(anchoredBefore) != snapshotDarwinInstallStat(listedBefore) {
		return nil, nil, errors.New("Darwin trusted-root listing descriptor differs from the installer directory")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > maxDarwinPersistedRootUpdates+16 {
		return nil, nil, fmt.Errorf("Darwin installer state entry count exceeds %d", maxDarwinPersistedRootUpdates+16)
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case darwinRootHistoryNamePattern.MatchString(name):
			live = append(live, name)
		case darwinRootPendingNamePattern.MatchString(name):
			pending = append(pending, name)
		case isDarwinRootHistoryNamespace(name):
			return nil, nil, fmt.Errorf("unknown Darwin trusted-root history entry %q", name)
		}
	}
	if len(live) > maxDarwinPersistedRootUpdates {
		return nil, nil, fmt.Errorf("Darwin trusted-root history count exceeds %d", maxDarwinPersistedRootUpdates)
	}
	sort.Strings(live)
	sort.Strings(pending)
	var listedAfter, anchoredAfter unix.Stat_t
	if err := unix.Fstat(fd, &listedAfter); err != nil {
		return nil, nil, err
	}
	if err := unix.Fstat(lock.directory.fd, &anchoredAfter); err != nil {
		return nil, nil, err
	}
	identity := snapshotDarwinInstallStat(anchoredBefore)
	if identity != snapshotDarwinInstallStat(listedAfter) || identity != snapshotDarwinInstallStat(anchoredAfter) {
		return nil, nil, errors.New("Darwin installer state directory changed while listing trusted-root history")
	}
	return live, pending, nil
}

func (lock *InstallerJournalLock) readDarwinRootUpdate(name string) ([]byte, error) {
	snapshot, err := lock.readDarwinRootUpdateRaw(name)
	if err != nil {
		return nil, err
	}
	if !snapshot.found {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), snapshot.raw...), nil
}

func (lock *InstallerJournalLock) readDarwinRootUpdateRaw(name string) (result darwinRootHistorySnapshot, returnErr error) {
	if !darwinRootHistoryNamePattern.MatchString(name) && !darwinRootPendingNamePattern.MatchString(name) {
		return result, fmt.Errorf("Darwin trusted-root filename %q is outside its reserved namespace", name)
	}
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(lock.directory.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	if err := validateDarwinRootHistoryStat(visibleBefore); err != nil {
		return result, fmt.Errorf("Darwin trusted-root file %q: %w", name, err)
	}
	path := filepath.Join(lock.store.directory, name)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	fd, err := unix.Openat(lock.directory.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("adopt Darwin trusted-root descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, releasetrust.MaxRootUpdateSize+1))
	if err != nil || len(raw) == 0 || len(raw) > releasetrust.MaxRootUpdateSize {
		return result, errors.Join(err, fmt.Errorf("Darwin trusted-root update must be between 1 and %d bytes", releasetrust.MaxRootUpdateSize))
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return result, err
	}
	if err := unix.Fstatat(lock.directory.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return result, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinRootHistoryStat(stat); err != nil {
			return result, err
		}
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(openedBefore) || identity != snapshotDarwinInstallStat(openedAfter) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return result, errors.New("Darwin trusted-root file changed while reading")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	return darwinRootHistorySnapshot{found: true, raw: raw, identity: identity}, nil
}

func validateDarwinRootHistoryStat(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != darwinRootHistoryFileMode || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size < 1 || stat.Size > releasetrust.MaxRootUpdateSize {
		return errors.New("must be exact root:wheel, single-link, mode-0400, flag-free, and within the root-update size bound")
	}
	return nil
}

func sameDarwinRootHistorySnapshot(left, right darwinRootHistorySnapshot) bool {
	if left.found != right.found {
		return false
	}
	return !left.found || left.identity == right.identity && bytes.Equal(left.raw, right.raw)
}

func equalDarwinRootNames(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func sameDarwinTrustedRoot(left, right releasetrust.ParsedRoot) bool {
	return left.Document.Version == right.Document.Version && left.SHA256 != "" && left.SHA256 == right.SHA256
}

func cloneDarwinTrustedRoot(source releasetrust.ParsedRoot) releasetrust.ParsedRoot {
	result, err := canonicalDarwinRoot(source)
	if err != nil {
		return releasetrust.ParsedRoot{}
	}
	return result
}

func cloneDarwinRootChainResult(source releasetrust.RootChainResult) releasetrust.RootChainResult {
	result := releasetrust.RootChainResult{Root: cloneDarwinTrustedRoot(source.Root), Applied: make([]releasetrust.AppliedRootUpdate, len(source.Applied))}
	for index, applied := range source.Applied {
		result.Applied[index] = releasetrust.AppliedRootUpdate{
			Raw: append([]byte(nil), applied.Raw...),
			Transition: releasetrust.VerifiedRootTransition{
				Root:                 cloneDarwinTrustedRoot(applied.Transition.Root),
				PreviousSignerKeyIDs: append([]string(nil), applied.Transition.PreviousSignerKeyIDs...),
				NewSignerKeyIDs:      append([]string(nil), applied.Transition.NewSignerKeyIDs...),
			},
		}
	}
	return result
}
