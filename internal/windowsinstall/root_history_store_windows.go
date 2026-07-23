//go:build windows

package windowsinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	releasetrust "mesh/internal/release"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

type windowsRootHistorySnapshot struct {
	found bool
	raw   []byte
	info  os.FileInfo
}

// LoadTrustedRoot recovers the sole authenticated pending successor and then
// replays the complete contiguous create-only history from compiledRoot.
func (store *ActivationJournalStore) LoadTrustedRoot(compiledRoot releasetrust.ParsedRoot) (result releasetrust.ParsedRoot, returnErr error) {
	if store == nil {
		return result, errors.New("Windows installer store is required")
	}
	initial, err := canonicalWindowsRoot(compiledRoot)
	if err != nil {
		return result, fmt.Errorf("compiled Windows release root: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return result, err
	}
	defer root.Close()
	if err := store.reconcileWindowsRootPending(root, initial); err != nil {
		return result, err
	}
	current, _, err := replayWindowsRootHistory(root, initial)
	if err != nil {
		return result, err
	}
	return cloneWindowsTrustedRoot(current), nil
}

// TrustedRootVersion returns an exact historical authority after a fresh full
// replay under the same cross-process installer lock.
func (store *ActivationJournalStore) TrustedRootVersion(compiledRoot releasetrust.ParsedRoot, version uint64) (result releasetrust.ParsedRoot, returnErr error) {
	if store == nil {
		return result, errors.New("Windows installer store is required")
	}
	initial, err := canonicalWindowsRoot(compiledRoot)
	if err != nil {
		return result, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return result, err
	}
	defer root.Close()
	if err := store.reconcileWindowsRootPending(root, initial); err != nil {
		return result, err
	}
	_, versions, err := replayWindowsRootHistory(root, initial)
	if err != nil {
		return result, err
	}
	authority, ok := versions[version]
	if !ok {
		return result, fmt.Errorf("trusted Windows root version %d is not in persisted history", version)
	}
	return cloneWindowsTrustedRoot(authority), nil
}

// ApplyTrustedRootUpdates verifies the complete proposed chain before any
// bytes are appended. Root history cannot advance beside an activation.
func (store *ActivationJournalStore) ApplyTrustedRootUpdates(compiledRoot releasetrust.ParsedRoot, rawUpdates [][]byte, now time.Time, clockSkew time.Duration) (result releasetrust.RootChainResult, returnErr error) {
	if store == nil {
		return result, errors.New("Windows installer store is required")
	}
	initial, err := canonicalWindowsRoot(compiledRoot)
	if err != nil {
		return result, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return result, err
	}
	defer root.Close()
	if err := rejectWindowsRootAdvanceDuringActivation(root); err != nil {
		return result, err
	}
	return store.applyWindowsRootUpdatesLocked(root, initial, rawUpdates, now, clockSkew)
}

func (store *ActivationJournalStore) applyWindowsRootUpdatesLocked(root *os.Root, initial releasetrust.ParsedRoot, rawUpdates [][]byte, now time.Time, clockSkew time.Duration) (result releasetrust.RootChainResult, returnErr error) {
	if err := store.reconcileWindowsRootPending(root, initial); err != nil {
		return result, err
	}
	current, _, err := replayWindowsRootHistory(root, initial)
	if err != nil {
		return result, err
	}
	result, err = releasetrust.EvaluateRootChain(current, rawUpdates, now, clockSkew)
	if err != nil {
		return result, err
	}
	for _, applied := range result.Applied {
		version := applied.Transition.Root.Document.Version
		if err := store.publishWindowsRootUpdate(root, version, applied.Raw); err != nil {
			return result, fmt.Errorf("persist Windows trusted-root version %d: %w", version, err)
		}
		persisted, _, err := replayWindowsRootHistory(root, initial)
		if err != nil {
			return result, err
		}
		if !sameWindowsTrustedRoot(persisted, applied.Transition.Root) {
			return result, fmt.Errorf("persisted Windows trusted-root version %d differs after replay", version)
		}
	}
	persisted, _, err := replayWindowsRootHistory(root, initial)
	if err != nil {
		return result, err
	}
	if !sameWindowsTrustedRoot(persisted, result.Root) {
		return result, errors.New("final Windows trusted-root history differs from the verified chain")
	}
	return cloneWindowsRootChainResult(result), nil
}

func rejectWindowsRootAdvanceDuringActivation(root *os.Root) error {
	if err := rejectWindowsMutationDuringRuntimeUninstallLocked(root); err != nil {
		return err
	}
	live, err := readWindowsActivationJournal(root, windowsActivationJournalName)
	if err != nil {
		return err
	}
	pending, err := readWindowsActivationJournal(root, windowsActivationJournalPendingName)
	if err != nil {
		return err
	}
	if live != nil || pending != nil {
		return errors.New("Windows trusted-root history cannot advance during an active installer transaction")
	}
	intake, err := readWindowsIntakeRecord(root, windowsAcceptedIntakeName)
	if err != nil {
		return err
	}
	intakePending, err := readWindowsIntakeRecord(root, windowsAcceptedIntakePendingName)
	if err != nil {
		return err
	}
	if intake != nil || intakePending != nil {
		return errors.New("Windows trusted-root history cannot advance while an accepted intake is active")
	}
	return nil
}

func replayWindowsRootHistory(root *os.Root, initial releasetrust.ParsedRoot) (releasetrust.ParsedRoot, map[uint64]releasetrust.ParsedRoot, error) {
	live, pending, err := listWindowsRootHistory(root)
	if err != nil {
		return releasetrust.ParsedRoot{}, nil, err
	}
	if len(pending) != 0 {
		return releasetrust.ParsedRoot{}, nil, errors.New("pending Windows trusted-root publication was not reconciled")
	}
	return replayWindowsRootNames(root, initial, live)
}

func replayWindowsRootNames(root *os.Root, initial releasetrust.ParsedRoot, names []string) (releasetrust.ParsedRoot, map[uint64]releasetrust.ParsedRoot, error) {
	current := cloneWindowsTrustedRoot(initial)
	versions := map[uint64]releasetrust.ParsedRoot{current.Document.Version: current}
	for _, name := range names {
		version, err := windowsRootHistoryVersion(name)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, err
		}
		if current.Document.Version == ^uint64(0) || version != current.Document.Version+1 {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("Windows trusted-root history gap: version %d does not follow %d", version, current.Document.Version)
		}
		snapshot, err := readWindowsRootUpdate(root, name)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, err
		}
		update, err := releasetrust.ParseRootUpdate(snapshot.raw)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("parse Windows trusted-root history %q: %w", name, err)
		}
		candidate, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil || candidate.Document.Version != version {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("Windows trusted-root history %q manifest version differs from its filename", name)
		}
		transition, err := releasetrust.VerifyRootTransition(current, update.RootManifest, update.Signatures)
		if err != nil {
			return releasetrust.ParsedRoot{}, nil, fmt.Errorf("verify Windows trusted-root history %q: %w", name, err)
		}
		current = transition.Root
		versions[version] = current
	}
	return cloneWindowsTrustedRoot(current), versions, nil
}

func (store *ActivationJournalStore) reconcileWindowsRootPending(root *os.Root, initial releasetrust.ParsedRoot) error {
	live, pending, err := listWindowsRootHistory(root)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	if len(pending) != 1 {
		return errors.New("multiple pending Windows trusted-root publications exist")
	}
	current, _, err := replayWindowsRootNames(root, initial, live)
	if err != nil {
		return err
	}
	name := pending[0]
	version, err := windowsRootPendingVersion(name)
	if err != nil {
		return err
	}
	if current.Document.Version == ^uint64(0) || version != current.Document.Version+1 {
		return fmt.Errorf("pending Windows trusted-root version %d does not follow %d", version, current.Document.Version)
	}
	snapshot, err := readWindowsRootUpdate(root, name)
	if err != nil {
		return err
	}
	update, err := releasetrust.ParseRootUpdate(snapshot.raw)
	if err != nil {
		return fmt.Errorf("parse pending Windows trusted-root version %d: %w", version, err)
	}
	candidate, err := releasetrust.ParseRoot(update.RootManifest)
	if err != nil || candidate.Document.Version != version {
		return fmt.Errorf("pending Windows trusted-root version %d differs from its filename", version)
	}
	transition, err := releasetrust.VerifyRootTransition(current, update.RootManifest, update.Signatures)
	if err != nil {
		return fmt.Errorf("verify pending Windows trusted-root version %d: %w", version, err)
	}
	liveAgain, pendingAgain, err := listWindowsRootHistory(root)
	if err != nil {
		return err
	}
	stable, err := readWindowsRootUpdate(root, name)
	if err != nil {
		return err
	}
	if !equalWindowsRootNames(live, liveAgain) || !equalWindowsRootNames(pending, pendingAgain) || !sameWindowsRootHistorySnapshot(snapshot, stable) {
		return errors.New("Windows trusted-root history changed while reconciling pending bytes")
	}
	if err := moveWindowsRootUpdateNoReplace(store.directory, name, windowsRootHistoryName(version)); err != nil {
		return err
	}
	replayed, _, err := replayWindowsRootHistory(root, initial)
	if err != nil {
		return err
	}
	if !sameWindowsTrustedRoot(replayed, transition.Root) {
		return errors.New("recovered Windows trusted-root publication differs after replay")
	}
	return nil
}

func (store *ActivationJournalStore) publishWindowsRootUpdate(root *os.Root, version uint64, raw []byte) error {
	name := windowsRootHistoryName(version)
	if existing, err := readWindowsRootUpdateOptional(root, name); err != nil {
		return err
	} else if existing.found {
		if bytes.Equal(existing.raw, raw) {
			return nil
		}
		return fmt.Errorf("Windows trusted-root equivocation at version %d", version)
	}
	pendingName := windowsRootPendingName(version)
	if pending, err := readWindowsRootUpdateOptional(root, pendingName); err != nil {
		return err
	} else if pending.found {
		return errors.New("pending Windows trusted-root publication was not reconciled before commit")
	}
	file, err := root.OpenFile(pendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		file.Close()
		return err
	}
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(raw) || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr, fmt.Errorf("wrote %d of %d Windows trusted-root bytes", written, len(raw)))
	}
	readback, err := readWindowsRootUpdate(root, pendingName)
	if err != nil || !bytes.Equal(readback.raw, raw) {
		return errors.Join(err, errors.New("pending Windows trusted-root bytes differ after write and sync"))
	}
	if err := moveWindowsRootUpdateNoReplace(store.directory, pendingName, name); err != nil {
		return err
	}
	committed, err := readWindowsRootUpdate(root, name)
	if err != nil || !bytes.Equal(committed.raw, raw) {
		return errors.Join(err, errors.New("published Windows trusted-root bytes differ after write-through rename"))
	}
	return nil
}

func moveWindowsRootUpdateNoReplace(directory, fromName, toName string) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(directory, fromName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(directory, toName))
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("publish Windows trusted-root update without replacement: %w", err)
	}
	return nil
}

func listWindowsRootHistory(root *os.Root) (live, pending []string, returnErr error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > maxWindowsPersistedRootUpdates+16 {
		return nil, nil, fmt.Errorf("Windows installer state entry count exceeds %d", maxWindowsPersistedRootUpdates+16)
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case windowsRootHistoryNamePattern.MatchString(name):
			live = append(live, name)
		case windowsRootPendingNamePattern.MatchString(name):
			pending = append(pending, name)
		case isWindowsRootHistoryNamespace(name):
			return nil, nil, fmt.Errorf("unknown Windows trusted-root history entry %q", name)
		}
	}
	if len(live) > maxWindowsPersistedRootUpdates {
		return nil, nil, fmt.Errorf("Windows trusted-root history count exceeds %d", maxWindowsPersistedRootUpdates)
	}
	sort.Strings(live)
	sort.Strings(pending)
	return live, pending, nil
}

func readWindowsRootUpdate(root *os.Root, name string) (windowsRootHistorySnapshot, error) {
	result, err := readWindowsRootUpdateOptional(root, name)
	if err != nil {
		return result, err
	}
	if !result.found {
		return result, os.ErrNotExist
	}
	return result, nil
}

func readWindowsRootUpdateOptional(root *os.Root, name string) (windowsRootHistorySnapshot, error) {
	var result windowsRootHistorySnapshot
	if !windowsRootHistoryNamePattern.MatchString(name) && !windowsRootPendingNamePattern.MatchString(name) {
		return result, fmt.Errorf("Windows trusted-root filename %q is outside its reserved namespace", name)
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > releasetrust.MaxRootUpdateSize {
		return result, errors.Join(err, fmt.Errorf("Windows trusted-root file %q is not one bounded real regular file", name))
	}
	file, err := root.Open(name)
	if err != nil {
		return result, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		return result, fmt.Errorf("Windows trusted-root file %q changed while opening", name)
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return result, fmt.Errorf("authenticate Windows trusted-root file %q: %w", name, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, releasetrust.MaxRootUpdateSize+1))
	if err != nil || len(raw) == 0 || len(raw) > releasetrust.MaxRootUpdateSize {
		return result, errors.Join(err, fmt.Errorf("Windows trusted-root update must be between 1 and %d bytes", releasetrust.MaxRootUpdateSize))
	}
	after, statErr := file.Stat()
	visible, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !sameStableWindowsFile(opened, after) || !sameStableWindowsFile(opened, visible) {
		return result, errors.New("Windows trusted-root file changed while reading")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return result, err
	}
	return windowsRootHistorySnapshot{found: true, raw: raw, info: opened}, nil
}

func sameWindowsRootHistorySnapshot(left, right windowsRootHistorySnapshot) bool {
	if left.found != right.found {
		return false
	}
	return !left.found || left.info != nil && right.info != nil && sameStableWindowsFile(left.info, right.info) && bytes.Equal(left.raw, right.raw)
}

func equalWindowsRootNames(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func sameWindowsTrustedRoot(left, right releasetrust.ParsedRoot) bool {
	return left.Document.Version == right.Document.Version && left.SHA256 != "" && left.SHA256 == right.SHA256
}

func cloneWindowsTrustedRoot(source releasetrust.ParsedRoot) releasetrust.ParsedRoot {
	result, err := canonicalWindowsRoot(source)
	if err != nil {
		return releasetrust.ParsedRoot{}
	}
	return result
}

func cloneWindowsRootChainResult(source releasetrust.RootChainResult) releasetrust.RootChainResult {
	result := releasetrust.RootChainResult{Root: cloneWindowsTrustedRoot(source.Root), Applied: make([]releasetrust.AppliedRootUpdate, len(source.Applied))}
	for index, applied := range source.Applied {
		result.Applied[index] = releasetrust.AppliedRootUpdate{
			Raw: append([]byte(nil), applied.Raw...),
			Transition: releasetrust.VerifiedRootTransition{
				Root:                 cloneWindowsTrustedRoot(applied.Transition.Root),
				PreviousSignerKeyIDs: append([]string(nil), applied.Transition.PreviousSignerKeyIDs...),
				NewSignerKeyIDs:      append([]string(nil), applied.Transition.NewSignerKeyIDs...),
			},
		}
	}
	return result
}
