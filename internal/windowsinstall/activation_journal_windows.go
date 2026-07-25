//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

const (
	windowsActivationJournalName        = "activation.json"
	windowsActivationJournalPendingName = ".activation.json.new"
)

// ActivationJournalStore publishes exact protected journal transitions in the
// installer-private ProgramData directory. A complete pending transition is
// recoverable after process or machine interruption.
type ActivationJournalStore struct {
	directory string
	mu        sync.Mutex
}

type lockedWindowsActivationJournalWriter struct {
	root      *os.Root
	directory string
}

func (writer *lockedWindowsActivationJournalWriter) Advance(current *WindowsActivationJournal, next WindowsActivationJournal) error {
	if writer == nil {
		return errors.New("locked Windows activation journal writer is required")
	}
	return advanceWindowsActivationJournalLocked(writer.root, writer.directory, current, next)
}

func NewActivationJournalStore(directory string) (*ActivationJournalStore, error) {
	if !cleanWindowsAbsolutePath(directory) {
		return nil, errors.New("Windows activation-journal directory must be a clean absolute non-root path")
	}
	return &ActivationJournalStore{directory: directory}, nil
}

func NewProductionActivationJournalStore() (*ActivationJournalStore, error) {
	gate, err := NewProductionRuntimeGate()
	if err != nil {
		return nil, err
	}
	return NewActivationJournalStore(gate.directory)
}

func (store *ActivationJournalStore) Create(journal WindowsActivationJournal) error {
	return store.Advance(nil, journal)
}

func (store *ActivationJournalStore) Advance(current *WindowsActivationJournal, next WindowsActivationJournal) (returnErr error) {
	if store == nil {
		return errors.New("Windows activation journal store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	installerLock, err := store.acquireInstallerLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, installerLock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	return advanceWindowsActivationJournalLocked(root, store.directory, current, next)
}

func advanceWindowsActivationJournalLocked(root *os.Root, directory string, current *WindowsActivationJournal, next WindowsActivationJournal) error {
	if root == nil {
		return errors.New("Windows activation journal root is required")
	}
	if err := validateWindowsActivationTransition(current, next); err != nil {
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
	if pending != nil {
		if !reflect.DeepEqual(*pending, next) {
			return errors.New("Windows activation pending journal differs from the requested transition")
		}
		if reflect.DeepEqual(live, &next) {
			if err := root.Remove(windowsActivationJournalPendingName); err != nil {
				return err
			}
			return proveWindowsActivationJournal(root, &next)
		}
		if !reflect.DeepEqual(live, current) {
			return errors.New("Windows activation live journal differs from the pending transition source")
		}
		if err := publishWindowsActivationPending(directory, current != nil); err != nil {
			return err
		}
		return proveWindowsActivationJournal(root, &next)
	}
	if !reflect.DeepEqual(live, current) {
		return errors.New("Windows activation live journal differs from the requested transition source")
	}
	if err := writeWindowsActivationPending(root, next); err != nil {
		return err
	}
	pending, err = readWindowsActivationJournal(root, windowsActivationJournalPendingName)
	if err != nil || pending == nil || !reflect.DeepEqual(*pending, next) {
		return errors.Join(err, errors.New("Windows activation pending journal was not proven after creation"))
	}
	live, err = readWindowsActivationJournal(root, windowsActivationJournalName)
	if err != nil || !reflect.DeepEqual(live, current) {
		return errors.Join(err, errors.New("Windows activation live journal changed before publication"))
	}
	if err := publishWindowsActivationPending(directory, current != nil); err != nil {
		return err
	}
	return proveWindowsActivationJournal(root, &next)
}

// Load completes only a canonical next-phase pending publication. It never
// invents a phase or selects between unrelated transaction identities.
func (store *ActivationJournalStore) Load() (result *WindowsActivationJournal, returnErr error) {
	if store == nil {
		return nil, errors.New("Windows activation journal store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	installerLock, err := store.acquireInstallerLock()
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, installerLock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return recoverWindowsActivationJournalLocked(root, store.directory)
}

func recoverWindowsActivationJournalLocked(root *os.Root, directory string) (*WindowsActivationJournal, error) {
	live, err := readWindowsActivationJournal(root, windowsActivationJournalName)
	if err != nil {
		return nil, err
	}
	pending, err := readWindowsActivationJournal(root, windowsActivationJournalPendingName)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return cloneWindowsActivationJournalPointer(live), nil
	}
	if err := validateWindowsActivationTransition(live, *pending); err != nil {
		return nil, fmt.Errorf("recover Windows activation pending journal: %w", err)
	}
	if err := publishWindowsActivationPending(directory, live != nil); err != nil {
		return nil, err
	}
	if err := proveWindowsActivationJournal(root, pending); err != nil {
		return nil, err
	}
	return cloneWindowsActivationJournalPointer(pending), nil
}

func publishWindowsActivationPending(directory string, replace bool) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsActivationJournalPendingName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsActivationJournalName))
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return fmt.Errorf("publish Windows activation journal: %w", err)
	}
	return nil
}

func (store *ActivationJournalStore) openRoot() (*os.Root, error) {
	root, info, err := openNoReparseRoot(store.directory)
	if err != nil {
		return nil, err
	}
	if err := inspectRootDirectory(root, info, windowssecurity.LocalSystemSID); err != nil {
		root.Close()
		return nil, fmt.Errorf("authenticate Windows activation-journal directory: %w", err)
	}
	return root, nil
}

func proveWindowsActivationJournal(root *os.Root, expected *WindowsActivationJournal) error {
	live, err := readWindowsActivationJournal(root, windowsActivationJournalName)
	if err != nil {
		return err
	}
	pending, err := readWindowsActivationJournal(root, windowsActivationJournalPendingName)
	if err != nil {
		return err
	}
	if pending != nil || !reflect.DeepEqual(live, expected) {
		return errors.New("Windows activation journal publication is not exact")
	}
	return nil
}

func writeWindowsActivationPending(root *os.Root, journal WindowsActivationJournal) error {
	raw, err := MarshalWindowsActivationJournal(journal)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(windowsActivationJournalPendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
		var shortWriteErr error
		if written != len(raw) {
			shortWriteErr = fmt.Errorf("wrote %d of %d Windows activation-journal bytes", written, len(raw))
		}
		return errors.Join(writeErr, syncErr, closeErr, shortWriteErr)
	}
	return nil
}

func readWindowsActivationJournal(root *os.Root, name string) (*WindowsActivationJournal, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maximumWindowsJournalBytes {
		return nil, errors.New("Windows activation journal is not a bounded real regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("Windows activation journal changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumWindowsJournalBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.Join(err, errors.New("Windows activation journal changed while reading"))
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("Windows activation journal changed during readback")
	}
	journal, err := ParseWindowsActivationJournal(raw)
	if err != nil {
		return nil, err
	}
	return &journal, nil
}

func cloneWindowsActivationJournalPointer(value *WindowsActivationJournal) *WindowsActivationJournal {
	if value == nil {
		return nil
	}
	copy := cloneWindowsActivationJournal(*value)
	return &copy
}
