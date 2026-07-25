//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

const (
	windowsRuntimeUninstallJournalName        = "runtime-uninstall.json"
	windowsRuntimeUninstallJournalPendingName = ".runtime-uninstall.json.new"
)

type lockedWindowsRuntimeUninstallJournalWriter struct {
	root      *os.Root
	directory string
}

func (writer *lockedWindowsRuntimeUninstallJournalWriter) AdvanceRuntimeUninstall(current *WindowsRuntimeUninstallJournal, next WindowsRuntimeUninstallJournal) error {
	if writer == nil {
		return errors.New("locked Windows runtime-uninstall journal writer is required")
	}
	return advanceWindowsRuntimeUninstallJournalLocked(writer.root, writer.directory, current, next)
}

func (store *ActivationJournalStore) CreateRuntimeUninstall(journal WindowsRuntimeUninstallJournal) error {
	return store.AdvanceRuntimeUninstall(nil, journal)
}

func (store *ActivationJournalStore) AdvanceRuntimeUninstall(current *WindowsRuntimeUninstallJournal, next WindowsRuntimeUninstallJournal) (returnErr error) {
	if store == nil {
		return errors.New("Windows installer store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err := rejectWindowsRuntimeUninstallOverlapLocked(root); err != nil {
		return err
	}
	return advanceWindowsRuntimeUninstallJournalLocked(root, store.directory, current, next)
}

func advanceWindowsRuntimeUninstallJournalLocked(root *os.Root, directory string, current *WindowsRuntimeUninstallJournal, next WindowsRuntimeUninstallJournal) error {
	if root == nil {
		return errors.New("Windows runtime-uninstall journal root is required")
	}
	if err := validateWindowsRuntimeUninstallTransition(current, next); err != nil {
		return err
	}
	live, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalName)
	if err != nil {
		return err
	}
	pending, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalPendingName)
	if err != nil {
		return err
	}
	if pending != nil {
		if !reflect.DeepEqual(*pending, next) {
			return errors.New("Windows runtime-uninstall pending journal differs from the requested transition")
		}
		if reflect.DeepEqual(live, &next) {
			if err := root.Remove(windowsRuntimeUninstallJournalPendingName); err != nil {
				return err
			}
			return proveWindowsRuntimeUninstallJournal(root, &next)
		}
		if !reflect.DeepEqual(live, current) {
			return errors.New("Windows runtime-uninstall live journal differs from the pending transition source")
		}
		if err := publishWindowsRuntimeUninstallPending(directory, current != nil); err != nil {
			return err
		}
		return proveWindowsRuntimeUninstallJournal(root, &next)
	}
	if !reflect.DeepEqual(live, current) {
		return errors.New("Windows runtime-uninstall live journal differs from the requested transition source")
	}
	if err := writeWindowsRuntimeUninstallPending(root, next); err != nil {
		return err
	}
	pending, err = readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalPendingName)
	if err != nil || pending == nil || !reflect.DeepEqual(*pending, next) {
		return errors.Join(err, errors.New("Windows runtime-uninstall pending journal was not proven after creation"))
	}
	live, err = readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalName)
	if err != nil || !reflect.DeepEqual(live, current) {
		return errors.Join(err, errors.New("Windows runtime-uninstall live journal changed before publication"))
	}
	if err := publishWindowsRuntimeUninstallPending(directory, current != nil); err != nil {
		return err
	}
	return proveWindowsRuntimeUninstallJournal(root, &next)
}

// LoadRuntimeUninstall completes only a canonical adjacent pending phase.
func (store *ActivationJournalStore) LoadRuntimeUninstall() (result *WindowsRuntimeUninstallJournal, returnErr error) {
	if store == nil {
		return nil, errors.New("Windows installer store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return recoverWindowsRuntimeUninstallJournalLocked(root, store.directory)
}

func recoverWindowsRuntimeUninstallJournalLocked(root *os.Root, directory string) (*WindowsRuntimeUninstallJournal, error) {
	live, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalName)
	if err != nil {
		return nil, err
	}
	pending, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalPendingName)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return cloneWindowsRuntimeUninstallJournalPointer(live), nil
	}
	if err := validateWindowsRuntimeUninstallTransition(live, *pending); err != nil {
		return nil, fmt.Errorf("recover Windows runtime-uninstall pending journal: %w", err)
	}
	if err := publishWindowsRuntimeUninstallPending(directory, live != nil); err != nil {
		return nil, err
	}
	if err := proveWindowsRuntimeUninstallJournal(root, pending); err != nil {
		return nil, err
	}
	return cloneWindowsRuntimeUninstallJournalPointer(pending), nil
}

func writeWindowsRuntimeUninstallPending(root *os.Root, journal WindowsRuntimeUninstallJournal) error {
	raw, err := MarshalWindowsRuntimeUninstallJournal(journal)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(windowsRuntimeUninstallJournalPendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
			shortWriteErr = fmt.Errorf("wrote %d of %d Windows runtime-uninstall journal bytes", written, len(raw))
		}
		return errors.Join(writeErr, syncErr, closeErr, shortWriteErr)
	}
	return nil
}

func publishWindowsRuntimeUninstallPending(directory string, replace bool) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsRuntimeUninstallJournalPendingName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsRuntimeUninstallJournalName))
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return fmt.Errorf("publish Windows runtime-uninstall journal: %w", err)
	}
	return nil
}

func proveWindowsRuntimeUninstallJournal(root *os.Root, expected *WindowsRuntimeUninstallJournal) error {
	live, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalName)
	if err != nil {
		return err
	}
	pending, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalPendingName)
	if err != nil {
		return err
	}
	if pending != nil || !reflect.DeepEqual(live, expected) {
		return errors.New("Windows runtime-uninstall journal publication is not exact")
	}
	return nil
}

func readWindowsRuntimeUninstallJournal(root *os.Root, name string) (*WindowsRuntimeUninstallJournal, error) {
	if name != windowsRuntimeUninstallJournalName && name != windowsRuntimeUninstallJournalPendingName {
		return nil, errors.New("Windows runtime-uninstall journal filename is unmanaged")
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maximumWindowsRuntimeUninstallJournalBytes {
		return nil, errors.Join(err, errors.New("Windows runtime-uninstall journal is not a bounded real regular file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		return nil, errors.New("Windows runtime-uninstall journal changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumWindowsRuntimeUninstallJournalBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.Join(err, errors.New("Windows runtime-uninstall journal changed while reading"))
	}
	after, err := root.Lstat(name)
	if err != nil || !sameStableWindowsFile(opened, after) {
		return nil, errors.New("Windows runtime-uninstall journal changed during readback")
	}
	journal, err := ParseWindowsRuntimeUninstallJournal(raw)
	if err != nil {
		return nil, err
	}
	return &journal, nil
}

func rejectWindowsRuntimeUninstallOverlapLocked(root *os.Root) error {
	activation, err := readWindowsActivationJournal(root, windowsActivationJournalName)
	if err != nil {
		return err
	}
	activationPending, err := readWindowsActivationJournal(root, windowsActivationJournalPendingName)
	if err != nil {
		return err
	}
	if activation != nil || activationPending != nil {
		return errors.New("Windows runtime uninstall cannot overlap an activation transaction")
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
		return errors.New("Windows runtime uninstall cannot overlap an accepted release intake")
	}
	return nil
}

func rejectWindowsMutationDuringRuntimeUninstallLocked(root *os.Root) error {
	live, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalName)
	if err != nil {
		return err
	}
	pending, err := readWindowsRuntimeUninstallJournal(root, windowsRuntimeUninstallJournalPendingName)
	if err != nil {
		return err
	}
	if live != nil || pending != nil {
		return errors.New("Windows installer mutation cannot overlap a runtime-uninstall transaction")
	}
	return nil
}

func cloneWindowsRuntimeUninstallJournalPointer(value *WindowsRuntimeUninstallJournal) *WindowsRuntimeUninstallJournal {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Source = cloneWindowsInstallState(value.Source)
	return &copy
}
