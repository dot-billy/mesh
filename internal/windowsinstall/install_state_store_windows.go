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
	windowsInstallStateName        = "install-state.json"
	windowsInstallStatePendingName = ".install-state.json.new"
)

func commitWindowsInstallStateLocked(root *os.Root, directory string, current *WindowsInstallState, next WindowsInstallState) error {
	if err := validateWindowsInstallStateTransition(current, next); err != nil {
		return err
	}
	live, err := readWindowsInstallState(root, windowsInstallStateName)
	if err != nil {
		return err
	}
	pending, err := readWindowsInstallState(root, windowsInstallStatePendingName)
	if err != nil {
		return err
	}
	if pending != nil {
		if !reflect.DeepEqual(*pending, next) {
			return errors.New("Windows pending install state differs from the requested transition")
		}
		if reflect.DeepEqual(live, &next) {
			if err := root.Remove(windowsInstallStatePendingName); err != nil {
				return err
			}
			return proveWindowsInstallState(root, &next)
		}
		if !reflect.DeepEqual(live, current) {
			return errors.New("Windows live install state differs from the pending transition source")
		}
		if err := publishWindowsInstallStatePending(directory, current != nil); err != nil {
			return err
		}
		return proveWindowsInstallState(root, &next)
	}
	if !reflect.DeepEqual(live, current) {
		return errors.New("Windows live install state differs from the requested transition source")
	}
	if err := writeWindowsInstallStatePending(root, next); err != nil {
		return err
	}
	pending, err = readWindowsInstallState(root, windowsInstallStatePendingName)
	if err != nil || pending == nil || !reflect.DeepEqual(*pending, next) {
		return errors.Join(err, errors.New("Windows pending install state was not proven after creation"))
	}
	live, err = readWindowsInstallState(root, windowsInstallStateName)
	if err != nil || !reflect.DeepEqual(live, current) {
		return errors.Join(err, errors.New("Windows live install state changed before publication"))
	}
	if err := publishWindowsInstallStatePending(directory, current != nil); err != nil {
		return err
	}
	return proveWindowsInstallState(root, &next)
}

// LoadInstallState completes only a canonical next transition from the exact
// live source. It never chooses between unrelated pending authority.
func (store *ActivationJournalStore) LoadInstallState() (result *WindowsInstallState, returnErr error) {
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
	return recoverWindowsInstallStateLocked(root, store.directory)
}

func recoverWindowsInstallStateLocked(root *os.Root, directory string) (*WindowsInstallState, error) {
	live, err := readWindowsInstallState(root, windowsInstallStateName)
	if err != nil {
		return nil, err
	}
	pending, err := readWindowsInstallState(root, windowsInstallStatePendingName)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return cloneWindowsInstallStatePointer(live), nil
	}
	if err := validateWindowsInstallStateTransition(live, *pending); err != nil {
		return nil, fmt.Errorf("recover Windows pending install state: %w", err)
	}
	if err := publishWindowsInstallStatePending(directory, live != nil); err != nil {
		return nil, err
	}
	if err := proveWindowsInstallState(root, pending); err != nil {
		return nil, err
	}
	return cloneWindowsInstallStatePointer(pending), nil
}

func writeWindowsInstallStatePending(root *os.Root, state WindowsInstallState) error {
	raw, err := MarshalWindowsInstallState(state)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(windowsInstallStatePendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
		return errors.Join(writeErr, syncErr, closeErr, fmt.Errorf("wrote %d of %d Windows install-state bytes", written, len(raw)))
	}
	return nil
}

func publishWindowsInstallStatePending(directory string, replace bool) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsInstallStatePendingName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsInstallStateName))
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return fmt.Errorf("publish Windows install state: %w", err)
	}
	return nil
}

func proveWindowsInstallState(root *os.Root, expected *WindowsInstallState) error {
	live, err := readWindowsInstallState(root, windowsInstallStateName)
	if err != nil {
		return err
	}
	pending, err := readWindowsInstallState(root, windowsInstallStatePendingName)
	if err != nil {
		return err
	}
	if pending != nil || !reflect.DeepEqual(live, expected) {
		return errors.New("Windows install-state publication is not exact")
	}
	return nil
}

func readWindowsInstallState(root *os.Root, name string) (*WindowsInstallState, error) {
	if name != windowsInstallStateName && name != windowsInstallStatePendingName {
		return nil, errors.New("Windows install-state filename is unmanaged")
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maximumWindowsInstallStateBytes {
		return nil, errors.Join(err, errors.New("Windows install state is not a bounded real regular file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		return nil, errors.New("Windows install state changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumWindowsInstallStateBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.Join(err, errors.New("Windows install state changed while reading"))
	}
	after, statErr := file.Stat()
	visible, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !sameStableWindowsFile(opened, after) || !sameStableWindowsFile(opened, visible) {
		return nil, errors.New("Windows install state changed during readback")
	}
	state, err := ParseWindowsInstallState(raw)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func cloneWindowsInstallStatePointer(value *WindowsInstallState) *WindowsInstallState {
	if value == nil {
		return nil
	}
	copy := cloneWindowsInstallState(*value)
	return &copy
}
