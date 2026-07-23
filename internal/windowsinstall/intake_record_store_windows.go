//go:build windows

package windowsinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"mesh/internal/onlinerelease"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

const (
	windowsAcceptedIntakeName        = "accepted-intake.json"
	windowsAcceptedIntakePendingName = ".accepted-intake.json.new"
)

func (store *ActivationJournalStore) persistWindowsAcceptedIntakeLocked(root *os.Root, bundle onlinerelease.Bundle, intake VerifiedWindowsIntake) error {
	record, err := NewWindowsIntakeRecord(bundle, intake)
	if err != nil {
		return err
	}
	existing, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil {
		return err
	}
	if existing != nil {
		if reflect.DeepEqual(*existing, record) {
			return nil
		}
		return errors.New("a different Windows accepted intake is already active")
	}
	raw, err := MarshalWindowsIntakeRecord(record)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(windowsAcceptedIntakePendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
		return errors.Join(writeErr, syncErr, closeErr, fmt.Errorf("wrote %d of %d Windows accepted-intake bytes", written, len(raw)))
	}
	pending, err := readWindowsIntakeRecord(root, windowsAcceptedIntakePendingName)
	if err != nil || pending == nil || !reflect.DeepEqual(*pending, record) {
		return errors.Join(err, errors.New("Windows accepted-intake pending file differs after sync"))
	}
	if err := moveWindowsIntakeNoReplace(store.directory); err != nil {
		return err
	}
	committed, err := readWindowsIntakeRecord(root, windowsAcceptedIntakeName)
	if err != nil || committed == nil || !reflect.DeepEqual(*committed, record) {
		return errors.Join(err, errors.New("Windows accepted intake differs after publication"))
	}
	return nil
}

func (store *ActivationJournalStore) recoverWindowsAcceptedIntakeLocked(root *os.Root) (*WindowsIntakeRecord, error) {
	live, err := readWindowsIntakeRecord(root, windowsAcceptedIntakeName)
	if err != nil {
		return nil, err
	}
	pending, err := readWindowsIntakeRecord(root, windowsAcceptedIntakePendingName)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return live, nil
	}
	if live != nil {
		if !reflect.DeepEqual(*live, *pending) {
			return nil, errors.New("Windows live and pending accepted intake disagree")
		}
		if err := root.Remove(windowsAcceptedIntakePendingName); err != nil {
			return nil, err
		}
		return live, nil
	}
	if err := moveWindowsIntakeNoReplace(store.directory); err != nil {
		return nil, err
	}
	live, err = readWindowsIntakeRecord(root, windowsAcceptedIntakeName)
	if err != nil || live == nil || !reflect.DeepEqual(*live, *pending) {
		return nil, errors.Join(err, errors.New("recovered Windows accepted intake differs after publication"))
	}
	return live, nil
}

func moveWindowsIntakeNoReplace(directory string) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsAcceptedIntakePendingName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(directory, windowsAcceptedIntakeName))
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("publish Windows accepted intake without replacement: %w", err)
	}
	return nil
}

func readWindowsIntakeRecord(root *os.Root, name string) (*WindowsIntakeRecord, error) {
	if name != windowsAcceptedIntakeName && name != windowsAcceptedIntakePendingName {
		return nil, errors.New("Windows accepted-intake filename is unmanaged")
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maximumWindowsIntakeBytes {
		return nil, errors.Join(err, errors.New("Windows accepted intake is not a bounded real regular file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		return nil, errors.New("Windows accepted intake changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumWindowsIntakeBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.Join(err, errors.New("Windows accepted intake changed while reading"))
	}
	after, statErr := file.Stat()
	visible, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !sameStableWindowsFile(opened, after) || !sameStableWindowsFile(opened, visible) {
		return nil, errors.New("Windows accepted intake changed during readback")
	}
	record, err := ParseWindowsIntakeRecord(raw)
	if err != nil {
		return nil, err
	}
	canonical, _ := MarshalWindowsIntakeRecord(record)
	if !bytes.Equal(raw, canonical) {
		return nil, errors.New("Windows accepted intake changed from canonical bytes")
	}
	return &record, nil
}
