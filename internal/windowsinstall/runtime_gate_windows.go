//go:build windows

package windowsinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

const (
	windowsRuntimeGateName         = "runtime.enabled"
	windowsRuntimeGateRecoveryName = ".runtime.enabled.new"
)

var windowsRuntimeGateContent = []byte("enabled\n")

type RuntimeGate struct {
	directory string
	mu        sync.Mutex
}

func NewRuntimeGate(directory string) (*RuntimeGate, error) {
	if !cleanWindowsAbsolutePath(directory) {
		return nil, errors.New("Windows runtime-gate directory must be a clean absolute non-root path")
	}
	return &RuntimeGate{directory: directory}, nil
}

func NewProductionRuntimeGate() (*RuntimeGate, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("resolve Windows ProgramData: %w", err)
	}
	return NewRuntimeGate(filepath.Join(programData, "Mesh", "installer"))
}

func EnsureProductionRuntimeGateDirectory() error {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return fmt.Errorf("resolve Windows ProgramData: %w", err)
	}
	meshDirectory := filepath.Join(programData, "Mesh")
	if err := ensureProtectedDirectory(meshDirectory, windowssecurity.LocalSystemSID); err != nil {
		return err
	}
	return ensureProtectedDirectory(filepath.Join(meshDirectory, "installer"), windowssecurity.LocalSystemSID)
}

func (gate *RuntimeGate) Inspect() (bool, error) {
	if gate == nil {
		return false, errors.New("Windows runtime gate is required")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	operations, err := openWindowsRuntimeGateOperations(gate.directory)
	if err != nil {
		return false, err
	}
	defer operations.Close()
	return inspectWindowsRuntimeGate(operations)
}

func (gate *RuntimeGate) Open() error {
	if gate == nil {
		return errors.New("Windows runtime gate is required")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	operations, err := openWindowsRuntimeGateOperations(gate.directory)
	if err != nil {
		return err
	}
	defer operations.Close()
	return openWindowsRuntimeGate(operations)
}

func (gate *RuntimeGate) Close() error {
	if gate == nil {
		return errors.New("Windows runtime gate is required")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	operations, err := openWindowsRuntimeGateOperations(gate.directory)
	if err != nil {
		return err
	}
	defer operations.Close()
	return closeWindowsRuntimeGate(operations)
}

type filesystemWindowsRuntimeGateOperations struct {
	directory string
	root      *os.Root
}

func openWindowsRuntimeGateOperations(directory string) (*filesystemWindowsRuntimeGateOperations, error) {
	root, info, err := openNoReparseRoot(directory)
	if err != nil {
		return nil, err
	}
	if err := inspectRootDirectory(root, info, windowssecurity.LocalSystemSID); err != nil {
		root.Close()
		return nil, fmt.Errorf("authenticate Windows runtime-gate directory: %w", err)
	}
	return &filesystemWindowsRuntimeGateOperations{directory: directory, root: root}, nil
}

func (operations *filesystemWindowsRuntimeGateOperations) Close() error {
	if operations == nil || operations.root == nil {
		return nil
	}
	err := operations.root.Close()
	operations.root = nil
	return err
}

func (operations *filesystemWindowsRuntimeGateOperations) InspectLive() (windowsRuntimeGateFileState, error) {
	return operations.inspectFile(windowsRuntimeGateName, false)
}
func (operations *filesystemWindowsRuntimeGateOperations) InspectPending() (windowsRuntimeGateFileState, error) {
	return operations.inspectFile(windowsRuntimeGateRecoveryName, true)
}

func (operations *filesystemWindowsRuntimeGateOperations) inspectFile(name string, allowPrefix bool) (windowsRuntimeGateFileState, error) {
	before, err := operations.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return windowsRuntimeGateAbsent, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > int64(len(windowsRuntimeGateContent)) || (!allowPrefix && before.Size() != int64(len(windowsRuntimeGateContent))) {
		return windowsRuntimeGateAbsent, fmt.Errorf("Windows runtime-gate file %q is not an exact bounded regular file", name)
	}
	file, err := operations.root.Open(name)
	if err != nil {
		return windowsRuntimeGateAbsent, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return windowsRuntimeGateAbsent, fmt.Errorf("Windows runtime-gate file %q changed while opening", name)
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return windowsRuntimeGateAbsent, fmt.Errorf("authenticate Windows runtime-gate file %q: %w", name, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(windowsRuntimeGateContent))+1))
	if err != nil {
		return windowsRuntimeGateAbsent, err
	}
	after, err := operations.root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		return windowsRuntimeGateAbsent, fmt.Errorf("Windows runtime-gate file %q changed during readback", name)
	}
	if bytes.Equal(raw, windowsRuntimeGateContent) {
		return windowsRuntimeGateComplete, nil
	}
	if allowPrefix && bytes.HasPrefix(windowsRuntimeGateContent, raw) {
		return windowsRuntimeGateIncomplete, nil
	}
	return windowsRuntimeGateAbsent, fmt.Errorf("Windows runtime-gate file %q has unexpected content", name)
}

func (operations *filesystemWindowsRuntimeGateOperations) CreatePending() error {
	file, err := operations.root.OpenFile(windowsRuntimeGateRecoveryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		file.Close()
		return err
	}
	written, writeErr := file.Write(windowsRuntimeGateContent)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(windowsRuntimeGateContent) || syncErr != nil || closeErr != nil {
		var shortWriteErr error
		if written != len(windowsRuntimeGateContent) {
			shortWriteErr = fmt.Errorf("wrote %d of %d Windows runtime-gate bytes", written, len(windowsRuntimeGateContent))
		}
		return errors.Join(writeErr, syncErr, closeErr, shortWriteErr)
	}
	return nil
}

func (operations *filesystemWindowsRuntimeGateOperations) SyncPending() error {
	file, err := operations.root.OpenFile(windowsRuntimeGateRecoveryName, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return err
	}
	return file.Sync()
}

func (operations *filesystemWindowsRuntimeGateOperations) RemoveLive() error {
	return operations.root.Remove(windowsRuntimeGateName)
}
func (operations *filesystemWindowsRuntimeGateOperations) RemovePending() error {
	return operations.root.Remove(windowsRuntimeGateRecoveryName)
}

func (operations *filesystemWindowsRuntimeGateOperations) PublishPendingNoReplace() error {
	live, err := operations.InspectLive()
	if err != nil || live != windowsRuntimeGateAbsent {
		return errors.Join(err, errors.New("Windows runtime gate already exists"))
	}
	pending, err := operations.InspectPending()
	if err != nil || pending != windowsRuntimeGateComplete {
		return errors.Join(err, errors.New("Windows runtime-gate recovery file is not publishable"))
	}
	from, err := windows.UTF16PtrFromString(filepath.Join(operations.directory, windowsRuntimeGateRecoveryName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(operations.directory, windowsRuntimeGateName))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

// Windows exposes FlushFileBuffers for files but no standard directory-fsync
// primitive. Publication itself uses MOVEFILE_WRITE_THROUGH; this explicit
// boundary intentionally does not claim a stronger metadata guarantee.
func (operations *filesystemWindowsRuntimeGateOperations) SyncDirectory() error { return nil }
