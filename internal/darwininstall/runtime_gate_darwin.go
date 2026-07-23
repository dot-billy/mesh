//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	ProductionStateDirectory     = "/private/var/db/mesh-installer"
	PersistentRuntimeGatePath    = ProductionStateDirectory + "/runtime.enabled"
	runtimeGateName              = "runtime.enabled"
	runtimeGateRecoveryName      = ".runtime.enabled.new"
	darwinInstallerDirectoryMode = uint16(0o700)
	darwinRuntimeGateMode        = uint16(0o400)
)

var runtimeGateContent = []byte("mesh-runtime-enabled-v1\n")

// RuntimeGate owns the persistent installer authorization consumed by the
// launchd agent. Callers still need the installer transaction lock; the mutex
// here prevents only in-process overlap.
type RuntimeGate struct {
	directory string
	mu        sync.Mutex
}

func NewRuntimeGate(directory string) (*RuntimeGate, error) {
	if !cleanDarwinInstallPath(directory) {
		return nil, errors.New("Darwin runtime-gate directory must be an exact absolute non-root path")
	}
	return &RuntimeGate{directory: directory}, nil
}

func ProductionRuntimeGate() *RuntimeGate {
	return &RuntimeGate{directory: ProductionStateDirectory}
}

func (gate *RuntimeGate) Inspect() (open bool, returnErr error) {
	if gate == nil {
		return false, errors.New("Darwin runtime gate is required")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	operations, err := openFilesystemRuntimeGateOperations(gate.directory)
	if err != nil {
		return false, err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.Close()) }()
	return inspectRuntimeGate(operations)
}

func (gate *RuntimeGate) Open() (returnErr error) {
	if gate == nil {
		return errors.New("Darwin runtime gate is required")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	operations, err := openFilesystemRuntimeGateOperations(gate.directory)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.Close()) }()
	return openRuntimeGate(operations)
}

func (gate *RuntimeGate) Close() (returnErr error) {
	if gate == nil {
		return errors.New("Darwin runtime gate is required")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	operations, err := openFilesystemRuntimeGateOperations(gate.directory)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.Close()) }()
	return closeRuntimeGate(operations)
}

// EnsureStateDirectory creates only the final directory component and proves
// an exact root:wheel mode-0700 physical directory with native ownership,
// mount, ACL, xattr, and durability checks. A newly created object that fails
// validation is removed through its already-open parent descriptor.
func EnsureStateDirectory(path string) (returnErr error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("Darwin installer state-directory creation requires root:wheel execution")
	}
	if !cleanDarwinInstallPath(path) {
		return errors.New("Darwin installer state directory must be an exact absolute non-root path")
	}
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return errors.New("Darwin installer state directory has no final component")
	}
	if err := nodeagent.InspectDarwinSensitivePath(parentPath); err != nil {
		return fmt.Errorf("authenticate Darwin installer state parent: %w", err)
	}
	var parentVisibleBefore unix.Stat_t
	if err := unix.Lstat(parentPath, &parentVisibleBefore); err != nil {
		return fmt.Errorf("stat Darwin installer state parent before open: %w", err)
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return fmt.Errorf("open Darwin installer state parent: %w", err)
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	if parent == nil {
		_ = unix.Close(parentFD)
		return errors.New("adopt Darwin installer state parent descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, parent.Close()) }()
	var parentOpened, parentVisibleAfter unix.Stat_t
	if err := unix.Fstat(parentFD, &parentOpened); err != nil {
		return fmt.Errorf("stat opened Darwin installer state parent: %w", err)
	}
	if err := unix.Lstat(parentPath, &parentVisibleAfter); err != nil {
		return fmt.Errorf("restat Darwin installer state parent: %w", err)
	}
	if snapshotDarwinInstallStat(parentVisibleBefore) != snapshotDarwinInstallStat(parentOpened) ||
		snapshotDarwinInstallStat(parentOpened) != snapshotDarwinInstallStat(parentVisibleAfter) {
		return errors.New("Darwin installer state parent changed while anchoring")
	}
	if err := nodeagent.InspectDarwinSensitivePath(parentPath); err != nil {
		return fmt.Errorf("reauthenticate Darwin installer state parent: %w", err)
	}

	created := false
	if err := unix.Mkdirat(parentFD, name, uint32(darwinInstallerDirectoryMode)); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create Darwin installer state directory: %w", err)
	}
	cleanupCreated := func(cause error) error {
		if !created {
			return cause
		}
		removeErr := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		syncErr := parent.Sync()
		return errors.Join(cause, removeErr, syncErr)
	}

	directoryFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return cleanupCreated(fmt.Errorf("open Darwin installer state directory: %w", err))
	}
	directory := os.NewFile(uintptr(directoryFD), path)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return cleanupCreated(errors.New("adopt Darwin installer state directory descriptor"))
	}
	directoryOpen := true
	defer func() {
		if directoryOpen {
			returnErr = errors.Join(returnErr, directory.Close())
		}
	}()
	closeDirectory := func() error {
		if !directoryOpen {
			return nil
		}
		directoryOpen = false
		return directory.Close()
	}
	if created {
		if err := unix.Fchown(directoryFD, 0, 0); err != nil {
			return cleanupCreated(errors.Join(fmt.Errorf("own Darwin installer state directory: %w", err), closeDirectory()))
		}
		if err := unix.Fchmod(directoryFD, uint32(darwinInstallerDirectoryMode)); err != nil {
			return cleanupCreated(errors.Join(fmt.Errorf("secure Darwin installer state directory: %w", err), closeDirectory()))
		}
	}
	if err := authenticateDarwinInstallerDirectory(path, parentFD, name, directoryFD); err != nil {
		return cleanupCreated(errors.Join(err, closeDirectory()))
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Darwin installer state directory: %w", err)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync Darwin installer state parent: %w", err)
	}
	return authenticateDarwinInstallerDirectory(path, parentFD, name, directoryFD)
}

func EnsureProductionStateDirectory() error {
	return EnsureStateDirectory(ProductionStateDirectory)
}

type filesystemRuntimeGateOperations struct {
	directoryPath string
	directory     *os.File
	fd            int
}

func openFilesystemRuntimeGateOperations(directoryPath string) (*filesystemRuntimeGateOperations, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("Darwin runtime-gate mutation requires root:wheel execution")
	}
	if !cleanDarwinInstallPath(directoryPath) {
		return nil, errors.New("Darwin runtime-gate directory path is invalid")
	}
	if err := nodeagent.InspectDarwinSensitivePath(directoryPath); err != nil {
		return nil, err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Lstat(directoryPath, &visibleBefore); err != nil {
		return nil, err
	}
	fd, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), directoryPath)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt Darwin runtime-gate directory descriptor")
	}
	var opened, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := unix.Lstat(directoryPath, &visibleAfter); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if snapshotDarwinInstallStat(visibleBefore) != snapshotDarwinInstallStat(opened) ||
		snapshotDarwinInstallStat(opened) != snapshotDarwinInstallStat(visibleAfter) {
		_ = directory.Close()
		return nil, errors.New("Darwin runtime-gate directory changed while anchoring")
	}
	if err := validateDarwinInstallerDirectoryStat(opened); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := nodeagent.InspectDarwinSensitivePath(directoryPath); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return &filesystemRuntimeGateOperations{directoryPath: directoryPath, directory: directory, fd: fd}, nil
}

func (operations *filesystemRuntimeGateOperations) Close() error {
	if operations == nil || operations.directory == nil {
		return nil
	}
	err := operations.directory.Close()
	operations.directory = nil
	operations.fd = -1
	return err
}

func (operations *filesystemRuntimeGateOperations) InspectLive() (runtimeGateFileState, error) {
	return operations.inspectFile(runtimeGateName, false)
}

func (operations *filesystemRuntimeGateOperations) InspectPending() (runtimeGateFileState, error) {
	return operations.inspectFile(runtimeGateRecoveryName, true)
}

func (operations *filesystemRuntimeGateOperations) inspectFile(name string, allowPrefix bool) (state runtimeGateFileState, returnErr error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(operations.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return runtimeGateAbsent, nil
	} else if err != nil {
		return runtimeGateAbsent, err
	}
	if err := validateDarwinRuntimeGateStat(visibleBefore, allowPrefix); err != nil {
		return runtimeGateAbsent, fmt.Errorf("Darwin runtime-gate file %q: %w", name, err)
	}
	path := filepath.Join(operations.directoryPath, name)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return runtimeGateAbsent, err
	}
	fd, err := unix.Openat(operations.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return runtimeGateAbsent, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return runtimeGateAbsent, errors.New("adopt Darwin runtime-gate file descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return runtimeGateAbsent, err
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(len(runtimeGateContent))+1))
	if err != nil {
		return runtimeGateAbsent, err
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return runtimeGateAbsent, err
	}
	if err := unix.Fstatat(operations.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return runtimeGateAbsent, err
	}
	for _, stat := range []unix.Stat_t{visibleBefore, openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinRuntimeGateStat(stat, allowPrefix); err != nil {
			return runtimeGateAbsent, err
		}
	}
	before := snapshotDarwinInstallStat(visibleBefore)
	if before != snapshotDarwinInstallStat(openedBefore) || before != snapshotDarwinInstallStat(openedAfter) || before != snapshotDarwinInstallStat(visibleAfter) {
		return runtimeGateAbsent, fmt.Errorf("Darwin runtime-gate file %q changed while reading", name)
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return runtimeGateAbsent, err
	}
	if bytes.Equal(content, runtimeGateContent) {
		return runtimeGateComplete, nil
	}
	if allowPrefix && bytes.HasPrefix(runtimeGateContent, content) {
		return runtimeGateIncomplete, nil
	}
	return runtimeGateAbsent, fmt.Errorf("Darwin runtime-gate file %q has unexpected content", name)
}

func (operations *filesystemRuntimeGateOperations) CreatePending() error {
	fd, err := unix.Openat(operations.fd, runtimeGateRecoveryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(darwinRuntimeGateMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), runtimeGateRecoveryName)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin runtime-gate recovery descriptor")
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Fchmod(fd, uint32(darwinRuntimeGateMode)); err != nil {
		_ = file.Close()
		return err
	}
	written, writeErr := file.Write(runtimeGateContent)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(runtimeGateContent) || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr, shortWriteError(written, len(runtimeGateContent)))
	}
	return nil
}

func shortWriteError(written, expected int) error {
	if written == expected {
		return nil
	}
	return io.ErrShortWrite
}

func (operations *filesystemRuntimeGateOperations) SyncPending() error {
	state, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if state != runtimeGateComplete {
		return errors.New("Darwin runtime-gate recovery file is not complete before sync")
	}
	fd, err := unix.Openat(operations.fd, runtimeGateRecoveryName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), runtimeGateRecoveryName)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin runtime-gate recovery descriptor for sync")
	}
	path := filepath.Join(operations.directoryPath, runtimeGateRecoveryName)
	var openedBefore, openedAfter, visibleBefore, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Fstatat(operations.fd, runtimeGateRecoveryName, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = file.Close()
		return err
	}
	if err := validateStableDarwinRuntimeGatePair(runtimeGateRecoveryName, openedBefore, visibleBefore, true); err != nil {
		_ = file.Close()
		return err
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		_ = file.Close()
		return err
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(runtimeGateContent))+1))
	if readErr != nil {
		_ = file.Close()
		return readErr
	}
	if !bytes.Equal(content, runtimeGateContent) {
		_ = file.Close()
		return errors.New("Darwin runtime-gate recovery file changed before sync")
	}
	syncErr := file.Sync()
	if syncErr == nil {
		syncErr = unix.Fstat(fd, &openedAfter)
	}
	if syncErr == nil {
		syncErr = unix.Fstatat(operations.fd, runtimeGateRecoveryName, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW)
	}
	if syncErr == nil {
		syncErr = validateStableDarwinRuntimeGatePair(runtimeGateRecoveryName, openedAfter, visibleAfter, true)
	}
	if syncErr == nil && snapshotDarwinInstallStat(openedBefore) != snapshotDarwinInstallStat(openedAfter) {
		syncErr = errors.New("Darwin runtime-gate recovery file changed while syncing")
	}
	if syncErr == nil {
		syncErr = nodeagent.InspectDarwinSensitivePath(path)
	}
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
}

func (operations *filesystemRuntimeGateOperations) RemoveLive() error {
	return operations.remove(runtimeGateName, operations.InspectLive)
}

func (operations *filesystemRuntimeGateOperations) RemovePending() error {
	return operations.remove(runtimeGateRecoveryName, operations.InspectPending)
}

func (operations *filesystemRuntimeGateOperations) remove(name string, inspect func() (runtimeGateFileState, error)) error {
	state, err := inspect()
	if err != nil {
		return err
	}
	if state == runtimeGateAbsent {
		return nil
	}
	return unix.Unlinkat(operations.fd, name, 0)
}

func (operations *filesystemRuntimeGateOperations) PublishPendingNoReplace() error {
	return unix.RenameatxNp(operations.fd, runtimeGateRecoveryName, operations.fd, runtimeGateName, unix.RENAME_EXCL)
}

func (operations *filesystemRuntimeGateOperations) SyncDirectory() error {
	return operations.directory.Sync()
}

type darwinInstallStatSnapshot struct {
	device       int32
	inode        uint64
	mode         uint16
	links        uint16
	uid          uint32
	gid          uint32
	size         int64
	modifiedSec  int64
	modifiedNSec int64
	changedSec   int64
	changedNSec  int64
	flags        uint32
	generation   uint32
}

func snapshotDarwinInstallStat(stat unix.Stat_t) darwinInstallStatSnapshot {
	return darwinInstallStatSnapshot{
		device: stat.Dev, inode: stat.Ino, mode: stat.Mode, links: stat.Nlink,
		uid: stat.Uid, gid: stat.Gid, size: stat.Size,
		modifiedSec: stat.Mtim.Sec, modifiedNSec: stat.Mtim.Nsec,
		changedSec: stat.Ctim.Sec, changedNSec: stat.Ctim.Nsec,
		flags: stat.Flags, generation: stat.Gen,
	}
}

func validateDarwinInstallerDirectoryDescriptor(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	return validateDarwinInstallerDirectoryStat(stat)
}

func authenticateDarwinInstallerDirectory(path string, parentFD int, name string, directoryFD int) error {
	var visibleBefore, openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat Darwin installer state directory before authentication: %w", err)
	}
	if err := unix.Fstat(directoryFD, &openedBefore); err != nil {
		return fmt.Errorf("stat opened Darwin installer state directory: %w", err)
	}
	if err := validateDarwinInstallerDirectoryStat(visibleBefore); err != nil {
		return err
	}
	if err := validateDarwinInstallerDirectoryStat(openedBefore); err != nil {
		return err
	}
	if snapshotDarwinInstallStat(visibleBefore) != snapshotDarwinInstallStat(openedBefore) {
		return errors.New("Darwin installer state directory path does not identify its opened descriptor")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return fmt.Errorf("authenticate Darwin installer state directory: %w", err)
	}
	if err := unix.Fstat(directoryFD, &openedAfter); err != nil {
		return fmt.Errorf("restat opened Darwin installer state directory: %w", err)
	}
	if err := unix.Fstatat(parentFD, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("restat Darwin installer state directory: %w", err)
	}
	if err := validateDarwinInstallerDirectoryStat(openedAfter); err != nil {
		return err
	}
	if err := validateDarwinInstallerDirectoryStat(visibleAfter); err != nil {
		return err
	}
	before := snapshotDarwinInstallStat(visibleBefore)
	if before != snapshotDarwinInstallStat(openedAfter) || before != snapshotDarwinInstallStat(visibleAfter) {
		return errors.New("Darwin installer state directory changed while authenticating")
	}
	return nil
}

func validateStableDarwinRuntimeGatePair(name string, opened unix.Stat_t, visible unix.Stat_t, allowPrefix bool) error {
	if err := validateDarwinRuntimeGateStat(opened, allowPrefix); err != nil {
		return fmt.Errorf("Darwin runtime-gate file %q opened descriptor: %w", name, err)
	}
	if err := validateDarwinRuntimeGateStat(visible, allowPrefix); err != nil {
		return fmt.Errorf("Darwin runtime-gate file %q visible path: %w", name, err)
	}
	if snapshotDarwinInstallStat(opened) != snapshotDarwinInstallStat(visible) {
		return fmt.Errorf("Darwin runtime-gate file %q path does not identify its opened descriptor", name)
	}
	return nil
}

func validateDarwinInstallerDirectoryStat(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != darwinInstallerDirectoryMode || stat.Uid != 0 || stat.Gid != 0 || stat.Flags != 0 {
		return errors.New("Darwin installer state directory must be an exact root:wheel mode-0700 real directory without file flags")
	}
	return nil
}

func validateDarwinRuntimeGateStat(stat unix.Stat_t, allowPrefix bool) error {
	minimum := int64(len(runtimeGateContent))
	if allowPrefix {
		minimum = 0
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != darwinRuntimeGateMode || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Flags != 0 || stat.Size < minimum || stat.Size > int64(len(runtimeGateContent)) {
		return errors.New("must be an exact root:wheel, single-link, mode-0400 bounded regular file without flags")
	}
	return nil
}

func cleanDarwinInstallPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}
