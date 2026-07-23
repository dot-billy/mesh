//go:build linux

package linuxinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	productionRuntimeGateDirectory = "/var/lib/mesh-installer"
	runtimeGateName                = "runtime.enabled"
	runtimeGateTemporaryName       = ".runtime.enabled.new"
	runtimeGateMode                = 0o400
)

var runtimeGateContent = []byte("mesh-runtime-enabled-v1\n")

var errRuntimeGatePublicationPending = errors.New("runtime gate has an unfinished open publication")

type managedRuntimeGate interface {
	Inspect() (bool, error)
	Open() error
	Close() error
}

// filesystemRuntimeGate is the single activation gate shared by both reviewed
// managed units. Its directory is the installer's root-private state directory,
// not the lifecycle agent's writable state tree.
type filesystemRuntimeGate struct {
	directory string
}

func productionRuntimeGate() *filesystemRuntimeGate {
	return &filesystemRuntimeGate{directory: productionRuntimeGateDirectory}
}

func newFilesystemRuntimeGate(directory string) (*filesystemRuntimeGate, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) || !filepath.IsAbs(abs) {
		return nil, errors.New("runtime gate directory must be a non-root absolute path")
	}
	return &filesystemRuntimeGate{directory: abs}, nil
}

func (gate *filesystemRuntimeGate) Inspect() (open bool, returnErr error) {
	root, directory, err := gate.openDirectory()
	if err != nil {
		return false, err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()
	if pending, _, err := inspectRuntimeGateRecoveryFile(root, directory, gate.path(runtimeGateTemporaryName)); err != nil {
		return false, err
	} else if pending {
		return false, errRuntimeGatePublicationPending
	}
	return inspectRuntimeGateFile(root, directory, gate.path(runtimeGateName), runtimeGateName)
}

// Open publishes the exact gate without replacing any existing directory
// entry. An exact fsynced temporary left by a crash is resumed; any unexpected
// file fails closed.
func (gate *filesystemRuntimeGate) Open() (returnErr error) {
	root, directory, err := gate.openDirectory()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()

	open, err := inspectRuntimeGateFile(root, directory, gate.path(runtimeGateName), runtimeGateName)
	if err != nil {
		return err
	}
	pending, complete, err := inspectRuntimeGateRecoveryFile(root, directory, gate.path(runtimeGateTemporaryName))
	if err != nil {
		return err
	}
	if open {
		if pending {
			return errors.New("open runtime gate has an unexpected recovery file")
		}
		return nil
	}
	if pending && !complete {
		if err := syscall.Unlinkat(int(directory.Fd()), runtimeGateTemporaryName); err != nil {
			return fmt.Errorf("remove incomplete runtime gate recovery file: %w", err)
		}
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync incomplete runtime gate recovery cleanup: %w", err)
		}
		pending = false
	}
	if !pending {
		file, err := root.OpenFile(runtimeGateTemporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, runtimeGateMode)
		if err != nil {
			return fmt.Errorf("create runtime gate recovery file: %w", err)
		}
		fileOpen := true
		defer func() {
			if fileOpen {
				returnErr = errors.Join(returnErr, file.Close())
			}
		}()
		if err := file.Chmod(runtimeGateMode); err != nil {
			return err
		}
		if written, err := file.Write(runtimeGateContent); err != nil {
			return err
		} else if written != len(runtimeGateContent) {
			return io.ErrShortWrite
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync runtime gate recovery file: %w", err)
		}
		if err := file.Close(); err != nil {
			return err
		}
		fileOpen = false
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync runtime gate recovery creation: %w", err)
		}
		if pending, complete, err = inspectRuntimeGateRecoveryFile(root, directory, gate.path(runtimeGateTemporaryName)); err != nil {
			return err
		} else if !pending || !complete {
			return errors.New("runtime gate recovery file disappeared after creation")
		}
	}
	if err := syncRuntimeGateRecoveryFile(root, directory, gate.path(runtimeGateTemporaryName)); err != nil {
		return err
	}
	if err := renameNoReplace(directory, runtimeGateTemporaryName, runtimeGateName); err != nil {
		return fmt.Errorf("publish runtime gate without replacement: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync runtime gate publication: %w", err)
	}
	if open, err = inspectRuntimeGateFile(root, directory, gate.path(runtimeGateName), runtimeGateName); err != nil {
		return err
	} else if !open {
		return errors.New("runtime gate publication is not visible")
	}
	if pending, _, err = inspectRuntimeGateRecoveryFile(root, directory, gate.path(runtimeGateTemporaryName)); err != nil {
		return err
	} else if pending {
		return errors.New("runtime gate recovery file remains after publication")
	}
	return nil
}

// Close makes both the live condition and any interrupted-open recovery file
// durably absent. It never removes content that did not first pass the exact
// owner, mode, link-count, ACL, metadata, and byte checks.
func (gate *filesystemRuntimeGate) Close() (returnErr error) {
	root, directory, err := gate.openDirectory()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()
	for _, name := range []string{runtimeGateName, runtimeGateTemporaryName} {
		var found bool
		var err error
		if name == runtimeGateName {
			found, err = inspectRuntimeGateFile(root, directory, gate.path(name), name)
		} else {
			found, _, err = inspectRuntimeGateRecoveryFile(root, directory, gate.path(name))
		}
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
			return fmt.Errorf("remove runtime gate file %q: %w", name, err)
		}
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return fmt.Errorf("runtime gate file %q remains after removal", name)
			}
			return err
		}
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync runtime gate removal %q: %w", name, err)
		}
	}
	for _, name := range []string{runtimeGateName, runtimeGateTemporaryName} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return fmt.Errorf("runtime gate file %q is not absent", name)
			}
			return err
		}
	}
	return nil
}

func (gate *filesystemRuntimeGate) openDirectory() (*os.Root, *os.File, error) {
	if gate == nil || !filepath.IsAbs(gate.directory) || filepath.Clean(gate.directory) != gate.directory || gate.directory == string(filepath.Separator) {
		return nil, nil, errors.New("runtime gate path is invalid")
	}
	if err := validatePrivateDirectory(gate.directory); err != nil {
		return nil, nil, fmt.Errorf("runtime gate directory: %w", err)
	}
	visible, err := os.Lstat(gate.directory)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(gate.directory)
	if err != nil {
		return nil, nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	rootInfo, rootErr := root.Stat(".")
	directoryInfo, directoryErr := directory.Stat()
	pathInfo, pathErr := os.Lstat(gate.directory)
	if rootErr != nil || directoryErr != nil || pathErr != nil || !sameDirectoryObject(visible, rootInfo) ||
		!sameDirectoryObject(visible, directoryInfo) || !sameDirectoryObject(visible, pathInfo) {
		_ = directory.Close()
		_ = root.Close()
		return nil, nil, errors.New("runtime gate directory changed while anchoring")
	}
	return root, directory, nil
}

func (gate *filesystemRuntimeGate) path(name string) string {
	return filepath.Join(gate.directory, name)
}

func inspectRuntimeGateFile(root *os.Root, directory *os.File, path, name string) (bool, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := validateRuntimeGateInfo(before); err != nil {
		return false, fmt.Errorf("runtime gate file %q: %w", name, err)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return false, err
	}
	descriptor, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = syscall.Close(descriptor)
		return false, errors.New("anchor runtime gate file")
	}
	openedBefore, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(runtimeGateContent))+1))
	openedAfter, afterStatErr := file.Stat()
	visible, visibleErr := root.Lstat(name)
	closeErr := file.Close()
	if statErr != nil || readErr != nil || afterStatErr != nil || visibleErr != nil || closeErr != nil {
		return false, errors.Join(statErr, readErr, afterStatErr, visibleErr, closeErr)
	}
	for _, info := range []os.FileInfo{openedBefore, openedAfter, visible} {
		if err := validateRuntimeGateInfo(info); err != nil {
			return false, err
		}
	}
	beforeIdentity, err := stateIdentity(before)
	if err != nil {
		return false, err
	}
	openedBeforeIdentity, err := stateIdentity(openedBefore)
	if err != nil {
		return false, err
	}
	openedAfterIdentity, err := stateIdentity(openedAfter)
	if err != nil {
		return false, err
	}
	visibleIdentity, err := stateIdentity(visible)
	if err != nil {
		return false, err
	}
	if beforeIdentity != openedBeforeIdentity || openedBeforeIdentity != openedAfterIdentity || openedAfterIdentity != visibleIdentity ||
		!bytes.Equal(content, runtimeGateContent) {
		return false, fmt.Errorf("runtime gate file %q changed or has unexpected content", name)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return false, err
	}
	return true, nil
}

// inspectRuntimeGateRecoveryFile also recognizes a crash-truncated prefix of
// the reviewed bytes. Such a file is never publishable, but it is safe for the
// installer to remove because its fixed name, owner, group, mode, link count,
// ACL state, stable inode metadata, size bound, and bytes all match an
// interrupted write made by Open.
func inspectRuntimeGateRecoveryFile(root *os.Root, directory *os.File, path string) (bool, bool, error) {
	before, err := root.Lstat(runtimeGateTemporaryName)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if err := validateRuntimeGateRecoveryInfo(before); err != nil {
		return false, false, fmt.Errorf("runtime gate recovery file: %w", err)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return false, false, err
	}
	descriptor, err := syscall.Openat(int(directory.Fd()), runtimeGateTemporaryName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, false, err
	}
	file := os.NewFile(uintptr(descriptor), runtimeGateTemporaryName)
	if file == nil {
		_ = syscall.Close(descriptor)
		return false, false, errors.New("anchor runtime gate recovery file")
	}
	openedBefore, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(runtimeGateContent))+1))
	openedAfter, afterStatErr := file.Stat()
	visible, visibleErr := root.Lstat(runtimeGateTemporaryName)
	closeErr := file.Close()
	if statErr != nil || readErr != nil || afterStatErr != nil || visibleErr != nil || closeErr != nil {
		return false, false, errors.Join(statErr, readErr, afterStatErr, visibleErr, closeErr)
	}
	for _, info := range []os.FileInfo{openedBefore, openedAfter, visible} {
		if err := validateRuntimeGateRecoveryInfo(info); err != nil {
			return false, false, err
		}
	}
	identities := make([]stateFileIdentity, 0, 4)
	for _, info := range []os.FileInfo{before, openedBefore, openedAfter, visible} {
		identity, err := stateIdentity(info)
		if err != nil {
			return false, false, err
		}
		identities = append(identities, identity)
	}
	if identities[0] != identities[1] || identities[1] != identities[2] || identities[2] != identities[3] ||
		!bytes.HasPrefix(runtimeGateContent, content) {
		return false, false, errors.New("runtime gate recovery file changed or is not a reviewed-byte prefix")
	}
	if err := rejectPOSIXACL(path); err != nil {
		return false, false, err
	}
	return true, len(content) == len(runtimeGateContent), nil
}

func syncRuntimeGateRecoveryFile(root *os.Root, directory *os.File, path string) error {
	found, complete, err := inspectRuntimeGateRecoveryFile(root, directory, path)
	if err != nil {
		return err
	}
	if !found || !complete {
		return errors.New("runtime gate recovery file is not complete before publication")
	}
	descriptor, err := syscall.Openat(int(directory.Fd()), runtimeGateTemporaryName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), runtimeGateTemporaryName)
	if file == nil {
		_ = syscall.Close(descriptor)
		return errors.New("anchor runtime gate recovery file for sync")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync resumed runtime gate recovery file: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync resumed runtime gate recovery directory: %w", err)
	}
	found, complete, err = inspectRuntimeGateRecoveryFile(root, directory, path)
	if err != nil {
		return err
	}
	if !found || !complete {
		return errors.New("runtime gate recovery file changed after sync")
	}
	return nil
}

func validateRuntimeGateInfo(info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != runtimeGateMode ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() != int64(len(runtimeGateContent)) {
		return errors.New("must be an exact mode-0400 regular file with reviewed size")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
		return errors.New("must have the exact effective owner and a single link")
	}
	return nil
}

func validateRuntimeGateRecoveryInfo(info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != runtimeGateMode ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > int64(len(runtimeGateContent)) {
		return errors.New("must be an exact mode-0400 bounded regular recovery file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
		return errors.New("must have the exact effective owner and a single link")
	}
	return nil
}
