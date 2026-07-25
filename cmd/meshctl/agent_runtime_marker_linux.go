//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	packagedNebulaService        = "mesh-nebula.service"
	packagedRuntimeDirectory     = "/run/mesh-agent"
	runtimeReadinessMarkerName   = "nebula.validated"
	runtimeReadinessRecoveryName = ".nebula.validated.new"
	runtimeReadinessMarkerMode   = 0o400
)

var runtimeReadinessMarkerContent = []byte("mesh-nebula-validated-v1\n")

type filesystemRuntimeReadinessMarker struct {
	directory string
}

func packagedRuntimeReadinessMarker(service string) (runtimeReadinessMarker, error) {
	if service != packagedNebulaService {
		return nil, nil
	}
	return newFilesystemRuntimeReadinessMarker(packagedRuntimeDirectory)
}

func newFilesystemRuntimeReadinessMarker(directory string) (*filesystemRuntimeReadinessMarker, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	if !filepath.IsAbs(abs) || abs == string(filepath.Separator) {
		return nil, errors.New("runtime readiness directory must be a non-root absolute path")
	}
	return &filesystemRuntimeReadinessMarker{directory: abs}, nil
}

func (marker *filesystemRuntimeReadinessMarker) Inspect() (open bool, returnErr error) {
	root, directory, absent, err := marker.openDirectory()
	if err != nil || absent {
		return false, err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()
	live, recovery, err := marker.readPair(root, directory)
	if err != nil {
		return false, err
	}
	if recovery.found {
		return false, errors.New("runtime readiness marker has an unfinished publication")
	}
	if !live.found {
		return false, nil
	}
	if !live.complete || live.links != 1 {
		return false, errors.New("runtime readiness marker is not an exact single-link publication")
	}
	return true, nil
}

func (marker *filesystemRuntimeReadinessMarker) Open() (returnErr error) {
	root, directory, absent, err := marker.openDirectory()
	if err != nil {
		return err
	}
	if absent {
		return errors.New("systemd runtime directory is absent; refuse to authorize Nebula startup")
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()

	live, recovery, err := marker.readPair(root, directory)
	if err != nil {
		return err
	}
	if live.found {
		if !live.complete {
			return errors.New("published runtime readiness marker has incomplete content")
		}
		if !recovery.found {
			if live.links != 1 {
				return errors.New("published runtime readiness marker has an unexpected hard link")
			}
			return nil
		}
		if !recovery.complete || live.links != 2 || recovery.links != 2 || !os.SameFile(live.info, recovery.info) {
			return errors.New("runtime readiness live and recovery names are not the exact interrupted publication")
		}
		// Persist the completed live link before discarding its recovery name.
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync interrupted readiness publication: %w", err)
		}
		if err := syscall.Unlinkat(int(directory.Fd()), runtimeReadinessRecoveryName); err != nil {
			return fmt.Errorf("remove readiness recovery link: %w", err)
		}
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync readiness recovery-link removal: %w", err)
		}
		return marker.requireExactLive(root, directory)
	}

	if recovery.found && !recovery.complete {
		if recovery.links != 1 {
			return errors.New("incomplete readiness recovery file has an unexpected hard link")
		}
		if err := syscall.Unlinkat(int(directory.Fd()), runtimeReadinessRecoveryName); err != nil {
			return fmt.Errorf("remove incomplete readiness recovery file: %w", err)
		}
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync incomplete readiness recovery cleanup: %w", err)
		}
		recovery = readinessFile{}
	}
	if !recovery.found {
		file, err := root.OpenFile(runtimeReadinessRecoveryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, runtimeReadinessMarkerMode)
		if err != nil {
			return fmt.Errorf("create readiness recovery file: %w", err)
		}
		fileOpen := true
		defer func() {
			if fileOpen {
				returnErr = errors.Join(returnErr, file.Close())
			}
		}()
		if err := file.Chmod(runtimeReadinessMarkerMode); err != nil {
			return err
		}
		if written, err := file.Write(runtimeReadinessMarkerContent); err != nil {
			return err
		} else if written != len(runtimeReadinessMarkerContent) {
			return io.ErrShortWrite
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync readiness recovery content: %w", err)
		}
		if err := file.Close(); err != nil {
			return err
		}
		fileOpen = false
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync readiness recovery creation: %w", err)
		}
	}
	if err := marker.syncCompleteRecovery(root, directory); err != nil {
		return err
	}
	if err := root.Link(runtimeReadinessRecoveryName, runtimeReadinessMarkerName); err != nil {
		return fmt.Errorf("publish readiness marker without replacement: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync readiness marker publication: %w", err)
	}
	live, recovery, err = marker.readPair(root, directory)
	if err != nil {
		return err
	}
	if !live.found || !live.complete || !recovery.found || !recovery.complete || live.links != 2 || recovery.links != 2 || !os.SameFile(live.info, recovery.info) {
		return errors.New("readiness marker hard-link publication is not exact")
	}
	if err := syscall.Unlinkat(int(directory.Fd()), runtimeReadinessRecoveryName); err != nil {
		return fmt.Errorf("remove published readiness recovery link: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync published readiness recovery cleanup: %w", err)
	}
	return marker.requireExactLive(root, directory)
}

func (marker *filesystemRuntimeReadinessMarker) Close() (returnErr error) {
	root, directory, absent, err := marker.openDirectory()
	if err != nil || absent {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()
	// Closure is intentionally content-agnostic. Even a corrupted publication
	// still satisfies systemd's ConditionPathExists, so fail-closed behavior is
	// to unlink the fixed names without following them and then verify absence.
	// An unexpected directory cannot be removed by unlinkat and is reported.
	var result error
	for _, name := range []string{runtimeReadinessMarkerName, runtimeReadinessRecoveryName} {
		if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			result = errors.Join(result, fmt.Errorf("inspect runtime readiness path %q for closure: %w", name, err))
			continue
		}
		if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
			result = errors.Join(result, fmt.Errorf("remove runtime readiness path %q: %w", name, err))
			continue
		}
		// The live name is first, and this sync is deliberately immediate:
		// callers may issue systemctl stop only after Close returns.
		if err := directory.Sync(); err != nil {
			result = errors.Join(result, fmt.Errorf("sync runtime readiness path %q removal: %w", name, err))
		}
	}
	for _, name := range []string{runtimeReadinessMarkerName, runtimeReadinessRecoveryName} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				result = errors.Join(result, fmt.Errorf("runtime readiness path %q remains after closure", name))
				continue
			}
			result = errors.Join(result, err)
		}
	}
	return result
}

type readinessFile struct {
	found    bool
	complete bool
	links    uint64
	info     os.FileInfo
}

func (marker *filesystemRuntimeReadinessMarker) readPair(root *os.Root, directory *os.File) (readinessFile, readinessFile, error) {
	live, err := marker.readFile(root, directory, runtimeReadinessMarkerName, false)
	if err != nil {
		return readinessFile{}, readinessFile{}, err
	}
	recovery, err := marker.readFile(root, directory, runtimeReadinessRecoveryName, true)
	return live, recovery, err
}

func (marker *filesystemRuntimeReadinessMarker) readFile(root *os.Root, directory *os.File, name string, allowPrefix bool) (readinessFile, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return readinessFile{}, nil
	}
	if err != nil {
		return readinessFile{}, err
	}
	if err := validateReadinessFileInfo(before, allowPrefix); err != nil {
		return readinessFile{}, fmt.Errorf("runtime readiness file %q: %w", name, err)
	}
	path := filepath.Join(marker.directory, name)
	if err := rejectReadinessPOSIXACL(path); err != nil {
		return readinessFile{}, err
	}
	descriptor, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return readinessFile{}, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = syscall.Close(descriptor)
		return readinessFile{}, errors.New("anchor runtime readiness file")
	}
	openedBefore, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(runtimeReadinessMarkerContent))+1))
	openedAfter, afterStatErr := file.Stat()
	visible, visibleErr := root.Lstat(name)
	closeErr := file.Close()
	if statErr != nil || readErr != nil || afterStatErr != nil || visibleErr != nil || closeErr != nil {
		return readinessFile{}, errors.Join(statErr, readErr, afterStatErr, visibleErr, closeErr)
	}
	for _, info := range []os.FileInfo{openedBefore, openedAfter, visible} {
		if err := validateReadinessFileInfo(info, allowPrefix); err != nil {
			return readinessFile{}, err
		}
	}
	identities := make([]readinessFileIdentity, 0, 4)
	for _, info := range []os.FileInfo{before, openedBefore, openedAfter, visible} {
		identity, err := readinessIdentity(info)
		if err != nil {
			return readinessFile{}, err
		}
		identities = append(identities, identity)
	}
	if identities[0] != identities[1] || identities[1] != identities[2] || identities[2] != identities[3] {
		return readinessFile{}, fmt.Errorf("runtime readiness file %q changed while reading", name)
	}
	complete := bytes.Equal(content, runtimeReadinessMarkerContent)
	if !complete && (!allowPrefix || !bytes.HasPrefix(runtimeReadinessMarkerContent, content)) {
		return readinessFile{}, fmt.Errorf("runtime readiness file %q has unexpected content", name)
	}
	if err := rejectReadinessPOSIXACL(path); err != nil {
		return readinessFile{}, err
	}
	return readinessFile{found: true, complete: complete, links: identities[0].links, info: visible}, nil
}

func (marker *filesystemRuntimeReadinessMarker) syncCompleteRecovery(root *os.Root, directory *os.File) error {
	recovery, err := marker.readFile(root, directory, runtimeReadinessRecoveryName, true)
	if err != nil {
		return err
	}
	if !recovery.found || !recovery.complete || recovery.links != 1 {
		return errors.New("readiness recovery file is not complete and singly linked")
	}
	descriptor, err := syscall.Openat(int(directory.Fd()), runtimeReadinessRecoveryName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), runtimeReadinessRecoveryName)
	if file == nil {
		_ = syscall.Close(descriptor)
		return errors.New("anchor readiness recovery file for sync")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync resumed readiness recovery file: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync resumed readiness recovery directory: %w", err)
	}
	return nil
}

func (marker *filesystemRuntimeReadinessMarker) requireExactLive(root *os.Root, directory *os.File) error {
	live, recovery, err := marker.readPair(root, directory)
	if err != nil {
		return err
	}
	if !live.found || !live.complete || live.links != 1 || recovery.found {
		return errors.New("runtime readiness marker publication is not exact")
	}
	return nil
}

func (marker *filesystemRuntimeReadinessMarker) openDirectory() (*os.Root, *os.File, bool, error) {
	if marker == nil || !filepath.IsAbs(marker.directory) || filepath.Clean(marker.directory) != marker.directory || marker.directory == string(filepath.Separator) {
		return nil, nil, false, errors.New("runtime readiness marker path is invalid")
	}
	visible, err := os.Lstat(marker.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, true, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	if err := validateReadinessDirectory(marker.directory, visible); err != nil {
		return nil, nil, false, err
	}
	root, err := os.OpenRoot(marker.directory)
	if err != nil {
		return nil, nil, false, err
	}
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, false, err
	}
	rootInfo, rootErr := root.Stat(".")
	directoryInfo, directoryErr := directory.Stat()
	pathInfo, pathErr := os.Lstat(marker.directory)
	if rootErr != nil || directoryErr != nil || pathErr != nil || !os.SameFile(visible, rootInfo) || !os.SameFile(visible, directoryInfo) || !os.SameFile(visible, pathInfo) {
		_ = directory.Close()
		_ = root.Close()
		return nil, nil, false, errors.New("runtime readiness directory changed while anchoring")
	}
	return root, directory, false, nil
}

func validateReadinessDirectory(path string, info os.FileInfo) error {
	if err := validateReadinessAncestors(path); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("runtime readiness directory must have the exact effective owner and mode 0700")
	}
	return rejectReadinessPOSIXACL(path)
}

func validateReadinessAncestors(path string) error {
	abs := filepath.Clean(path)
	current := string(filepath.Separator)
	previous, err := os.Lstat(current)
	if err != nil {
		return err
	}
	for _, component := range strings.Split(strings.TrimPrefix(abs, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		if previous.Mode().Perm()&0o022 != 0 && previous.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("runtime readiness ancestor %q is writable without sticky protection", current)
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("runtime readiness ancestor %q is untrusted", current)
		}
		if err := rejectReadinessPOSIXACL(current); err != nil {
			return err
		}
		previous = info
	}
	return nil
}

func rejectReadinessPOSIXACL(path string) error {
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		size, err := syscall.Getxattr(path, attribute, nil)
		if err == nil && size > 0 {
			return fmt.Errorf("runtime readiness path %q has POSIX ACL %q", path, attribute)
		}
		if err != nil && !errors.Is(err, syscall.ENODATA) && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.EOPNOTSUPP) {
			return err
		}
	}
	return nil
}

func validateReadinessFileInfo(info os.FileInfo, allowPrefix bool) error {
	maximum := int64(len(runtimeReadinessMarkerContent))
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != runtimeReadinessMarkerMode ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > maximum || !allowPrefix && info.Size() != maximum {
		return errors.New("must be an exact mode-0400 bounded regular readiness file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink < 1 || stat.Nlink > 2 {
		return errors.New("must have the exact effective owner and at most the publication link pair")
	}
	return nil
}

type readinessFileIdentity struct {
	device, inode, links uint64
	mode, uid, gid       uint32
	size                 int64
	mtimeSeconds         int64
	mtimeNanoseconds     int64
	ctimeSeconds         int64
	ctimeNanoseconds     int64
}

func readinessIdentity(info os.FileInfo) (readinessFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return readinessFileIdentity{}, errors.New("runtime readiness file has no Linux stat identity")
	}
	return readinessFileIdentity{
		device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink),
		mode: uint32(stat.Mode), uid: uint32(stat.Uid), gid: uint32(stat.Gid), size: info.Size(),
		mtimeSeconds: int64(stat.Mtim.Sec), mtimeNanoseconds: int64(stat.Mtim.Nsec),
		ctimeSeconds: int64(stat.Ctim.Sec), ctimeNanoseconds: int64(stat.Ctim.Nsec),
	}, nil
}
