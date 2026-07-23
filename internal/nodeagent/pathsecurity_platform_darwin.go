//go:build darwin

package nodeagent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	darwinExtendedSecurityResultLimit = 4096
	darwinXattrListLimit              = 64 << 10
	darwinSecurityXattr               = "com.apple.system.Security"
)

func validatePlatformPathSecurity(path string) error {
	return validateDarwinPathWith(path, darwinPathWalkOperations{
		openRoot: func() (int, error) {
			return unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
		},
		openAt: func(parent int, name string, requireDirectory bool) (int, error) {
			flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NOFOLLOW_ANY | unix.O_NONBLOCK
			if requireDirectory {
				flags |= unix.O_DIRECTORY
			}
			return unix.Openat(parent, name, flags, 0)
		},
		inspect:    inspectDarwinPathDescriptor,
		close:      unix.Close,
		isNotExist: func(err error) bool { return errors.Is(err, unix.ENOENT) },
	})
}

// InspectDarwinSensitivePath exposes the descriptor-anchored native path walk
// to the privileged Darwin installer. It authenticates ownership semantics,
// ancestors, ACLs, and security xattrs; callers remain responsible for the
// exact type, owner, group, mode, link, flag, and content policy of the leaf.
func InspectDarwinSensitivePath(path string) error {
	return validatePlatformPathSecurity(path)
}

// SyncDarwinSensitiveDirectory repeats the complete native path inspection,
// opens the exact physical directory without following a link, and syncs it.
func SyncDarwinSensitiveDirectory(path string) error {
	return syncDarwinDirectory(path)
}

func inspectDarwinPathDescriptor(fd int, path string, ancestor bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect sensitive Darwin path %q: %w", path, err)
	}
	if ancestor && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("sensitive Darwin path ancestor %q is not a directory", path)
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("sensitive Darwin path %q is owned by untrusted uid %d", path, stat.Uid)
	}
	if ancestor && stat.Mode&0o022 != 0 {
		return fmt.Errorf("sensitive Darwin path ancestor %q is group- or world-writable", path)
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return fmt.Errorf("inspect filesystem for sensitive Darwin path %q: %w", path, err)
	}
	if filesystem.Flags&unix.MNT_UNKNOWNPERMISSIONS != 0 {
		return fmt.Errorf("sensitive Darwin path %q is on a filesystem that ignores ownership", path)
	}
	first, err := readDarwinExtendedSecurity(fd)
	if err != nil {
		return fmt.Errorf("inspect extended ACL for sensitive Darwin path %q: %w", path, err)
	}
	hasACL, err := parseDarwinExtendedSecurityResult(first)
	if err != nil {
		return fmt.Errorf("validate extended ACL for sensitive Darwin path %q: %w", path, err)
	}
	if hasACL {
		return fmt.Errorf("sensitive Darwin path %q has an extended ACL", path)
	}
	if err := rejectDarwinSecurityXattr(fd); err != nil {
		return fmt.Errorf("inspect security xattr for sensitive Darwin path %q: %w", path, err)
	}
	second, err := readDarwinExtendedSecurity(fd)
	if err != nil {
		return fmt.Errorf("reinspect extended ACL for sensitive Darwin path %q: %w", path, err)
	}
	if !bytes.Equal(first, second) {
		return fmt.Errorf("extended ACL changed while inspecting sensitive Darwin path %q", path)
	}
	return nil
}

func readDarwinExtendedSecurity(fd int) ([]byte, error) {
	attributes := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY,
	}
	buffer := make([]byte, darwinExtendedSecurityResultLimit)
	_, _, errno := unix.Syscall6(
		unix.SYS_FGETATTRLIST,
		uintptr(fd),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		unix.FSOPT_PACK_INVAL_ATTRS,
		0,
	)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return nil, errno
	}
	if len(buffer) < 4 {
		return nil, errors.New("Darwin extended-security result has no length")
	}
	length := binary.LittleEndian.Uint32(buffer[0:4])
	if length < darwinACLResultFixedBytes || uint64(length) > uint64(len(buffer)) {
		return nil, fmt.Errorf("Darwin extended-security result length %d is outside the accepted bound", length)
	}
	return append([]byte(nil), buffer[:length]...), nil
}

func rejectDarwinSecurityXattr(fd int) error {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := unix.Flistxattr(fd, nil)
		if err != nil {
			return err
		}
		if size == 0 {
			return nil
		}
		if size < 0 || size > darwinXattrListLimit {
			return fmt.Errorf("extended-attribute name list size %d is outside the accepted bound", size)
		}
		names := make([]byte, size)
		read, err := unix.Flistxattr(fd, names)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return err
		}
		if read < 0 || read > len(names) {
			return errors.New("extended-attribute name list exceeded its inspected buffer")
		}
		names = names[:read]
		stableSize, err := unix.Flistxattr(fd, nil)
		if err != nil {
			return err
		}
		if stableSize != read {
			continue
		}
		for len(names) > 0 {
			end := bytes.IndexByte(names, 0)
			if end <= 0 {
				return errors.New("extended-attribute name list is malformed")
			}
			if string(names[:end]) == darwinSecurityXattr {
				return fmt.Errorf("forbidden %q extended attribute is present", darwinSecurityXattr)
			}
			names = names[end+1:]
		}
		return nil
	}
	return errors.New("extended-attribute name list did not stabilize")
}

func syncDarwinDirectory(path string) error {
	if err := validatePlatformPathSecurity(path); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return fmt.Errorf("open Darwin directory for sync: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin directory descriptor for sync")
	}
	defer file.Close()
	if err := inspectDarwinPathDescriptor(fd, path, false); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync Darwin directory: %w", err)
	}
	return nil
}

// InspectDarwinPersistentRuntimeGate authenticates the exact installer-owned
// authorization file without following a path component. Absence is a cleanly
// closed gate; every malformed or ambiguous object is an error.
func InspectDarwinPersistentRuntimeGate(path string) (open bool, returnErr error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return false, errors.New("Darwin persistent runtime gate inspection requires root:wheel execution")
	}
	if err := validatePlatformPathSecurity(path); err != nil {
		return false, err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Lstat(path, &visibleBefore); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect Darwin persistent runtime gate: %w", err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return false, fmt.Errorf("open Darwin persistent runtime gate: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return false, errors.New("adopt Darwin persistent runtime gate descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	if err := inspectDarwinPathDescriptor(fd, path, false); err != nil {
		return false, err
	}
	var openedBefore unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return false, fmt.Errorf("inspect opened Darwin persistent runtime gate: %w", err)
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(len(darwinPersistentRuntimeGateContent))+1))
	if err != nil {
		return false, fmt.Errorf("read Darwin persistent runtime gate: %w", err)
	}
	var openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return false, fmt.Errorf("reinspect opened Darwin persistent runtime gate: %w", err)
	}
	if err := unix.Lstat(path, &visibleAfter); err != nil {
		return false, fmt.Errorf("reinspect visible Darwin persistent runtime gate: %w", err)
	}
	before := darwinRuntimeGateSnapshotFromStat(visibleBefore)
	opened := darwinRuntimeGateSnapshotFromStat(openedBefore)
	after := darwinRuntimeGateSnapshotFromStat(openedAfter)
	visible := darwinRuntimeGateSnapshotFromStat(visibleAfter)
	if before != opened || opened != after || after != visible {
		return false, errors.New("Darwin persistent runtime gate changed while reading")
	}
	if err := validateDarwinPersistentRuntimeGate(opened, content); err != nil {
		return false, err
	}
	if err := inspectDarwinPathDescriptor(fd, path, false); err != nil {
		return false, err
	}
	return true, nil
}

func darwinRuntimeGateSnapshotFromStat(stat unix.Stat_t) darwinRuntimeGateSnapshot {
	return darwinRuntimeGateSnapshot{
		device: stat.Dev, inode: stat.Ino, mode: stat.Mode, links: stat.Nlink,
		uid: stat.Uid, gid: stat.Gid, size: stat.Size,
		modifiedS: stat.Mtim.Sec, modifiedNS: stat.Mtim.Nsec,
		changedS: stat.Ctim.Sec, changedNS: stat.Ctim.Nsec,
		flags: stat.Flags, generation: stat.Gen,
	}
}

// InspectDarwinPackagedExecutable authenticates one physical executable path.
// The caller must resolve the reviewed /opt/mesh/current selector first; this
// function then rejects any remaining or newly introduced symlink component.
func InspectDarwinPackagedExecutable(path string) (returnErr error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("Darwin packaged executable inspection requires root:wheel execution")
	}
	if err := validatePlatformPathSecurity(path); err != nil {
		return err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Lstat(path, &visibleBefore); err != nil {
		return fmt.Errorf("inspect Darwin packaged executable: %w", err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open Darwin packaged executable: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin packaged executable descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	if err := inspectDarwinPathDescriptor(fd, path, false); err != nil {
		return err
	}
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return fmt.Errorf("inspect opened Darwin packaged executable: %w", err)
	}
	if err := validateDarwinPackagedExecutable(darwinRuntimeGateSnapshotFromStat(openedBefore)); err != nil {
		return err
	}
	if err := inspectDarwinPathDescriptor(fd, path, false); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return fmt.Errorf("reinspect opened Darwin packaged executable: %w", err)
	}
	if err := unix.Lstat(path, &visibleAfter); err != nil {
		return fmt.Errorf("reinspect visible Darwin packaged executable: %w", err)
	}
	before := darwinRuntimeGateSnapshotFromStat(visibleBefore)
	opened := darwinRuntimeGateSnapshotFromStat(openedBefore)
	after := darwinRuntimeGateSnapshotFromStat(openedAfter)
	visible := darwinRuntimeGateSnapshotFromStat(visibleAfter)
	if before != opened || opened != after || after != visible {
		return errors.New("Darwin packaged executable changed while inspecting")
	}
	return nil
}
