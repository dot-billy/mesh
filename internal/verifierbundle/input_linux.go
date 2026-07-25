//go:build linux

package verifierbundle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

type inputIdentity struct {
	device, inode, linkCount uint64
	size                     int64
	ownerUID, ownerGID, mode uint32
	modificationUnixNano     int64
	changeUnixNano           int64
}

func snapshotRegularFile(path string, maximum int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("input path is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	identity, ok := inputIdentityFromInfo(before)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file, not a symlink")
	}
	if identity.linkCount != 1 {
		return nil, errors.New("input regular file must have link count 1")
	}
	if identity.size <= 0 || identity.size > maximum {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", maximum)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open input descriptor")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !inputIdentityMatches(identity, opened) {
		return nil, errors.New("input changed while opening without symlink following")
	}
	content, err := io.ReadAll(io.LimitReader(file, identity.size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != identity.size {
		return nil, errors.New("input was truncated or appended while reading")
	}
	after, descriptorErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if descriptorErr != nil || pathErr != nil || !inputIdentityMatches(identity, after) || !inputIdentityMatches(identity, pathAfter) {
		return nil, errors.New("input identity, size, mode, ownership, link count, or timestamps changed while snapshotting")
	}
	return content, nil
}

func inputIdentityFromInfo(info os.FileInfo) (inputIdentity, bool) {
	if info == nil {
		return inputIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return inputIdentity{}, false
	}
	return inputIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, linkCount: uint64(stat.Nlink), size: stat.Size,
		ownerUID: stat.Uid, ownerGID: stat.Gid, mode: stat.Mode,
		modificationUnixNano: int64(stat.Mtim.Sec)*1e9 + int64(stat.Mtim.Nsec),
		changeUnixNano:       int64(stat.Ctim.Sec)*1e9 + int64(stat.Ctim.Nsec),
	}, true
}

func inputIdentityMatches(expected inputIdentity, info os.FileInfo) bool {
	actual, ok := inputIdentityFromInfo(info)
	return ok && actual == expected && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
