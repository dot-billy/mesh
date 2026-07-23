//go:build linux || darwin

package postgresconfig

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type fileSnapshot struct {
	device     uint64
	inode      uint64
	links      uint64
	uid        uint32
	gid        uint32
	mode       uint32
	size       int64
	changeSec  int64
	changeNsec int64
}

func readPrivateFile(path string, afterFirstRead func()) ([]byte, error) {
	file, err := openWithoutSymlinks(path)
	if err != nil {
		return nil, errOpen
	}
	defer file.Close()

	before, err := inspectFile(file)
	if err != nil || !acceptablePrivateFile(before) {
		return nil, errMetadata
	}
	first, err := readExactFile(file, before.size)
	if err != nil {
		return nil, errRead
	}
	if afterFirstRead != nil {
		afterFirstRead()
	}
	middle, err := inspectFile(file)
	if err != nil || before != middle {
		return nil, errRead
	}
	second, err := readExactFile(file, middle.size)
	if err != nil {
		return nil, errRead
	}
	after, err := inspectFile(file)
	if err != nil || middle != after || !bytes.Equal(first, second) {
		clear(first)
		clear(second)
		return nil, errRead
	}
	clear(second)
	return first, nil
}

func openWithoutSymlinks(path string) (*os.File, error) {
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 0 || components[0] == "" {
		return nil, errOpen
	}
	directoryFD, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, errOpen
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		unix.Close(directoryFD)
		if openErr != nil {
			return nil, errOpen
		}
		directoryFD = nextFD
	}

	fd, openErr := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	unix.Close(directoryFD)
	if openErr != nil {
		return nil, errOpen
	}
	file := os.NewFile(uintptr(fd), "postgres-dsn")
	if file == nil {
		unix.Close(fd)
		return nil, errOpen
	}
	return file, nil
}

func inspectFile(file *os.File) (fileSnapshot, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileSnapshot{}, err
	}
	changeSec, changeNsec := statChangeTime(&stat)
	return fileSnapshot{
		device:     uint64(stat.Dev),
		inode:      uint64(stat.Ino),
		links:      uint64(stat.Nlink),
		uid:        stat.Uid,
		gid:        stat.Gid,
		mode:       uint32(stat.Mode),
		size:       stat.Size,
		changeSec:  changeSec,
		changeNsec: changeNsec,
	}, nil
}

func acceptablePrivateFile(snapshot fileSnapshot) bool {
	if snapshot.mode&unix.S_IFMT != unix.S_IFREG || snapshot.links != 1 || snapshot.uid != uint32(os.Geteuid()) {
		return false
	}
	permissions := snapshot.mode & 0o7777
	if permissions != 0o400 && permissions != 0o600 {
		return false
	}
	return snapshot.size > 0 && snapshot.size <= MaxDSNFileBytes
}

func readExactFile(file *os.File, size int64) ([]byte, error) {
	if size <= 0 || size > MaxDSNFileBytes {
		return nil, errRead
	}
	buffer := make([]byte, int(size))
	n, err := file.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		clear(buffer)
		return nil, errRead
	}
	if n != len(buffer) {
		clear(buffer)
		return nil, errRead
	}
	var extra [1]byte
	n, err = file.ReadAt(extra[:], size)
	if n != 0 || !errors.Is(err, io.EOF) {
		clear(buffer)
		return nil, errRead
	}
	return buffer, nil
}
