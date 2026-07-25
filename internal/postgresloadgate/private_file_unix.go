//go:build linux || darwin

package postgresloadgate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumPrivateLineBytes = 4096

type privateFileSnapshot struct {
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

func readPrivateCanonicalLine(path, label string) (string, error) {
	return readPrivateCanonicalLineWithHook(path, label, nil)
}

func readPrivateCanonicalLineWithHook(path, label string, afterFirstRead func()) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", fmt.Errorf("%s path must be clean and absolute", label)
	}
	file, err := openPrivatePathWithoutSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("open %s failed", label)
	}
	defer file.Close()
	before, err := inspectPrivateFile(file)
	if err != nil || !acceptablePrivateLineFile(before) {
		return "", fmt.Errorf("%s must be an owner-controlled single-link 0400/0600 bounded regular file", label)
	}
	first, err := readExactPrivateFile(file, before.size)
	if err != nil {
		return "", fmt.Errorf("read %s failed", label)
	}
	defer clear(first)
	if afterFirstRead != nil {
		afterFirstRead()
	}
	middle, err := inspectPrivateFile(file)
	if err != nil || before != middle || !acceptablePrivateLineFile(middle) {
		return "", fmt.Errorf("%s changed during its stable read", label)
	}
	second, err := readExactPrivateFile(file, middle.size)
	if err != nil {
		return "", fmt.Errorf("reread %s failed", label)
	}
	defer clear(second)
	after, err := inspectPrivateFile(file)
	if err != nil || middle != after || !acceptablePrivateLineFile(after) || !bytes.Equal(first, second) {
		return "", fmt.Errorf("%s changed during its stable read", label)
	}
	if len(first) < 2 || first[len(first)-1] != '\n' || strings.ContainsAny(string(first[:len(first)-1]), "\r\n\x00") {
		return "", fmt.Errorf("%s must contain one canonical line", label)
	}
	value := string(first[:len(first)-1])
	return value, nil
}

func openPrivatePathWithoutSymlinks(path string) (*os.File, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[0] == "" {
		return nil, errors.New("private path has no components")
	}
	directoryFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		_ = unix.Close(directoryFD)
		if openErr != nil {
			return nil, openErr
		}
		directoryFD = nextFD
	}
	fd, openErr := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	_ = unix.Close(directoryFD)
	if openErr != nil {
		return nil, openErr
	}
	file := os.NewFile(uintptr(fd), "private-load-gate-input")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("construct private file failed")
	}
	return file, nil
}

func inspectPrivateFile(file *os.File) (privateFileSnapshot, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return privateFileSnapshot{}, err
	}
	return privateFileSnapshot{
		device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink),
		uid: stat.Uid, gid: stat.Gid, mode: uint32(stat.Mode), size: stat.Size,
		changeSec: stat.Ctim.Sec, changeNsec: stat.Ctim.Nsec,
	}, nil
}

func acceptablePrivateLineFile(snapshot privateFileSnapshot) bool {
	if snapshot.mode&unix.S_IFMT != unix.S_IFREG || snapshot.links != 1 || snapshot.uid != uint32(os.Geteuid()) {
		return false
	}
	permissions := snapshot.mode & 0o7777
	return (permissions == 0o400 || permissions == 0o600) && snapshot.size >= 2 && snapshot.size <= maximumPrivateLineBytes
}

func readExactPrivateFile(file *os.File, size int64) ([]byte, error) {
	if size < 2 || size > maximumPrivateLineBytes {
		return nil, errors.New("private file size is invalid")
	}
	buffer := make([]byte, int(size))
	n, err := file.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		clear(buffer)
		return nil, err
	}
	if n != len(buffer) {
		clear(buffer)
		return nil, errors.New("private file read was incomplete")
	}
	var extra [1]byte
	n, err = file.ReadAt(extra[:], size)
	if n != 0 || !errors.Is(err, io.EOF) {
		clear(buffer)
		return nil, errors.New("private file contains trailing bytes")
	}
	return buffer, nil
}
