//go:build linux

package linuxinstall

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	releasetrust "mesh/internal/release"
)

const linuxAnonymousTemporaryFlag = 0x410000 // O_TMPFILE on supported Linux architectures.

// CaptureArtifact snapshots an untrusted local source into an unlinked,
// root-private file while authenticating the exact bytes copied. This protects
// extraction from both pathname substitution and concurrent in-place writes to
// an operator-owned source inode. The caller owns and must close the result.
func CaptureArtifact(sourcePath string, expected releasetrust.Artifact, privateRoot *os.Root) (*os.File, error) {
	if privateRoot == nil {
		return nil, errors.New("private installer root is required")
	}
	rootInfo, err := privateRoot.Stat(".")
	rootStat, statOK := rootInfoSys(rootInfo)
	if err != nil || !statOK || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootInfo.Mode().Perm() != 0o700 || rootInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		rootStat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("private installer root must be a real effective-user-owned mode-0700 directory without special bits")
	}
	before, err := os.Lstat(sourcePath)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("source artifact must be a regular file, not a symlink")
	}
	descriptor, err := syscall.Open(sourcePath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	source := os.NewFile(uintptr(descriptor), sourcePath)
	if source == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("open source artifact descriptor")
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("source artifact changed while opening")
	}
	return captureArtifactFile(source, expected, privateRoot)
}

func rootInfoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func captureArtifactFile(source *os.File, expected releasetrust.Artifact, privateRoot *os.Root) (captured *os.File, returnErr error) {
	// O_TMPFILE makes the potentially large authenticated copy anonymous from
	// its first byte, so SIGKILL or power loss cannot strand multi-gigabyte
	// .artifact-* files in /var/lib/mesh-installer.
	destination, err := privateRoot.OpenFile(".", os.O_RDWR|linuxAnonymousTemporaryFlag, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create anonymous captured artifact: %w", err)
	}
	defer func() {
		if destination != nil {
			returnErr = errors.Join(returnErr, destination.Close())
		}
	}()
	if err := releasetrust.VerifyArtifact(io.TeeReader(source, destination), expected); err != nil {
		return nil, fmt.Errorf("authenticate captured artifact: %w", err)
	}
	if err := destination.Sync(); err != nil {
		return nil, fmt.Errorf("sync captured artifact: %w", err)
	}
	info, err := destination.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateAnonymousPrivateRegular(info, releasetrust.MaxArtifactSize); err != nil || info.Size() != expected.Size {
		return nil, errors.New("captured artifact private file is invalid")
	}
	readerDescriptor, err := syscall.Open("/proc/self/fd/"+strconv.FormatUint(uint64(destination.Fd()), 10), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("reopen anonymous captured artifact read-only: %w", err)
	}
	reader := os.NewFile(uintptr(readerDescriptor), "authenticated-linux-bundle")
	if reader == nil {
		_ = syscall.Close(readerDescriptor)
		return nil, errors.New("anchor read-only captured artifact")
	}
	readerOwned := true
	defer func() {
		if readerOwned {
			if err := reader.Close(); err != nil && returnErr == nil {
				returnErr = err
			}
		}
	}()
	readerInfo, err := reader.Stat()
	if err != nil || !os.SameFile(info, readerInfo) {
		return nil, errors.New("captured artifact changed while opening read-only")
	}
	if err := destination.Close(); err != nil {
		return nil, fmt.Errorf("close captured artifact writer: %w", err)
	}
	destination = nil
	readerOwned = false
	return reader, nil
}

func validateAnonymousPrivateRegular(info os.FileInfo, maxSize int64) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > maxSize {
		return errors.New("anonymous artifact must be a bounded mode-0600 regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 0 {
		return errors.New("anonymous artifact must be effective-user-owned and unlinked")
	}
	return nil
}

func syncRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
