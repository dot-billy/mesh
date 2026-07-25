package windowsbundle

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"time"
)

const tarBlockSize int64 = 512

func canonicalHeader(name string, mode uint32, size int64, modTime time.Time) *tar.Header {
	return &tar.Header{
		Name: name, Mode: int64(mode), Uid: 0, Gid: 0, Size: size,
		ModTime: modTime.UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
		Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
	}
}

func writeMember(writer *tar.Writer, name string, mode uint32, content []byte, modTime time.Time) error {
	if writer == nil {
		return errors.New("tar writer is nil")
	}
	if err := writer.WriteHeader(canonicalHeader(name, mode, int64(len(content)), modTime)); err != nil {
		return fmt.Errorf("write canonical USTAR header for %s: %w", name, err)
	}
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("write canonical USTAR payload for %s: %w", name, err)
	}
	return nil
}

func canonicalHeaderBlock(name string, mode uint32, size int64, modTime time.Time) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(canonicalHeader(name, mode, size, modTime)); err != nil {
		return nil, err
	}
	if buffer.Len() != int(tarBlockSize) {
		return nil, fmt.Errorf("canonical USTAR header is %d bytes", buffer.Len())
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

func paddedSize(size int64) int64 {
	if remainder := size % tarBlockSize; remainder != 0 {
		return size + tarBlockSize - remainder
	}
	return size
}

func exactArchiveSize(packageSize int64, entries []Entry) (int64, error) {
	if packageSize <= 0 || packageSize > maxPackageJSONSize {
		return 0, errors.New("package.json size is outside the supported bound")
	}
	total := tarBlockSize + paddedSize(packageSize) + 2*tarBlockSize
	for _, entry := range entries {
		member := tarBlockSize + paddedSize(entry.Size)
		if member < 0 || total > MaxArchiveSize-member {
			return 0, errors.New("archive size exceeds the supported bound")
		}
		total += member
	}
	return total, nil
}
