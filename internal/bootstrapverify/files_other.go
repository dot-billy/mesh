//go:build !linux

package bootstrapverify

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func readStableRegularFile(_ string, path string, limit int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("path cannot be empty")
	}
	if limit <= 0 {
		return nil, errors.New("file size limit must be positive")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file, not a symlink")
	}
	if before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Mode() != before.Mode() || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("input changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, before.Size()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != before.Size() {
		return nil, errors.New("input was truncated or appended while reading")
	}
	opened, openedErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if openedErr != nil || pathErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, current) || opened.Mode() != before.Mode() || current.Mode() != before.Mode() || opened.Size() != before.Size() || current.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) || !current.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("input identity, size, mode, or timestamp changed")
	}
	return raw, nil
}
