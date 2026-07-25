//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
)

func readAuthoringPublicFile(role, path string, limit int) ([]byte, error) {
	input, err := openSnapshotInput(snapshotInputSpec{role: role, path: path, limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	defer input.file.Close()
	raw, err := readStableSnapshotInput(input, snapshotAssemblyHooks{})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func writeAuthoringPublicFile(role, path string, content []byte, mode os.FileMode) error {
	if err := writeNewFile(path, content, mode); err != nil {
		return err
	}
	readback, err := readAuthoringPublicFile(role, path, len(content))
	if err != nil {
		return fmt.Errorf("read back %s: %w", role, err)
	}
	if !bytes.Equal(readback, content) {
		return fmt.Errorf("%s readback differs from requested bytes", role)
	}
	return nil
}
