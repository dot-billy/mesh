//go:build !linux

package main

import (
	"bytes"
	"fmt"
	"os"
)

func readAuthoringPublicFile(_ string, path string, limit int) ([]byte, error) {
	return readRegularFile(path, limit)
}

func writeAuthoringPublicFile(role, path string, content []byte, mode os.FileMode) error {
	if err := writeNewFile(path, content, mode); err != nil {
		return err
	}
	readback, err := readRegularFile(path, len(content))
	if err != nil {
		return fmt.Errorf("read back %s: %w", role, err)
	}
	if !bytes.Equal(readback, content) {
		return fmt.Errorf("%s readback differs from requested bytes", role)
	}
	return nil
}
