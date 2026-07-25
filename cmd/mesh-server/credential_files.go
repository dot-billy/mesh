package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxCredentialFileSize = 4096

// readPrivateCredentialFile keeps production recovery credentials out of the
// process environment. The path and descriptor checks mirror the identity
// policy boundary: one owner-controlled regular file, no symlinked directory
// components, no hard links, and no permissive group/other bits.
func readPrivateCredentialFile(flagName, path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return "", fmt.Errorf("%s must be a clean absolute file path", flagName)
	}
	if err := rejectCredentialSymlinkPath(flagName, filepath.Dir(path)); err != nil {
		return "", err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", flagName, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxCredentialFileSize {
		return "", fmt.Errorf("%s must be a private, owner-controlled, single-link regular file", flagName)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", flagName, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !identityConfigFilePrivate(file, after) {
		return "", fmt.Errorf("%s changed while opening", flagName)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCredentialFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", flagName, err)
	}
	if len(raw) < 1 || len(raw) > maxCredentialFileSize || bytes.IndexByte(raw, 0) >= 0 {
		return "", fmt.Errorf("%s is empty, oversized, or contains a NUL byte", flagName)
	}
	value := string(raw)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if value == "" || strings.TrimSpace(value) != value || (string(raw) != value && string(raw) != value+"\n") {
		return "", fmt.Errorf("%s must contain one canonical credential with an optional final newline", flagName)
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return "", fmt.Errorf("%s must contain one canonical printable-ASCII credential", flagName)
		}
	}
	return value, nil
}

func rejectCredentialSymlinkPath(flagName, directory string) error {
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect %s path: %w", flagName, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s path component %q is not a real directory", flagName, current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func resolveProductionCredential(flagName, path, environmentName string) (string, error) {
	environmentValue := strings.TrimSpace(os.Getenv(environmentName))
	if path != "" && environmentValue != "" {
		return "", fmt.Errorf("%s and %s cannot both be set", flagName, environmentName)
	}
	if path != "" {
		return readPrivateCredentialFile(flagName, path)
	}
	if environmentValue == "" {
		return "", errors.New(environmentName + " or " + flagName + " is required")
	}
	return environmentValue, nil
}
