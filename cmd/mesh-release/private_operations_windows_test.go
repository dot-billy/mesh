//go:build windows

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateKeyOperationsFailClosedOnWindows(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.json")
	tests := map[string]func(*bytes.Buffer) error{
		"generate-key": func(output *bytes.Buffer) error {
			return generateKey([]string{"--private", privatePath}, output)
		},
		"export-public": func(output *bytes.Buffer) error {
			return exportPublic([]string{"--private", privatePath, "--public", filepath.Join(directory, "public.json")}, output)
		},
		"sign": func(output *bytes.Buffer) error {
			return sign([]string{"--private", privatePath, "--manifest", filepath.Join(directory, "release.json"), "--signature", filepath.Join(directory, "release.sig.json")}, output)
		},
	}
	for name, operation := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			err := operation(&output)
			if err == nil || !strings.Contains(err.Error(), "Windows ACL") || !strings.Contains(err.Error(), "POSIX signing host") {
				t.Fatalf("operation returned %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("operation wrote output %q", output.String())
			}
		})
	}
	if _, _, err := loadPrivateKey(privatePath); err == nil || !strings.Contains(err.Error(), "Windows ACL") {
		t.Fatalf("direct private-key load returned %v", err)
	}
	if _, err := readPrivateFile(privatePath, 1); err == nil || !strings.Contains(err.Error(), "Windows ACL") {
		t.Fatalf("direct private-file read returned %v", err)
	}
	if _, err := os.Lstat(privatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private-key output exists: %v", err)
	}
}
