//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateKeyRequiresEffectiveOwnerAndExactMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateFileSecurityForUID(info, uint32(os.Geteuid())+1); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("wrong owner returned %v", err)
	}
	for _, mode := range []os.FileMode{0o000, 0o200, 0o440, 0o640, 0o700} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePrivateFileSecurity(info); err == nil || !strings.Contains(err.Error(), "0400 or 0600") {
			t.Fatalf("mode %04o returned %v", mode, err)
		}
	}
}
