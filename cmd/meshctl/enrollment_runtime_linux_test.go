//go:build linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInstalledLinuxRuntimeDirectoryRequiresExactReleaseRoot(t *testing.T) {
	validID := "s00000000000000000001-r0123456789abcdef-a0123456789abcdef"
	if err := validateInstalledRuntimeDirectory(filepath.Join(linuxProductionReleasesRoot, validID, "bin")); err != nil {
		t.Fatalf("valid installed runtime directory: %v", err)
	}
	for _, path := range []string{
		filepath.Join("/tmp/mesh/releases", validID, "bin"),
		filepath.Join(linuxProductionReleasesRoot, "release-latest", "bin"),
		filepath.Join(linuxProductionReleasesRoot, validID, "other"),
	} {
		if err := validateInstalledRuntimeDirectory(path); err == nil ||
			(!strings.Contains(err.Error(), "release root") && !strings.Contains(err.Error(), "release bin")) {
			t.Fatalf("unsafe runtime directory %q error = %v", path, err)
		}
	}
}
