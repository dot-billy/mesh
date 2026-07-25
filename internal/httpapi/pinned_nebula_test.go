package httpapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func pinnedNebulaCertForTest(t *testing.T) string {
	t.Helper()

	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	rawPath, err := exec.Command(goBinary, "tool", "-n", "nebula-cert").Output()
	if err != nil {
		t.Fatalf("resolve pinned nebula-cert: %v", err)
	}
	path := strings.TrimSpace(string(rawPath))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect pinned nebula-cert: %v", err)
	}
	if !filepath.IsAbs(path) || !info.Mode().IsRegular() {
		t.Fatal("pinned nebula-cert did not resolve to one physical executable")
	}
	version, err := exec.Command(path, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("read pinned nebula-cert version: %v", err)
	}
	if strings.TrimSpace(string(version)) != "Version: 1.10.3" {
		t.Fatalf("pinned nebula-cert version is not 1.10.3")
	}
	return path
}
