//go:build darwin

package nodeagent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const darwinNativeFaultTestEnvironment = "MESH_DARWIN_NATIVE_FAULT_TEST"

func requireDarwinNativeRoot(t *testing.T) {
	t.Helper()
	if os.Getenv(darwinNativeFaultTestEnvironment) != "1" {
		t.Skip("set MESH_DARWIN_NATIVE_FAULT_TEST=1 through the native harness")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("native Darwin path-security fault injection requires root:wheel")
	}
}

func TestDarwinNativePathSecurityFaults(t *testing.T) {
	requireDarwinNativeRoot(t)
	root, err := os.MkdirTemp("/private/var/db", ".mesh-native-path-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = exec.Command("/bin/chmod", "-RN", root).Run()
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove exact native fault-test directory: %v", err)
		}
	}()

	executable := filepath.Join(root, "nebula")
	payload, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, payload, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(executable, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := InspectDarwinPackagedExecutable(executable); err != nil {
		t.Fatalf("exact packaged executable: %v", err)
	}

	t.Run("writable executable", func(t *testing.T) {
		if err := os.Chmod(executable, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(executable, 0o555)
		if err := InspectDarwinPackagedExecutable(executable); err == nil || !strings.Contains(err.Error(), "mode-0555") {
			t.Fatalf("writable executable validation error = %v", err)
		}
	})

	t.Run("hard link", func(t *testing.T) {
		link := filepath.Join(root, "nebula-hardlink")
		if err := os.Link(executable, link); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(link)
		if err := InspectDarwinPackagedExecutable(executable); err == nil || !strings.Contains(err.Error(), "singly linked") {
			t.Fatalf("hard-linked executable validation error = %v", err)
		}
	})

	t.Run("symlink component", func(t *testing.T) {
		alias := root + "-alias"
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(alias)
		if err := InspectDarwinPackagedExecutable(filepath.Join(alias, "nebula")); err == nil {
			t.Fatal("symlinked executable path was accepted")
		}
	})

	t.Run("extended ACL", func(t *testing.T) {
		output, err := exec.Command("/bin/chmod", "+a", "everyone deny write", executable).CombinedOutput()
		if err != nil {
			t.Fatalf("inject extended ACL: %v: %s", err, output)
		}
		defer exec.Command("/bin/chmod", "-N", executable).Run()
		if err := InspectDarwinPackagedExecutable(executable); err == nil || !strings.Contains(err.Error(), "extended ACL") {
			t.Fatalf("ACL-bearing executable validation error = %v", err)
		}
	})

	gate := filepath.Join(root, "runtime.enabled")
	if err := os.WriteFile(gate, darwinPersistentRuntimeGateContent, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gate, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(gate, 0, 0); err != nil {
		t.Fatal(err)
	}
	if open, err := InspectDarwinPersistentRuntimeGate(gate); err != nil || !open {
		t.Fatalf("exact persistent gate = %v, %v", open, err)
	}
	if err := os.Chmod(gate, 0o600); err != nil {
		t.Fatal(err)
	}
	if open, err := InspectDarwinPersistentRuntimeGate(gate); err == nil || open {
		t.Fatalf("writable persistent gate = %v, %v", open, err)
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	if open, err := InspectDarwinPersistentRuntimeGate(gate); err != nil || open {
		t.Fatalf("absent persistent gate = %v, %v", open, err)
	}

	if _, err := os.Lstat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Fatal("native fault-test directory disappeared before cleanup")
		}
		t.Fatal(err)
	}
}
