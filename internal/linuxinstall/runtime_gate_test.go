//go:build linux

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemRuntimeGateExactIdempotentLifecycle(t *testing.T) {
	directory := t.TempDir()
	gate, err := newFilesystemRuntimeGate(directory)
	if err != nil {
		t.Fatal(err)
	}
	if open, err := gate.Inspect(); err != nil || open {
		t.Fatalf("initial gate open=%t err=%v", open, err)
	}
	if err := gate.Open(); err != nil {
		t.Fatal(err)
	}
	if err := gate.Open(); err != nil {
		t.Fatalf("idempotent open: %v", err)
	}
	if open, err := gate.Inspect(); err != nil || !open {
		t.Fatalf("published gate open=%t err=%v", open, err)
	}
	content, err := os.ReadFile(filepath.Join(directory, runtimeGateName))
	if err != nil || string(content) != string(runtimeGateContent) {
		t.Fatalf("gate content=%q err=%v", content, err)
	}
	if info, err := os.Lstat(filepath.Join(directory, runtimeGateName)); err != nil || info.Mode().Perm() != runtimeGateMode {
		t.Fatalf("gate mode=%v err=%v", info, err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if open, err := gate.Inspect(); err != nil || open {
		t.Fatalf("closed gate open=%t err=%v", open, err)
	}
}

func TestFilesystemRuntimeGateResumesAndClosesCrashRecoveryFile(t *testing.T) {
	directory := t.TempDir()
	gate, err := newFilesystemRuntimeGate(directory)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(directory, runtimeGateTemporaryName)
	if err := os.WriteFile(temporary, runtimeGateContent, runtimeGateMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(temporary, runtimeGateMode); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Inspect(); err == nil || !strings.Contains(err.Error(), "unfinished") {
		t.Fatalf("unfinished publication accepted: %v", err)
	}
	if err := gate.Open(); err != nil {
		t.Fatalf("resume exact publication: %v", err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery name remains: %v", err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, runtimeGateContent, runtimeGateMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(temporary, runtimeGateMode); err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err != nil {
		t.Fatalf("close interrupted open: %v", err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery name remains after close: %v", err)
	}
}

func TestFilesystemRuntimeGateRecoversCrashTruncatedPrefix(t *testing.T) {
	for _, operation := range []string{"open", "close"} {
		t.Run(operation, func(t *testing.T) {
			directory := t.TempDir()
			gate, err := newFilesystemRuntimeGate(directory)
			if err != nil {
				t.Fatal(err)
			}
			temporary := filepath.Join(directory, runtimeGateTemporaryName)
			if err := os.WriteFile(temporary, runtimeGateContent[:7], runtimeGateMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(temporary, runtimeGateMode); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "open":
				if err := gate.Open(); err != nil {
					t.Fatalf("restart interrupted open: %v", err)
				}
				if open, err := gate.Inspect(); err != nil || !open {
					t.Fatalf("recovered gate open=%t err=%v", open, err)
				}
			case "close":
				if err := gate.Close(); err != nil {
					t.Fatalf("quarantine interrupted open: %v", err)
				}
				if open, err := gate.Inspect(); err != nil || open {
					t.Fatalf("quarantined gate open=%t err=%v", open, err)
				}
			}
		})
	}
}

func TestFilesystemRuntimeGateRejectsUnexpectedFiles(t *testing.T) {
	for _, test := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{name: "content", content: []byte("not-the-gate\n"), mode: runtimeGateMode},
		{name: "mode", content: runtimeGateContent, mode: 0o600},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			gate, err := newFilesystemRuntimeGate(directory)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, runtimeGateName)
			if err := os.WriteFile(path, test.content, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := gate.Inspect(); err == nil {
				t.Fatal("unexpected runtime gate accepted")
			}
			if err := gate.Open(); err == nil {
				t.Fatal("unexpected runtime gate overwritten")
			}
			if err := gate.Close(); err == nil {
				t.Fatal("unexpected runtime gate removed")
			}
		})
	}
}
