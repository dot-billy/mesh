//go:build linux

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestChildRuntimeGateTreatsMissingRuntimeDirectoryAsClosed(t *testing.T) {
	gate := newTestChildRuntimeGate(t, filepath.Join(t.TempDir(), "missing"), false)
	open, err := gate.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("missing agent RuntimeDirectory was treated as authorized")
	}
	if err := gate.ProveRuntimeDirectoryAbsent(); err != nil {
		t.Fatalf("prove missing RuntimeDirectory: %v", err)
	}
}

func TestChildRuntimeGateDoesNotTreatEmptyRuntimeDirectoryAsAbsent(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "mesh-agent")
	gate := newTestChildRuntimeGate(t, directory, true)
	open, err := gate.Inspect()
	if err != nil || open {
		t.Fatalf("empty RuntimeDirectory inspection=(%t,%v)", open, err)
	}
	if err := gate.ProveRuntimeDirectoryAbsent(); err == nil {
		t.Fatal("empty but present agent RuntimeDirectory passed absence proof")
	}
}

func TestChildRuntimeGateAcceptsOnlyExactLivePublication(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "mesh-agent")
	gate := newTestChildRuntimeGate(t, directory, true)
	writeChildRuntimeGateTestFile(t, filepath.Join(directory, childRuntimeGateName), childRuntimeGateContent)
	open, err := gate.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if !open {
		t.Fatal("exact agent readiness marker was not accepted")
	}

	outside := filepath.Join(directory, "outside")
	if err := os.Link(filepath.Join(directory, childRuntimeGateName), outside); err != nil {
		t.Fatal(err)
	}
	if open, err := gate.Inspect(); err == nil || open {
		t.Fatalf("multiply linked live marker inspection=(%t,%v), want closed error", open, err)
	}
}

func TestChildRuntimeGateReportsExactInterruptedPublications(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "truncated recovery",
			setup: func(t *testing.T, directory string) {
				writeChildRuntimeGateTestFile(t, filepath.Join(directory, childRuntimeGateRecoveryName), childRuntimeGateContent[:9])
			},
		},
		{
			name: "complete recovery",
			setup: func(t *testing.T, directory string) {
				writeChildRuntimeGateTestFile(t, filepath.Join(directory, childRuntimeGateRecoveryName), childRuntimeGateContent)
			},
		},
		{
			name: "linked live and recovery",
			setup: func(t *testing.T, directory string) {
				recovery := filepath.Join(directory, childRuntimeGateRecoveryName)
				writeChildRuntimeGateTestFile(t, recovery, childRuntimeGateContent)
				if err := os.Link(recovery, filepath.Join(directory, childRuntimeGateName)); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "mesh-agent")
			gate := newTestChildRuntimeGate(t, directory, true)
			test.setup(t, directory)
			open, err := gate.Inspect()
			if open || !errors.Is(err, errChildRuntimeGatePublicationPending) {
				t.Fatalf("interrupted publication inspection=(%t,%v)", open, err)
			}
		})
	}
}

func TestChildRuntimeGateRejectsMalformedState(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "wrong content",
			setup: func(t *testing.T, directory string) {
				writeChildRuntimeGateTestFile(t, filepath.Join(directory, childRuntimeGateName), []byte("not authorized\n"))
			},
		},
		{
			name: "wrong mode",
			setup: func(t *testing.T, directory string) {
				path := filepath.Join(directory, childRuntimeGateName)
				writeChildRuntimeGateTestFile(t, path, childRuntimeGateContent)
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, directory string) {
				target := filepath.Join(directory, "target")
				writeChildRuntimeGateTestFile(t, target, childRuntimeGateContent)
				if err := os.Symlink(target, filepath.Join(directory, childRuntimeGateName)); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "mesh-agent")
			gate := newTestChildRuntimeGate(t, directory, true)
			test.setup(t, directory)
			if open, err := gate.Inspect(); err == nil || open {
				t.Fatalf("malformed marker inspection=(%t,%v), want closed error", open, err)
			}
		})
	}
}

func newTestChildRuntimeGate(t *testing.T, directory string, create bool) *filesystemChildRuntimeGate {
	t.Helper()
	if create {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gate, err := newFilesystemChildRuntimeGate(directory, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func writeChildRuntimeGateTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, childRuntimeGateMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, childRuntimeGateMode); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		t.Fatalf("test marker has unexpected owner: %+v", stat)
	}
}
