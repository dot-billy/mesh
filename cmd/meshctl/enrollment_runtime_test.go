package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mesh/internal/nodeagent"
)

func TestInspectEnrollmentRuntimeRequiresOneMatchedInstalledPair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixture")
	}
	private := t.TempDir()
	nebula, nebulaCert := writeFakeNebulaPair(t, private, "1.10.3", "1.10.3")
	meshctl := filepath.Join(private, "meshctl")
	writeFakeExecutable(t, meshctl, "#!/bin/sh\nexit 0\n")

	prepared, err := inspectEnrollmentRuntime(
		context.Background(), nebula, nebulaCert, meshctl, true, nodeagent.ExecCommandRunner{},
	)
	if err != nil {
		t.Fatalf("inspect matched runtime pair: %v", err)
	}
	if prepared.nebulaBinary != nebula || prepared.nebulaCertBinary != nebulaCert || prepared.version != "1.10.3" {
		t.Fatalf("prepared runtime = %#v", prepared)
	}

	other := t.TempDir()
	otherCert := filepath.Join(other, "nebula-cert")
	writeFakeExecutable(t, otherCert, "#!/bin/sh\necho 'Version: 1.10.3'\n")
	if _, err := inspectEnrollmentRuntime(
		context.Background(), nebula, otherCert, meshctl, true, nodeagent.ExecCommandRunner{},
	); err == nil || !strings.Contains(err.Error(), "one authenticated installed release") {
		t.Fatalf("split runtime pair error = %v", err)
	}
}

func TestInspectEnrollmentRuntimeRejectsVersionMismatchAndOldCert(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixture")
	}
	for _, test := range []struct {
		name        string
		nebula      string
		nebulaCert  string
		errorSubstr string
	}{
		{name: "mismatch", nebula: "1.10.3", nebulaCert: "1.11.0", errorSubstr: "nebula reports version 1.10.3 but nebula-cert reports 1.11.0"},
		{name: "old cert", nebula: "1.10.3", nebulaCert: "1.10.2", errorSubstr: "nebula-cert: Nebula 1.10.2 is unsupported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			private := t.TempDir()
			nebula, nebulaCert := writeFakeNebulaPair(t, private, test.nebula, test.nebulaCert)
			meshctl := filepath.Join(private, "meshctl")
			writeFakeExecutable(t, meshctl, "#!/bin/sh\nexit 0\n")
			if _, err := inspectEnrollmentRuntime(
				context.Background(), nebula, nebulaCert, meshctl, true, nodeagent.ExecCommandRunner{},
			); err == nil || !strings.Contains(err.Error(), test.errorSubstr) {
				t.Fatalf("runtime mismatch error = %v", err)
			}
		})
	}
}

func TestEnrollmentChecksRuntimeBeforeReadingTokenOrCreatingTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixture")
	}
	private := t.TempDir()
	reader := &failOnRead{err: errors.New("token input must not be read")}
	statePath := filepath.Join(private, "state", "agent.json")
	outputPath := filepath.Join(private, "output", "nebula")
	err := enrollWithIO([]string{
		"--server", "https://mesh.example.com",
		"--token-file", "-",
		"--state", statePath,
		"--output", outputPath,
		"--nebula", filepath.Join(private, "missing-nebula"),
		"--nebula-cert", filepath.Join(private, "missing-nebula-cert"),
	}, reader, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "Nebula runtime prerequisite failed before enrollment") ||
		!strings.Contains(err.Error(), "mesh-install install-online EXACT_BUNDLE_URL") {
		t.Fatalf("missing runtime error = %v", err)
	}
	if reader.reads != 0 {
		t.Fatalf("enrollment read token %d time(s) before runtime verification", reader.reads)
	}
	for _, path := range []string{filepath.Dir(statePath), filepath.Dir(outputPath)} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("enrollment created %q before runtime verification: %v", path, statErr)
		}
	}
}

type failOnRead struct {
	reads int
	err   error
}

func (r *failOnRead) Read([]byte) (int, error) {
	r.reads++
	return 0, r.err
}

func writeFakeNebulaPair(t *testing.T, directory, nebulaVersion, nebulaCertVersion string) (string, string) {
	t.Helper()
	nebula := filepath.Join(directory, "nebula")
	nebulaCert := filepath.Join(directory, "nebula-cert")
	writeFakeExecutable(t, nebula, "#!/bin/sh\necho 'Version: "+nebulaVersion+"'\n")
	writeFakeExecutable(t, nebulaCert, "#!/bin/sh\necho 'Version: "+nebulaCertVersion+"'\n")
	return nebula, nebulaCert
}

func writeFakeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

var _ io.Reader = (*failOnRead)(nil)
