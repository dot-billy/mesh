package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVerifierHasOneNarrowCommandSurface(t *testing.T) {
	var output bytes.Buffer
	if code := run([]string{"--help"}, &bytes.Buffer{}, &output); code != 0 {
		t.Fatalf("help exited %d", code)
	}
	help := output.String()
	for _, required := range []string{"--root", "--expected-root-sha256", "--handoff", "--expected-handoff-sha256", "--handoff-anchor", "--manifest", "--signature", "--installer"} {
		if !strings.Contains(help, required) {
			t.Fatalf("help omits %s: %q", required, help)
		}
	}
	for _, forbidden := range []string{"generate-key", "export-public", "create-root", " sign ", "private-key", "output-file"} {
		if strings.Contains(help, forbidden) {
			t.Fatalf("help exposes forbidden capability %q: %q", forbidden, help)
		}
	}
}

func TestVerifierArgumentsAndTimeFailClosed(t *testing.T) {
	var diagnostics bytes.Buffer
	if code := run(nil, &bytes.Buffer{}, &diagnostics); code == 0 || !strings.Contains(diagnostics.String(), "are required") {
		t.Fatalf("empty invocation returned %d, %q", code, diagnostics.String())
	}
	if _, err := parseVerificationTime("2026-07-21T12:00:00+00:00"); err == nil {
		t.Fatal("noncanonical verification time accepted")
	}
	if _, err := parseVerificationTime("2026-07-21T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	diagnostics.Reset()
	code := run([]string{
		"--root", "root", "--expected-root-sha256", strings.Repeat("0", 64),
		"--handoff", "handoff", "--expected-handoff-sha256", strings.Repeat("1", 64),
		"--manifest", "manifest", "--signature", "signature", "--installer", "installer",
	}, &bytes.Buffer{}, &diagnostics)
	if code == 0 || !strings.Contains(diagnostics.String(), "exactly one trust anchor") {
		t.Fatalf("mixed trust anchors returned %d, %q", code, diagnostics.String())
	}
	diagnostics.Reset()
	code = run([]string{
		"--root", "root", "--handoff", "handoff",
		"--expected-handoff-sha256", strings.Repeat("1", 64), "--handoff-anchor", "anchor",
		"--manifest", "manifest", "--signature", "signature", "--installer", "installer",
	}, &bytes.Buffer{}, &diagnostics)
	if code == 0 || !strings.Contains(diagnostics.String(), "exactly one trust anchor") {
		t.Fatalf("mixed handoff authorities returned %d, %q", code, diagnostics.String())
	}
}
