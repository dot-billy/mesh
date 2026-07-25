package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBootstrapCommandUsageAndArgumentsFailClosed(t *testing.T) {
	for _, command := range []string{"create-bootstrap-manifest", "verify-bootstrap"} {
		if !strings.Contains(releaseUsage, command) {
			t.Fatalf("release usage omits %s: %q", command, releaseUsage)
		}
	}
	if err := createBootstrapManifest(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty create-bootstrap-manifest accepted")
	}
	if err := verifyBootstrap(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty verify-bootstrap accepted")
	}
	if _, err := parseCommandTime("2026-07-20T12:00:00+00:00", "--now"); err == nil {
		t.Fatal("noncanonical verification time accepted")
	}
}
