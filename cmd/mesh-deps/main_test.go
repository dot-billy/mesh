package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunRejectsUnsupportedOrOverrideInputs(t *testing.T) {
	tests := [][]string{
		nil,
		{"other"},
		{"fetch-nebula"},
		{"fetch-nebula", "--os", "linux", "--arch", "386", "--output-dir", "new"},
		{"fetch-nebula", "--os", "linux", "--arch", "amd64", "--output-dir", "new", "extra"},
		{"fetch-nebula", "--os", "linux", "--arch", "amd64", "--output-dir", "new", "--url", "https://evil.example"},
		{"fetch-nebula", "--os", "linux", "--arch", "amd64", "--output-dir", "new", "--hash", strings.Repeat("0", 64)},
		{"fetch-nebula", "--os", "linux", "--arch", "amd64", "--output-dir", "new", "--version", "latest"},
		{"build-nebula-observer"},
		{"build-nebula-observer", "--arch", "386", "--output-dir", "new"},
		{"build-nebula-observer", "--arch", "amd64", "--output-dir", "new", "extra"},
		{"build-nebula-observer", "--arch", "amd64", "--output-dir", "new", "--source", "/tmp/alternate"},
		{"build-nebula-observer", "--arch", "amd64", "--output-dir", "new", "--patch", "alternate.patch"},
		{"build-nebula-observer", "--arch", "amd64", "--output-dir", "new", "--toolchain", "latest"},
		{"build-nebula-windows-runtime"},
		{"build-nebula-windows-runtime", "--arch", "386", "--output-dir", "new"},
		{"build-nebula-windows-runtime", "--arch", "amd64", "--output-dir", "new", "extra"},
		{"build-nebula-windows-runtime", "--arch", "amd64", "--output-dir", "new", "--source", "/tmp/alternate"},
		{"build-nebula-darwin-runtime"},
		{"build-nebula-darwin-runtime", "--arch", "386", "--output-dir", "new"},
		{"build-nebula-darwin-runtime", "--arch", "amd64", "--output-dir", "new", "extra"},
		{"build-nebula-darwin-runtime", "--arch", "amd64", "--output-dir", "new", "--source", "/tmp/alternate"},
	}
	for _, args := range tests {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments accepted: %q", args)
		}
	}
}
