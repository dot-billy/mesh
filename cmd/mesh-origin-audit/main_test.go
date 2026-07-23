package main

import (
	"bytes"
	"testing"
	"time"
)

func TestRunRejectsIncompleteAndAmbiguousArgumentsWithoutOutput(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"--generation", "/tmp/generation"},
		{"--generation", "/tmp/generation", "--origin", "https://origin.example", "extra"},
		{"--generation", "/tmp/generation", "--origin", "https://origin.example", "--output", ""},
	} {
		var output bytes.Buffer
		if err := run(arguments, &output, func() time.Time { return time.Now().UTC() }); err == nil || output.Len() != 0 {
			t.Fatalf("run(%q) = output %q, error %v", arguments, output.Bytes(), err)
		}
	}
}
