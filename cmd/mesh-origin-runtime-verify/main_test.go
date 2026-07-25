package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"mesh/internal/origindeploy"
	"mesh/internal/releaseorigin"
)

type noCallRunner struct{}

func (noCallRunner) InspectContainer(context.Context, string, string, string) ([]byte, error) {
	panic("unexpected Docker container inspection")
}

func (noCallRunner) InspectImage(context.Context, string, string, string) ([]byte, error) {
	panic("unexpected Docker image inspection")
}

func TestRunRejectsIncompleteAndAmbiguousArgumentsWithoutOutput(t *testing.T) {
	inspector := func(string) (releaseorigin.GenerationReceipt, error) {
		panic("unexpected generation inspection")
	}
	for _, arguments := range [][]string{
		nil,
		{"--image-receipt", "/receipt"},
		{"--image-receipt", "/receipt", "--compose-config", "/compose", "extra"},
		{"--image-receipt", "/receipt", "--compose-config", "/compose", "--output", ""},
	} {
		var output bytes.Buffer
		if err := run(arguments, &output, func() time.Time { return time.Now().UTC() }, noCallRunner{}, origindeploy.GenerationInspector(inspector)); err == nil || output.Len() != 0 {
			t.Fatalf("run(%q) = output %q, error %v", arguments, output.Bytes(), err)
		}
	}
}
