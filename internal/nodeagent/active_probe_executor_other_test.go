//go:build !linux

package nodeagent

import (
	"context"
	"testing"

	"mesh/internal/runtimetelemetry"
)

func TestUnsupportedActiveProbeDoesNotAttemptIO(t *testing.T) {
	executor := newPlatformActiveProbeExecutor()
	if executor.Supported() {
		t.Fatal("non-Linux active probe executor reported support")
	}
	if result := executor.Probe(context.Background(), activeProbePlan{}); result != runtimetelemetry.UnsupportedActiveProbe() {
		t.Fatalf("unsupported result = %#v", result)
	}
}
