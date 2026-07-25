//go:build !linux

package nodeagent

import (
	"context"

	"mesh/internal/runtimetelemetry"
)

type unsupportedActiveProbeExecutor struct{}

func newPlatformActiveProbeExecutor() activeProbeExecutor { return unsupportedActiveProbeExecutor{} }

func (unsupportedActiveProbeExecutor) Supported() bool { return false }

func (unsupportedActiveProbeExecutor) Probe(context.Context, activeProbePlan) runtimetelemetry.ActiveProbeResult {
	return runtimetelemetry.UnsupportedActiveProbe()
}
