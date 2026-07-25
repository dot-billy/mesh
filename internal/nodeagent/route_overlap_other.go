//go:build !linux

package nodeagent

import (
	"context"

	"mesh/internal/runtimetelemetry"
)

type unsupportedRouteOverlapInspector struct{}

func newPlatformRouteOverlapInspector() routeOverlapInspector {
	return unsupportedRouteOverlapInspector{}
}

func (unsupportedRouteOverlapInspector) Supported() bool { return false }

func (unsupportedRouteOverlapInspector) Inspect(context.Context, verifiedRuntimeTopology) runtimetelemetry.RouteOverlapResult {
	return runtimetelemetry.UnsupportedRouteOverlap()
}
