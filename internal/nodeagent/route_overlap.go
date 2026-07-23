package nodeagent

import (
	"context"
	"net/netip"

	"mesh/internal/runtimetelemetry"
)

type routeOverlapInspector interface {
	Supported() bool
	Inspect(context.Context, verifiedRuntimeTopology) runtimetelemetry.RouteOverlapResult
}

type routeInventoryEntry struct {
	prefix         netip.Prefix
	interfaceIndex int
}

func (a *Agent) resolveRouteOverlap(ctx context.Context, bundle Bundle) runtimetelemetry.RouteOverlapResult {
	if ctx == nil || ctx.Err() != nil || a == nil || a.Store == nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	topology, err := verifiedRuntimeTopologyFromBundle(bundle)
	if err != nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	inspector := a.routeOverlapInspector
	if inspector == nil {
		inspector = newPlatformRouteOverlapInspector()
	}
	if inspector == nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	if !inspector.Supported() {
		return runtimetelemetry.UnsupportedRouteOverlap()
	}
	result := inspector.Inspect(ctx, topology)
	if ctx.Err() != nil || runtimetelemetry.ValidateRouteOverlap(result) != nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	return runtimetelemetry.CloneRouteOverlap(result)
}

func routeInventoryOverlaps(network netip.Prefix, overlayInterface int, routes []routeInventoryEntry) (bool, bool) {
	if !network.IsValid() || !network.Addr().Is4() || network != network.Masked() || overlayInterface < 1 {
		return false, false
	}
	for _, route := range routes {
		if !route.prefix.IsValid() || !route.prefix.Addr().Is4() || route.prefix != route.prefix.Masked() || route.prefix.Bits() == 0 || route.interfaceIndex < 0 {
			return false, false
		}
		if route.interfaceIndex == overlayInterface {
			continue
		}
		if route.prefix.Contains(network.Addr()) || network.Contains(route.prefix.Addr()) {
			return true, true
		}
	}
	return false, true
}

// preEnrollmentRouteInventoryOverlaps checks the same bounded non-default
// inventory before a Nebula interface exists. Every intersecting route is a
// collision at this stage, so there is no overlay interface to exclude.
func preEnrollmentRouteInventoryOverlaps(network netip.Prefix, routes []routeInventoryEntry) (bool, bool) {
	if !network.IsValid() || !network.Addr().Is4() || network != network.Masked() {
		return false, false
	}
	for _, route := range routes {
		if !route.prefix.IsValid() || !route.prefix.Addr().Is4() || route.prefix != route.prefix.Masked() || route.prefix.Bits() == 0 || route.interfaceIndex < 0 {
			return false, false
		}
		if route.prefix.Contains(network.Addr()) || network.Contains(route.prefix.Addr()) {
			return true, true
		}
	}
	return false, true
}
