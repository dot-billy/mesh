//go:build linux

package nodeagent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"mesh/internal/runtimetelemetry"
)

func TestLinuxRouteOverlapInspectorExcludesExactOverlayAndDefaultButFindsEveryIntersection(t *testing.T) {
	topology := verifiedRuntimeTopology{
		localAddress: netip.MustParseAddr("10.42.0.9"),
		network:      netip.MustParsePrefix("10.42.0.0/24"),
	}
	interfaces := func() ([]routeInterface, error) {
		return []routeInterface{
			{index: 2, up: true, addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24")}},
			{index: 7, up: true, addresses: []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}},
		}, nil
	}
	tests := []struct {
		name       string
		routes     []routeInventoryEntry
		wantResult runtimetelemetry.RouteOverlapResult
	}{
		{
			name: "only overlay route",
			routes: []routeInventoryEntry{
				{prefix: netip.MustParsePrefix("10.42.0.0/24"), interfaceIndex: 7},
				{prefix: netip.MustParsePrefix("10.42.0.9/32"), interfaceIndex: 7},
				{prefix: netip.MustParsePrefix("192.0.2.0/24"), interfaceIndex: 2},
			},
			wantResult: runtimetelemetry.ObservedRouteOverlap(false),
		},
		{
			name: "broader private route",
			routes: []routeInventoryEntry{
				{prefix: netip.MustParsePrefix("10.0.0.0/8"), interfaceIndex: 2},
				{prefix: netip.MustParsePrefix("10.42.0.0/24"), interfaceIndex: 7},
			},
			wantResult: runtimetelemetry.ObservedRouteOverlap(true),
		},
		{
			name: "narrower policy route",
			routes: []routeInventoryEntry{
				{prefix: netip.MustParsePrefix("10.42.0.128/25"), interfaceIndex: 0},
				{prefix: netip.MustParsePrefix("10.42.0.0/24"), interfaceIndex: 7},
			},
			wantResult: runtimetelemetry.ObservedRouteOverlap(true),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspector := &linuxRouteOverlapInspector{
				interfaces: interfaces,
				routes:     func() ([]routeInventoryEntry, error) { return test.routes, nil },
			}
			if got := inspector.Inspect(context.Background(), topology); got.State != test.wantResult.State || got.Overlap != test.wantResult.Overlap || got.SampleAgeMS == nil || *got.SampleAgeMS != 0 {
				t.Fatalf("Inspect = %#v, want %#v", got, test.wantResult)
			}
		})
	}
}

func TestLinuxRouteOverlapInspectorFailsClosedOnAmbiguousInterfaceInventoryOrReadFailure(t *testing.T) {
	topology := verifiedRuntimeTopology{localAddress: netip.MustParseAddr("10.42.0.9"), network: netip.MustParsePrefix("10.42.0.0/24")}
	tests := []struct {
		name       string
		interfaces func() ([]routeInterface, error)
		routes     func() ([]routeInventoryEntry, error)
	}{
		{
			name: "missing overlay interface",
			interfaces: func() ([]routeInterface, error) {
				return []routeInterface{{index: 2, up: true, addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24")}}}, nil
			},
			routes: func() ([]routeInventoryEntry, error) { return nil, nil },
		},
		{
			name: "duplicate overlay address",
			interfaces: func() ([]routeInterface, error) {
				address := []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}
				return []routeInterface{{index: 7, up: true, addresses: address}, {index: 8, up: true, addresses: address}}, nil
			},
			routes: func() ([]routeInventoryEntry, error) { return nil, nil },
		},
		{
			name:       "interface read failure",
			interfaces: func() ([]routeInterface, error) { return nil, errors.New("private detail") },
			routes:     func() ([]routeInventoryEntry, error) { return nil, nil },
		},
		{
			name: "route read failure",
			interfaces: func() ([]routeInterface, error) {
				return []routeInterface{{index: 7, up: true, addresses: []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}}}, nil
			},
			routes: func() ([]routeInventoryEntry, error) { return nil, errors.New("private detail") },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspector := &linuxRouteOverlapInspector{interfaces: test.interfaces, routes: test.routes}
			if got := inspector.Inspect(context.Background(), topology); got != runtimetelemetry.UnavailableRouteOverlap() {
				t.Fatalf("Inspect = %#v", got)
			}
		})
	}
}
