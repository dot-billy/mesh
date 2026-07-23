package nodeagent

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/control"
)

func validEnrollmentPreflightPlan() control.EnrollmentPreflight {
	return control.EnrollmentPreflight{
		Schema: control.EnrollmentPreflightSchemaV1, TargetRole: "member", NetworkCIDR: "10.234.0.0/24",
		LighthouseEndpoints: []string{"198.51.100.8:4242", "LH.EXAMPLE.:4243", "lh.example:4242"},
		TokenExpiresAt:      time.Date(2026, 7, 21, 6, 0, 0, 0, time.UTC),
	}
}

func TestPreflightEnrollmentEnvironmentChecksActualRouteAndDeduplicatedDNS(t *testing.T) {
	plan := validEnrollmentPreflightPlan()
	resolver := &preflightTestResolver{results: map[string][]string{"lh.example": {"203.0.113.4"}}}
	routesCalled := false
	result, err := preflightEnrollmentEnvironment(
		context.Background(), plan, resolver,
		func(_ context.Context, prefix netip.Prefix) (bool, bool, error) {
			routesCalled = true
			if prefix.String() != plan.NetworkCIDR {
				t.Fatalf("route prefix = %s", prefix)
			}
			return true, false, nil
		},
		func() time.Time { return plan.TokenExpiresAt.Add(-time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	if !routesCalled || result.RouteState != EnrollmentRouteClear || result.DNSNames != 1 || result.ResolvedDNSNames != 1 {
		t.Fatalf("unexpected local preflight: %#v routes_called=%v", result, routesCalled)
	}
	if got := resolver.calledHosts(); !reflect.DeepEqual(got, []string{"lh.example"}) {
		t.Fatalf("resolver calls = %#v", got)
	}
}

func TestPreflightEnrollmentEnvironmentFailsClosedBeforeEnrollment(t *testing.T) {
	plan := validEnrollmentPreflightPlan()
	now := func() time.Time { return plan.TokenExpiresAt.Add(-time.Minute) }
	clearRoutes := func(context.Context, netip.Prefix) (bool, bool, error) { return true, false, nil }
	resolved := &preflightTestResolver{results: map[string][]string{"lh.example": {"203.0.113.4"}}}

	tests := []struct {
		name    string
		mutate  func(*control.EnrollmentPreflight)
		resolve endpointDNSResolver
		routes  preEnrollmentRouteInspector
		now     func() time.Time
		message string
	}{
		{name: "route conflict", resolve: resolved, routes: func(context.Context, netip.Prefix) (bool, bool, error) { return true, true, nil }, message: "route conflict"},
		{name: "route unavailable", resolve: resolved, routes: func(context.Context, netip.Prefix) (bool, bool, error) {
			return true, false, errors.New("private diagnostic")
		}, message: "inspect pre-enrollment routes"},
		{name: "DNS failure", resolve: &preflightTestResolver{errors: map[string]error{"lh.example": errors.New("private resolver diagnostic")}}, routes: clearRoutes, message: "1 of 1 lighthouse names"},
		{name: "member without lighthouse", mutate: func(value *control.EnrollmentPreflight) { value.LighthouseEndpoints = []string{} }, resolve: resolved, routes: clearRoutes, message: "no active lighthouse"},
		{name: "expired", resolve: resolved, routes: clearRoutes, now: func() time.Time { return plan.TokenExpiresAt }, message: "expired"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := plan
			candidate.LighthouseEndpoints = append([]string(nil), plan.LighthouseEndpoints...)
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			clock := now
			if test.now != nil {
				clock = test.now
			}
			_, err := preflightEnrollmentEnvironment(context.Background(), candidate, test.resolve, test.routes, clock)
			if err == nil || !containsText(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestPreflightEnrollmentEnvironmentAllowsExplicitUnsupportedRouteCheck(t *testing.T) {
	plan := validEnrollmentPreflightPlan()
	resolver := &preflightTestResolver{results: map[string][]string{"lh.example": {"203.0.113.4"}}}
	result, err := preflightEnrollmentEnvironment(
		context.Background(), plan, resolver,
		func(context.Context, netip.Prefix) (bool, bool, error) { return false, false, nil },
		func() time.Time { return plan.TokenExpiresAt.Add(-time.Minute) },
	)
	if err != nil || result.RouteState != EnrollmentRouteUnsupported {
		t.Fatalf("unsupported route result=%#v err=%v", result, err)
	}
}

func TestPreEnrollmentRouteInventoryOverlap(t *testing.T) {
	network := netip.MustParsePrefix("10.234.0.0/24")
	if overlap, complete := preEnrollmentRouteInventoryOverlaps(network, []routeInventoryEntry{{prefix: netip.MustParsePrefix("10.0.0.0/8"), interfaceIndex: 2}}); !complete || !overlap {
		t.Fatalf("supernet overlap=%v complete=%v", overlap, complete)
	}
	if overlap, complete := preEnrollmentRouteInventoryOverlaps(network, []routeInventoryEntry{{prefix: netip.MustParsePrefix("192.168.0.0/16"), interfaceIndex: 2}}); !complete || overlap {
		t.Fatalf("disjoint overlap=%v complete=%v", overlap, complete)
	}
}

func containsText(value, fragment string) bool {
	return strings.Contains(value, fragment)
}

type preflightTestResolver struct {
	mu      sync.Mutex
	results map[string][]string
	errors  map[string]error
	calls   []string
}

func (r *preflightTestResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, host)
	return append([]string(nil), r.results[host]...), r.errors[host]
}

func (r *preflightTestResolver) calledHosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}
