package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"mesh/internal/control"
)

const (
	EnrollmentRouteClear       = "clear"
	EnrollmentRouteUnsupported = "unsupported"
)

type EnrollmentEnvironmentResult struct {
	RouteState       string
	DNSNames         int
	ResolvedDNSNames int
}

type preEnrollmentRouteInspector func(context.Context, netip.Prefix) (supported, overlap bool, err error)

// PreflightEnrollmentEnvironment checks the future host's actual non-default
// IPv4 route inventory and resolver before the one-time enrollment credential
// is consumed. It does not dial UDP and therefore makes no reachability claim.
func PreflightEnrollmentEnvironment(ctx context.Context, plan control.EnrollmentPreflight) (EnrollmentEnvironmentResult, error) {
	return preflightEnrollmentEnvironment(ctx, plan, net.DefaultResolver, inspectPreEnrollmentRoutes, time.Now)
}

func preflightEnrollmentEnvironment(
	ctx context.Context,
	plan control.EnrollmentPreflight,
	resolver endpointDNSResolver,
	inspectRoutes preEnrollmentRouteInspector,
	now func() time.Time,
) (EnrollmentEnvironmentResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment check requires an active context")
	}
	if err := control.ValidateEnrollmentPreflight(plan); err != nil {
		return EnrollmentEnvironmentResult{}, err
	}
	if now == nil || !now().UTC().Before(plan.TokenExpiresAt) {
		return EnrollmentEnvironmentResult{}, errors.New("one-time enrollment token expired before local preflight")
	}
	if inspectRoutes == nil {
		return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment route inspector is unavailable")
	}
	prefix, err := netip.ParsePrefix(plan.NetworkCIDR)
	if err != nil || prefix != prefix.Masked() || !prefix.Addr().Is4() {
		return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment network is invalid")
	}
	supported, overlap, err := inspectRoutes(ctx, prefix)
	if err != nil {
		return EnrollmentEnvironmentResult{}, fmt.Errorf("inspect pre-enrollment routes: %w", err)
	}
	if overlap {
		return EnrollmentEnvironmentResult{}, fmt.Errorf("pre-enrollment route conflict: %s overlaps a current non-default route", plan.NetworkCIDR)
	}
	result := EnrollmentEnvironmentResult{RouteState: EnrollmentRouteUnsupported}
	if supported {
		result.RouteState = EnrollmentRouteClear
	}

	if plan.TargetRole == "member" && len(plan.LighthouseEndpoints) == 0 {
		return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment DNS check: no active lighthouse endpoint is available for this member")
	}
	names := make(map[string]string)
	for _, endpoint := range plan.LighthouseEndpoints {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment lighthouse endpoint is invalid")
		}
		if net.ParseIP(host) != nil {
			continue
		}
		key, ok := canonicalRenderedDNSName(host)
		if !ok {
			return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment lighthouse DNS name is invalid")
		}
		names[key] = host
	}
	result.DNSNames = len(names)
	if len(names) == 0 {
		return result, nil
	}
	resolved, complete := resolveEndpointDNSNames(ctx, names, resolver)
	if !complete {
		return EnrollmentEnvironmentResult{}, errors.New("pre-enrollment DNS check was unavailable")
	}
	result.ResolvedDNSNames = int(resolved)
	if result.ResolvedDNSNames != result.DNSNames {
		return EnrollmentEnvironmentResult{}, fmt.Errorf("pre-enrollment DNS check failed: %d of %d lighthouse names did not resolve from this host", result.DNSNames-result.ResolvedDNSNames, result.DNSNames)
	}
	return result, nil
}
