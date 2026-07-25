package runtimetelemetry

import "fmt"

const (
	RouteOverlapVersionV1             = 1
	MaxRouteOverlapSampleAgeMS uint64 = 90_000
)

type RouteOverlapState string

const (
	RouteOverlapUnsupported RouteOverlapState = "unsupported"
	RouteOverlapUnavailable RouteOverlapState = "unavailable"
	RouteOverlapObserved    RouteOverlapState = "observed"
)

// RouteOverlapResult is the complete privacy-preserving route evidence
// allowlist. It deliberately contains no interface, prefix, gateway, table,
// metric, protocol, or route count.
type RouteOverlapResult struct {
	Version     int               `json:"version"`
	State       RouteOverlapState `json:"state"`
	SampleAgeMS *uint64           `json:"sample_age_ms"`
	Overlap     bool              `json:"overlap"`
}

func ValidateRouteOverlap(result RouteOverlapResult) error {
	if result.Version != RouteOverlapVersionV1 {
		return fmt.Errorf("%w: unsupported route-overlap version", ErrInvalid)
	}
	switch result.State {
	case RouteOverlapUnsupported, RouteOverlapUnavailable:
		if result.SampleAgeMS != nil || result.Overlap {
			return fmt.Errorf("%w: inactive route-overlap result has inconsistent evidence", ErrInvalid)
		}
	case RouteOverlapObserved:
		if result.SampleAgeMS == nil || *result.SampleAgeMS > MaxRouteOverlapSampleAgeMS {
			return fmt.Errorf("%w: observed route-overlap result has inconsistent evidence", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unrecognized route-overlap state", ErrInvalid)
	}
	return nil
}

func CloneRouteOverlap(result RouteOverlapResult) RouteOverlapResult {
	if result.SampleAgeMS != nil {
		age := *result.SampleAgeMS
		result.SampleAgeMS = &age
	}
	return result
}

func UnsupportedRouteOverlap() RouteOverlapResult {
	return RouteOverlapResult{Version: RouteOverlapVersionV1, State: RouteOverlapUnsupported}
}

func UnavailableRouteOverlap() RouteOverlapResult {
	return RouteOverlapResult{Version: RouteOverlapVersionV1, State: RouteOverlapUnavailable}
}

func ObservedRouteOverlap(overlap bool) RouteOverlapResult {
	age := uint64(0)
	return RouteOverlapResult{Version: RouteOverlapVersionV1, State: RouteOverlapObserved, SampleAgeMS: &age, Overlap: overlap}
}
