package runtimetelemetry

import "fmt"

const (
	EndpointDNSVersionV1             = 1
	MaxEndpointDNSNames       uint64 = 64
	MaxEndpointDNSSampleAgeMS uint64 = 90_000
)

type EndpointDNSState string

const (
	EndpointDNSUnsupported EndpointDNSState = "unsupported"
	EndpointDNSUnavailable EndpointDNSState = "unavailable"
	EndpointDNSObserved    EndpointDNSState = "observed"
)

// EndpointDNSResult is the complete member-side DNS evidence allowlist. It
// deliberately carries only counts; queried names, returned addresses,
// resolver configuration, and errors never leave the node.
type EndpointDNSResult struct {
	Version       int              `json:"version"`
	State         EndpointDNSState `json:"state"`
	SampleAgeMS   *uint64          `json:"sample_age_ms"`
	DNSNames      uint64           `json:"dns_names"`
	ResolvedNames uint64           `json:"resolved_names"`
}

func ValidateEndpointDNS(result EndpointDNSResult) error {
	if result.Version != EndpointDNSVersionV1 {
		return fmt.Errorf("%w: unsupported endpoint DNS version", ErrInvalid)
	}
	switch result.State {
	case EndpointDNSUnsupported, EndpointDNSUnavailable:
		if result.SampleAgeMS != nil || result.DNSNames != 0 || result.ResolvedNames != 0 {
			return fmt.Errorf("%w: unavailable endpoint DNS carries evidence", ErrInvalid)
		}
	case EndpointDNSObserved:
		if result.SampleAgeMS == nil || *result.SampleAgeMS > MaxEndpointDNSSampleAgeMS ||
			result.DNSNames > MaxEndpointDNSNames || result.ResolvedNames > result.DNSNames {
			return fmt.Errorf("%w: invalid observed endpoint DNS evidence", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unrecognized endpoint DNS state", ErrInvalid)
	}
	return nil
}

func CloneEndpointDNS(result EndpointDNSResult) EndpointDNSResult {
	if result.SampleAgeMS != nil {
		age := *result.SampleAgeMS
		result.SampleAgeMS = &age
	}
	return result
}

func UnsupportedEndpointDNS() EndpointDNSResult {
	return EndpointDNSResult{Version: EndpointDNSVersionV1, State: EndpointDNSUnsupported}
}

func UnavailableEndpointDNS() EndpointDNSResult {
	return EndpointDNSResult{Version: EndpointDNSVersionV1, State: EndpointDNSUnavailable}
}

func ObservedEndpointDNS(names, resolved uint64) EndpointDNSResult {
	age := uint64(0)
	return EndpointDNSResult{
		Version: EndpointDNSVersionV1, State: EndpointDNSObserved, SampleAgeMS: &age,
		DNSNames: names, ResolvedNames: resolved,
	}
}
