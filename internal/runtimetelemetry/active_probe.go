package runtimetelemetry

import "fmt"

const (
	ActiveProbeVersionV1             = 1
	MaxActiveProbeTargets     uint64 = 8
	MaxActiveProbeSampleAgeMS uint64 = 30_000
	MaxActiveProbeDurationMS  uint64 = 6_000
)

type ActiveProbeState string

const (
	ProbeNotEligible           ActiveProbeState = "not_eligible"
	ProbeUnsupported           ActiveProbeState = "unsupported"
	ProbeCapabilityUnavailable ActiveProbeState = "capability_unavailable"
	ProbeAttempted             ActiveProbeState = "attempted"
	ProbeUnavailable           ActiveProbeState = "unavailable"
)

// ActiveProbeResult is the fixed, aggregate-only public probe allowlist. It
// intentionally contains no target, local address, nonce, packet, socket
// error, policy, or process identity.
type ActiveProbeResult struct {
	Version     int              `json:"version"`
	State       ActiveProbeState `json:"state"`
	SampleAgeMS *uint64          `json:"sample_age_ms"`
	Attempted   uint64           `json:"attempted"`
	Replied     uint64           `json:"replied"`
	DurationMS  uint64           `json:"duration_ms"`
}

func ValidateActiveProbe(result ActiveProbeResult) error {
	if result.Version != ActiveProbeVersionV1 {
		return fmt.Errorf("%w: unsupported active probe version", ErrInvalid)
	}
	if result.DurationMS > MaxActiveProbeDurationMS {
		return fmt.Errorf("%w: active probe duration exceeds its bound", ErrInvalid)
	}
	if result.SampleAgeMS != nil && *result.SampleAgeMS > MaxActiveProbeSampleAgeMS {
		return fmt.Errorf("%w: active probe sample age exceeds its bound", ErrInvalid)
	}
	switch result.State {
	case ProbeNotEligible:
		if result.SampleAgeMS == nil || *result.SampleAgeMS != 0 || result.Attempted != 0 || result.Replied != 0 || result.DurationMS != 0 {
			return fmt.Errorf("%w: not-eligible active probe has inconsistent evidence", ErrInvalid)
		}
	case ProbeUnsupported, ProbeUnavailable:
		if result.SampleAgeMS != nil || result.Attempted != 0 || result.Replied != 0 || result.DurationMS != 0 {
			return fmt.Errorf("%w: inactive active probe has inconsistent evidence", ErrInvalid)
		}
	case ProbeCapabilityUnavailable:
		if result.SampleAgeMS == nil || result.Attempted != 0 || result.Replied != 0 {
			return fmt.Errorf("%w: capability-unavailable active probe has inconsistent evidence", ErrInvalid)
		}
	case ProbeAttempted:
		if result.SampleAgeMS == nil || result.Attempted < 1 || result.Attempted > MaxActiveProbeTargets || result.Replied > result.Attempted {
			return fmt.Errorf("%w: attempted active probe has inconsistent evidence", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unrecognized active probe state", ErrInvalid)
	}
	return nil
}

func CloneActiveProbe(result ActiveProbeResult) ActiveProbeResult {
	if result.SampleAgeMS != nil {
		age := *result.SampleAgeMS
		result.SampleAgeMS = &age
	}
	return result
}

func UnsupportedActiveProbe() ActiveProbeResult {
	return ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeUnsupported}
}

func UnavailableActiveProbe() ActiveProbeResult {
	return ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeUnavailable}
}

func NotEligibleActiveProbe() ActiveProbeResult {
	age := uint64(0)
	return ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeNotEligible, SampleAgeMS: &age}
}
