package runtimetelemetry

import (
	"errors"
	"reflect"
	"testing"
)

func TestActiveProbeValidStatesAndClone(t *testing.T) {
	zero, ten := uint64(0), uint64(10)
	values := []ActiveProbeResult{
		{Version: ActiveProbeVersionV1, State: ProbeNotEligible, SampleAgeMS: &zero},
		{Version: ActiveProbeVersionV1, State: ProbeUnsupported},
		{Version: ActiveProbeVersionV1, State: ProbeCapabilityUnavailable, SampleAgeMS: &ten, DurationMS: 1},
		{Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &zero, Attempted: 8, Replied: 7, DurationMS: MaxActiveProbeDurationMS},
		{Version: ActiveProbeVersionV1, State: ProbeUnavailable},
	}
	for _, value := range values {
		if err := ValidateActiveProbe(value); err != nil {
			t.Fatalf("valid %q result rejected: %v", value.State, err)
		}
		clone := CloneActiveProbe(value)
		if !reflect.DeepEqual(clone, value) {
			t.Fatalf("clone = %#v, want %#v", clone, value)
		}
		if value.SampleAgeMS != nil {
			*clone.SampleAgeMS++
			if *value.SampleAgeMS == *clone.SampleAgeMS {
				t.Fatalf("clone for %q retained sample age pointer", value.State)
			}
		}
	}
	if got := UnsupportedActiveProbe(); got.State != ProbeUnsupported || ValidateActiveProbe(got) != nil {
		t.Fatalf("unsupported constructor = %#v", got)
	}
	if got := UnavailableActiveProbe(); got.State != ProbeUnavailable || ValidateActiveProbe(got) != nil {
		t.Fatalf("unavailable constructor = %#v", got)
	}
	if got := NotEligibleActiveProbe(); got.State != ProbeNotEligible || got.SampleAgeMS == nil || *got.SampleAgeMS != 0 || ValidateActiveProbe(got) != nil {
		t.Fatalf("not-eligible constructor = %#v", got)
	}
}

func TestActiveProbeRejectsInconsistentResults(t *testing.T) {
	zero, one, tooOld := uint64(0), uint64(1), MaxActiveProbeSampleAgeMS+1
	validAttempt := ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &zero, Attempted: 1}
	tests := map[string]ActiveProbeResult{
		"version":                  {Version: ActiveProbeVersionV1 + 1, State: ProbeUnsupported},
		"state":                    {Version: ActiveProbeVersionV1, State: ActiveProbeState("maybe")},
		"not eligible missing age": {Version: ActiveProbeVersionV1, State: ProbeNotEligible},
		"not eligible attempted":   {Version: ActiveProbeVersionV1, State: ProbeNotEligible, SampleAgeMS: &zero, Attempted: 1},
		"not eligible aged":        {Version: ActiveProbeVersionV1, State: ProbeNotEligible, SampleAgeMS: &one},
		"not eligible duration":    {Version: ActiveProbeVersionV1, State: ProbeNotEligible, SampleAgeMS: &zero, DurationMS: 1},
		"unsupported age":          {Version: ActiveProbeVersionV1, State: ProbeUnsupported, SampleAgeMS: &zero},
		"unsupported count":        {Version: ActiveProbeVersionV1, State: ProbeUnsupported, Replied: 1},
		"capability missing age":   {Version: ActiveProbeVersionV1, State: ProbeCapabilityUnavailable},
		"capability attempted":     {Version: ActiveProbeVersionV1, State: ProbeCapabilityUnavailable, SampleAgeMS: &zero, Attempted: 1},
		"attempted missing age":    {Version: ActiveProbeVersionV1, State: ProbeAttempted, Attempted: 1},
		"attempted zero":           {Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &zero},
		"attempted above maximum":  {Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &zero, Attempted: MaxActiveProbeTargets + 1},
		"replies above attempts":   {Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &zero, Attempted: 1, Replied: 2},
		"duration above maximum":   {Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &zero, Attempted: 1, DurationMS: MaxActiveProbeDurationMS + 1},
		"sample age above maximum": {Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &tooOld, Attempted: 1},
		"unavailable age":          {Version: ActiveProbeVersionV1, State: ProbeUnavailable, SampleAgeMS: &one},
		"unavailable duration":     {Version: ActiveProbeVersionV1, State: ProbeUnavailable, DurationMS: 1},
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateActiveProbe(value); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid result returned %v", err)
			}
		})
	}
	if err := ValidateActiveProbe(validAttempt); err != nil {
		t.Fatalf("control attempted result rejected: %v", err)
	}
}
