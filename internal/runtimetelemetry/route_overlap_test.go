package runtimetelemetry

import "testing"

func TestRouteOverlapResultExactStatesAndClone(t *testing.T) {
	zero, oldest := uint64(0), MaxRouteOverlapSampleAgeMS
	valid := []RouteOverlapResult{
		UnsupportedRouteOverlap(),
		UnavailableRouteOverlap(),
		{Version: RouteOverlapVersionV1, State: RouteOverlapObserved, SampleAgeMS: &zero},
		{Version: RouteOverlapVersionV1, State: RouteOverlapObserved, SampleAgeMS: &oldest, Overlap: true},
	}
	for _, result := range valid {
		if err := ValidateRouteOverlap(result); err != nil {
			t.Fatalf("valid result %#v returned %v", result, err)
		}
	}
	observed := ObservedRouteOverlap(true)
	cloned := CloneRouteOverlap(observed)
	*observed.SampleAgeMS = 9
	if cloned.SampleAgeMS == observed.SampleAgeMS || *cloned.SampleAgeMS != 0 || !cloned.Overlap {
		t.Fatalf("clone retained caller pointer: original=%#v clone=%#v", observed, cloned)
	}
}

func TestRouteOverlapResultRejectsAmbiguousEvidence(t *testing.T) {
	zero, tooOld := uint64(0), MaxRouteOverlapSampleAgeMS+1
	invalid := []RouteOverlapResult{
		{},
		{Version: 2, State: RouteOverlapUnsupported},
		{Version: RouteOverlapVersionV1, State: "unknown"},
		{Version: RouteOverlapVersionV1, State: RouteOverlapUnsupported, SampleAgeMS: &zero},
		{Version: RouteOverlapVersionV1, State: RouteOverlapUnavailable, Overlap: true},
		{Version: RouteOverlapVersionV1, State: RouteOverlapObserved},
		{Version: RouteOverlapVersionV1, State: RouteOverlapObserved, SampleAgeMS: &tooOld},
	}
	for _, result := range invalid {
		if err := ValidateRouteOverlap(result); err == nil {
			t.Fatalf("invalid result accepted: %#v", result)
		}
	}
}
