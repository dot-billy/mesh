package runtimetelemetry

import "testing"

func TestEndpointDNSResultExactStatesAndClone(t *testing.T) {
	oldest := MaxEndpointDNSSampleAgeMS
	valid := []EndpointDNSResult{
		UnsupportedEndpointDNS(),
		UnavailableEndpointDNS(),
		ObservedEndpointDNS(0, 0),
		{Version: EndpointDNSVersionV1, State: EndpointDNSObserved, SampleAgeMS: &oldest, DNSNames: MaxEndpointDNSNames, ResolvedNames: MaxEndpointDNSNames},
	}
	for _, result := range valid {
		if err := ValidateEndpointDNS(result); err != nil {
			t.Fatalf("valid endpoint DNS result rejected: %#v: %v", result, err)
		}
	}
	observed := ObservedEndpointDNS(2, 1)
	cloned := CloneEndpointDNS(observed)
	*cloned.SampleAgeMS = 7
	if *observed.SampleAgeMS != 0 {
		t.Fatal("endpoint DNS clone retained the sample-age pointer")
	}
}

func TestEndpointDNSResultRejectsAmbiguousEvidence(t *testing.T) {
	zero, tooOld := uint64(0), MaxEndpointDNSSampleAgeMS+1
	invalid := []EndpointDNSResult{
		{},
		{Version: 2, State: EndpointDNSUnsupported},
		{Version: EndpointDNSVersionV1, State: "unknown"},
		{Version: EndpointDNSVersionV1, State: EndpointDNSUnsupported, SampleAgeMS: &zero},
		{Version: EndpointDNSVersionV1, State: EndpointDNSUnavailable, DNSNames: 1},
		{Version: EndpointDNSVersionV1, State: EndpointDNSObserved},
		{Version: EndpointDNSVersionV1, State: EndpointDNSObserved, SampleAgeMS: &tooOld},
		{Version: EndpointDNSVersionV1, State: EndpointDNSObserved, SampleAgeMS: &zero, DNSNames: MaxEndpointDNSNames + 1},
		{Version: EndpointDNSVersionV1, State: EndpointDNSObserved, SampleAgeMS: &zero, DNSNames: 1, ResolvedNames: 2},
	}
	for _, result := range invalid {
		if err := ValidateEndpointDNS(result); err == nil {
			t.Fatalf("invalid endpoint DNS result accepted: %#v", result)
		}
	}
}
