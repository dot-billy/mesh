package runtimetelemetry

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func nextTransitionObservation(previous Observation) Observation {
	next := cloneObservation(previous)
	next.Snapshot.SampleSequence++
	next.Snapshot.ProcessUptimeMS += 1_000
	return next
}

func transitionProbe(attempted, replied uint64) ActiveProbeResult {
	age := uint64(0)
	return ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &age, Attempted: attempted, Replied: replied, DurationMS: 1}
}

func TestMemoryStoreClassifiesOnlyConfigBoundProbeTransitions(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	digestA, digestB := string(bytes.Repeat([]byte{'a'}, 64)), string(bytes.Repeat([]byte{'b'}, 64))
	observation := validObservation()
	put := func(sequence int64, probe ActiveProbeResult, digest string, want ProbeTransition) {
		t.Helper()
		record, changed, err := store.PutWithConfig("node_a", sequence, now.Add(time.Duration(sequence)*time.Second), observation, probe, UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest)
		if err != nil || !changed || record.ProbeTransition != want || record.AppliedConfigSHA256 != digest {
			t.Fatalf("sequence %d record=%#v changed=%t err=%v want transition=%s", sequence, record, changed, err, want)
		}
		observation = nextTransitionObservation(observation)
	}
	put(1, transitionProbe(2, 0), digestA, ProbeTransitionUnclassified)
	put(2, transitionProbe(2, 0), digestA, ProbeTransitionStable)
	put(3, transitionProbe(2, 1), digestA, ProbeTransitionChanged)
	put(4, transitionProbe(2, 2), digestA, ProbeTransitionRecovered)
	put(5, transitionProbe(2, 1), digestA, ProbeTransitionDegraded)
	put(6, transitionProbe(2, 1), digestA, ProbeTransitionStable)
	put(7, transitionProbe(2, 2), digestB, ProbeTransitionUnclassified)
	put(8, UnsupportedActiveProbe(), digestB, ProbeTransitionUnavailable)
	put(9, NotEligibleActiveProbe(), digestB, ProbeTransitionNotEligible)
}

func TestMemoryStoreRejectsProbePlanAmbiguityAndDigestEquivocation(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 21, 18, 30, 0, 0, time.UTC)
	digest := string(bytes.Repeat([]byte{'c'}, 64))
	observation := validObservation()
	first, changed, err := store.PutWithConfig("node_a", 1, now, observation, transitionProbe(2, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest)
	if err != nil || !changed || first.ProbeTransition != ProbeTransitionUnclassified {
		t.Fatalf("initial transition=%#v changed=%t err=%v", first, changed, err)
	}
	next := nextTransitionObservation(observation)
	if _, _, err := store.PutWithConfig("node_a", 2, now.Add(time.Second), next, transitionProbe(1, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-config attempted-count ambiguity returned %v", err)
	}
	if _, _, err := store.PutWithConfig("node_a", 1, now.Add(time.Second), observation, transitionProbe(2, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), string(bytes.Repeat([]byte{'d'}, 64))); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-heartbeat digest equivocation returned %v", err)
	}
	if _, _, err := store.PutWithConfig("node_b", 1, now, observation, transitionProbe(1, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), "not-a-digest"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid config digest returned %v", err)
	}
	stored, found, err := store.Get("node_a")
	if err != nil || !found || stored.HeartbeatSequence != 1 || stored.ProbeTransition != ProbeTransitionUnclassified {
		t.Fatalf("rejected transition changed stored record: %#v found=%t err=%v", stored, found, err)
	}
}

func TestMemoryStoreDoesNotClassifyAcrossHeartbeatGap(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 21, 18, 45, 0, 0, time.UTC)
	digest := string(bytes.Repeat([]byte{'e'}, 64))
	observation := validObservation()
	if _, _, err := store.PutWithConfig("node_a", 1, now, observation, transitionProbe(2, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest); err != nil {
		t.Fatal(err)
	}
	observation = nextTransitionObservation(observation)
	record, changed, err := store.PutWithConfig("node_a", 3, now.Add(time.Second), observation, transitionProbe(2, 2), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest)
	if err != nil || !changed || record.ProbeTransition != ProbeTransitionUnclassified {
		t.Fatalf("heartbeat gap transition=%#v changed=%t err=%v", record, changed, err)
	}
}

func TestDecodeStateMigratesCanonicalV6WithoutFabricatingTransitionHistory(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v6","records":[{"node_id":"node_a","heartbeat_sequence":3,"received_at":"2026-07-20T17:00:00Z","process_continuity":"unavailable","observation":{"version":2,"state":"unknown"},"active_probe":{"version":1,"state":"attempted","sample_age_ms":0,"attempted":2,"replied":2,"duration_ms":1},"route_overlap":{"version":1,"state":"unsupported","sample_age_ms":null,"overlap":false},"endpoint_dns":{"version":1,"state":"unsupported","sample_age_ms":null,"dns_names":0,"resolved_names":0}}]}`)
	state, err := DecodeState(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if state.Schema != StateSchemaV7 || len(state.Records) != 1 || state.Records[0].AppliedConfigSHA256 != "" || state.Records[0].ProbeTransition != ProbeTransitionUnclassified {
		t.Fatalf("v6 migration fabricated transition history: %#v", state)
	}
	current, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte(`"schema":"mesh-runtime-telemetry-state-v7"`)) || !bytes.Contains(current, []byte(`"applied_config_sha256":"","probe_transition":"unclassified"`)) {
		t.Fatalf("v7 encoding=%s", current)
	}
}

func TestMemoryStoreBindsActiveProbeWithoutChangingProcessContinuity(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	first, changed, err := store.Put("node_a", 1, now, validObservation(), UnsupportedActiveProbe())
	if err != nil || !changed || first.ActiveProbe.State != ProbeUnsupported || first.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("first put = %#v changed=%t err=%v", first, changed, err)
	}

	conflict := NotEligibleActiveProbe()
	if _, _, err := store.Put("node_a", 1, now.Add(time.Second), validObservation(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-heartbeat probe equivocation returned %v", err)
	}

	observation := validObservation()
	observation.Snapshot.SampleSequence++
	observation.Snapshot.ProcessUptimeMS++
	age := uint64(0)
	probe := ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &age, Attempted: 2, Replied: 1, DurationMS: 4}
	second, changed, err := store.Put("node_a", 2, now.Add(time.Minute), observation, probe)
	if err != nil || !changed || second.ProcessContinuity != ContinuityContinuous || second.ActiveProbe.State != ProbeAttempted {
		t.Fatalf("second put = %#v changed=%t err=%v", second, changed, err)
	}
	*probe.SampleAgeMS = 9
	stored, found, err := store.Get("node_a")
	if err != nil || !found || stored.ActiveProbe.SampleAgeMS == nil || *stored.ActiveProbe.SampleAgeMS != 0 {
		t.Fatalf("stored probe retained caller pointer: %#v found=%t err=%v", stored, found, err)
	}
	retryProbe := CloneActiveProbe(second.ActiveProbe)
	retry, changed, err := store.Put("node_a", 2, now.Add(2*time.Minute), observation, retryProbe)
	if err != nil || changed || retry.ActiveProbe.SampleAgeMS == second.ActiveProbe.SampleAgeMS || !retry.ReceivedAt.Equal(second.ReceivedAt) {
		t.Fatalf("exact retry = %#v changed=%t err=%v", retry, changed, err)
	}
}

func TestDecodeStateMigratesCanonicalV3ActiveProbe(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v3","records":[{"node_id":"node_a","heartbeat_sequence":3,"received_at":"2026-07-20T16:00:00Z","process_continuity":"unavailable","observation":{"version":2,"state":"unknown"}}]}`)
	state, err := DecodeState(legacy)
	if err != nil {
		t.Fatalf("DecodeState v3: %v", err)
	}
	if state.Schema != StateSchemaV7 || len(state.Records) != 1 || state.Records[0].ActiveProbe != UnsupportedActiveProbe() || state.Records[0].ProbeTransition != ProbeTransitionUnavailable || state.Records[0].RouteOverlap != UnsupportedRouteOverlap() || state.Records[0].EndpointDNS != UnsupportedEndpointDNS() {
		t.Fatalf("migrated state = %#v", state)
	}
	current, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte(`"schema":"mesh-runtime-telemetry-state-v7"`)) ||
		!bytes.Contains(current, []byte(`"active_probe":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0}`)) {
		t.Fatalf("v7 encoding = %s", current)
	}
}

func TestMemoryStoreBindsRouteOverlapWithoutChangingProcessContinuity(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 16, 30, 0, 0, time.UTC)
	route := ObservedRouteOverlap(false)
	first, changed, err := store.PutWithRoute("node_a", 1, now, validObservation(), UnsupportedActiveProbe(), route)
	if err != nil || !changed || first.RouteOverlap.State != RouteOverlapObserved || first.RouteOverlap.Overlap || first.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("first put = %#v changed=%t err=%v", first, changed, err)
	}
	conflict := ObservedRouteOverlap(true)
	if _, _, err := store.PutWithRoute("node_a", 1, now.Add(time.Second), validObservation(), UnsupportedActiveProbe(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-heartbeat route equivocation returned %v", err)
	}
	*route.SampleAgeMS = 9
	stored, found, err := store.Get("node_a")
	if err != nil || !found || stored.RouteOverlap.SampleAgeMS == nil || *stored.RouteOverlap.SampleAgeMS != 0 {
		t.Fatalf("stored route evidence retained caller pointer: %#v found=%t err=%v", stored, found, err)
	}
}

func TestDecodeStateMigratesCanonicalV4RouteEvidence(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v4","records":[{"node_id":"node_a","heartbeat_sequence":3,"received_at":"2026-07-20T16:00:00Z","process_continuity":"unavailable","observation":{"version":2,"state":"unknown"},"active_probe":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0}}]}`)
	state, err := DecodeState(legacy)
	if err != nil {
		t.Fatalf("DecodeState v4: %v", err)
	}
	if state.Schema != StateSchemaV7 || len(state.Records) != 1 || state.Records[0].ProbeTransition != ProbeTransitionUnavailable || state.Records[0].RouteOverlap != UnsupportedRouteOverlap() || state.Records[0].EndpointDNS != UnsupportedEndpointDNS() {
		t.Fatalf("migrated state = %#v", state)
	}
	current, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte(`"schema":"mesh-runtime-telemetry-state-v7"`)) ||
		!bytes.Contains(current, []byte(`"route_overlap":{"version":1,"state":"unsupported","sample_age_ms":null,"overlap":false}`)) {
		t.Fatalf("v7 encoding = %s", current)
	}
}

func TestMemoryStoreBindsEndpointDNSWithoutChangingProcessContinuity(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 17, 0, 0, 0, time.UTC)
	dns := ObservedEndpointDNS(2, 1)
	first, changed, err := store.PutWithDNS("node_a", 1, now, validObservation(), UnsupportedActiveProbe(), UnsupportedRouteOverlap(), dns)
	if err != nil || !changed || first.EndpointDNS.State != EndpointDNSObserved || first.EndpointDNS.DNSNames != 2 || first.EndpointDNS.ResolvedNames != 1 || first.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("first put = %#v changed=%t err=%v", first, changed, err)
	}
	conflict := ObservedEndpointDNS(2, 2)
	if _, _, err := store.PutWithDNS("node_a", 1, now.Add(time.Second), validObservation(), UnsupportedActiveProbe(), UnsupportedRouteOverlap(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-heartbeat endpoint DNS equivocation returned %v", err)
	}
	*dns.SampleAgeMS = 9
	stored, found, err := store.Get("node_a")
	if err != nil || !found || stored.EndpointDNS.SampleAgeMS == nil || *stored.EndpointDNS.SampleAgeMS != 0 {
		t.Fatalf("stored endpoint DNS evidence retained caller pointer: %#v found=%t err=%v", stored, found, err)
	}
}

func TestDecodeStateMigratesCanonicalV5EndpointDNS(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v5","records":[{"node_id":"node_a","heartbeat_sequence":3,"received_at":"2026-07-20T17:00:00Z","process_continuity":"unavailable","observation":{"version":2,"state":"unknown"},"active_probe":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0},"route_overlap":{"version":1,"state":"unsupported","sample_age_ms":null,"overlap":false}}]}`)
	state, err := DecodeState(legacy)
	if err != nil {
		t.Fatalf("DecodeState v5: %v", err)
	}
	if state.Schema != StateSchemaV7 || len(state.Records) != 1 || state.Records[0].ProbeTransition != ProbeTransitionUnavailable || state.Records[0].EndpointDNS != UnsupportedEndpointDNS() {
		t.Fatalf("migrated state = %#v", state)
	}
	current, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte(`"schema":"mesh-runtime-telemetry-state-v7"`)) ||
		!bytes.Contains(current, []byte(`"endpoint_dns":{"version":1,"state":"unsupported","sample_age_ms":null,"dns_names":0,"resolved_names":0}`)) {
		t.Fatalf("v7 encoding = %s", current)
	}
}
