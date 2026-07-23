package runtimetelemetry

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestStateDocumentCanonicalRoundTrip(t *testing.T) {
	state := State{Schema: StateSchema, Records: []Record{{
		NodeID: "node_a", HeartbeatSequence: 3, ReceivedAt: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		ProcessContinuity: ContinuityUnclassified, Observation: validObservation(), ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
	}}}
	raw, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(raw)
	if err != nil || len(decoded.Records) != 1 || decoded.Records[0].NodeID != "node_a" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	copy := append([]byte(nil), raw...)
	copy = append(copy, ' ')
	if _, err := DecodeState(copy); !errors.Is(err, ErrInvalid) {
		t.Fatalf("noncanonical state returned %v", err)
	}
}

func TestDecodeStateMigratesCanonicalV1Document(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[{"node_id":"node_a","heartbeat_sequence":3,"received_at":"2026-07-20T12:00:00Z","observation":{"version":1,"state":"observed","snapshot":{"process_instance_id":"0123456789abcdef0123456789abcdef","sample_sequence":7,"process_uptime_ms":60000,"handshakes":{"completed_total":3,"timed_out_total":1,"pending":0,"most_recent_completion_age_ms":500},"peers":{"established":2,"authenticated_rx_within_2m":1,"authenticated_rx_within_5m":2,"oldest_authenticated_rx_age_ms":300},"lighthouses":{"configured":2,"established":1,"authenticated_rx_within_2m":1,"authenticated_rx_within_5m":1,"overflow":false}}}}]}`)
	if _, err := decodeStateV1(legacy); err != nil {
		t.Fatalf("decodeStateV1 fixture setup: %v", err)
	}

	state, err := DecodeState(legacy)
	if err != nil {
		t.Fatalf("DecodeState legacy v1: %v", err)
	}
	if state.Schema != StateSchemaV7 || len(state.Records) != 1 || state.Records[0].Observation.Version != VersionV1 ||
		state.Records[0].ProcessContinuity != ContinuityUnclassified ||
		state.Records[0].ActiveProbe != UnsupportedActiveProbe() || state.Records[0].ProbeTransition != ProbeTransitionUnavailable || state.Records[0].AppliedConfigSHA256 != "" ||
		state.Records[0].RouteOverlap != UnsupportedRouteOverlap() ||
		state.Records[0].EndpointDNS != UnsupportedEndpointDNS() ||
		state.Records[0].Observation.Snapshot == nil || state.Records[0].Observation.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS != nil {
		t.Fatalf("legacy state was not safely migrated: %#v", state)
	}
	current, err := EncodeState(state)
	if err != nil {
		t.Fatalf("EncodeState migrated v7: %v", err)
	}
	if bytes.Equal(current, legacy) || !bytes.Contains(current, []byte(`"schema":"mesh-runtime-telemetry-state-v7"`)) ||
		!bytes.Contains(current, []byte(`"process_continuity":"unclassified"`)) ||
		!bytes.Contains(current, []byte(`"active_probe":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0}`)) ||
		!bytes.Contains(current, []byte(`"applied_config_sha256":"","probe_transition":"unavailable"`)) ||
		!bytes.Contains(current, []byte(`"route_overlap":{"version":1,"state":"unsupported","sample_age_ms":null,"overlap":false}`)) ||
		!bytes.Contains(current, []byte(`"endpoint_dns":{"version":1,"state":"unsupported","sample_age_ms":null,"dns_names":0,"resolved_names":0}`)) ||
		!bytes.Contains(current, []byte(`"most_recent_authenticated_rx_age_ms":null`)) {
		t.Fatalf("migrated document is not canonical v7: %s", current)
	}
}

func TestDecodeStateMigratesCanonicalV2Document(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v2","records":[{"node_id":"node_a","heartbeat_sequence":3,"received_at":"2026-07-20T12:00:00Z","observation":{"version":2,"state":"observed","snapshot":{"process_instance_id":"0123456789abcdef0123456789abcdef","sample_sequence":7,"process_uptime_ms":60000,"handshakes":{"completed_total":3,"timed_out_total":1,"pending":0,"most_recent_completion_age_ms":500},"peers":{"established":2,"authenticated_rx_within_2m":1,"authenticated_rx_within_5m":2,"oldest_authenticated_rx_age_ms":300},"lighthouses":{"configured":2,"established":1,"authenticated_rx_within_2m":1,"authenticated_rx_within_5m":1,"most_recent_authenticated_rx_age_ms":250,"overflow":false}}}},{"node_id":"node_b","heartbeat_sequence":4,"received_at":"2026-07-20T12:01:00Z","observation":{"version":2,"state":"unknown"}}]}`)
	if _, err := decodeStateV2(legacy); err != nil {
		t.Fatalf("decodeStateV2 fixture setup: %v", err)
	}
	state, err := DecodeState(legacy)
	if err != nil {
		t.Fatalf("DecodeState legacy v2: %v", err)
	}
	if state.Schema != StateSchemaV7 || len(state.Records) != 2 ||
		state.Records[0].ProcessContinuity != ContinuityUnclassified ||
		state.Records[1].ProcessContinuity != ContinuityUnavailable ||
		state.Records[0].ActiveProbe != UnsupportedActiveProbe() || state.Records[1].ActiveProbe != UnsupportedActiveProbe() ||
		state.Records[0].RouteOverlap != UnsupportedRouteOverlap() || state.Records[1].RouteOverlap != UnsupportedRouteOverlap() ||
		state.Records[0].EndpointDNS != UnsupportedEndpointDNS() || state.Records[1].EndpointDNS != UnsupportedEndpointDNS() {
		t.Fatalf("legacy v2 state was not conservatively migrated: %#v", state)
	}
	current, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, legacy) || !bytes.Contains(current, []byte(`"schema":"mesh-runtime-telemetry-state-v7"`)) ||
		!bytes.Contains(current, []byte(`"process_continuity":"unavailable"`)) {
		t.Fatalf("migrated v2 document is not canonical v7: %s", current)
	}
}

func TestStateDocumentRejectsUnknownDuplicateAndTrailingData(t *testing.T) {
	valid, err := EncodeState(EmptyState())
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		[]byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[],"unknown":true}`),
		[]byte(`{"schema":"mesh-runtime-telemetry-state-v1","schema":"mesh-runtime-telemetry-state-v1","records":[]}`),
		append(append([]byte(nil), valid...), []byte(`{}`)...),
		bytes.Repeat([]byte{'x'}, MaxStateDocumentBytes+1),
	}
	for _, raw := range tests {
		if _, err := DecodeState(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid document returned %v", err)
		}
	}
}
