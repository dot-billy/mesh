package runtimetelemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"mesh/internal/runtimeobserver"
)

func TestBuildFleetProjectionIsStrictAggregateOnlyAndCanonical(t *testing.T) {
	now := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	probeAge := uint64(25)
	probe := ActiveProbeResult{Version: ActiveProbeVersionV1, State: ProbeAttempted, SampleAgeMS: &probeAge, Attempted: 2, Replied: 1, DurationMS: 14}
	records := []Record{{
		NodeID: "node-a", HeartbeatSequence: 7, ReceivedAt: now.Add(-time.Minute),
		ProcessContinuity: ContinuityContinuous, Observation: validObservation(), ActiveProbe: probe, AppliedConfigSHA256: strings.Repeat("a", 64), ProbeTransition: ProbeTransitionUnclassified, RouteOverlap: ObservedRouteOverlap(false), EndpointDNS: ObservedEndpointDNS(1, 1),
	}}
	projection, err := BuildFleetProjection(records, now)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Schema != FleetProjectionSchema || !projection.GeneratedAt.Equal(now) ||
		projection.Policy.ObservationStaleAfterSeconds != 300 || !projection.Policy.AggregateOnly ||
		projection.Policy.EndToEndReachabilityProven || len(projection.Records) != 1 {
		t.Fatalf("unexpected projection: %#v", projection)
	}
	projected := projection.Records[0]
	if projected.NodeID != "node-a" || projected.HeartbeatSequence != 7 || projected.ObservationVersion != VersionV2 ||
		projected.ProcessContinuity != ContinuityContinuous || projected.State != StateObserved ||
		projected.Snapshot == nil || projected.Snapshot.Peers.Established != 2 ||
		projected.ActiveProbe.State != ProbeAttempted || projected.ProbeTransition != ProbeTransitionUnclassified || projected.ActiveProbe.SampleAgeMS == nil || *projected.ActiveProbe.SampleAgeMS != probeAge {
		t.Fatalf("unexpected projected record: %#v", projected)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("process_instance_id"), []byte("0123456789abcdef0123456789abcdef"),
		[]byte("target_ip"), []byte("local_ip"), []byte("plan_sha256"), []byte("applied_config_sha256"), []byte(strings.Repeat("a", 64)), []byte("nonce"), []byte("packet"), []byte("socket_error"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("administrator projection exposed process identity: %s", raw)
		}
	}

	// Projection values must not alias mutable repository records.
	*records[0].Observation.Snapshot.Peers.OldestAuthenticatedRXAgeMS = 999
	if *projected.Snapshot.Peers.OldestAuthenticatedRXAgeMS == 999 {
		t.Fatal("fleet projection aliases repository observation memory")
	}
	*records[0].Observation.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = 999
	if *projected.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS == 999 {
		t.Fatal("fleet projection aliases retained lighthouse age memory")
	}
	*records[0].ActiveProbe.SampleAgeMS = 999
	if *projected.ActiveProbe.SampleAgeMS == 999 {
		t.Fatal("fleet projection aliases repository active-probe memory")
	}
}

func TestBuildFleetProjectionPreservesLegacyObservationVersion(t *testing.T) {
	now := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	legacy := validObservation()
	legacy.Version = VersionV1
	legacy.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = nil
	projection, err := BuildFleetProjection([]Record{{
		NodeID: "node-a", HeartbeatSequence: 7, ReceivedAt: now.Add(-time.Minute),
		ProcessContinuity: ContinuityUnclassified, Observation: legacy, ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
	}}, now)
	if err != nil {
		t.Fatalf("BuildFleetProjection legacy v1: %v", err)
	}
	if projection.Schema != FleetProjectionSchemaV5 || projection.Records[0].ObservationVersion != VersionV1 ||
		projection.Records[0].ProcessContinuity != ContinuityUnclassified ||
		projection.Records[0].ActiveProbe != UnsupportedActiveProbe() ||
		projection.Records[0].Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS != nil {
		t.Fatalf("legacy projection lost compatibility metadata: %#v", projection)
	}
}

func TestBuildFleetProjectionFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	valid := Record{NodeID: "node-a", HeartbeatSequence: 1, ReceivedAt: now, ProcessContinuity: ContinuityUnclassified, Observation: validObservation(), ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS()}
	future := valid
	future.ReceivedAt = now.Add(time.Nanosecond)
	unsafe := valid
	unsafe.HeartbeatSequence = int64(runtimeobserver.MaxExactJSONInteger) + 1
	nodeB := valid
	nodeB.NodeID = "node-b"
	invalidContinuity := valid
	invalidContinuity.ProcessContinuity = ContinuityUnavailable
	tests := map[string]struct {
		records []Record
		now     time.Time
	}{
		"nil records":        {records: nil, now: now},
		"local timestamp":    {records: []Record{valid}, now: now.In(time.FixedZone("offset", 3600))},
		"future receipt":     {records: []Record{future}, now: now},
		"unsafe sequence":    {records: []Record{unsafe}, now: now},
		"noncanonical order": {records: []Record{nodeB, valid}, now: now},
		"invalid continuity": {records: []Record{invalidContinuity}, now: now},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildFleetProjection(test.records, test.now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("BuildFleetProjection error = %v", err)
			}
		})
	}
}
