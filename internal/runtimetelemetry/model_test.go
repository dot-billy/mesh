package runtimetelemetry

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validObservation() Observation {
	handshakeAge, receiveAge, lighthouseReceiveAge := uint64(500), uint64(300), uint64(250)
	return Observation{Version: VersionV2, State: StateObserved, Snapshot: &Snapshot{
		ProcessInstanceID: "0123456789abcdef0123456789abcdef", SampleSequence: 7, ProcessUptimeMS: 60_000,
		Handshakes:  HandshakeAggregate{CompletedTotal: 3, TimedOutTotal: 1, Pending: 0, MostRecentCompletionAgeMS: &handshakeAge},
		Peers:       PeerAggregate{Established: 2, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 2, OldestAuthenticatedRXAgeMS: &receiveAge},
		Lighthouses: LighthouseAggregate{Configured: 2, Established: 1, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 1, MostRecentAuthenticatedRXAgeMS: &lighthouseReceiveAge},
	}}
}

func TestNormalizeObservationPreservesV1SemanticsWithoutInventingHistory(t *testing.T) {
	legacy := validObservation()
	legacy.Version = VersionV1
	legacy.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = nil

	upgraded, err := NormalizeObservation(legacy)
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if upgraded.Version != VersionV1 || upgraded.Snapshot == nil || upgraded.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS != nil {
		t.Fatalf("legacy observation was not safely upgraded: %#v", upgraded)
	}
}

func TestValidateObservationAllowsRetainedLighthouseRXWithoutTunnel(t *testing.T) {
	observation := validObservation()
	observation.Snapshot.Peers = PeerAggregate{}
	age := uint64(59_000)
	observation.Snapshot.Lighthouses = LighthouseAggregate{Configured: 1, MostRecentAuthenticatedRXAgeMS: &age}
	if err := ValidateObservation(observation); err != nil {
		t.Fatalf("retained lighthouse receive rejected: %v", err)
	}
}

func TestValidateObservationFailClosedShapes(t *testing.T) {
	if err := ValidateObservation(Observation{Version: VersionV2, State: StateUnknown}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateObservation(validObservation()); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Observation){
		"unknown snapshot":  func(value *Observation) { value.State = StateUnknown },
		"missing snapshot":  func(value *Observation) { value.Snapshot = nil },
		"instance identity": func(value *Observation) { value.Snapshot.ProcessInstanceID = "ABC" },
		"peer ordering":     func(value *Observation) { value.Snapshot.Peers.AuthenticatedRXWithin2m = 3 },
		"lighthouse subset": func(value *Observation) { value.Snapshot.Lighthouses.Established = 3 },
		"overflow":          func(value *Observation) { value.Snapshot.Lighthouses.Overflow = true },
		"retained lighthouse age beyond uptime": func(value *Observation) {
			age := uint64(60_001)
			value.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = &age
		},
		"current lighthouse receive without retained age": func(value *Observation) {
			value.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = nil
		},
		"age beyond uptime": func(value *Observation) {
			age := uint64(60_001)
			value.Snapshot.Peers.OldestAuthenticatedRXAgeMS = &age
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := validObservation()
			mutate(&candidate)
			if err := ValidateObservation(candidate); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid observation returned %v", err)
			}
		})
	}
}

func TestValidateStateRequiresCanonicalUniqueRecords(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	recordA := Record{NodeID: "node_a", HeartbeatSequence: 1, ReceivedAt: now, ProcessContinuity: ContinuityUnclassified, Observation: validObservation(), ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS()}
	recordB := recordA
	recordB.NodeID = "node_b"
	if err := ValidateState(State{Schema: StateSchema, Records: []Record{recordA, recordB}}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateState(State{Schema: StateSchema, Records: []Record{recordB, recordA}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unordered state returned %v", err)
	}
	if err := ValidateState(State{Schema: StateSchema, Records: []Record{recordA, recordA}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate state returned %v", err)
	}
}

func TestValidateRecordRequiresConsistentProcessContinuity(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		observation Observation
		continuity  ProcessContinuity
	}{
		{name: "unknown unclassified", observation: Observation{Version: VersionV2, State: StateUnknown}, continuity: ContinuityUnclassified},
		{name: "observed unavailable", observation: validObservation(), continuity: ContinuityUnavailable},
		{name: "observed invalid", observation: validObservation(), continuity: ProcessContinuity("invalid")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := Record{NodeID: "node_a", HeartbeatSequence: 1, ReceivedAt: now, ProcessContinuity: test.continuity, Observation: test.observation, ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS()}
			if err := ValidateRecord(record); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid continuity returned %v", err)
			}
		})
	}
}

func TestValidateRecordRequiresConfigBoundConsistentProbeTransition(t *testing.T) {
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		probe      ActiveProbeResult
		transition ProbeTransition
		digest     string
	}{
		{name: "comparative transition without digest", probe: transitionProbe(2, 1), transition: ProbeTransitionStable},
		{name: "recovered remains partial", probe: transitionProbe(2, 1), transition: ProbeTransitionRecovered, digest: digest},
		{name: "degraded is complete", probe: transitionProbe(2, 2), transition: ProbeTransitionDegraded, digest: digest},
		{name: "changed is complete", probe: transitionProbe(2, 2), transition: ProbeTransitionChanged, digest: digest},
		{name: "unsupported recovered", probe: UnsupportedActiveProbe(), transition: ProbeTransitionRecovered, digest: digest},
		{name: "invalid digest", probe: transitionProbe(2, 1), transition: ProbeTransitionUnclassified, digest: "invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := Record{
				NodeID: "node_a", HeartbeatSequence: 1, ReceivedAt: now,
				ProcessContinuity: ContinuityUnclassified, Observation: validObservation(),
				ActiveProbe: test.probe, AppliedConfigSHA256: test.digest, ProbeTransition: test.transition,
				RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
			}
			if err := ValidateRecord(record); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid transition returned %v", err)
			}
		})
	}
}
