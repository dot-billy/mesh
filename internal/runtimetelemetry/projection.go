package runtimetelemetry

import (
	"fmt"
	"time"
)

const (
	FleetProjectionSchemaV2      = "mesh-runtime-telemetry-fleet-v2"
	FleetProjectionSchemaV3      = "mesh-runtime-telemetry-fleet-v3"
	FleetProjectionSchemaV4      = "mesh-runtime-telemetry-fleet-v4"
	FleetProjectionSchemaV5      = "mesh-runtime-telemetry-fleet-v5"
	FleetProjectionSchema        = FleetProjectionSchemaV5
	ObservationStaleAfter        = 5 * time.Minute
	EndToEndReachabilityProven   = false
	FleetProjectionAggregateOnly = true
)

// FleetProjection is the administrator-facing, read-only observation
// contract. It is intentionally separate from lifecycle health and omits the
// observer process identity. The policy fields make the evidence boundary
// explicit to every strict client.
type FleetProjection struct {
	Schema      string                `json:"schema"`
	GeneratedAt time.Time             `json:"generated_at"`
	Policy      FleetProjectionPolicy `json:"policy"`
	Records     []FleetRecord         `json:"records"`
}

type FleetProjectionPolicy struct {
	ObservationStaleAfterSeconds int64 `json:"observation_stale_after_seconds"`
	AggregateOnly                bool  `json:"aggregate_only"`
	EndToEndReachabilityProven   bool  `json:"end_to_end_reachability_proven"`
}

type FleetRecord struct {
	NodeID             string                    `json:"node_id"`
	HeartbeatSequence  int64                     `json:"heartbeat_sequence"`
	ReceivedAt         time.Time                 `json:"received_at"`
	ObservationVersion int                       `json:"observation_version"`
	ProcessContinuity  ProcessContinuity         `json:"process_continuity"`
	State              ObservationState          `json:"state"`
	Snapshot           *FleetObservationSnapshot `json:"snapshot,omitempty"`
	ActiveProbe        ActiveProbeResult         `json:"active_probe"`
	ProbeTransition    ProbeTransition           `json:"probe_transition"`
}

// FleetObservationSnapshot exposes only aggregate counters and ages. In
// particular, ProcessInstanceID is not part of the administrator contract.
type FleetObservationSnapshot struct {
	SampleSequence  uint64              `json:"sample_sequence"`
	ProcessUptimeMS uint64              `json:"process_uptime_ms"`
	Handshakes      HandshakeAggregate  `json:"handshakes"`
	Peers           PeerAggregate       `json:"peers"`
	Lighthouses     LighthouseAggregate `json:"lighthouses"`
}

// BuildFleetProjection validates the complete repository view before creating
// an allowlisted API projection. Reports received after GeneratedAt fail
// closed instead of being presented as fresh evidence after a server-clock
// regression.
func BuildFleetProjection(records []Record, generatedAt time.Time) (FleetProjection, error) {
	if generatedAt.IsZero() || generatedAt.Location() != time.UTC {
		return FleetProjection{}, fmt.Errorf("%w: invalid fleet projection timestamp", ErrInvalid)
	}
	if err := ValidateState(State{Schema: StateSchema, Records: records}); err != nil {
		return FleetProjection{}, err
	}
	projection := FleetProjection{
		Schema:      FleetProjectionSchema,
		GeneratedAt: generatedAt,
		Policy: FleetProjectionPolicy{
			ObservationStaleAfterSeconds: int64(ObservationStaleAfter / time.Second),
			AggregateOnly:                FleetProjectionAggregateOnly,
			EndToEndReachabilityProven:   EndToEndReachabilityProven,
		},
		Records: make([]FleetRecord, 0, len(records)),
	}
	for index, record := range records {
		if record.ReceivedAt.After(generatedAt) {
			return FleetProjection{}, fmt.Errorf("%w: record %d was received after projection generation", ErrInvalid, index)
		}
		projected := FleetRecord{
			NodeID: record.NodeID, HeartbeatSequence: record.HeartbeatSequence,
			ReceivedAt: record.ReceivedAt, ObservationVersion: record.Observation.Version,
			ProcessContinuity: record.ProcessContinuity, State: record.Observation.State,
			ActiveProbe: CloneActiveProbe(record.ActiveProbe), ProbeTransition: record.ProbeTransition,
		}
		if record.Observation.Snapshot != nil {
			snapshot := record.Observation.Snapshot
			projected.Snapshot = &FleetObservationSnapshot{
				SampleSequence: snapshot.SampleSequence, ProcessUptimeMS: snapshot.ProcessUptimeMS,
				Handshakes: snapshot.Handshakes, Peers: snapshot.Peers, Lighthouses: snapshot.Lighthouses,
			}
			projected.Snapshot.Handshakes.MostRecentCompletionAgeMS = cloneUint64(snapshot.Handshakes.MostRecentCompletionAgeMS)
			projected.Snapshot.Peers.OldestAuthenticatedRXAgeMS = cloneUint64(snapshot.Peers.OldestAuthenticatedRXAgeMS)
			projected.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = cloneUint64(snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS)
		}
		projection.Records = append(projection.Records, projected)
	}
	return projection, nil
}
