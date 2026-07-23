// Package runtimetelemetry defines the separately versioned persistence plane
// for aggregate Nebula runtime observations. It intentionally does not extend
// the strict, independently versioned control document.
package runtimetelemetry

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"mesh/internal/runtimeobserver"
)

const (
	StateSchemaV1 = "mesh-runtime-telemetry-state-v1"
	StateSchemaV2 = "mesh-runtime-telemetry-state-v2"
	StateSchemaV3 = "mesh-runtime-telemetry-state-v3"
	StateSchemaV4 = "mesh-runtime-telemetry-state-v4"
	StateSchemaV5 = "mesh-runtime-telemetry-state-v5"
	StateSchemaV6 = "mesh-runtime-telemetry-state-v6"
	StateSchemaV7 = "mesh-runtime-telemetry-state-v7"
	StateSchema   = StateSchemaV7
	VersionV1     = 1
	VersionV2     = 2
	MaxRecords    = 1 << 16
)

var (
	ErrConflict = errors.New("runtime telemetry conflicts with an accepted report")
	ErrInvalid  = errors.New("invalid runtime telemetry")
	ErrReplay   = errors.New("runtime telemetry report replay")

	nodeIDPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	instanceIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	configDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type ObservationState string

const (
	StateUnknown  ObservationState = "unknown"
	StateObserved ObservationState = "observed"
)

type ProcessContinuity string

const (
	ContinuityUnavailable  ProcessContinuity = "unavailable"
	ContinuityUnclassified ProcessContinuity = "unclassified"
	ContinuityContinuous   ProcessContinuity = "continuous"
	ContinuityRestarted    ProcessContinuity = "restarted"
)

type ProbeTransition string

const (
	ProbeTransitionUnavailable  ProbeTransition = "unavailable"
	ProbeTransitionNotEligible  ProbeTransition = "not_eligible"
	ProbeTransitionUnclassified ProbeTransition = "unclassified"
	ProbeTransitionStable       ProbeTransition = "stable"
	ProbeTransitionRecovered    ProbeTransition = "recovered"
	ProbeTransitionDegraded     ProbeTransition = "degraded"
	ProbeTransitionChanged      ProbeTransition = "changed"
)

// Observation is the complete current persisted allowlist. Unknown deliberately
// carries no error or cached snapshot; a failed local observation must not
// preserve a previous healthy-looking sample.
type Observation struct {
	Version  int              `json:"version"`
	State    ObservationState `json:"state"`
	Snapshot *Snapshot        `json:"snapshot,omitempty"`
}

type Snapshot struct {
	ProcessInstanceID string              `json:"process_instance_id"`
	SampleSequence    uint64              `json:"sample_sequence"`
	ProcessUptimeMS   uint64              `json:"process_uptime_ms"`
	Handshakes        HandshakeAggregate  `json:"handshakes"`
	Peers             PeerAggregate       `json:"peers"`
	Lighthouses       LighthouseAggregate `json:"lighthouses"`
}

type HandshakeAggregate struct {
	CompletedTotal            uint64  `json:"completed_total"`
	TimedOutTotal             uint64  `json:"timed_out_total"`
	Pending                   uint64  `json:"pending"`
	MostRecentCompletionAgeMS *uint64 `json:"most_recent_completion_age_ms"`
}

type PeerAggregate struct {
	Established                uint64  `json:"established"`
	AuthenticatedRXWithin2m    uint64  `json:"authenticated_rx_within_2m"`
	AuthenticatedRXWithin5m    uint64  `json:"authenticated_rx_within_5m"`
	OldestAuthenticatedRXAgeMS *uint64 `json:"oldest_authenticated_rx_age_ms"`
}

type LighthouseAggregate struct {
	Configured                     uint64  `json:"configured"`
	Established                    uint64  `json:"established"`
	AuthenticatedRXWithin2m        uint64  `json:"authenticated_rx_within_2m"`
	AuthenticatedRXWithin5m        uint64  `json:"authenticated_rx_within_5m"`
	MostRecentAuthenticatedRXAgeMS *uint64 `json:"most_recent_authenticated_rx_age_ms"`
	Overflow                       bool    `json:"overflow"`
}

// Record binds an observation to the already accepted lifecycle heartbeat
// sequence and to control-plane receive time. Agent wall-clock time is never
// used as freshness evidence.
type Record struct {
	NodeID              string             `json:"node_id"`
	HeartbeatSequence   int64              `json:"heartbeat_sequence"`
	ReceivedAt          time.Time          `json:"received_at"`
	ProcessContinuity   ProcessContinuity  `json:"process_continuity"`
	Observation         Observation        `json:"observation"`
	ActiveProbe         ActiveProbeResult  `json:"active_probe"`
	AppliedConfigSHA256 string             `json:"applied_config_sha256"`
	ProbeTransition     ProbeTransition    `json:"probe_transition"`
	RouteOverlap        RouteOverlapResult `json:"route_overlap"`
	EndpointDNS         EndpointDNSResult  `json:"endpoint_dns"`
}

type State struct {
	Schema  string   `json:"schema"`
	Records []Record `json:"records"`
}

// ReportInput is the agent API envelope. HeartbeatSequence must identify the
// exact lifecycle heartbeat already accepted by the control plane.
type ReportInput struct {
	HeartbeatSequence int64               `json:"heartbeat_sequence"`
	Observation       Observation         `json:"observation"`
	ActiveProbe       *ActiveProbeResult  `json:"active_probe,omitempty"`
	RouteOverlap      *RouteOverlapResult `json:"route_overlap,omitempty"`
	EndpointDNS       *EndpointDNSResult  `json:"endpoint_dns,omitempty"`
}

func EmptyState() State {
	return State{Schema: StateSchema, Records: []Record{}}
}

func ValidateObservation(observation Observation) error {
	if observation.Version != VersionV1 && observation.Version != VersionV2 {
		return fmt.Errorf("%w: unsupported observation version", ErrInvalid)
	}
	switch observation.State {
	case StateUnknown:
		if observation.Snapshot != nil {
			return fmt.Errorf("%w: unknown observation carries a snapshot", ErrInvalid)
		}
		return nil
	case StateObserved:
		if observation.Snapshot == nil {
			return fmt.Errorf("%w: observed telemetry has no snapshot", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unrecognized observation state", ErrInvalid)
	}
	return validateSnapshot(*observation.Snapshot, observation.Version)
}

// NormalizeObservation validates either supported report version and returns
// a detached representation. V1 remains V1 so a migration never fabricates
// the exact retained age that older observers did not report.
func NormalizeObservation(observation Observation) (Observation, error) {
	if err := ValidateObservation(observation); err != nil {
		return Observation{}, err
	}
	normalized := cloneObservation(observation)
	return normalized, nil
}

func validateSnapshot(snapshot Snapshot, version int) error {
	if !instanceIDPattern.MatchString(snapshot.ProcessInstanceID) ||
		snapshot.SampleSequence > runtimeobserver.MaxExactJSONInteger ||
		snapshot.ProcessUptimeMS > runtimeobserver.MaxExactJSONInteger {
		return fmt.Errorf("%w: invalid process identity or counter", ErrInvalid)
	}
	handshakes, peers, lighthouses := snapshot.Handshakes, snapshot.Peers, snapshot.Lighthouses
	if handshakes.CompletedTotal > runtimeobserver.MaxExactJSONInteger ||
		handshakes.TimedOutTotal > runtimeobserver.MaxExactJSONInteger ||
		handshakes.Pending > runtimeobserver.MaxAggregateCount ||
		(handshakes.CompletedTotal == 0) != (handshakes.MostRecentCompletionAgeMS == nil) ||
		!validAge(handshakes.MostRecentCompletionAgeMS, snapshot.ProcessUptimeMS) {
		return fmt.Errorf("%w: invalid handshake aggregate", ErrInvalid)
	}
	if peers.Established > runtimeobserver.MaxAggregateCount ||
		peers.AuthenticatedRXWithin2m > peers.AuthenticatedRXWithin5m ||
		peers.AuthenticatedRXWithin5m > peers.Established ||
		(peers.Established == 0 && peers.OldestAuthenticatedRXAgeMS != nil) ||
		(peers.OldestAuthenticatedRXAgeMS == nil && peers.AuthenticatedRXWithin5m != 0) ||
		!validAge(peers.OldestAuthenticatedRXAgeMS, snapshot.ProcessUptimeMS) {
		return fmt.Errorf("%w: invalid peer aggregate", ErrInvalid)
	}
	if lighthouses.Configured > runtimeobserver.MaxConfiguredLighthouses ||
		lighthouses.Established > lighthouses.Configured ||
		lighthouses.Established > peers.Established ||
		lighthouses.AuthenticatedRXWithin2m > lighthouses.AuthenticatedRXWithin5m ||
		lighthouses.AuthenticatedRXWithin5m > lighthouses.Established ||
		lighthouses.AuthenticatedRXWithin2m > peers.AuthenticatedRXWithin2m ||
		lighthouses.AuthenticatedRXWithin5m > peers.AuthenticatedRXWithin5m ||
		lighthouses.Overflow != (lighthouses.Configured > runtimeobserver.MaxLighthouseEntries) ||
		!validAge(lighthouses.MostRecentAuthenticatedRXAgeMS, snapshot.ProcessUptimeMS) ||
		(lighthouses.Configured == 0 && lighthouses.MostRecentAuthenticatedRXAgeMS != nil) ||
		(version == VersionV1 && lighthouses.MostRecentAuthenticatedRXAgeMS != nil) ||
		(version == VersionV2 && lighthouses.AuthenticatedRXWithin5m > 0 && lighthouses.MostRecentAuthenticatedRXAgeMS == nil) ||
		(version == VersionV2 && lighthouses.AuthenticatedRXWithin2m > 0 && *lighthouses.MostRecentAuthenticatedRXAgeMS > runtimeobserver.AuthenticatedRX2mLimit) ||
		(version == VersionV2 && lighthouses.AuthenticatedRXWithin5m > 0 && *lighthouses.MostRecentAuthenticatedRXAgeMS > runtimeobserver.AuthenticatedRX5mLimit) {
		return fmt.Errorf("%w: invalid lighthouse aggregate", ErrInvalid)
	}
	if handshakes.CompletedTotal < peers.Established {
		return fmt.Errorf("%w: established peers exceed completed handshakes", ErrInvalid)
	}
	return nil
}

func validAge(age *uint64, uptime uint64) bool {
	return age == nil || (*age <= runtimeobserver.MaxAgeMilliseconds && *age <= uptime)
}

func ValidateRecord(record Record) error {
	if !nodeIDPattern.MatchString(record.NodeID) || record.HeartbeatSequence < 1 ||
		record.HeartbeatSequence > int64(runtimeobserver.MaxExactJSONInteger) ||
		record.ReceivedAt.IsZero() || record.ReceivedAt.Location() != time.UTC {
		return fmt.Errorf("%w: invalid record identity, sequence, or timestamp", ErrInvalid)
	}
	if err := ValidateObservation(record.Observation); err != nil {
		return err
	}
	if err := ValidateActiveProbe(record.ActiveProbe); err != nil {
		return err
	}
	if record.AppliedConfigSHA256 != "" && !configDigestPattern.MatchString(record.AppliedConfigSHA256) {
		return fmt.Errorf("%w: invalid applied configuration digest", ErrInvalid)
	}
	if !validProbeTransition(record.ActiveProbe, record.ProbeTransition) {
		return fmt.Errorf("%w: active probe has invalid transition", ErrInvalid)
	}
	if comparativeProbeTransition(record.ProbeTransition) && record.AppliedConfigSHA256 == "" {
		return fmt.Errorf("%w: comparative active probe transition has no configuration binding", ErrInvalid)
	}
	if err := ValidateRouteOverlap(record.RouteOverlap); err != nil {
		return err
	}
	if err := ValidateEndpointDNS(record.EndpointDNS); err != nil {
		return err
	}
	switch record.Observation.State {
	case StateUnknown:
		if record.ProcessContinuity != ContinuityUnavailable {
			return fmt.Errorf("%w: unknown observation has invalid process continuity", ErrInvalid)
		}
	case StateObserved:
		if record.ProcessContinuity != ContinuityUnclassified && record.ProcessContinuity != ContinuityContinuous && record.ProcessContinuity != ContinuityRestarted {
			return fmt.Errorf("%w: observed telemetry has invalid process continuity", ErrInvalid)
		}
	}
	return nil
}

func initialProbeTransition(probe ActiveProbeResult) ProbeTransition {
	switch probe.State {
	case ProbeNotEligible:
		return ProbeTransitionNotEligible
	case ProbeAttempted:
		return ProbeTransitionUnclassified
	default:
		return ProbeTransitionUnavailable
	}
}

func validProbeTransition(probe ActiveProbeResult, transition ProbeTransition) bool {
	switch probe.State {
	case ProbeNotEligible:
		return transition == ProbeTransitionNotEligible
	case ProbeAttempted:
		switch transition {
		case ProbeTransitionUnclassified, ProbeTransitionStable:
			return true
		case ProbeTransitionRecovered:
			return probe.Replied == probe.Attempted
		case ProbeTransitionDegraded, ProbeTransitionChanged:
			return probe.Replied < probe.Attempted
		default:
			return false
		}
	case ProbeUnsupported, ProbeCapabilityUnavailable, ProbeUnavailable:
		return transition == ProbeTransitionUnavailable
	default:
		return false
	}
}

func comparativeProbeTransition(transition ProbeTransition) bool {
	return transition == ProbeTransitionStable || transition == ProbeTransitionRecovered ||
		transition == ProbeTransitionDegraded || transition == ProbeTransitionChanged
}

func ValidateState(state State) error {
	if state.Schema != StateSchema || state.Records == nil || len(state.Records) > MaxRecords {
		return fmt.Errorf("%w: invalid state schema or cardinality", ErrInvalid)
	}
	if !sort.SliceIsSorted(state.Records, func(i, j int) bool { return state.Records[i].NodeID < state.Records[j].NodeID }) {
		return fmt.Errorf("%w: records are not canonically ordered", ErrInvalid)
	}
	for index, record := range state.Records {
		if err := ValidateRecord(record); err != nil {
			return fmt.Errorf("record %d: %w", index, err)
		}
		if index > 0 && state.Records[index-1].NodeID == record.NodeID {
			return fmt.Errorf("%w: duplicate node record", ErrInvalid)
		}
	}
	return nil
}
