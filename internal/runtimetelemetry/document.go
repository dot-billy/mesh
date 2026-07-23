package runtimetelemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

const MaxStateDocumentBytes = 32 << 20

// EncodeState emits the one canonical current document representation.
func EncodeState(state State) ([]byte, error) {
	if err := ValidateState(state); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode runtime telemetry state: %w", err)
	}
	if len(raw) == 0 || len(raw) > MaxStateDocumentBytes {
		return nil, fmt.Errorf("%w: state exceeds the %d-byte safety limit", ErrInvalid, MaxStateDocumentBytes)
	}
	return raw, nil
}

// DecodeState rejects invalid UTF-8, duplicate or unknown fields, trailing
// data, noncanonical encodings, invalid cross-field aggregates, and oversized
// state before it can become freshness evidence.
func DecodeState(raw []byte) (State, error) {
	if len(raw) == 0 || len(raw) > MaxStateDocumentBytes || !utf8.Valid(raw) {
		return State{}, fmt.Errorf("%w: invalid state document size or encoding", ErrInvalid)
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return State{}, err
	}
	if state, err := decodeCurrentState(raw); err == nil {
		return state, nil
	}
	if state, err := decodeStateV6(raw); err == nil {
		return state, nil
	}
	if state, err := decodeStateV5(raw); err == nil {
		return state, nil
	}
	if state, err := decodeStateV4(raw); err == nil {
		return state, nil
	}
	if state, err := decodeStateV3(raw); err == nil {
		return state, nil
	}
	if state, err := decodeStateV2(raw); err == nil {
		return state, nil
	}
	if state, err := decodeStateV1(raw); err == nil {
		return state, nil
	}
	return State{}, fmt.Errorf("%w: unsupported or noncanonical state document", ErrInvalid)
}

type stateV6 struct {
	Schema  string     `json:"schema"`
	Records []recordV6 `json:"records"`
}

type recordV6 struct {
	NodeID            string             `json:"node_id"`
	HeartbeatSequence int64              `json:"heartbeat_sequence"`
	ReceivedAt        time.Time          `json:"received_at"`
	ProcessContinuity ProcessContinuity  `json:"process_continuity"`
	Observation       Observation        `json:"observation"`
	ActiveProbe       ActiveProbeResult  `json:"active_probe"`
	RouteOverlap      RouteOverlapResult `json:"route_overlap"`
	EndpointDNS       EndpointDNSResult  `json:"endpoint_dns"`
}

func decodeStateV6(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy stateV6
	if err := decoder.Decode(&legacy); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalid
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(raw, canonical) || legacy.Schema != StateSchemaV6 || legacy.Records == nil || len(legacy.Records) > MaxRecords {
		return State{}, ErrInvalid
	}
	state := State{Schema: StateSchema, Records: make([]Record, len(legacy.Records))}
	for index, legacyRecord := range legacy.Records {
		normalized, err := NormalizeObservation(legacyRecord.Observation)
		if err != nil {
			return State{}, err
		}
		state.Records[index] = Record{
			NodeID: legacyRecord.NodeID, HeartbeatSequence: legacyRecord.HeartbeatSequence,
			ReceivedAt: legacyRecord.ReceivedAt, ProcessContinuity: legacyRecord.ProcessContinuity,
			Observation: normalized, ActiveProbe: CloneActiveProbe(legacyRecord.ActiveProbe),
			ProbeTransition: initialProbeTransition(legacyRecord.ActiveProbe),
			RouteOverlap:    CloneRouteOverlap(legacyRecord.RouteOverlap), EndpointDNS: CloneEndpointDNS(legacyRecord.EndpointDNS),
		}
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

type stateV5 struct {
	Schema  string     `json:"schema"`
	Records []recordV5 `json:"records"`
}

type recordV5 struct {
	NodeID            string             `json:"node_id"`
	HeartbeatSequence int64              `json:"heartbeat_sequence"`
	ReceivedAt        time.Time          `json:"received_at"`
	ProcessContinuity ProcessContinuity  `json:"process_continuity"`
	Observation       Observation        `json:"observation"`
	ActiveProbe       ActiveProbeResult  `json:"active_probe"`
	RouteOverlap      RouteOverlapResult `json:"route_overlap"`
}

func decodeStateV5(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy stateV5
	if err := decoder.Decode(&legacy); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalid
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(raw, canonical) || legacy.Schema != StateSchemaV5 || legacy.Records == nil || len(legacy.Records) > MaxRecords {
		return State{}, ErrInvalid
	}
	state := State{Schema: StateSchema, Records: make([]Record, len(legacy.Records))}
	for index, legacyRecord := range legacy.Records {
		normalized, err := NormalizeObservation(legacyRecord.Observation)
		if err != nil {
			return State{}, err
		}
		state.Records[index] = Record{
			NodeID: legacyRecord.NodeID, HeartbeatSequence: legacyRecord.HeartbeatSequence,
			ReceivedAt: legacyRecord.ReceivedAt, ProcessContinuity: legacyRecord.ProcessContinuity,
			Observation: normalized, ActiveProbe: CloneActiveProbe(legacyRecord.ActiveProbe),
			ProbeTransition: initialProbeTransition(legacyRecord.ActiveProbe),
			RouteOverlap:    CloneRouteOverlap(legacyRecord.RouteOverlap), EndpointDNS: UnsupportedEndpointDNS(),
		}
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

type stateV4 struct {
	Schema  string     `json:"schema"`
	Records []recordV4 `json:"records"`
}

type recordV4 struct {
	NodeID            string            `json:"node_id"`
	HeartbeatSequence int64             `json:"heartbeat_sequence"`
	ReceivedAt        time.Time         `json:"received_at"`
	ProcessContinuity ProcessContinuity `json:"process_continuity"`
	Observation       Observation       `json:"observation"`
	ActiveProbe       ActiveProbeResult `json:"active_probe"`
}

func decodeStateV4(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy stateV4
	if err := decoder.Decode(&legacy); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalid
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(raw, canonical) || legacy.Schema != StateSchemaV4 || legacy.Records == nil || len(legacy.Records) > MaxRecords {
		return State{}, ErrInvalid
	}
	state := State{Schema: StateSchema, Records: make([]Record, len(legacy.Records))}
	for index, legacyRecord := range legacy.Records {
		normalized, err := NormalizeObservation(legacyRecord.Observation)
		if err != nil {
			return State{}, err
		}
		state.Records[index] = Record{
			NodeID: legacyRecord.NodeID, HeartbeatSequence: legacyRecord.HeartbeatSequence,
			ReceivedAt: legacyRecord.ReceivedAt, ProcessContinuity: legacyRecord.ProcessContinuity,
			Observation: normalized, ActiveProbe: CloneActiveProbe(legacyRecord.ActiveProbe),
			ProbeTransition: initialProbeTransition(legacyRecord.ActiveProbe),
			RouteOverlap:    UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
		}
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

type stateV3 struct {
	Schema  string     `json:"schema"`
	Records []recordV3 `json:"records"`
}

type recordV3 struct {
	NodeID            string            `json:"node_id"`
	HeartbeatSequence int64             `json:"heartbeat_sequence"`
	ReceivedAt        time.Time         `json:"received_at"`
	ProcessContinuity ProcessContinuity `json:"process_continuity"`
	Observation       Observation       `json:"observation"`
}

func decodeStateV3(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy stateV3
	if err := decoder.Decode(&legacy); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalid
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(raw, canonical) || legacy.Schema != StateSchemaV3 || legacy.Records == nil || len(legacy.Records) > MaxRecords {
		return State{}, ErrInvalid
	}
	state := State{Schema: StateSchema, Records: make([]Record, len(legacy.Records))}
	for index, legacyRecord := range legacy.Records {
		normalized, err := NormalizeObservation(legacyRecord.Observation)
		if err != nil {
			return State{}, err
		}
		state.Records[index] = Record{
			NodeID: legacyRecord.NodeID, HeartbeatSequence: legacyRecord.HeartbeatSequence,
			ReceivedAt: legacyRecord.ReceivedAt, ProcessContinuity: legacyRecord.ProcessContinuity,
			Observation: normalized, ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
		}
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

type stateV2 struct {
	Schema  string     `json:"schema"`
	Records []recordV2 `json:"records"`
}

type recordV2 struct {
	NodeID            string      `json:"node_id"`
	HeartbeatSequence int64       `json:"heartbeat_sequence"`
	ReceivedAt        time.Time   `json:"received_at"`
	Observation       Observation `json:"observation"`
}

func decodeStateV2(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy stateV2
	if err := decoder.Decode(&legacy); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalid
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(raw, canonical) || legacy.Schema != StateSchemaV2 || legacy.Records == nil || len(legacy.Records) > MaxRecords {
		return State{}, ErrInvalid
	}
	state := State{Schema: StateSchema, Records: make([]Record, len(legacy.Records))}
	for index, legacyRecord := range legacy.Records {
		normalized, err := NormalizeObservation(legacyRecord.Observation)
		if err != nil {
			return State{}, err
		}
		state.Records[index] = Record{
			NodeID: legacyRecord.NodeID, HeartbeatSequence: legacyRecord.HeartbeatSequence,
			ReceivedAt: legacyRecord.ReceivedAt, ProcessContinuity: migratedContinuity(normalized), Observation: normalized,
			ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
		}
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func decodeCurrentState(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("%w: decode state document: %v", ErrInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, fmt.Errorf("%w: trailing state document data", ErrInvalid)
	}
	canonical, err := EncodeState(state)
	if err != nil {
		return State{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return State{}, fmt.Errorf("%w: state document is not canonical", ErrInvalid)
	}
	return state, nil
}

type stateV1 struct {
	Schema  string     `json:"schema"`
	Records []recordV1 `json:"records"`
}

type recordV1 struct {
	NodeID            string        `json:"node_id"`
	HeartbeatSequence int64         `json:"heartbeat_sequence"`
	ReceivedAt        time.Time     `json:"received_at"`
	Observation       observationV1 `json:"observation"`
}

type observationV1 struct {
	Version  int              `json:"version"`
	State    ObservationState `json:"state"`
	Snapshot *snapshotV1      `json:"snapshot,omitempty"`
}

type snapshotV1 struct {
	ProcessInstanceID string                `json:"process_instance_id"`
	SampleSequence    uint64                `json:"sample_sequence"`
	ProcessUptimeMS   uint64                `json:"process_uptime_ms"`
	Handshakes        HandshakeAggregate    `json:"handshakes"`
	Peers             PeerAggregate         `json:"peers"`
	Lighthouses       lighthouseAggregateV1 `json:"lighthouses"`
}

type lighthouseAggregateV1 struct {
	Configured              uint64 `json:"configured"`
	Established             uint64 `json:"established"`
	AuthenticatedRXWithin2m uint64 `json:"authenticated_rx_within_2m"`
	AuthenticatedRXWithin5m uint64 `json:"authenticated_rx_within_5m"`
	Overflow                bool   `json:"overflow"`
}

func decodeStateV1(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy stateV1
	if err := decoder.Decode(&legacy); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalid
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(raw, canonical) || legacy.Schema != StateSchemaV1 || legacy.Records == nil || len(legacy.Records) > MaxRecords {
		return State{}, ErrInvalid
	}
	state := State{Schema: StateSchema, Records: make([]Record, len(legacy.Records))}
	for index, legacyRecord := range legacy.Records {
		observation := Observation{Version: legacyRecord.Observation.Version, State: legacyRecord.Observation.State}
		if legacyRecord.Observation.Snapshot != nil {
			legacySnapshot := legacyRecord.Observation.Snapshot
			observation.Snapshot = &Snapshot{
				ProcessInstanceID: legacySnapshot.ProcessInstanceID,
				SampleSequence:    legacySnapshot.SampleSequence,
				ProcessUptimeMS:   legacySnapshot.ProcessUptimeMS,
				Handshakes:        legacySnapshot.Handshakes,
				Peers:             legacySnapshot.Peers,
				Lighthouses: LighthouseAggregate{
					Configured: legacySnapshot.Lighthouses.Configured, Established: legacySnapshot.Lighthouses.Established,
					AuthenticatedRXWithin2m: legacySnapshot.Lighthouses.AuthenticatedRXWithin2m,
					AuthenticatedRXWithin5m: legacySnapshot.Lighthouses.AuthenticatedRXWithin5m,
					Overflow:                legacySnapshot.Lighthouses.Overflow,
				},
			}
		}
		normalized, err := NormalizeObservation(observation)
		if err != nil {
			return State{}, err
		}
		state.Records[index] = Record{
			NodeID: legacyRecord.NodeID, HeartbeatSequence: legacyRecord.HeartbeatSequence,
			ReceivedAt: legacyRecord.ReceivedAt, ProcessContinuity: migratedContinuity(normalized), Observation: normalized,
			ActiveProbe: UnsupportedActiveProbe(), ProbeTransition: ProbeTransitionUnavailable, RouteOverlap: UnsupportedRouteOverlap(), EndpointDNS: UnsupportedEndpointDNS(),
		}
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func migratedContinuity(observation Observation) ProcessContinuity {
	if observation.State == StateUnknown {
		return ContinuityUnavailable
	}
	return ContinuityUnclassified
}

func rejectDuplicateJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return fmt.Errorf("%w: duplicate or malformed state JSON", ErrInvalid)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing state JSON", ErrInvalid)
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object name is not a string")
			}
			if _, duplicate := names[name]; duplicate {
				return errors.New("duplicate object name")
			}
			names[name] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object terminator")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array terminator")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
