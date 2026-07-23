package runtimetelemetry

import (
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"
)

var ErrClosed = errors.New("runtime telemetry store is closed")

// Store is the backend-neutral bounded observation repository. Put is
// idempotent only for an exact same-sequence retry; lower sequences are replay.
type Store interface {
	Put(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult) (Record, bool, error)
	PutWithRoute(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult) (Record, bool, error)
	PutWithDNS(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult) (Record, bool, error)
	PutWithConfig(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult, appliedConfigSHA256 string) (Record, bool, error)
	Get(nodeID string) (Record, bool, error)
	List() ([]Record, error)
	Delete(nodeID string) (bool, error)
	CheckReadiness() error
	Close() error
}

// MemoryStore exercises the exact transition contract and is useful for
// service tests. Durable file and PostgreSQL adapters implement the same seam.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
	closed  bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (s *MemoryStore) Put(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult) (Record, bool, error) {
	return s.PutWithRoute(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, UnsupportedRouteOverlap())
}

func (s *MemoryStore) PutWithRoute(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult) (Record, bool, error) {
	return s.PutWithDNS(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, UnsupportedEndpointDNS())
}

func (s *MemoryStore) PutWithDNS(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult) (Record, bool, error) {
	return s.PutWithConfig(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, endpointDNS, "")
}

func (s *MemoryStore) PutWithConfig(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult, appliedConfigSHA256 string) (Record, bool, error) {
	candidate, err := newCandidateRecord(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, endpointDNS, appliedConfigSHA256)
	if err != nil {
		return Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, false, ErrClosed
	}
	existing, found := s.records[nodeID]
	var previous *Record
	if found {
		previous = &existing
	}
	accepted, changed, err := transitionRecord(previous, candidate)
	if err != nil || !changed {
		return accepted, changed, err
	}
	if !found && len(s.records) >= MaxRecords {
		return Record{}, false, ErrInvalid
	}
	s.records[nodeID] = cloneRecord(accepted)
	return cloneRecord(accepted), true, nil
}

func newCandidateRecord(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult, appliedConfigSHA256 string) (Record, error) {
	continuity := ContinuityUnclassified
	if observation.State == StateUnknown {
		continuity = ContinuityUnavailable
	}
	candidate := Record{
		NodeID: nodeID, HeartbeatSequence: heartbeatSequence, ReceivedAt: receivedAt,
		ProcessContinuity: continuity, Observation: cloneObservation(observation), ActiveProbe: CloneActiveProbe(activeProbe),
		AppliedConfigSHA256: appliedConfigSHA256, ProbeTransition: initialProbeTransition(activeProbe),
		RouteOverlap: CloneRouteOverlap(routeOverlap), EndpointDNS: CloneEndpointDNS(endpointDNS),
	}
	if err := ValidateRecord(candidate); err != nil {
		return Record{}, err
	}
	return candidate, nil
}

func transitionRecord(existing *Record, candidate Record) (Record, bool, error) {
	if existing != nil {
		switch {
		case candidate.HeartbeatSequence < existing.HeartbeatSequence:
			return Record{}, false, ErrReplay
		case candidate.HeartbeatSequence == existing.HeartbeatSequence:
			if !reflect.DeepEqual(existing.Observation, candidate.Observation) || !reflect.DeepEqual(existing.ActiveProbe, candidate.ActiveProbe) || existing.AppliedConfigSHA256 != candidate.AppliedConfigSHA256 || !reflect.DeepEqual(existing.RouteOverlap, candidate.RouteOverlap) || !reflect.DeepEqual(existing.EndpointDNS, candidate.EndpointDNS) {
				return Record{}, false, ErrConflict
			}
			return cloneRecord(*existing), false, nil
		}
	}

	switch {
	case candidate.Observation.State == StateUnknown:
		candidate.ProcessContinuity = ContinuityUnavailable
	case existing == nil || existing.Observation.State == StateUnknown:
		candidate.ProcessContinuity = ContinuityUnclassified
	default:
		previous := existing.Observation.Snapshot
		current := candidate.Observation.Snapshot
		if previous.ProcessInstanceID != current.ProcessInstanceID {
			candidate.ProcessContinuity = ContinuityRestarted
			break
		}
		if current.SampleSequence <= previous.SampleSequence {
			return Record{}, false, ErrReplay
		}
		if candidate.Observation.Version != existing.Observation.Version ||
			current.ProcessUptimeMS < previous.ProcessUptimeMS ||
			current.Handshakes.CompletedTotal < previous.Handshakes.CompletedTotal ||
			current.Handshakes.TimedOutTotal < previous.Handshakes.TimedOutTotal {
			return Record{}, false, ErrConflict
		}
		candidate.ProcessContinuity = ContinuityContinuous
	}
	transition, err := transitionActiveProbe(existing, candidate)
	if err != nil {
		return Record{}, false, err
	}
	candidate.ProbeTransition = transition
	if err := ValidateRecord(candidate); err != nil {
		return Record{}, false, err
	}
	return cloneRecord(candidate), true, nil
}

func transitionActiveProbe(existing *Record, candidate Record) (ProbeTransition, error) {
	current := initialProbeTransition(candidate.ActiveProbe)
	if candidate.ActiveProbe.State != ProbeAttempted || existing == nil || existing.ActiveProbe.State != ProbeAttempted ||
		candidate.HeartbeatSequence != existing.HeartbeatSequence+1 || candidate.AppliedConfigSHA256 == "" ||
		existing.AppliedConfigSHA256 != candidate.AppliedConfigSHA256 {
		return current, nil
	}
	if candidate.ActiveProbe.Attempted != existing.ActiveProbe.Attempted {
		return "", ErrConflict
	}
	previousComplete := existing.ActiveProbe.Replied == existing.ActiveProbe.Attempted
	currentComplete := candidate.ActiveProbe.Replied == candidate.ActiveProbe.Attempted
	switch {
	case candidate.ActiveProbe.Replied == existing.ActiveProbe.Replied:
		return ProbeTransitionStable, nil
	case !previousComplete && currentComplete:
		return ProbeTransitionRecovered, nil
	case previousComplete && !currentComplete:
		return ProbeTransitionDegraded, nil
	default:
		return ProbeTransitionChanged, nil
	}
}

func (s *MemoryStore) Get(nodeID string) (Record, bool, error) {
	if !nodeIDPattern.MatchString(nodeID) {
		return Record{}, false, ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, false, ErrClosed
	}
	record, found := s.records[nodeID]
	return cloneRecord(record), found, nil
}

func (s *MemoryStore) List() ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].NodeID < records[j].NodeID })
	return records, nil
}

func (s *MemoryStore) Delete(nodeID string) (bool, error) {
	if !nodeIDPattern.MatchString(nodeID) {
		return false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	if _, found := s.records[nodeID]; !found {
		return false, nil
	}
	delete(s.records, nodeID)
	return true, nil
}

func (s *MemoryStore) CheckReadiness() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func cloneRecord(record Record) Record {
	record.Observation = cloneObservation(record.Observation)
	record.ActiveProbe = CloneActiveProbe(record.ActiveProbe)
	record.RouteOverlap = CloneRouteOverlap(record.RouteOverlap)
	record.EndpointDNS = CloneEndpointDNS(record.EndpointDNS)
	return record
}

func cloneObservation(observation Observation) Observation {
	if observation.Snapshot == nil {
		return observation
	}
	snapshot := *observation.Snapshot
	snapshot.Handshakes.MostRecentCompletionAgeMS = cloneUint64(snapshot.Handshakes.MostRecentCompletionAgeMS)
	snapshot.Peers.OldestAuthenticatedRXAgeMS = cloneUint64(snapshot.Peers.OldestAuthenticatedRXAgeMS)
	snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = cloneUint64(snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS)
	observation.Snapshot = &snapshot
	return observation
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
