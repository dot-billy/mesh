package runtimetelemetry

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"mesh/internal/postgresstore"
)

const (
	defaultPostgresOperationTimeout = 15 * time.Second
	postgresUpdateOperation         = "runtime_telemetry.state.update"
	postgresMigrateOperation        = "runtime_telemetry.state.migrate_v7"
)

type PostgresStoreOptions struct {
	OperationTimeout time.Duration
}

type postgresRepository interface {
	Initialize(context.Context, postgresstore.Domain, []byte) (postgresstore.WriteResult, error)
	Read(context.Context, postgresstore.Domain) (postgresstore.Document, error)
	Update(context.Context, postgresstore.Domain, string, func([]byte) ([]byte, error)) (postgresstore.WriteResult, error)
	CheckReadiness(context.Context) error
}

type PostgresStore struct {
	repository       postgresRepository
	operationTimeout time.Duration
	closed           atomic.Bool
}

var _ Store = (*PostgresStore)(nil)

func NewPostgresStore(store *postgresstore.Store, options PostgresStoreOptions) (*PostgresStore, error) {
	return newPostgresStore(store, options)
}

func newPostgresStore(repository postgresRepository, options PostgresStoreOptions) (*PostgresStore, error) {
	if nilPostgresRepository(repository) {
		return nil, errors.New("runtime telemetry PostgreSQL repository is required")
	}
	timeout := options.OperationTimeout
	if timeout == 0 {
		timeout = defaultPostgresOperationTimeout
	}
	if timeout < 0 {
		return nil, errors.New("runtime telemetry PostgreSQL timeout must not be negative")
	}
	return &PostgresStore{repository: repository, operationTimeout: timeout}, nil
}

// EnsureInitialized creates only the reconstructible telemetry document. It
// must run after authenticated two-document import so it cannot weaken the
// importer's exact-empty-database precondition.
func (s *PostgresStore) EnsureInitialized(ctx context.Context) error {
	operationCtx, cancel, err := s.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	raw, err := EncodeState(EmptyState())
	if err != nil {
		return err
	}
	_, err = s.repository.Initialize(operationCtx, postgresstore.DomainRuntimeTelemetry, raw)
	if err == nil {
		return nil
	}
	if !errors.Is(err, postgresstore.ErrAlreadyInitialized) {
		return translatePostgresError("initialize runtime telemetry state", err)
	}
	_, err = s.repository.Update(operationCtx, postgresstore.DomainRuntimeTelemetry, postgresMigrateOperation, func(existing []byte) ([]byte, error) {
		state, err := DecodeState(existing)
		if err != nil {
			return nil, err
		}
		return EncodeState(state)
	})
	return translatePostgresError("migrate runtime telemetry state", err)
}

func (s *PostgresStore) Put(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult) (Record, bool, error) {
	return s.PutWithRoute(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, UnsupportedRouteOverlap())
}

func (s *PostgresStore) PutWithRoute(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult) (Record, bool, error) {
	return s.PutWithDNS(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, UnsupportedEndpointDNS())
}

func (s *PostgresStore) PutWithDNS(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult) (Record, bool, error) {
	return s.PutWithConfig(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, endpointDNS, "")
}

func (s *PostgresStore) PutWithConfig(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult, appliedConfigSHA256 string) (Record, bool, error) {
	candidate, err := newCandidateRecord(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, endpointDNS, appliedConfigSHA256)
	if err != nil {
		return Record{}, false, err
	}
	ctx, cancel, err := s.operationContext(context.Background())
	if err != nil {
		return Record{}, false, err
	}
	defer cancel()
	changed := false
	accepted := candidate
	result, err := s.repository.Update(ctx, postgresstore.DomainRuntimeTelemetry, postgresUpdateOperation, func(raw []byte) ([]byte, error) {
		state, err := DecodeState(raw)
		if err != nil {
			return nil, err
		}
		index := sort.Search(len(state.Records), func(index int) bool { return state.Records[index].NodeID >= nodeID })
		var previous *Record
		if index < len(state.Records) && state.Records[index].NodeID == nodeID {
			existing := state.Records[index]
			previous = &existing
		}
		transitioned, transitionChanged, err := transitionRecord(previous, candidate)
		if err != nil {
			return nil, err
		}
		accepted = transitioned
		if !transitionChanged {
			return raw, nil
		}
		if previous == nil {
			if len(state.Records) >= MaxRecords {
				return nil, ErrInvalid
			}
			state.Records = append(state.Records, Record{})
			copy(state.Records[index+1:], state.Records[index:])
		}
		state.Records[index] = cloneRecord(accepted)
		changed = true
		return EncodeState(state)
	})
	if err != nil {
		return Record{}, false, translatePostgresError("update runtime telemetry state", err)
	}
	return cloneRecord(accepted), changed && result.Changed, nil
}

func (s *PostgresStore) Get(nodeID string) (Record, bool, error) {
	if !nodeIDPattern.MatchString(nodeID) {
		return Record{}, false, ErrInvalid
	}
	state, err := s.readState()
	if err != nil {
		return Record{}, false, err
	}
	index := sort.Search(len(state.Records), func(index int) bool { return state.Records[index].NodeID >= nodeID })
	if index == len(state.Records) || state.Records[index].NodeID != nodeID {
		return Record{}, false, nil
	}
	return cloneRecord(state.Records[index]), true, nil
}

func (s *PostgresStore) List() ([]Record, error) {
	state, err := s.readState()
	if err != nil {
		return nil, err
	}
	records := make([]Record, len(state.Records))
	for index := range state.Records {
		records[index] = cloneRecord(state.Records[index])
	}
	return records, nil
}

func (s *PostgresStore) Delete(nodeID string) (bool, error) {
	if !nodeIDPattern.MatchString(nodeID) {
		return false, ErrInvalid
	}
	ctx, cancel, err := s.operationContext(context.Background())
	if err != nil {
		return false, err
	}
	defer cancel()
	deleted := false
	result, err := s.repository.Update(ctx, postgresstore.DomainRuntimeTelemetry, postgresUpdateOperation, func(raw []byte) ([]byte, error) {
		state, err := DecodeState(raw)
		if err != nil {
			return nil, err
		}
		index := sort.Search(len(state.Records), func(index int) bool { return state.Records[index].NodeID >= nodeID })
		if index == len(state.Records) || state.Records[index].NodeID != nodeID {
			return raw, nil
		}
		copy(state.Records[index:], state.Records[index+1:])
		state.Records = state.Records[:len(state.Records)-1]
		deleted = true
		return EncodeState(state)
	})
	if err != nil {
		return false, translatePostgresError("delete runtime telemetry record", err)
	}
	return deleted && result.Changed, nil
}

func (s *PostgresStore) CheckReadiness() error {
	ctx, cancel, err := s.operationContext(context.Background())
	if err != nil {
		return err
	}
	defer cancel()
	if err := s.repository.CheckReadiness(ctx); err != nil {
		return translatePostgresError("check runtime telemetry PostgreSQL readiness", err)
	}
	document, err := s.repository.Read(ctx, postgresstore.DomainRuntimeTelemetry)
	if err != nil {
		return translatePostgresError("read ready runtime telemetry state", err)
	}
	_, err = DecodeState(document.Bytes)
	return err
}

func (s *PostgresStore) Close() error {
	if s != nil {
		s.closed.Store(true)
	}
	return nil
}

func (s *PostgresStore) readState() (State, error) {
	ctx, cancel, err := s.operationContext(context.Background())
	if err != nil {
		return State{}, err
	}
	defer cancel()
	document, err := s.repository.Read(ctx, postgresstore.DomainRuntimeTelemetry)
	if err != nil {
		return State{}, translatePostgresError("read runtime telemetry state", err)
	}
	state, err := DecodeState(document.Bytes)
	if err != nil {
		return State{}, fmt.Errorf("decode PostgreSQL runtime telemetry state: %w", err)
	}
	return state, nil
}

func (s *PostgresStore) operationContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || s.closed.Load() || nilPostgresRepository(s.repository) || s.operationTimeout <= 0 {
		return nil, nil, ErrClosed
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, s.operationTimeout)
	return ctx, cancel, nil
}

func nilPostgresRepository(repository postgresRepository) bool {
	if repository == nil {
		return true
	}
	value := reflect.ValueOf(repository)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func translatePostgresError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
