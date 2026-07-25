package control

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"mesh/internal/postgresstore"
)

const (
	defaultPostgresStateOperationTimeout = 15 * time.Second
	postgresControlUpdateOperation       = "control.state.update"
)

// PostgresStateStoreOptions bounds database work initiated by the contextless
// StateStore contract used by Service. A zero timeout selects the default.
type PostgresStateStoreOptions struct {
	OperationTimeout time.Duration
}

type postgresControlRepository interface {
	Read(context.Context, postgresstore.Domain) (postgresstore.Document, error)
	Update(context.Context, postgresstore.Domain, string, func([]byte) ([]byte, error)) (postgresstore.WriteResult, error)
	CheckReadiness(context.Context) error
}

// PostgresStateStore adapts the exact-byte PostgreSQL document primitive to
// the control service's transactional StateStore contract. It intentionally
// carries no state cache: every operation observes the authoritative document.
type PostgresStateStore struct {
	repository       postgresControlRepository
	operationTimeout time.Duration
}

var _ StateStore = (*PostgresStateStore)(nil)

// NewPostgresStateStore constructs the production adapter. Schema migration
// and control-document initialization/import are separate operator steps and
// must already be complete before this adapter can serve requests.
func NewPostgresStateStore(store *postgresstore.Store, options PostgresStateStoreOptions) (*PostgresStateStore, error) {
	return newPostgresStateStore(store, options)
}

func newPostgresStateStore(repository postgresControlRepository, options PostgresStateStoreOptions) (*PostgresStateStore, error) {
	if nilPostgresControlRepository(repository) {
		return nil, fmt.Errorf("%w: postgres control repository is required", ErrInvalidStateStore)
	}
	timeout := options.OperationTimeout
	if timeout == 0 {
		timeout = defaultPostgresStateOperationTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: postgres control operation timeout must not be negative", ErrInvalidStateStore)
	}
	return &PostgresStateStore{repository: repository, operationTimeout: timeout}, nil
}

func nilPostgresControlRepository(repository postgresControlRepository) bool {
	if repository == nil {
		return true
	}
	value := reflect.ValueOf(repository)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (s *PostgresStateStore) operationContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || nilPostgresControlRepository(s.repository) || s.operationTimeout <= 0 {
		return nil, nil, ErrInvalidStateStore
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, s.operationTimeout)
	return ctx, cancel, nil
}

func (s *PostgresStateStore) View(fn func(State) error) error {
	if fn == nil {
		return errors.New("control state view callback is required")
	}
	ctx, cancel, err := s.operationContext(context.Background())
	if err != nil {
		return err
	}
	defer cancel()
	document, err := s.repository.Read(ctx, postgresstore.DomainControl)
	if err != nil {
		return translatePostgresControlError("read postgres control state", err)
	}
	state, err := decodeValidPostgresControlState(document.Bytes)
	if err != nil {
		return translatePostgresControlError("read postgres control state", err)
	}
	return fn(state)
}

func (s *PostgresStateStore) Update(fn func(*State) error) error {
	if fn == nil {
		return errors.New("control state update callback is required")
	}
	ctx, cancel, err := s.operationContext(context.Background())
	if err != nil {
		return err
	}
	defer cancel()
	_, err = s.repository.Update(ctx, postgresstore.DomainControl, postgresControlUpdateOperation, func(raw []byte) ([]byte, error) {
		current, err := decodeValidPostgresControlState(raw)
		if err != nil {
			return nil, err
		}
		// Clone twice so the callback cannot mutate the comparison baseline.
		// Comparing normalized clones also treats nil and non-nil empty slices
		// consistently, preserving non-canonical but valid source bytes on a
		// semantic no-op.
		baseline, err := cloneState(current)
		if err != nil {
			return nil, fmt.Errorf("clone postgres control comparison state: %w", err)
		}
		next, err := cloneState(current)
		if err != nil {
			return nil, fmt.Errorf("clone postgres control mutation state: %w", err)
		}
		if err := fn(&next); err != nil {
			return nil, err
		}
		if err := validateStateGraph(next); err != nil {
			return nil, fmt.Errorf("refuse invalid postgres control state mutation: %w", err)
		}
		if reflect.DeepEqual(next, baseline) {
			return raw, nil
		}
		encoded, err := encodePersistedState(next)
		if err != nil {
			return nil, fmt.Errorf("encode postgres control state: %w", err)
		}
		if len(encoded) == 0 || len(encoded) > maxPersistedStateSize {
			return nil, fmt.Errorf("postgres control state exceeds the %d-byte safety limit", maxPersistedStateSize)
		}
		return encoded, nil
	})
	if err != nil {
		return translatePostgresControlError("update postgres control state", err)
	}
	return nil
}

// CheckReadiness combines the low-level PostgreSQL schema, primary, receipt,
// and uncertain-write checks with a fresh strict decode and full structural
// validation of the current control document. Master-key authentication and
// CA private-key checks remain explicit Service startup/readiness concerns.
func (s *PostgresStateStore) CheckReadiness(parent context.Context) error {
	ctx, cancel, err := s.operationContext(parent)
	if err != nil {
		return err
	}
	defer cancel()
	if err := s.repository.CheckReadiness(ctx); err != nil {
		return translatePostgresControlError("check postgres control readiness", err)
	}
	document, err := s.repository.Read(ctx, postgresstore.DomainControl)
	if err != nil {
		return translatePostgresControlError("read ready postgres control state", err)
	}
	if _, err := decodeValidPostgresControlState(document.Bytes); err != nil {
		return translatePostgresControlError("validate ready postgres control state", err)
	}
	return nil
}

func decodeValidPostgresControlState(raw []byte) (State, error) {
	if len(raw) == 0 || len(raw) > maxPersistedStateSize {
		return State{}, fmt.Errorf("%w: control document size %d is outside its safety bound", postgresstore.ErrCorruptDocument, len(raw))
	}
	var state State
	if err := decodePersistedState(raw, &state); err != nil {
		return State{}, fmt.Errorf("%w: decode control document: %w", postgresstore.ErrCorruptDocument, err)
	}
	if err := validateStateGraph(state); err != nil {
		return State{}, fmt.Errorf("%w: validate control document: %w", postgresstore.ErrCorruptDocument, err)
	}
	return state, nil
}

func translatePostgresControlError(operation string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, postgresstore.ErrClosed):
		return fmt.Errorf("%s: %w: %w", operation, ErrClosed, err)
	case errors.Is(err, postgresstore.ErrUncertainCommit):
		return fmt.Errorf("%s: %w: %w", operation, ErrUncertainCommit, err)
	case errors.Is(err, postgresstore.ErrNotCommitted):
		return fmt.Errorf("%s was not committed: %w", operation, err)
	case errors.Is(err, postgresstore.ErrCorruptDocument):
		return fmt.Errorf("%s is corrupt: %w", operation, err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s timed out: %w", operation, err)
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}
