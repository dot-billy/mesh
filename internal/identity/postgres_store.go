package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"mesh/internal/postgresstore"
)

const (
	defaultPostgresIdentityOperationTimeout = 15 * time.Second
	postgresIdentityUpdateOperation         = "identity.state.update"
)

var ErrInvalidPostgresStore = errors.New("invalid postgres identity store")

// PostgresStoreOptions bounds each authoritative database operation. A zero
// timeout selects the secure default; negative durations are rejected.
type PostgresStoreOptions struct {
	OperationTimeout time.Duration
}

type postgresIdentityRepository interface {
	Read(context.Context, postgresstore.Domain) (postgresstore.Document, error)
	Update(context.Context, postgresstore.Domain, string, func([]byte) ([]byte, error)) (postgresstore.WriteResult, error)
	CheckReadiness(context.Context) error
}

// PostgresStore adapts the exact-byte PostgreSQL document primitive to the
// single identityOperations implementation. It has no cache: every request
// reads or row-locks the authoritative identity document.
type PostgresStore struct {
	*identityOperations
	repository       postgresIdentityRepository
	operationTimeout time.Duration

	// lifecycleMu protects admission counters only. It is never held during a
	// repository call or identity callback, so Close can gate new work without
	// introducing callback lock reentrancy.
	lifecycleMu     sync.Mutex
	lifecycleClosed bool
	inFlight        int
	drained         chan struct{}
}

var _ SessionStore = (*PostgresStore)(nil)
var _ IdentityAuditStore = (*PostgresStore)(nil)
var _ BreakGlassStore = (*PostgresStore)(nil)

// NewPostgresStore constructs the production identity adapter. Schema setup
// and identity-document import/initialization are explicit operator steps and
// must already be complete. Closing this adapter never closes the shared
// low-level postgresstore.Store.
func NewPostgresStore(store *postgresstore.Store, sealer Sealer, options PostgresStoreOptions) (*PostgresStore, error) {
	return newPostgresStore(store, sealer, options)
}

func newPostgresStore(repository postgresIdentityRepository, sealer Sealer, options PostgresStoreOptions) (*PostgresStore, error) {
	if nilPostgresIdentityRepository(repository) {
		return nil, fmt.Errorf("%w: repository is required", ErrInvalidPostgresStore)
	}
	if nilInterface(sealer) {
		return nil, fmt.Errorf("%w: purpose-bound sealer is required", ErrInvalidPostgresStore)
	}
	timeout := options.OperationTimeout
	if timeout == 0 {
		timeout = defaultPostgresIdentityOperationTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: operation timeout must not be negative", ErrInvalidPostgresStore)
	}
	store := &PostgresStore{repository: repository, operationTimeout: timeout}
	store.identityOperations = newIdentityOperations(store, sealer)
	return store, nil
}

func nilPostgresIdentityRepository(repository postgresIdentityRepository) bool {
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

func (s *PostgresStore) operationContext(parent context.Context) (context.Context, func(), error) {
	if s == nil || nilPostgresIdentityRepository(s.repository) || s.operationTimeout <= 0 {
		return nil, nil, ErrInvalidPostgresStore
	}
	if err := identityContextError(parent); err != nil {
		return nil, nil, err
	}
	s.lifecycleMu.Lock()
	if s.lifecycleClosed {
		s.lifecycleMu.Unlock()
		return nil, nil, ErrClosed
	}
	if s.inFlight == 0 {
		s.drained = make(chan struct{})
	}
	s.inFlight++
	s.lifecycleMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, s.operationTimeout)
	done := func() {
		cancel()
		s.lifecycleMu.Lock()
		s.inFlight--
		if s.inFlight == 0 {
			close(s.drained)
		}
		s.lifecycleMu.Unlock()
	}
	return ctx, done, nil
}

// Close closes only this logical adapter. The low-level store may be shared by
// the control adapter and other identity adapter instances and remains open.
func (s *PostgresStore) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	s.lifecycleClosed = true
	if s.inFlight == 0 {
		s.lifecycleMu.Unlock()
		return nil
	}
	drained := s.drained
	s.lifecycleMu.Unlock()
	<-drained
	return nil
}

func (s *PostgresStore) viewIdentityState(parent context.Context, inspect func(identityState) error) error {
	if inspect == nil {
		return errors.New("identity state view callback is required")
	}
	ctx, done, err := s.operationContext(parent)
	if err != nil {
		return err
	}
	defer done()
	document, err := s.repository.Read(ctx, postgresstore.DomainIdentity)
	if err != nil {
		return translatePostgresIdentityError("read postgres identity state", err)
	}
	state, err := decodeValidPostgresIdentityState(document.Bytes, s.sealer)
	if err != nil {
		return translatePostgresIdentityError("read postgres identity state", err)
	}
	if err := ctx.Err(); err != nil {
		return translatePostgresIdentityError("read postgres identity state", err)
	}
	err = inspect(state)
	if contextErr := ctx.Err(); contextErr != nil {
		return translatePostgresIdentityError("read postgres identity state", contextErr)
	}
	return err
}

func (s *PostgresStore) updateIdentityState(parent context.Context, mutate func(*identityState) error) error {
	if mutate == nil {
		return errors.New("identity state update callback is required")
	}
	ctx, done, err := s.operationContext(parent)
	if err != nil {
		return err
	}
	defer done()
	_, err = s.repository.Update(ctx, postgresstore.DomainIdentity, postgresIdentityUpdateOperation, func(raw []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current, err := decodeValidPostgresIdentityState(raw, s.sealer)
		if err != nil {
			return nil, err
		}
		// Keep an immutable semantic baseline and a separate callback-owned
		// working copy. The low-level store separately detaches callback bytes.
		baseline := cloneIdentityState(current)
		next := cloneIdentityState(current)
		if err := mutate(&next); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if reflect.DeepEqual(next, baseline) {
			return raw, nil
		}
		encoded, err := encodeIdentityStateDocument(next)
		if err != nil {
			return nil, fmt.Errorf("encode postgres identity state: %w", err)
		}
		return encoded, nil
	})
	if err != nil {
		return translatePostgresIdentityError("update postgres identity state", err)
	}
	return nil
}

// CheckReadiness combines the low-level exact-two-document, writable-primary,
// schema, receipt, and uncertain-write checks with a fresh strict identity
// decode and full sealed-payload validation.
func (s *PostgresStore) CheckReadiness(parent context.Context) error {
	ctx, done, err := s.operationContext(parent)
	if err != nil {
		return err
	}
	defer done()
	if err := s.repository.CheckReadiness(ctx); err != nil {
		return translatePostgresIdentityError("check postgres identity readiness", err)
	}
	document, err := s.repository.Read(ctx, postgresstore.DomainIdentity)
	if err != nil {
		return translatePostgresIdentityError("read ready postgres identity state", err)
	}
	if _, err := decodeValidPostgresIdentityState(document.Bytes, s.sealer); err != nil {
		return translatePostgresIdentityError("validate ready postgres identity state", err)
	}
	if err := ctx.Err(); err != nil {
		return translatePostgresIdentityError("check postgres identity readiness", err)
	}
	return nil
}

// ExportRecoverySnapshot returns an exact detached copy of the current
// authoritative identity document after strict and cryptographic validation.
func (s *PostgresStore) ExportRecoverySnapshot(parent context.Context) ([]byte, error) {
	ctx, done, err := s.operationContext(parent)
	if err != nil {
		return nil, err
	}
	defer done()
	document, err := s.repository.Read(ctx, postgresstore.DomainIdentity)
	if err != nil {
		return nil, translatePostgresIdentityError("export postgres identity recovery snapshot", err)
	}
	if _, err := decodeValidPostgresIdentityState(document.Bytes, s.sealer); err != nil {
		return nil, translatePostgresIdentityError("validate postgres identity recovery snapshot", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, translatePostgresIdentityError("export postgres identity recovery snapshot", err)
	}
	return append([]byte(nil), document.Bytes...), nil
}

func decodeValidPostgresIdentityState(raw []byte, sealer Sealer) (identityState, error) {
	state, err := decodeIdentityStateDocument(raw, false)
	if err != nil {
		return identityState{}, fmt.Errorf("%w: decode identity document: %w", postgresstore.ErrCorruptDocument, err)
	}
	validator := newIdentityOperations(nil, sealer)
	if err := validator.validateState(state); err != nil {
		return identityState{}, fmt.Errorf("%w: validate identity document: %w", postgresstore.ErrCorruptDocument, err)
	}
	return state, nil
}

func translatePostgresIdentityError(operation string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, postgresstore.ErrClosed):
		return fmt.Errorf("%s: %w: %w", operation, ErrClosed, err)
	case errors.Is(err, postgresstore.ErrUncertainCommit):
		return fmt.Errorf("%s: %w: %w", operation, ErrUncertainCommit, err)
	case errors.Is(err, ErrClosed), errors.Is(err, ErrUncertainCommit):
		return fmt.Errorf("%s: %w", operation, err)
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
