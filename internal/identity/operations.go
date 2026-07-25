package identity

import (
	"context"
	"errors"
	"fmt"
)

// identityStateBackend is the private whole-document transaction boundary used
// by the identity business rules. Implementations must isolate callback state
// from their committed state (including after a successful callback), invoke
// each callback at most once, serialize updates, commit only when the callback
// succeeds, and preserve an exact no-op without writing. Update callbacks must
// not be retained. Backend durability failures must be returned to the caller;
// they must never be converted into a successful commit.
//
// The state type and contract deliberately remain private. A future durable
// backend belongs in this package and cannot bypass the canonical identity
// validation and purpose-bound sealing implemented by identityOperations.
type identityStateBackend interface {
	viewIdentityState(context.Context, func(identityState) error) error
	updateIdentityState(context.Context, func(*identityState) error) error
}

// currentIdentityStateBackend is an optional trusted-read optimization. It is
// private because the callback receives backend-owned state and therefore must
// neither mutate nor retain it. identityOperations callbacks are package-owned,
// read-only, and clone every value they return. FileStore uses this path for
// authentication and list reads so random credentials cannot amplify into an
// O(document size) allocation. Other backends safely fall back to a detached
// viewIdentityState snapshot.
type currentIdentityStateBackend interface {
	readCurrentIdentityState(context.Context, func(identityState) error) error
}

// identityOperations owns the single implementation of SessionStore and
// IdentityAuditStore business behavior. FileStore embeds it and supplies the
// filesystem transaction adapter; another backend can reuse the same rules by
// constructing a core over its own whole-document transaction implementation.
type identityOperations struct {
	backend identityStateBackend
	sealer  Sealer
}

func newIdentityOperations(backend identityStateBackend, sealer Sealer) *identityOperations {
	return &identityOperations{backend: backend, sealer: sealer}
}

func identityContextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("identity store context is required")
	}
	return ctx.Err()
}

func (s *identityOperations) view(ctx context.Context, inspect func(identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.backend == nil {
		return ErrClosed
	}
	if inspect == nil {
		return errors.New("identity state view callback is required")
	}
	wrapped := func(state identityState) error {
		if err := identityContextError(ctx); err != nil {
			return err
		}
		err := inspect(state)
		if contextErr := identityContextError(ctx); contextErr != nil {
			return contextErr
		}
		return err
	}
	if current, ok := s.backend.(currentIdentityStateBackend); ok {
		return current.readCurrentIdentityState(ctx, wrapped)
	}
	return s.backend.viewIdentityState(ctx, wrapped)
}

func (s *identityOperations) update(ctx context.Context, mutate func(*identityState) error) error {
	if err := identityContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.backend == nil {
		return ErrClosed
	}
	if mutate == nil {
		return errors.New("identity state update callback is required")
	}
	return s.backend.updateIdentityState(ctx, func(next *identityState) error {
		if err := identityContextError(ctx); err != nil {
			return err
		}
		if err := mutate(next); err != nil {
			return err
		}
		if err := identityContextError(ctx); err != nil {
			return err
		}
		if err := s.validateState(*next); err != nil {
			return fmt.Errorf("refuse invalid identity mutation: %w", err)
		}
		return identityContextError(ctx)
	})
}
