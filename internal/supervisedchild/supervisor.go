package supervisedchild

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultCleanupTimeout = 30 * time.Second

// Gate is an ephemeral authorization marker. Close must revoke the marker
// before returning; Inspect independently proves its current state.
type Gate interface {
	Open() error
	Close() error
	Inspect() (bool, error)
}

// Starter starts exactly the requested executable and argument vector.
// Process.Prove is still required because a successful start alone is not
// sufficient runtime identity evidence.
type Starter interface {
	Start(context.Context, string, []string) (Process, error)
}

// Process is one exact child. Wait returns nil only after that child is proven
// to have exited; an ordinary non-zero child exit must therefore be normalized
// by the platform adapter rather than treated as an unproven wait.
type Process interface {
	Prove(context.Context, string, []string) error
	Terminate() error
	Wait(context.Context) error
}

// Observation never reports Healthy until the authorization gate and exact
// child executable/config pair have both been independently proven.
type Observation struct {
	Healthy bool
}

// Supervisor serializes direct-child publication, proof, and quarantine.
type Supervisor struct {
	binary  string
	config  string
	starter Starter
	gate    Gate
	// cleanupTimeout is deliberately local to teardown: caller cancellation
	// must not strand a child, while a broken platform adapter must not block
	// lifecycle progress forever.
	cleanupTimeout time.Duration

	mu    sync.Mutex
	child Process
}

// New constructs a supervisor for an exact, already-clean absolute binary and
// config path. It does not resolve PATH entries or silently normalize input.
func New(binary, config string, starter Starter, gate Gate) (*Supervisor, error) {
	if err := validateExactPath("Nebula binary", binary); err != nil {
		return nil, err
	}
	if err := validateExactPath("Nebula config", config); err != nil {
		return nil, err
	}
	if starter == nil {
		return nil, errors.New("a supervised-child starter is required")
	}
	if gate == nil {
		return nil, errors.New("a supervised-child authorization gate is required")
	}
	return &Supervisor{
		binary: binary, config: config, starter: starter, gate: gate,
		cleanupTimeout: defaultCleanupTimeout,
	}, nil
}

func validateExactPath(kind, path string) error {
	if path == "" || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", kind)
	}
	if filepath.Clean(path) != path || path == filepath.VolumeName(path)+string(filepath.Separator) {
		return fmt.Errorf("%s must be an exact clean non-root path", kind)
	}
	return nil
}

func (s *Supervisor) expectedArguments() []string {
	return []string{"-config", s.config}
}

// Reload first proves the old child quarantined, then publishes authorization,
// starts the exact command, and proves both surfaces before acknowledging.
func (s *Supervisor) Reload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := s.quarantineLocked(ctx); err != nil {
		return fmt.Errorf("quarantine previous supervised child: %w", err)
	}
	// Cleanup intentionally ignored caller cancellation. Recheck it before
	// publishing authorization so a canceled reload cannot reopen the gate or
	// start a replacement after the old child has been proven gone.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("reload supervised child canceled before authorization: %w", err)
	}
	if err := s.gate.Open(); err != nil {
		cleanupErr := s.quarantineLocked(ctx)
		return errors.Join(fmt.Errorf("open supervised-child authorization gate: %w", err), cleanupFailure(cleanupErr))
	}
	child, err := s.starter.Start(ctx, s.binary, s.expectedArguments())
	if child != nil {
		s.child = child
	}
	if err != nil {
		cleanupErr := s.quarantineLocked(ctx)
		return errors.Join(fmt.Errorf("start supervised child: %w", err), cleanupFailure(cleanupErr))
	}
	if child == nil {
		cleanupErr := s.quarantineLocked(ctx)
		return errors.Join(errors.New("start supervised child returned no process"), cleanupFailure(cleanupErr))
	}
	if _, err := s.observeLocked(ctx); err != nil {
		cleanupErr := s.quarantineLocked(ctx)
		return errors.Join(fmt.Errorf("prove started supervised child: %w", err), cleanupFailure(cleanupErr))
	}
	return nil
}

func cleanupFailure(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("fail-closed supervised-child cleanup was not proven: %w", err)
}

// Observe proves the current gate and child. The zero observation accompanies
// every error and cannot be mistaken for a healthy acknowledgement.
func (s *Supervisor) Observe(ctx context.Context) (Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	return s.observeLocked(ctx)
}

func (s *Supervisor) observeLocked(ctx context.Context) (Observation, error) {
	open, err := s.gate.Inspect()
	if err != nil {
		return Observation{}, fmt.Errorf("inspect supervised-child authorization gate: %w", err)
	}
	if !open {
		return Observation{}, errors.New("supervised-child authorization gate is closed")
	}
	if s.child == nil {
		return Observation{}, errors.New("supervised-child authorization is open without a tracked child")
	}
	if err := s.child.Prove(ctx, s.binary, s.expectedArguments()); err != nil {
		return Observation{}, fmt.Errorf("prove exact supervised child: %w", err)
	}
	return Observation{Healthy: true}, nil
}

// Quarantine always attempts gate closure before child termination, waits for
// the exact child, and then independently proves the gate closed. All failures
// are retained so callers cannot mistake a partial teardown for success.
func (s *Supervisor) Quarantine(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	return s.quarantineLocked(ctx)
}

func (s *Supervisor) quarantineLocked(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := s.cleanupTimeout
	if timeout <= 0 {
		timeout = defaultCleanupTimeout
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return s.quarantineWithContextLocked(cleanupCtx)
}

func (s *Supervisor) quarantineWithContextLocked(ctx context.Context) error {
	var result error
	if err := s.gate.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close supervised-child authorization gate: %w", err))
	}
	if s.child != nil {
		if err := s.child.Terminate(); err != nil {
			result = errors.Join(result, fmt.Errorf("terminate supervised child: %w", err))
		}
		if err := s.child.Wait(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("wait for supervised child exit: %w", err))
		} else {
			s.child = nil
		}
	}
	open, err := s.gate.Inspect()
	if err != nil {
		result = errors.Join(result, fmt.Errorf("prove supervised-child authorization gate closed: %w", err))
	} else if open {
		result = errors.Join(result, errors.New("supervised-child authorization gate remains open after closure"))
	}
	return result
}
