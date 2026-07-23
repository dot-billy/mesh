package main

import (
	"context"
	"errors"
	"fmt"

	"mesh/internal/supervisedchild"
)

type persistentRuntimeGate interface {
	Inspect() (bool, error)
}

func authorizeSupervisedRuntime(gate persistentRuntimeGate, construct func() (runtimeController, error)) (runtimeController, error) {
	if gate == nil || construct == nil {
		return nil, errors.New("supervised Nebula runtime authorization is incomplete")
	}
	open, err := gate.Inspect()
	if err != nil {
		return nil, fmt.Errorf("inspect installer-owned persistent runtime gate: %w", err)
	}
	if !open {
		return nil, errors.New("installer-owned persistent runtime gate is closed")
	}
	return construct()
}

type supervisedChildController interface {
	Reload(context.Context) error
	Observe(context.Context) (supervisedchild.Observation, error)
	Quarantine(context.Context) error
}

type supervisedNebulaRuntime struct {
	persistent persistentRuntimeGate
	child      supervisedChildController
}

func (runtime *supervisedNebulaRuntime) AuthorizeCycle(ctx context.Context) error {
	if runtime == nil || runtime.persistent == nil || runtime.child == nil {
		return errors.New("supervised Nebula runtime is incomplete")
	}
	open, err := runtime.persistent.Inspect()
	if err == nil && open {
		return nil
	}
	cause := err
	if cause == nil {
		cause = errors.New("installer-owned persistent runtime gate is closed")
	}
	if quarantineErr := runtime.child.Quarantine(ctx); quarantineErr != nil {
		return errors.Join(cause, fmt.Errorf("quarantine supervised child after persistent-gate failure: %w", quarantineErr))
	}
	return cause
}

func (runtime *supervisedNebulaRuntime) Reload(ctx context.Context) error {
	if err := runtime.AuthorizeCycle(ctx); err != nil {
		return err
	}
	return runtime.child.Reload(ctx)
}

func (runtime *supervisedNebulaRuntime) Observe(ctx context.Context) (runtimeObservation, error) {
	if err := runtime.AuthorizeCycle(ctx); err != nil {
		return runtimeObservation{}, err
	}
	observation, err := runtime.child.Observe(ctx)
	if err != nil {
		return runtimeObservation{}, err
	}
	if !observation.Healthy {
		return runtimeObservation{}, errors.New("supervised Nebula child is not healthy")
	}
	return runtimeObservation{HeartbeatAllowed: true, NebulaRunning: true, Status: "healthy"}, nil
}

func (runtime *supervisedNebulaRuntime) Quarantine(ctx context.Context) error {
	if runtime == nil || runtime.child == nil {
		return errors.New("supervised Nebula runtime is incomplete")
	}
	return runtime.child.Quarantine(ctx)
}

func (runtime *supervisedNebulaRuntime) CloseReadinessMarker() error {
	cleanupCtx, cancel := runtimeCleanupContext(context.Background())
	defer cancel()
	return runtime.Quarantine(cleanupCtx)
}
