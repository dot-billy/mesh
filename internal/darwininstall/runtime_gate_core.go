package darwininstall

import (
	"errors"
	"fmt"
)

var (
	errRuntimeGatePublicationPending = errors.New("Darwin runtime gate has an unfinished open publication")
	errRuntimeGateIncompletePending  = errors.New("Darwin runtime gate recovery file is incomplete")
)

type runtimeGateFileState uint8

const (
	runtimeGateAbsent runtimeGateFileState = iota
	runtimeGateIncomplete
	runtimeGateComplete
)

type runtimeGateOperations interface {
	InspectLive() (runtimeGateFileState, error)
	InspectPending() (runtimeGateFileState, error)
	CreatePending() error
	SyncPending() error
	RemoveLive() error
	RemovePending() error
	PublishPendingNoReplace() error
	SyncDirectory() error
}

func inspectRuntimeGate(operations runtimeGateOperations) (bool, error) {
	if operations == nil {
		return false, errors.New("Darwin runtime-gate operations are required")
	}
	live, err := operations.InspectLive()
	if err != nil {
		return false, err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return false, err
	}
	if pending != runtimeGateAbsent {
		return false, errRuntimeGatePublicationPending
	}
	switch live {
	case runtimeGateAbsent:
		return false, nil
	case runtimeGateComplete:
		return true, nil
	default:
		return false, errors.New("live Darwin runtime gate is incomplete")
	}
}

func openRuntimeGate(operations runtimeGateOperations) error {
	if operations == nil {
		return errors.New("Darwin runtime-gate operations are required")
	}
	live, err := operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if live == runtimeGateComplete {
		if pending != runtimeGateAbsent {
			return errors.New("open Darwin runtime gate has an unexpected recovery file")
		}
		return nil
	}
	if live != runtimeGateAbsent {
		return errors.New("live Darwin runtime gate is incomplete")
	}
	if pending == runtimeGateIncomplete {
		if err := operations.RemovePending(); err != nil {
			return fmt.Errorf("remove incomplete Darwin runtime-gate recovery file: %w", err)
		}
		if err := operations.SyncDirectory(); err != nil {
			return fmt.Errorf("sync incomplete Darwin runtime-gate cleanup: %w", err)
		}
		pending = runtimeGateAbsent
	}
	if pending == runtimeGateAbsent {
		if err := operations.CreatePending(); err != nil {
			return fmt.Errorf("create Darwin runtime-gate recovery file: %w", err)
		}
		if err := operations.SyncDirectory(); err != nil {
			return fmt.Errorf("sync Darwin runtime-gate recovery creation: %w", err)
		}
		pending, err = operations.InspectPending()
		if err != nil {
			return err
		}
		if pending != runtimeGateComplete {
			return errors.New("Darwin runtime-gate recovery file is not complete after creation")
		}
	}
	if pending != runtimeGateComplete {
		return errRuntimeGateIncompletePending
	}
	if err := operations.SyncPending(); err != nil {
		return fmt.Errorf("sync Darwin runtime-gate recovery file: %w", err)
	}
	if err := operations.PublishPendingNoReplace(); err != nil {
		return fmt.Errorf("publish Darwin runtime gate without replacement: %w", err)
	}
	if err := operations.SyncDirectory(); err != nil {
		return fmt.Errorf("sync Darwin runtime-gate publication: %w", err)
	}
	open, err := inspectRuntimeGate(operations)
	if err != nil {
		return err
	}
	if !open {
		return errors.New("Darwin runtime-gate publication is not visible")
	}
	return nil
}

func closeRuntimeGate(operations runtimeGateOperations) error {
	if operations == nil {
		return errors.New("Darwin runtime-gate operations are required")
	}
	for _, file := range []struct {
		name    string
		inspect func() (runtimeGateFileState, error)
		remove  func() error
	}{
		{name: "live", inspect: operations.InspectLive, remove: operations.RemoveLive},
		{name: "recovery", inspect: operations.InspectPending, remove: operations.RemovePending},
	} {
		state, err := file.inspect()
		if err != nil {
			return err
		}
		if state == runtimeGateAbsent {
			continue
		}
		if err := file.remove(); err != nil {
			return fmt.Errorf("remove %s Darwin runtime-gate file: %w", file.name, err)
		}
		if err := operations.SyncDirectory(); err != nil {
			return fmt.Errorf("sync %s Darwin runtime-gate removal: %w", file.name, err)
		}
	}
	live, err := operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if live != runtimeGateAbsent || pending != runtimeGateAbsent {
		return errors.New("Darwin runtime-gate files remain after closure")
	}
	return nil
}
