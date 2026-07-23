package windowsinstall

import (
	"errors"
	"fmt"
)

var errWindowsRuntimeGatePublicationPending = errors.New("Windows runtime gate has an unfinished open publication")

type windowsRuntimeGateFileState uint8

const (
	windowsRuntimeGateAbsent windowsRuntimeGateFileState = iota
	windowsRuntimeGateIncomplete
	windowsRuntimeGateComplete
)

type windowsRuntimeGateOperations interface {
	InspectLive() (windowsRuntimeGateFileState, error)
	InspectPending() (windowsRuntimeGateFileState, error)
	CreatePending() error
	SyncPending() error
	RemoveLive() error
	RemovePending() error
	PublishPendingNoReplace() error
	SyncDirectory() error
}

func inspectWindowsRuntimeGate(operations windowsRuntimeGateOperations) (bool, error) {
	if operations == nil {
		return false, errors.New("Windows runtime-gate operations are required")
	}
	live, err := operations.InspectLive()
	if err != nil {
		return false, err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return false, err
	}
	if pending != windowsRuntimeGateAbsent {
		return false, errWindowsRuntimeGatePublicationPending
	}
	switch live {
	case windowsRuntimeGateAbsent:
		return false, nil
	case windowsRuntimeGateComplete:
		return true, nil
	default:
		return false, errors.New("live Windows runtime gate is incomplete")
	}
}

func openWindowsRuntimeGate(operations windowsRuntimeGateOperations) error {
	if operations == nil {
		return errors.New("Windows runtime-gate operations are required")
	}
	live, err := operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if live == windowsRuntimeGateComplete {
		if pending != windowsRuntimeGateAbsent {
			return errors.New("open Windows runtime gate has an unexpected recovery file")
		}
		return nil
	}
	if live != windowsRuntimeGateAbsent {
		return errors.New("live Windows runtime gate is incomplete")
	}
	if pending == windowsRuntimeGateIncomplete {
		if err := operations.RemovePending(); err != nil {
			return fmt.Errorf("remove incomplete Windows runtime-gate recovery file: %w", err)
		}
		if err := operations.SyncDirectory(); err != nil {
			return fmt.Errorf("sync incomplete Windows runtime-gate cleanup: %w", err)
		}
		pending = windowsRuntimeGateAbsent
	}
	if pending == windowsRuntimeGateAbsent {
		if err := operations.CreatePending(); err != nil {
			return fmt.Errorf("create Windows runtime-gate recovery file: %w", err)
		}
		if err := operations.SyncDirectory(); err != nil {
			return fmt.Errorf("sync Windows runtime-gate recovery creation: %w", err)
		}
		pending, err = operations.InspectPending()
		if err != nil {
			return err
		}
	}
	if pending != windowsRuntimeGateComplete {
		return errors.New("Windows runtime-gate recovery file is incomplete")
	}
	if err := operations.SyncPending(); err != nil {
		return fmt.Errorf("sync Windows runtime-gate recovery file: %w", err)
	}
	if err := operations.PublishPendingNoReplace(); err != nil {
		return fmt.Errorf("publish Windows runtime gate without replacement: %w", err)
	}
	if err := operations.SyncDirectory(); err != nil {
		return fmt.Errorf("sync Windows runtime-gate publication: %w", err)
	}
	open, err := inspectWindowsRuntimeGate(operations)
	if err != nil {
		return err
	}
	if !open {
		return errors.New("Windows runtime-gate publication is not visible")
	}
	return nil
}

func closeWindowsRuntimeGate(operations windowsRuntimeGateOperations) error {
	if operations == nil {
		return errors.New("Windows runtime-gate operations are required")
	}
	for _, file := range []struct {
		name    string
		inspect func() (windowsRuntimeGateFileState, error)
		remove  func() error
	}{
		{name: "live", inspect: operations.InspectLive, remove: operations.RemoveLive},
		{name: "recovery", inspect: operations.InspectPending, remove: operations.RemovePending},
	} {
		state, err := file.inspect()
		if err != nil {
			return err
		}
		if state == windowsRuntimeGateAbsent {
			continue
		}
		if err := file.remove(); err != nil {
			return fmt.Errorf("remove %s Windows runtime-gate file: %w", file.name, err)
		}
		if err := operations.SyncDirectory(); err != nil {
			return fmt.Errorf("sync %s Windows runtime-gate removal: %w", file.name, err)
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
	if live != windowsRuntimeGateAbsent || pending != windowsRuntimeGateAbsent {
		return errors.New("Windows runtime-gate files remain after closure")
	}
	return nil
}
