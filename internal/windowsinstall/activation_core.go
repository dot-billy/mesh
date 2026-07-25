package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type windowsActivationJournalWriter interface {
	Advance(*WindowsActivationJournal, WindowsActivationJournal) error
}

type windowsActivationOperations interface {
	ValidateActivationJournal(WindowsActivationJournal) error
	InspectRuntimeGate() (bool, error)
	CloseRuntimeGate() error
	OpenRuntimeGate() error
	QuiesceSourceService(context.Context) error
	SwitchCurrent() error
	InstallTargetService(context.Context) error
	StartTargetService(context.Context) error
	StopTargetService(context.Context) error
	ProveTarget(context.Context, bool, bool) error
}

// advanceWindowsActivation replays each mutation-bearing phase from its start
// and advances the journal only after exact proof. Any failure after selection
// quarantines the target by closing the persistent gate and stopping the
// service; the selected journal remains durable for deterministic recovery.
func advanceWindowsActivation(ctx context.Context, writer windowsActivationJournalWriter, operations windowsActivationOperations, journal WindowsActivationJournal) (WindowsActivationJournal, error) {
	if writer == nil || operations == nil {
		return WindowsActivationJournal{}, errors.New("Windows activation journal writer and operations are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := journal.Validate(); err != nil {
		return WindowsActivationJournal{}, err
	}
	if err := operations.ValidateActivationJournal(journal); err != nil {
		return WindowsActivationJournal{}, fmt.Errorf("bind Windows activation operations: %w", err)
	}

	if journal.Phase == WindowsActivationPrepared {
		if err := proveWindowsGateClosed(operations); err != nil {
			return journal, err
		}
		if err := operations.QuiesceSourceService(ctx); err != nil {
			return journal, err
		}
		next, err := journal.WithPhase(WindowsActivationQuiesced)
		if err != nil {
			return journal, err
		}
		if err := writer.Advance(&journal, next); err != nil {
			return journal, err
		}
		journal = next
	}

	if journal.Phase == WindowsActivationQuiesced {
		if err := proveWindowsGateClosed(operations); err != nil {
			return journal, err
		}
		if err := operations.QuiesceSourceService(ctx); err != nil {
			return journal, err
		}
		if err := operations.SwitchCurrent(); err != nil {
			return journal, err
		}
		if err := operations.InstallTargetService(ctx); err != nil {
			return journal, err
		}
		next, err := journal.WithPhase(WindowsActivationSelected)
		if err != nil {
			return journal, err
		}
		if err := writer.Advance(&journal, next); err != nil {
			return journal, err
		}
		journal = next
	}

	if journal.Phase == WindowsActivationSelected {
		activationErr := activateSelectedWindowsTarget(ctx, operations, journal)
		if activationErr != nil {
			return journal, errors.Join(activationErr, quarantineWindowsActivation(operations))
		}
		next, err := journal.WithPhase(WindowsActivationActivated)
		if err != nil {
			return journal, err
		}
		if err := writer.Advance(&journal, next); err != nil {
			return journal, errors.Join(err, quarantineWindowsActivation(operations))
		}
		journal = next
	}

	if err := activateSelectedWindowsTarget(ctx, operations, journal); err != nil {
		return journal, errors.Join(err, quarantineWindowsActivation(operations))
	}
	return journal, nil
}

func proveWindowsGateClosed(operations windowsActivationOperations) error {
	open, err := operations.InspectRuntimeGate()
	if err != nil {
		if !errors.Is(err, errWindowsRuntimeGatePublicationPending) {
			return err
		}
		if err := operations.CloseRuntimeGate(); err != nil {
			return err
		}
		open = false
	}
	if open {
		if err := operations.CloseRuntimeGate(); err != nil {
			return err
		}
	}
	open, err = operations.InspectRuntimeGate()
	if err != nil {
		return err
	}
	if open {
		return errors.New("Windows runtime gate remains open before selector or service mutation")
	}
	return nil
}

func activateSelectedWindowsTarget(ctx context.Context, operations windowsActivationOperations, journal WindowsActivationJournal) error {
	// Replay target selection and service installation because a crash can land
	// after either mutation but before the selected journal publication.
	if err := operations.SwitchCurrent(); err != nil {
		return err
	}
	if err := operations.InstallTargetService(ctx); err != nil {
		return err
	}
	if journal.DesiredRuntimeGateOpen {
		if err := operations.OpenRuntimeGate(); err != nil {
			return err
		}
	} else if err := operations.CloseRuntimeGate(); err != nil {
		return err
	}
	if journal.DesiredServiceRunning {
		if err := operations.StartTargetService(ctx); err != nil {
			return err
		}
	} else if err := operations.StopTargetService(ctx); err != nil {
		return err
	}
	return operations.ProveTarget(ctx, journal.DesiredServiceRunning, journal.DesiredRuntimeGateOpen)
}

func quarantineWindowsActivation(operations windowsActivationOperations) error {
	stopContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return errors.Join(operations.CloseRuntimeGate(), operations.StopTargetService(stopContext))
}
