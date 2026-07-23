package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

const WindowsRuntimeUninstallJournalSchema = "mesh-windows-runtime-uninstall-journal-v1"

type WindowsRuntimeUninstallPhase string

const (
	WindowsUninstallPrepared         WindowsRuntimeUninstallPhase = "prepared"
	WindowsUninstallGateClosed       WindowsRuntimeUninstallPhase = "gate-closed"
	WindowsUninstallServiceStopped   WindowsRuntimeUninstallPhase = "service-stopped"
	WindowsUninstallServiceDeleted   WindowsRuntimeUninstallPhase = "service-deleted"
	WindowsUninstallCurrentRemoved   WindowsRuntimeUninstallPhase = "current-removed"
	WindowsUninstallStateDeactivated WindowsRuntimeUninstallPhase = "state-deactivated"
)

type WindowsRuntimeUninstallJournal struct {
	Schema  string                       `json:"schema"`
	Source  WindowsInstallState          `json:"source"`
	Current CurrentDescriptor            `json:"current"`
	Phase   WindowsRuntimeUninstallPhase `json:"phase"`
}

func NewWindowsRuntimeUninstallJournal(source WindowsInstallState) (WindowsRuntimeUninstallJournal, error) {
	if err := source.Validate(); err != nil {
		return WindowsRuntimeUninstallJournal{}, err
	}
	if source.Active == nil {
		return WindowsRuntimeUninstallJournal{}, errors.New("Windows runtime uninstall requires an active release")
	}
	current, err := source.Active.CurrentDescriptor()
	if err != nil {
		return WindowsRuntimeUninstallJournal{}, err
	}
	journal := WindowsRuntimeUninstallJournal{
		Schema: WindowsRuntimeUninstallJournalSchema, Source: cloneWindowsInstallState(source),
		Current: current, Phase: WindowsUninstallPrepared,
	}
	return journal, journal.Validate()
}

func (journal WindowsRuntimeUninstallJournal) Validate() error {
	if journal.Schema != WindowsRuntimeUninstallJournalSchema {
		return errors.New("Windows runtime-uninstall journal schema is invalid")
	}
	if err := journal.Source.Validate(); err != nil {
		return fmt.Errorf("Windows runtime-uninstall source: %w", err)
	}
	if journal.Source.Active == nil {
		return errors.New("Windows runtime-uninstall source has no active release")
	}
	want, err := journal.Source.Active.CurrentDescriptor()
	if err != nil {
		return err
	}
	if err := journal.Current.Validate(); err != nil || journal.Current != want {
		return errors.Join(err, errors.New("Windows runtime-uninstall current descriptor differs from active authority"))
	}
	switch journal.Phase {
	case WindowsUninstallPrepared, WindowsUninstallGateClosed, WindowsUninstallServiceStopped,
		WindowsUninstallServiceDeleted, WindowsUninstallCurrentRemoved, WindowsUninstallStateDeactivated:
		return nil
	default:
		return fmt.Errorf("Windows runtime-uninstall phase %q is invalid", journal.Phase)
	}
}

func validateWindowsRuntimeUninstallTransition(current *WindowsRuntimeUninstallJournal, next WindowsRuntimeUninstallJournal) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if current == nil {
		if next.Phase != WindowsUninstallPrepared {
			return errors.New("initial Windows runtime-uninstall journal must be prepared")
		}
		return nil
	}
	if err := current.Validate(); err != nil {
		return err
	}
	left, right := *current, next
	left.Phase, right.Phase = "", ""
	if !reflect.DeepEqual(left, right) {
		return errors.New("Windows runtime-uninstall transition changed immutable authority")
	}
	if current.Phase == next.Phase {
		return nil
	}
	phases := []WindowsRuntimeUninstallPhase{
		WindowsUninstallPrepared, WindowsUninstallGateClosed, WindowsUninstallServiceStopped,
		WindowsUninstallServiceDeleted, WindowsUninstallCurrentRemoved, WindowsUninstallStateDeactivated,
	}
	for index := 0; index+1 < len(phases); index++ {
		if current.Phase == phases[index] && next.Phase == phases[index+1] {
			return nil
		}
	}
	return fmt.Errorf("Windows runtime-uninstall phase cannot advance from %q to %q", current.Phase, next.Phase)
}

type windowsRuntimeUninstallJournalWriter interface {
	AdvanceRuntimeUninstall(*WindowsRuntimeUninstallJournal, WindowsRuntimeUninstallJournal) error
}

type windowsRuntimeUninstallOperations interface {
	ValidateRuntimeUninstall(WindowsRuntimeUninstallJournal) error
	InspectRuntimeGate() (bool, error)
	CloseRuntimeGate() error
	InspectService() (installed bool, running bool, err error)
	StopService(context.Context) error
	DeleteService(context.Context) error
	InspectCurrent() (*CurrentDescriptor, error)
	RemoveCurrent(CurrentDescriptor) error
	InspectInstallState() (*WindowsInstallState, error)
	DeactivateInstallState(WindowsInstallState) error
}

func advanceWindowsRuntimeUninstall(ctx context.Context, writer windowsRuntimeUninstallJournalWriter, operations windowsRuntimeUninstallOperations, journal WindowsRuntimeUninstallJournal) (WindowsRuntimeUninstallJournal, error) {
	if ctx == nil || writer == nil || operations == nil {
		return WindowsRuntimeUninstallJournal{}, errors.New("Windows runtime-uninstall context, writer, and operations are required")
	}
	if err := journal.Validate(); err != nil {
		return WindowsRuntimeUninstallJournal{}, err
	}
	if err := operations.ValidateRuntimeUninstall(journal); err != nil {
		return WindowsRuntimeUninstallJournal{}, fmt.Errorf("bind Windows runtime-uninstall operations: %w", err)
	}
	current := journal
	advance := func(phase WindowsRuntimeUninstallPhase) error {
		next := current
		next.Phase = phase
		if err := writer.AdvanceRuntimeUninstall(&current, next); err != nil {
			return err
		}
		current = next
		return nil
	}

	if current.Phase == WindowsUninstallPrepared {
		open, err := operations.InspectRuntimeGate()
		if err != nil {
			return current, err
		}
		if open {
			if err := operations.CloseRuntimeGate(); err != nil {
				return current, err
			}
		}
		if open, err := operations.InspectRuntimeGate(); err != nil || open {
			return current, errors.Join(err, errors.New("Windows runtime gate remained open during uninstall"))
		}
		if err := advance(WindowsUninstallGateClosed); err != nil {
			return current, err
		}
	}
	if current.Phase == WindowsUninstallGateClosed {
		installed, running, err := operations.InspectService()
		if err != nil {
			return current, err
		}
		if installed && running {
			if err := operations.StopService(ctx); err != nil {
				return current, err
			}
		}
		installed, running, err = operations.InspectService()
		if err != nil || running {
			return current, errors.Join(err, errors.New("Windows node-agent service did not reach a stopped or absent state"))
		}
		if err := advance(WindowsUninstallServiceStopped); err != nil {
			return current, err
		}
	}
	if current.Phase == WindowsUninstallServiceStopped {
		installed, running, err := operations.InspectService()
		if err != nil || running {
			return current, errors.Join(err, errors.New("Windows node-agent service is not safely stopped for deletion"))
		}
		if installed {
			if err := operations.DeleteService(ctx); err != nil {
				return current, err
			}
		}
		installed, running, err = operations.InspectService()
		if err != nil || installed || running {
			return current, errors.Join(err, errors.New("Windows node-agent service remained installed after deletion"))
		}
		if err := advance(WindowsUninstallServiceDeleted); err != nil {
			return current, err
		}
	}
	if current.Phase == WindowsUninstallServiceDeleted {
		selected, err := operations.InspectCurrent()
		if err != nil {
			return current, err
		}
		if selected != nil {
			if *selected != current.Current {
				return current, errors.New("Windows runtime uninstall found an unexpected current selection")
			}
			if err := operations.RemoveCurrent(current.Current); err != nil {
				return current, err
			}
		}
		if selected, err := operations.InspectCurrent(); err != nil || selected != nil {
			return current, errors.Join(err, errors.New("Windows current selection remained after uninstall"))
		}
		if err := advance(WindowsUninstallCurrentRemoved); err != nil {
			return current, err
		}
	}
	if current.Phase == WindowsUninstallCurrentRemoved {
		state, err := operations.InspectInstallState()
		if err != nil || state == nil {
			return current, errors.Join(err, errors.New("Windows runtime uninstall lost install-state authority"))
		}
		deactivated, err := current.Source.DeactivateRuntime()
		if err != nil {
			return current, err
		}
		if reflect.DeepEqual(*state, current.Source) {
			if err := operations.DeactivateInstallState(current.Source); err != nil {
				return current, err
			}
		} else if !reflect.DeepEqual(*state, deactivated) {
			return current, errors.New("Windows install state differs from the uninstall source or finalized state")
		}
		state, err = operations.InspectInstallState()
		if err != nil || state == nil || !reflect.DeepEqual(*state, deactivated) {
			return current, errors.Join(err, errors.New("Windows install state was not deactivated exactly"))
		}
		if err := advance(WindowsUninstallStateDeactivated); err != nil {
			return current, err
		}
	}
	return current, nil
}
