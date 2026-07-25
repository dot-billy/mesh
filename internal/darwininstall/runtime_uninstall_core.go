package darwininstall

import (
	"errors"
	"reflect"
)

type darwinRuntimeUninstallOperations interface {
	ValidateRuntimeUninstall(DarwinInstallState) error
	InspectRuntimeGate() (bool, error)
	CloseRuntimeGate() error
	BootoutService() error
	RemoveLaunchdPlist() error
	RemoveCurrentSelection() error
	InspectInstallState() (DarwinInstallState, error)
	DeactivateInstallState(DarwinInstallState) error
}

// deactivateDarwinRuntime applies the only safe runtime-uninstall order. The
// source install state remains durable authority until gate, service, plist,
// and selector removal have each completed and been proven. Every operation is
// idempotent so a retry can recover response loss without a weaker shortcut.
func deactivateDarwinRuntime(operations darwinRuntimeUninstallOperations, source DarwinInstallState) (DarwinInstallState, error) {
	if operations == nil {
		return DarwinInstallState{}, errors.New("Darwin runtime-uninstall operations are required")
	}
	if err := source.Validate(); err != nil {
		return DarwinInstallState{}, err
	}
	if source.Active == nil {
		return DarwinInstallState{}, errors.New("Darwin runtime uninstall requires an active release")
	}
	if err := operations.ValidateRuntimeUninstall(source); err != nil {
		return DarwinInstallState{}, err
	}
	open, err := operations.InspectRuntimeGate()
	if err != nil {
		return DarwinInstallState{}, err
	}
	if open {
		if err := operations.CloseRuntimeGate(); err != nil {
			return DarwinInstallState{}, err
		}
	}
	if open, err := operations.InspectRuntimeGate(); err != nil || open {
		return DarwinInstallState{}, errors.Join(err, errors.New("Darwin runtime gate remained open during uninstall"))
	}
	if err := operations.BootoutService(); err != nil {
		return DarwinInstallState{}, err
	}
	if err := operations.RemoveLaunchdPlist(); err != nil {
		return DarwinInstallState{}, err
	}
	if err := operations.RemoveCurrentSelection(); err != nil {
		return DarwinInstallState{}, err
	}
	deactivated, err := source.DeactivateRuntime()
	if err != nil {
		return DarwinInstallState{}, err
	}
	state, err := operations.InspectInstallState()
	if err != nil {
		return DarwinInstallState{}, err
	}
	if sameDarwinInstallState(state, source) {
		if err := operations.DeactivateInstallState(source); err != nil {
			return DarwinInstallState{}, err
		}
	} else if !reflect.DeepEqual(state, deactivated) {
		return DarwinInstallState{}, errors.New("Darwin install state differs from runtime-uninstall source or response-loss result")
	}
	state, err = operations.InspectInstallState()
	if err != nil || !sameDarwinInstallState(state, deactivated) {
		return DarwinInstallState{}, errors.Join(err, errors.New("Darwin install state was not deactivated exactly"))
	}
	return state, nil
}
