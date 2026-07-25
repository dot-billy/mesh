package windowsinstall

import (
	"errors"
	"reflect"
)

type currentSwitchOperations interface {
	InspectTarget(CurrentDescriptor) error
	InspectCurrent() (*CurrentDescriptor, error)
	InspectTemporary(CurrentDescriptor) (bool, error)
	CreateTemporary(CurrentDescriptor) error
	RemoveTemporary() error
	SyncRoot() error
	ReplaceCurrent(CurrentDescriptor) error
}

func switchCurrentRelease(operations currentSwitchOperations, expectedPrior *CurrentDescriptor, target CurrentDescriptor) error {
	if operations == nil {
		return errors.New("Windows current-switch operations are required")
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if expectedPrior != nil {
		if err := expectedPrior.Validate(); err != nil {
			return err
		}
		if reflect.DeepEqual(*expectedPrior, target) {
			return errors.New("Windows current-switch prior and target must differ")
		}
	}
	if err := operations.InspectTarget(target); err != nil {
		return err
	}
	current, err := operations.InspectCurrent()
	if err != nil {
		return err
	}
	temporary, err := operations.InspectTemporary(target)
	if err != nil {
		return err
	}
	if descriptorEqual(current, &target) {
		if temporary {
			if err := operations.RemoveTemporary(); err != nil {
				return err
			}
		}
		if err := operations.SyncRoot(); err != nil {
			return err
		}
		return proveCurrentRelease(operations, target)
	}
	if !descriptorEqual(current, expectedPrior) {
		return errors.New("Windows current release differs from the transaction's expected prior release")
	}
	if !temporary {
		if err := operations.CreateTemporary(target); err != nil {
			return err
		}
	}
	if err := operations.SyncRoot(); err != nil {
		return err
	}
	currentAgain, err := operations.InspectCurrent()
	if err != nil {
		return err
	}
	temporaryAgain, err := operations.InspectTemporary(target)
	if err != nil {
		return err
	}
	if !descriptorEqual(currentAgain, expectedPrior) || !temporaryAgain {
		return errors.New("Windows current release changed while preparing its switch")
	}
	if err := operations.ReplaceCurrent(target); err != nil {
		return err
	}
	if err := operations.SyncRoot(); err != nil {
		return err
	}
	return proveCurrentRelease(operations, target)
}

func proveCurrentRelease(operations currentSwitchOperations, target CurrentDescriptor) error {
	if err := operations.InspectTarget(target); err != nil {
		return err
	}
	current, err := operations.InspectCurrent()
	if err != nil {
		return err
	}
	temporary, err := operations.InspectTemporary(target)
	if err != nil {
		return err
	}
	if !descriptorEqual(current, &target) || temporary {
		return errors.New("Windows current release switch is not exact")
	}
	return nil
}

func descriptorEqual(left, right *CurrentDescriptor) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return reflect.DeepEqual(*left, *right)
}
