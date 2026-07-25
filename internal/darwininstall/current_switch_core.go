package darwininstall

import "errors"

type currentReleaseSelection struct {
	InstalledID string
	Exists      bool
}

type currentSwitchOperations interface {
	InspectTarget() error
	InspectCurrent() (currentReleaseSelection, error)
	InspectTemporary() (bool, error)
	CreateTemporary() error
	RemoveTemporary() error
	SyncRoot() error
	ReplaceCurrent() error
}

// switchCurrentRelease selects target only when current still equals the
// transaction's expected prior release (or is absent when expectedPrior is
// empty). A recognized temporary is a crash-recovery object, never authority.
func switchCurrentRelease(operations currentSwitchOperations, expectedPrior string, target string) error {
	if operations == nil || target == "" || expectedPrior == target {
		return errors.New("Darwin current-switch operations, distinct prior, and target are required")
	}
	if err := operations.InspectTarget(); err != nil {
		return err
	}
	current, err := operations.InspectCurrent()
	if err != nil {
		return err
	}
	temporary, err := operations.InspectTemporary()
	if err != nil {
		return err
	}
	if current.Exists && current.InstalledID == target {
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
	if currentSelectionID(current) != expectedPrior {
		return errors.New("Darwin current release differs from the transaction's expected prior release")
	}
	if !temporary {
		if err := operations.CreateTemporary(); err != nil {
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
	temporaryAgain, err := operations.InspectTemporary()
	if err != nil {
		return err
	}
	if currentSelectionID(currentAgain) != expectedPrior || !temporaryAgain {
		return errors.New("Darwin current release changed while preparing its switch")
	}
	if err := operations.ReplaceCurrent(); err != nil {
		return err
	}
	if err := operations.SyncRoot(); err != nil {
		return err
	}
	return proveCurrentRelease(operations, target)
}

func proveCurrentRelease(operations currentSwitchOperations, target string) error {
	if err := operations.InspectTarget(); err != nil {
		return err
	}
	current, err := operations.InspectCurrent()
	if err != nil {
		return err
	}
	temporary, err := operations.InspectTemporary()
	if err != nil {
		return err
	}
	if !current.Exists || current.InstalledID != target || temporary {
		return errors.New("Darwin current release switch is not exact and durable")
	}
	return nil
}

func currentSelectionID(selection currentReleaseSelection) string {
	if !selection.Exists {
		return ""
	}
	return selection.InstalledID
}
