package darwininstall

import "errors"

type currentRemovalOperations interface {
	InspectTarget() error
	InspectCurrent() (currentReleaseSelection, error)
	InspectTemporary() (bool, error)
	RemoveCurrent() error
	SyncRoot() error
}

// removeDarwinCurrentSelection removes only the exact authenticated active
// selector. The immutable target remains present and authenticated. Absence is
// an idempotent response-loss result; a different selector or transaction
// temporary is never removed.
func removeDarwinCurrentSelection(operations currentRemovalOperations, expectedInstalledID string) error {
	if operations == nil || expectedInstalledID == "" {
		return errors.New("Darwin current removal operations and installed ID are required")
	}
	if err := operations.InspectTarget(); err != nil {
		return err
	}
	temporary, err := operations.InspectTemporary()
	if err != nil {
		return err
	}
	if temporary {
		return errors.New("Darwin current removal refuses a transaction temporary")
	}
	current, err := operations.InspectCurrent()
	if err != nil {
		return err
	}
	if current.Exists {
		if current.InstalledID != expectedInstalledID {
			return errors.New("Darwin current removal found an unexpected selected release")
		}
		if err := operations.RemoveCurrent(); err != nil {
			return err
		}
	}
	if err := operations.SyncRoot(); err != nil {
		return err
	}
	if err := operations.InspectTarget(); err != nil {
		return err
	}
	current, err = operations.InspectCurrent()
	if err != nil {
		return err
	}
	temporary, err = operations.InspectTemporary()
	if err != nil {
		return err
	}
	if current.Exists || temporary {
		return errors.New("Darwin current selector remains after removal")
	}
	return nil
}
