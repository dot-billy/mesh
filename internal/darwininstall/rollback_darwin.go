//go:build darwin

package darwininstall

import (
	"errors"
	"fmt"
)

// BeginRollback durably prepares the sole legal active/previous swap. It
// reauthenticates the published target and current selection before recording
// any desired state, and performs no service or symlink mutation itself.
func (store *InstallerJournalStore) BeginRollback(layout *ReleaseLayout) (returnErr error) {
	if store == nil || layout == nil {
		return errors.New("Darwin rollback requires an installer store and release layout")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	journal, found, err := lock.Load()
	if err != nil {
		return err
	}
	if found {
		if journal.Operation == JournalOperationRollback {
			return nil
		}
		return errors.New("an unfinished Darwin activation must be resumed before rollback")
	}
	if _, found, err := lock.LoadIntakeRecord(); err != nil {
		return err
	} else if found {
		return errors.New("an accepted Darwin intake must finish before rollback")
	}
	state, stateFound, err := lock.LoadInstallState()
	if err != nil {
		return err
	}
	if !stateFound || state.Active == nil || state.Previous == nil {
		return errors.New("Darwin rollback requires persisted active and previous releases")
	}
	if _, err := state.RollbackPrevious(); err != nil {
		return err
	}
	source := *state.Active
	target := *state.Previous
	inspection, err := layout.InspectPublishedAuthority(target)
	if err != nil {
		return fmt.Errorf("authenticate Darwin rollback target: %w", err)
	}
	current, err := layout.NewCurrentSwitch(source.InstalledID, target.InstalledID, inspection)
	if err != nil {
		return err
	}
	layout.mu.Lock()
	if err := layout.validateAnchorsLocked(); err != nil {
		layout.mu.Unlock()
		return err
	}
	selected, err := layout.readCurrentLocked()
	layout.mu.Unlock()
	if err != nil {
		return err
	}
	if currentSelectionID(selected) != source.InstalledID {
		return errors.New("Darwin current release differs from the persisted active rollback source")
	}
	gate, err := NewRuntimeGate(store.directory)
	if err != nil {
		return err
	}
	restoreGate, err := gate.Inspect()
	if err != nil {
		return err
	}
	journal, err = NewRollbackJournal(
		target.InstalledID, source.InstalledID, current.TemporaryName(), inspection,
		source, target, state.HighWater, restoreGate,
	)
	if err != nil {
		return err
	}
	return lock.Commit(journal)
}

// ResumeJournalWithService reconstructs journal-bound current/plist/gate
// operations and drives either activation or rollback to its terminal proof.
// The plist override exists for the disposable root-only native harness.
func (store *InstallerJournalStore) ResumeJournalWithService(layout *ReleaseLayout, service LaunchdServiceController, plistDirectory string) (returnErr error) {
	if store == nil || layout == nil || service == nil {
		return errors.New("Darwin journal recovery requires a store, release layout, and launchd service controller")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	journal, found, loadErr := lock.Load()
	closeErr := lock.Close()
	if err := errors.Join(loadErr, closeErr); err != nil {
		return err
	}
	if !found {
		return nil
	}
	if bound, ok := service.(interface{ ValidateInstallerJournal(InstallerJournal) error }); ok {
		if err := bound.ValidateInstallerJournal(journal); err != nil {
			return err
		}
	}
	current, err := layout.ResumeCurrentSwitch(
		journal.ExpectedPrior, journal.InstalledID, journal.CurrentTemporaryName, journal.Inspection,
	)
	if err != nil {
		return err
	}
	gate, err := NewRuntimeGate(store.directory)
	if err != nil {
		return err
	}
	activation, err := NewLaunchdActivation(gate, current, service, plistDirectory)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, activation.Close()) }()
	return store.Resume(layout, activation)
}

func (store *InstallerJournalStore) ResumeProductionJournal(layout *ReleaseLayout, service LaunchdServiceController) error {
	return store.ResumeJournalWithService(layout, service, ProductionLaunchdDirectory)
}

// ResumeProductionJournalWithLaunchctl constructs the fixed system-domain
// controller from the current journal and then revalidates that binding inside
// the ordinary recovery path before any launchctl mutation.
func (store *InstallerJournalStore) ResumeProductionJournalWithLaunchctl(layout *ReleaseLayout) (returnErr error) {
	if store == nil || layout == nil {
		return errors.New("production launchctl recovery requires a store and release layout")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	journal, found, loadErr := lock.Load()
	closeErr := lock.Close()
	if err := errors.Join(loadErr, closeErr); err != nil {
		return err
	}
	if !found {
		return nil
	}
	controller, err := NewProductionLaunchctlServiceController(layout, journal.InstalledID, journal.Inspection)
	if err != nil {
		return err
	}
	return store.ResumeProductionJournal(layout, controller)
}

// Rollback performs or resumes one explicit journaled rollback and returns
// only after current, plist, launchd, gate, and install state agree.
func (store *InstallerJournalStore) Rollback(layout *ReleaseLayout, service LaunchdServiceController) error {
	if err := store.BeginRollback(layout); err != nil {
		return err
	}
	return store.ResumeProductionJournal(layout, service)
}
