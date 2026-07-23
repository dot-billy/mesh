//go:build windows

package windowsinstall

import (
	"errors"
	"os"
	"reflect"
)

// ValidateAcceptedActivation proves that the durable install-state high-water
// and accepted-intake handoff authorize this exact journal before any selector,
// service, or runtime-gate mutation.
func (store *ActivationJournalStore) ValidateAcceptedActivation(journal WindowsActivationJournal) (returnErr error) {
	if store == nil {
		return errors.New("Windows installer store is required")
	}
	if err := journal.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err := rejectWindowsMutationDuringRuntimeUninstallLocked(root); err != nil {
		return err
	}
	if journal.Operation != WindowsOperationActivate {
		return errors.New("accepted Windows activation validation does not authorize rollback")
	}
	return validateAuthorizedWindowsTransactionLocked(root, store.directory, journal, false)
}

func validateAuthorizedWindowsTransactionLocked(root *os.Root, directory string, journal WindowsActivationJournal, allowConsumedIntake bool) error {
	state, err := recoverWindowsInstallStateLocked(root, directory)
	if err != nil {
		return err
	}
	if state == nil {
		return errors.New("Windows transaction has no durable install state")
	}
	if _, err := authorizeWindowsTransactionState(*state, journal); err != nil {
		return err
	}
	record, err := readWindowsIntakeRecord(root, windowsAcceptedIntakeName)
	if err != nil {
		return err
	}
	pending, err := readWindowsIntakeRecord(root, windowsAcceptedIntakePendingName)
	if err != nil {
		return err
	}
	if pending != nil {
		return errors.New("Windows activation cannot proceed with a pending accepted-intake publication")
	}
	if journal.Operation == WindowsOperationRollback {
		if record != nil {
			return errors.New("Windows rollback cannot overlap an accepted release intake")
		}
		return nil
	}
	if record == nil {
		if !allowConsumedIntake {
			return errors.New("Windows activation has no durable accepted-intake handoff")
		}
		return nil
	}
	intake, err := record.Intake()
	if err != nil {
		return err
	}
	if !windowsIntakeMatchesAuthority(intake, journal.Authority) {
		return errors.New("Windows accepted intake differs from activation authority")
	}
	return nil
}

// FinalizeAcceptedWindowsActivation commits active/previous state, consumes
// the matching intake handoff, and clears the exact activated journal in that
// order under one cross-process lock. Every step is replay-safe after a crash.
func (store *ActivationJournalStore) FinalizeAcceptedWindowsActivation(expected WindowsActivationJournal) (result WindowsInstallState, returnErr error) {
	if expected.Operation != WindowsOperationActivate {
		return result, errors.New("accepted Windows activation finalization does not authorize rollback")
	}
	return store.finalizeWindowsTransaction(expected)
}

// FinalizeWindowsRollback atomically swaps active/previous state without
// consuming release intake or lowering the retained high-water authority.
func (store *ActivationJournalStore) FinalizeWindowsRollback(expected WindowsActivationJournal) (result WindowsInstallState, returnErr error) {
	if expected.Operation != WindowsOperationRollback {
		return result, errors.New("Windows rollback finalization requires a rollback journal")
	}
	return store.finalizeWindowsTransaction(expected)
}

func (store *ActivationJournalStore) finalizeWindowsTransaction(expected WindowsActivationJournal) (result WindowsInstallState, returnErr error) {
	if store == nil {
		return result, errors.New("Windows installer store is required")
	}
	if err := expected.Validate(); err != nil || expected.Phase != WindowsActivationActivated {
		return result, errors.Join(err, errors.New("only an activated Windows journal can be finalized"))
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return result, err
	}
	defer root.Close()
	if err := rejectWindowsMutationDuringRuntimeUninstallLocked(root); err != nil {
		return result, err
	}
	live, err := recoverWindowsActivationJournalLocked(root, store.directory)
	if err != nil {
		return result, err
	}
	if live == nil {
		state, err := recoverWindowsInstallStateLocked(root, store.directory)
		if err != nil {
			return result, err
		}
		intake, err := readWindowsIntakeRecord(root, windowsAcceptedIntakeName)
		if err != nil {
			return result, err
		}
		pending, err := readWindowsIntakeRecord(root, windowsAcceptedIntakePendingName)
		if err != nil {
			return result, err
		}
		if state != nil && windowsStateReflectsFinalizedActivation(*state, expected) && intake == nil && pending == nil {
			return cloneWindowsInstallState(*state), nil
		}
		return result, errors.New("Windows activation finalization is absent or differs from the requested transaction")
	}
	if !reflect.DeepEqual(*live, expected) {
		return result, errors.Join(err, errors.New("Windows activated journal differs before finalization"))
	}
	if err := validateAuthorizedWindowsTransactionLocked(root, store.directory, expected, true); err != nil {
		return result, err
	}
	state, err := recoverWindowsInstallStateLocked(root, store.directory)
	if err != nil || state == nil {
		return result, errors.Join(err, errors.New("Windows install state is absent before activation finalization"))
	}
	next := cloneWindowsInstallState(*state)
	if !windowsStateReflectsFinalizedActivation(*state, expected) {
		switch expected.Operation {
		case WindowsOperationActivate:
			next, err = state.ActivateAccepted()
		case WindowsOperationRollback:
			next, err = state.RollbackPrevious()
		default:
			return result, errors.New("Windows transaction operation is unsupported")
		}
		if err != nil {
			return result, err
		}
		if err := commitWindowsInstallStateLocked(root, store.directory, state, next); err != nil {
			return result, err
		}
	}
	record, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil {
		return result, err
	}
	if expected.Operation == WindowsOperationRollback && record != nil {
		return result, errors.New("Windows rollback finalization found an accepted release intake")
	}
	if record != nil {
		intake, err := record.Intake()
		if err != nil || !windowsIntakeMatchesAuthority(intake, expected.Authority) {
			return result, errors.Join(err, errors.New("Windows accepted intake changed before finalization"))
		}
		if err := discardWindowsArtifactCaptureLocked(root, intake.Candidate.Artifact); err != nil {
			return result, err
		}
		if err := root.Remove(windowsAcceptedIntakeName); err != nil {
			return result, err
		}
	}
	if err := root.Remove(windowsActivationJournalName); err != nil {
		return result, err
	}
	if journal, err := readWindowsActivationJournal(root, windowsActivationJournalName); err != nil || journal != nil {
		return result, errors.Join(err, errors.New("Windows activation journal remained after finalization"))
	}
	if intake, err := readWindowsIntakeRecord(root, windowsAcceptedIntakeName); err != nil || intake != nil {
		return result, errors.Join(err, errors.New("Windows accepted intake remained after finalization"))
	}
	return next, nil
}

func windowsIntakeMatchesAuthority(intake VerifiedWindowsIntake, authority AuthenticatedWindowsRelease) bool {
	candidate := intake.Candidate
	return intake.InstallerBootstrapRootSHA256 == authority.InstallerBootstrapRootSHA256 &&
		candidate.ReleaseEpoch == authority.ReleaseEpoch && candidate.Sequence == authority.Sequence &&
		candidate.TrustedRootVersion == authority.TrustedRootVersion && candidate.TrustedRootSHA256 == authority.TrustedRootSHA256 &&
		candidate.ChannelManifestSHA256 == authority.ChannelManifestSHA256 && candidate.ReleaseManifestSHA256 == authority.ReleaseManifestSHA256 &&
		candidate.Artifact.OS == "windows" && candidate.Artifact.Arch == authority.Arch && candidate.Artifact.SHA256 == authority.ArtifactSHA256 &&
		candidate.Version == authority.Version && candidate.MinimumSecurityFloor == authority.MinimumSecurityFloor &&
		candidate.Channel == authority.Channel && candidate.VerifiedAt == authority.VerifiedAt
}
