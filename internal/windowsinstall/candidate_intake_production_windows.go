//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	"mesh/internal/windowsinstallercompat"
)

// AuthenticateProductionWindowsCandidate binds untrusted transport to the
// release root and build identity compiled into this installer. The accepted
// record retains the exact canonical signed bytes for restart verification.
func (store *ActivationJournalStore) AuthenticateProductionWindowsCandidate(bundle onlinerelease.Bundle, now time.Time) (VerifiedWindowsIntake, error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return VerifiedWindowsIntake{}, fmt.Errorf("load compiled Windows installer trust: %w", err)
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return VerifiedWindowsIntake{}, fmt.Errorf("load compiled Windows installer identity: %w", err)
	}
	return store.authenticateWindowsCandidateUsing(bundle, now, bootstrap, build)
}

func (store *ActivationJournalStore) authenticateWindowsCandidateUsing(bundle onlinerelease.Bundle, now time.Time, bootstrap installtrust.Bootstrap, build buildinfo.Info) (VerifiedWindowsIntake, error) {
	if err := validateWindowsProductionInputs(bootstrap, build, now); err != nil {
		return VerifiedWindowsIntake{}, err
	}
	return store.AcceptWindowsCandidate(
		bootstrap.InitialRoot, bundle, bootstrap.InitialRootSHA256, now, 0, build.SecurityFloor, build.Arch,
	)
}

// LoadProductionWindowsIntake replays root history and re-verifies the exact
// persisted signed bytes at their original accepted time before returning any
// cached candidate fields as authority.
func (store *ActivationJournalStore) LoadProductionWindowsIntake() (VerifiedWindowsIntake, bool, error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return VerifiedWindowsIntake{}, false, fmt.Errorf("load compiled Windows installer trust: %w", err)
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return VerifiedWindowsIntake{}, false, fmt.Errorf("load compiled Windows installer identity: %w", err)
	}
	return store.loadWindowsIntakeUsing(bootstrap, build)
}

func (store *ActivationJournalStore) loadWindowsIntakeUsing(bootstrap installtrust.Bootstrap, build buildinfo.Info) (result VerifiedWindowsIntake, found bool, returnErr error) {
	if err := validateWindowsProductionInputs(bootstrap, build, time.Now().UTC()); err != nil {
		return result, false, err
	}
	if store == nil {
		return result, false, errors.New("Windows installer store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return result, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return result, false, err
	}
	defer root.Close()
	if err := rejectWindowsCandidateAcceptanceDuringActivation(root); err != nil {
		return result, false, err
	}
	if err := store.reconcileWindowsRootPending(root, bootstrap.InitialRoot); err != nil {
		return result, false, err
	}
	record, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || record == nil {
		return result, false, err
	}
	result, err = verifyExistingWindowsIntakeLocked(
		root, store.directory, bootstrap.InitialRoot, *record, build.SecurityFloor, build.Arch,
	)
	return result, true, err
}

func validateWindowsProductionInputs(bootstrap installtrust.Bootstrap, build buildinfo.Info, now time.Time) error {
	compatibility, err := windowsinstallercompat.Current()
	if err != nil || compatibility.ReadMinimum != 1 || compatibility.ReadMaximum != 1 || compatibility.WriteVersion != 1 {
		return errors.Join(err, errors.New("compiled Windows installer-state compatibility is invalid"))
	}
	if build.OS != "windows" || build.Arch != "amd64" && build.Arch != "arm64" {
		return errors.New("Mesh Windows installation is supported only on windows/amd64 and windows/arm64")
	}
	if build.SecurityFloor == 0 || now.IsZero() {
		return errors.New("Windows installer build floor and verification time are required")
	}
	if bootstrap.InitialRootSHA256 == "" || bootstrap.InitialRoot.SHA256 != bootstrap.InitialRootSHA256 {
		return errors.New("compiled Windows installer root identity is inconsistent")
	}
	return nil
}
