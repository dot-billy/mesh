//go:build darwin

package darwininstall

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ValidateProductionDarwinInstalledRuntime authenticates the one active
// installer-managed release before production enrollment is allowed to execute
// any of its binaries. The meshctl enrollment boundary intentionally retains a
// separate release gate after this succeeds until native lifecycle evidence is
// accepted.
func ValidateProductionDarwinInstalledRuntime(binaryDirectory string) (returnErr error) {
	if !filepath.IsAbs(binaryDirectory) || filepath.Clean(binaryDirectory) != binaryDirectory {
		return errors.New("Darwin enrollment runtime directory must be canonical and absolute")
	}
	layout, err := OpenReleaseLayout(ProductionMeshRoot)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, layout.Close()) }()
	return validateDarwinInstalledRuntime(
		layout,
		ProductionInstallerJournalStore(),
		ProductionRuntimeGate(),
		ProductionLaunchdDirectory,
		binaryDirectory,
	)
}

func validateDarwinInstalledRuntime(
	layout *ReleaseLayout,
	store *InstallerJournalStore,
	gate *RuntimeGate,
	launchdDirectory string,
	binaryDirectory string,
) (returnErr error) {
	if layout == nil || store == nil || gate == nil {
		return errors.New("Darwin installed-runtime validation dependencies are required")
	}
	if !cleanDarwinInstallPath(launchdDirectory) ||
		!filepath.IsAbs(binaryDirectory) ||
		filepath.Clean(binaryDirectory) != binaryDirectory {
		return errors.New("Darwin installed-runtime validation paths must be canonical and absolute")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil {
		return err
	} else if found {
		return errors.New("Darwin production enrollment cannot overlap an installer journal")
	}
	if _, found, err := lock.LoadIntakeRecord(); err != nil {
		return err
	} else if found {
		return errors.New("Darwin production enrollment cannot overlap accepted release intake")
	}
	state, found, err := lock.LoadInstallState()
	if err != nil || !found || state.Active == nil {
		return errors.Join(err, errors.New("Darwin production enrollment requires one active installed release"))
	}
	if err := validateDarwinRuntimeDirectory(binaryDirectory, layout.releasesPath, state.Active.InstalledID); err != nil {
		return err
	}
	inspection, err := layout.InspectPublishedAuthority(*state.Active)
	if err != nil {
		return fmt.Errorf("authenticate Darwin enrollment release: %w", err)
	}
	if err := verifyDarwinReleaseSignatures(
		filepath.Join(layout.releasesPath, state.Active.InstalledID),
		inspection,
	); err != nil {
		return fmt.Errorf("admit Darwin enrollment release code signatures: %w", err)
	}
	current, err := layout.NewCurrentSwitch("", state.Active.InstalledID, inspection)
	if err != nil {
		return err
	}
	if err := current.ProveSelected(); err != nil {
		return fmt.Errorf("prove Darwin enrollment release selection: %w", err)
	}
	publisher, err := NewLaunchdPlistPublisher(layout, state.Active.InstalledID, inspection, launchdDirectory)
	if err != nil {
		return err
	}
	inspectErr := publisher.Inspect()
	closeErr := publisher.Close()
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return fmt.Errorf("authenticate Darwin enrollment launchd plist: %w", err)
	}
	gateOpen, err := gate.Inspect()
	if err != nil {
		return err
	}
	if gateOpen {
		return errors.New("Darwin production enrollment requires a closed runtime gate")
	}
	return nil
}

func validateProductionDarwinRuntimeDirectory(binaryDirectory, activeInstalledID string) error {
	return validateDarwinRuntimeDirectory(binaryDirectory, ProductionReleasesRoot, activeInstalledID)
}

func validateDarwinRuntimeDirectory(binaryDirectory, releasesDirectory, activeInstalledID string) error {
	if !darwinInstalledIDPattern.MatchString(activeInstalledID) {
		return errors.New("Darwin active installed release ID is not canonical")
	}
	if !cleanDarwinInstallPath(releasesDirectory) {
		return errors.New("Darwin releases directory is not canonical")
	}
	expected := filepath.Join(releasesDirectory, activeInstalledID, "bin")
	if binaryDirectory != expected {
		return errors.New("Darwin enrollment runtime is not the exact active installer-managed release")
	}
	return nil
}
