//go:build darwin

package darwininstall

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"mesh/internal/darwinbundle"
	"mesh/internal/onlinerelease"
)

// DarwinInstallResult is the bounded proof returned by the privileged Darwin
// installer command. It reports only state that the installer reauthenticated
// from its immutable release, current selector, exact launchd plist, and
// persistent runtime gate. It deliberately does not infer process state from
// launchctl's non-API diagnostic output.
type DarwinInstallResult struct {
	Operation                 InstallerJournalOperation   `json:"operation"`
	Release                   AuthenticatedDarwinRelease  `json:"release"`
	Previous                  *AuthenticatedDarwinRelease `json:"previous,omitempty"`
	FirstInstall              bool                        `json:"first_install"`
	AlreadyActive             bool                        `json:"already_active,omitempty"`
	LaunchdPlistExact         bool                        `json:"launchd_plist_exact"`
	RuntimeGateOpen           bool                        `json:"runtime_gate_open"`
	LaunchdKickstartSucceeded bool                        `json:"launchd_kickstart_succeeded,omitempty"`
}

type productionDarwinInstallation struct {
	layout *ReleaseLayout
	store  *InstallerJournalStore
	gate   *RuntimeGate
}

// ApplyProductionDarwinOnline authenticates and installs the exact release
// selected by one canonical online bundle URL. First installation publishes
// and loads the exact launchd job while leaving the runtime gate closed until
// enrollment has created private node state.
func ApplyProductionDarwinOnline(ctx context.Context, bundleURL string) (result DarwinInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin online installation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	canonical, err := onlinerelease.CanonicalBundleURL(bundleURL)
	if err != nil || canonical != bundleURL {
		return result, errors.Join(err, errors.New("Darwin online installation requires one exact canonical bundle URL"))
	}
	installation, err := ensureProductionDarwinInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	if err := installation.requireNoJournal(); err != nil {
		return result, err
	}
	client := onlinerelease.NewClient()
	bundle, err := client.FetchBundle(ctx, canonical)
	if err != nil {
		return result, fmt.Errorf("fetch Darwin release metadata: %w", err)
	}
	intake, err := installation.store.AuthenticateProductionDarwinCandidate(bundle, time.Now().UTC())
	if err != nil {
		return result, err
	}
	capture, err := installation.store.FetchProductionDarwinArtifact(ctx, intake)
	if err != nil {
		return result, err
	}
	if err := capture.Close(); err != nil {
		return result, fmt.Errorf("close Darwin artifact capture: %w", err)
	}
	return installation.activateAccepted(intake)
}

// ApplyProductionDarwinSnapshot applies one exact root-private three-file
// offline snapshot through the same accepted-intake transaction as online
// installation.
func ApplyProductionDarwinSnapshot(ctx context.Context, sourceDirectory string) (result DarwinInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin snapshot installation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	installation, err := ensureProductionDarwinInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	if err := installation.requireNoJournal(); err != nil {
		return result, err
	}
	intake, capture, err := installation.store.ImportProductionDarwinSnapshot(ctx, sourceDirectory, time.Now().UTC())
	if err != nil {
		return result, err
	}
	if err := capture.Close(); err != nil {
		return result, fmt.Errorf("close Darwin offline artifact capture: %w", err)
	}
	return installation.activateAccepted(intake)
}

// ApplyProductionDarwinPackageSnapshot is the compiled post-install boundary
// for a protected flat package. It resumes only already durable installer
// authority before importing the package policy's fixed snapshot through the
// same exact offline intake. It does not enroll the node or open the runtime
// gate.
func ApplyProductionDarwinPackageSnapshot(ctx context.Context, sourceDirectory string) (result DarwinInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin package snapshot installation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	installation, err := ensureProductionDarwinInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()

	journal, found, err := installation.loadJournal()
	if err != nil {
		return result, err
	}
	if found {
		if err := installation.store.ResumeProductionJournalWithLaunchctl(installation.layout); err != nil {
			return result, err
		}
		if _, err := installation.resultFromState(journal.Operation, false, false); err != nil {
			return result, err
		}
	}
	intake, found, err := installation.store.LoadProductionDarwinIntake()
	if err != nil {
		return result, err
	}
	if found {
		if _, err := installation.activateAccepted(intake); err != nil {
			return result, err
		}
	}
	if err := installation.requireNoRuntimeUninstallResidue(); err != nil {
		return result, err
	}

	intake, capture, err := installation.store.ImportProductionDarwinSnapshot(ctx, sourceDirectory, time.Now().UTC())
	if err != nil {
		return result, err
	}
	if err := capture.Close(); err != nil {
		return result, fmt.Errorf("close Darwin package artifact capture: %w", err)
	}
	return installation.activateAccepted(intake)
}

// RecoverProductionDarwinInstallation resumes only the exact activation or
// rollback journal already durable on disk, or a durable accepted intake whose
// artifact capture has completed. An interrupted download remains bound to its
// original install command and cannot silently change from offline to online.
func RecoverProductionDarwinInstallation(ctx context.Context) (result DarwinInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin installation recovery requires a context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	installation, err := openProductionDarwinInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	journal, found, err := installation.loadJournal()
	if err != nil {
		return result, err
	}
	if found {
		if err := installation.store.ResumeProductionJournalWithLaunchctl(installation.layout); err != nil {
			return result, err
		}
		return installation.resultFromState(journal.Operation, false, false)
	}
	intake, found, err := installation.store.LoadProductionDarwinIntake()
	if err != nil {
		return result, err
	}
	if found {
		return installation.activateAccepted(intake)
	}
	if err := installation.requireNoRuntimeUninstallResidue(); err != nil {
		return result, err
	}
	return result, errors.New("Darwin installation has no unfinished transaction to recover")
}

// RollbackProductionDarwinInstallation selects only the exact persisted
// previous release named by expectedInstalledID. The comparison is repeated
// while holding the journal lock so a concurrent transaction cannot redirect
// rollback authority. Retrying after response loss is an idempotent success.
func RollbackProductionDarwinInstallation(ctx context.Context, expectedInstalledID string) (result DarwinInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin rollback requires a context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !darwinInstalledIDPattern.MatchString(expectedInstalledID) {
		return result, errors.New("Darwin rollback target must be one canonical installed ID")
	}
	installation, err := openProductionDarwinInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	journal, found, err := installation.loadJournal()
	if err != nil {
		return result, err
	}
	if found {
		if journal.Operation != JournalOperationRollback || journal.InstalledID != expectedInstalledID {
			return result, errors.New("Darwin installation has a different unfinished transaction; run recover first")
		}
		if err := installation.store.ResumeProductionJournalWithLaunchctl(installation.layout); err != nil {
			return result, err
		}
		return installation.resultFromState(JournalOperationRollback, false, false)
	}
	if _, found, err := installation.store.LoadProductionDarwinIntake(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Darwin rollback cannot overlap an accepted release intake")
	}
	state, found, err := installation.store.LoadInstallState()
	if err != nil || !found || state.Active == nil {
		return result, errors.Join(err, errors.New("Darwin rollback requires an active installation"))
	}
	if _, err := installation.proveActive(*state.Active); err != nil {
		return result, errors.Join(err, errors.New("Darwin activation surface is incomplete; run uninstall-runtime to resume fail-closed deactivation"))
	}
	if state.Active.InstalledID == expectedInstalledID {
		return installation.resultFromState(JournalOperationRollback, true, false)
	}
	if state.Previous == nil || state.Previous.InstalledID != expectedInstalledID {
		return result, errors.New("Darwin rollback target must equal the exact persisted previous installed ID")
	}
	if err := installation.store.BeginRollbackTo(installation.layout, expectedInstalledID); err != nil {
		return result, err
	}
	if err := installation.store.ResumeProductionJournalWithLaunchctl(installation.layout); err != nil {
		return result, err
	}
	return installation.resultFromState(JournalOperationRollback, false, false)
}

// ActivateProductionDarwinRuntime opens the persistent runtime gate only after
// proving the exact selected release and launchd plist, then asks launchd to
// start the already-loaded fixed system job. It does not select a release or
// accept any caller-provided executable, arguments, environment, or plist.
func ActivateProductionDarwinRuntime(ctx context.Context) (result DarwinInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin runtime activation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	installation, err := openProductionDarwinInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	lock, err := installation.store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Darwin runtime activation cannot overlap an installer journal")
	}
	if _, found, err := lock.LoadIntakeRecord(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Darwin runtime activation cannot overlap an accepted release intake")
	}
	state, found, err := lock.LoadInstallState()
	if err != nil || !found || state.Active == nil {
		return result, errors.Join(err, errors.New("Darwin runtime activation requires an active release"))
	}
	inspection, err := installation.proveActive(*state.Active)
	if err != nil {
		return result, err
	}
	if err := validateProductionDarwinEnrollment(ctx, *state.Active); err != nil {
		return result, err
	}
	controller, err := NewProductionLaunchctlServiceController(installation.layout, state.Active.InstalledID, inspection)
	if err != nil {
		return result, err
	}
	alreadyOpen, err := installation.gate.Inspect()
	if err != nil {
		return result, err
	}
	if !alreadyOpen {
		if err := installation.gate.Open(); err != nil {
			return result, err
		}
	}
	if err := controller.Kickstart(); err != nil {
		return result, errors.Join(
			err,
			installation.gate.Close(),
			controller.Bootout(),
			errors.New("Darwin runtime activation failed closed"),
		)
	}
	return installation.resultFromKnownState(state, JournalOperationActivate, alreadyOpen, true)
}

func ensureProductionDarwinInstallation() (*productionDarwinInstallation, error) {
	if err := EnsureProductionStateDirectory(); err != nil {
		return nil, err
	}
	layout, err := EnsureProductionReleaseLayout()
	if err != nil {
		return nil, err
	}
	return &productionDarwinInstallation{
		layout: layout,
		store:  ProductionInstallerJournalStore(),
		gate:   ProductionRuntimeGate(),
	}, nil
}

func openProductionDarwinInstallation() (*productionDarwinInstallation, error) {
	layout, err := OpenReleaseLayout(ProductionMeshRoot)
	if err != nil {
		return nil, err
	}
	return &productionDarwinInstallation{
		layout: layout,
		store:  ProductionInstallerJournalStore(),
		gate:   ProductionRuntimeGate(),
	}, nil
}

func (installation *productionDarwinInstallation) Close() error {
	if installation == nil || installation.layout == nil {
		return nil
	}
	err := installation.layout.Close()
	installation.layout = nil
	return err
}

func (installation *productionDarwinInstallation) loadJournal() (journal InstallerJournal, found bool, returnErr error) {
	lock, err := installation.store.AcquireLock()
	if err != nil {
		return journal, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	return lock.Load()
}

func (installation *productionDarwinInstallation) requireNoJournal() error {
	if _, found, err := installation.loadJournal(); err != nil {
		return err
	} else if found {
		return errors.New("Darwin installation has an unfinished transaction; run recover first")
	}
	return installation.requireNoRuntimeUninstallResidue()
}

func (installation *productionDarwinInstallation) requireNoRuntimeUninstallResidue() error {
	state, found, err := installation.store.LoadInstallState()
	if err != nil || !found || state.Active == nil {
		return err
	}
	if _, err := installation.proveActive(*state.Active); err != nil {
		return errors.Join(err, errors.New("Darwin activation surface is incomplete; run uninstall-runtime to resume fail-closed deactivation"))
	}
	return nil
}

func (installation *productionDarwinInstallation) activateAccepted(intake VerifiedDarwinIntake) (result DarwinInstallResult, returnErr error) {
	if state, finalized, err := installation.finalizeAlreadyActiveIntake(intake); err != nil {
		return result, err
	} else if finalized {
		return installation.resultFromKnownState(state, JournalOperationActivate, true, false)
	}
	stage, authority, err := installation.store.StageAcceptedIntake(installation.layout, intake)
	if err != nil {
		return result, err
	}
	stageOpen := true
	defer func() {
		if stageOpen {
			returnErr = errors.Join(returnErr, stage.Close())
		}
	}()
	if err := verifyDarwinReleaseSignatures(stage.Path(), stage.inspection); err != nil {
		return result, fmt.Errorf("admit staged Darwin release code signatures: %w", err)
	}
	state, found, err := installation.store.LoadInstallState()
	if err != nil {
		return result, err
	}
	expectedPrior := ""
	if found && state.Active != nil {
		expectedPrior = state.Active.InstalledID
	}
	current, err := installation.layout.NewCurrentSwitch(expectedPrior, authority.InstalledID, stage.inspection)
	if err != nil {
		return result, err
	}
	restoreGate, err := installation.gate.Inspect()
	if err != nil {
		return result, err
	}
	if (!found || state.Active == nil) && restoreGate {
		return result, errors.New("first Darwin installation refuses a pre-existing open runtime gate")
	}
	journal, err := NewInstallerJournalFor(stage, current, authority, restoreGate)
	if err != nil {
		return result, err
	}
	controller, err := NewProductionLaunchctlServiceController(installation.layout, authority.InstalledID, stage.inspection)
	if err != nil {
		return result, err
	}
	activation, err := NewProductionLaunchdActivation(installation.gate, current, controller)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, activation.Close()) }()
	if err := installation.store.BeginAcceptedIntake(installation.layout, journal, activation, intake); err != nil {
		return result, err
	}
	if err := stage.Close(); err != nil {
		return result, err
	}
	stageOpen = false
	if err := installation.store.Resume(installation.layout, activation); err != nil {
		return result, err
	}
	return installation.resultFromState(JournalOperationActivate, false, false)
}

func (installation *productionDarwinInstallation) finalizeAlreadyActiveIntake(intake VerifiedDarwinIntake) (result DarwinInstallState, finalized bool, returnErr error) {
	lock, err := installation.store.AcquireLock()
	if err != nil {
		return result, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil || found {
		return result, false, errors.Join(err, errors.New("already-active Darwin intake cannot overlap an installer journal"))
	}
	record, found, err := lock.LoadIntakeRecord()
	if err != nil || !found {
		return result, false, errors.Join(err, errors.New("already-active Darwin intake record is absent"))
	}
	persisted, err := record.Intake()
	if err != nil || persisted != intake {
		return result, false, errors.Join(err, errors.New("already-active Darwin intake differs from its durable record"))
	}
	state, found, err := lock.LoadInstallState()
	if err != nil || !found || state.Active == nil {
		return result, false, err
	}
	if state.HighWater != *state.Active ||
		state.Active.ArtifactSHA256 != intake.Candidate.Artifact.SHA256 ||
		state.Active.ChannelManifestSHA256 != intake.Candidate.ChannelManifestSHA256 ||
		state.Active.ReleaseManifestSHA256 != intake.Candidate.ReleaseManifestSHA256 {
		return result, false, nil
	}
	inspection, err := installation.layout.InspectPublishedAuthority(*state.Active)
	if err != nil {
		return result, false, err
	}
	authority, err := intake.Complete(inspection)
	if err != nil || authority != *state.Active {
		return result, false, errors.Join(err, errors.New("already-active Darwin intake differs from the published active authority"))
	}
	if _, err := installation.proveActive(*state.Active); err != nil {
		return result, false, err
	}
	stageName, err := darwinAcceptedStageName(intake.Candidate)
	if err != nil {
		return result, false, err
	}
	installation.layout.mu.Lock()
	err = installation.layout.removeAcceptedStageLocked(stageName)
	installation.layout.mu.Unlock()
	if err != nil {
		return result, false, err
	}
	if err := lock.discardAcceptedArtifact(record.Candidate.Artifact); err != nil {
		return result, false, err
	}
	if err := lock.ClearIntakeRecord(record); err != nil {
		return result, false, err
	}
	return state, true, nil
}

func (installation *productionDarwinInstallation) resultFromState(operation InstallerJournalOperation, already, kickstartSucceeded bool) (DarwinInstallResult, error) {
	state, found, err := installation.store.LoadInstallState()
	if err != nil || !found {
		return DarwinInstallResult{}, errors.Join(err, errors.New("Darwin install result requires durable install state"))
	}
	return installation.resultFromKnownState(state, operation, already, kickstartSucceeded)
}

func (installation *productionDarwinInstallation) resultFromKnownState(state DarwinInstallState, operation InstallerJournalOperation, already, kickstartSucceeded bool) (DarwinInstallResult, error) {
	if err := state.Validate(); err != nil || state.Active == nil {
		return DarwinInstallResult{}, errors.Join(err, errors.New("Darwin install result requires an active release"))
	}
	if operation != JournalOperationActivate && operation != JournalOperationRollback {
		return DarwinInstallResult{}, errors.New("Darwin install result operation is unsupported")
	}
	if _, err := installation.proveActive(*state.Active); err != nil {
		return DarwinInstallResult{}, err
	}
	gateOpen, err := installation.gate.Inspect()
	if err != nil {
		return DarwinInstallResult{}, err
	}
	if kickstartSucceeded && !gateOpen {
		return DarwinInstallResult{}, errors.New("Darwin launchd kickstart success requires an open runtime gate")
	}
	return DarwinInstallResult{
		Operation:                 operation,
		Release:                   *state.Active,
		Previous:                  cloneAuthenticatedDarwinRelease(state.Previous),
		FirstInstall:              state.Previous == nil,
		AlreadyActive:             already,
		LaunchdPlistExact:         true,
		RuntimeGateOpen:           gateOpen,
		LaunchdKickstartSucceeded: kickstartSucceeded,
	}, nil
}

func (installation *productionDarwinInstallation) proveActive(authority AuthenticatedDarwinRelease) (inspection darwinbundle.CandidateInspection, returnErr error) {
	if err := installation.layout.RejectCurrentTransactionTemporaries(); err != nil {
		return inspection, err
	}
	inspection, err := installation.layout.InspectPublishedAuthority(authority)
	if err != nil {
		return inspection, fmt.Errorf("authenticate active Darwin release: %w", err)
	}
	if err := verifyDarwinReleaseSignatures(
		filepath.Join(installation.layout.releasesPath, authority.InstalledID),
		inspection,
	); err != nil {
		return inspection, fmt.Errorf("admit active Darwin release code signatures: %w", err)
	}
	current, err := installation.layout.NewCurrentSwitch("", authority.InstalledID, inspection)
	if err != nil {
		return inspection, err
	}
	if err := current.ProveSelected(); err != nil {
		return inspection, fmt.Errorf("prove active Darwin current selector: %w", err)
	}
	publisher, err := NewProductionLaunchdPlistPublisher(installation.layout, authority.InstalledID, inspection)
	if err != nil {
		return inspection, err
	}
	defer func() { returnErr = errors.Join(returnErr, publisher.Close()) }()
	if err := publisher.Inspect(); err != nil {
		return inspection, fmt.Errorf("authenticate active Darwin launchd plist: %w", err)
	}
	return inspection, nil
}
