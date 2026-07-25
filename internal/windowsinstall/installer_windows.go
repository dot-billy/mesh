//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"mesh/internal/onlinerelease"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

type WindowsInstallResult struct {
	Operation        WindowsActivationOperation   `json:"operation"`
	Release          AuthenticatedWindowsRelease  `json:"release"`
	Previous         *AuthenticatedWindowsRelease `json:"previous,omitempty"`
	FirstInstall     bool                         `json:"first_install"`
	AlreadyActive    bool                         `json:"already_active,omitempty"`
	ServiceInstalled bool                         `json:"service_installed"`
	ServiceRunning   bool                         `json:"service_running"`
	RuntimeGateOpen  bool                         `json:"runtime_gate_open"`
}

type productionWindowsInstallation struct {
	meshRoot  string
	statePath string
	layout    *ReleaseLayout
	store     *ActivationJournalStore
	gate      *RuntimeGate
}

// ApplyProductionWindowsOnline authenticates, captures, publishes, and
// installs the exact release selected by one canonical online bundle URL.
// First installation deliberately leaves the service stopped and runtime gate
// closed until enrollment has produced its private agent state.
func ApplyProductionWindowsOnline(ctx context.Context, bundleURL string) (result WindowsInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows online installation requires a context")
	}
	updateStart := time.Now().UTC()
	canonical, err := onlinerelease.CanonicalBundleURL(bundleURL)
	if err != nil || canonical != bundleURL {
		return result, errors.Join(err, errors.New("Windows online installation requires one exact canonical bundle URL"))
	}
	client := onlinerelease.NewClient()
	bundle, err := client.FetchBundle(ctx, canonical)
	if err != nil {
		return result, err
	}
	installation, err := ensureProductionWindowsInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	if err := installation.requireNoActivationJournal(); err != nil {
		return result, err
	}
	intake, err := installation.store.AuthenticateProductionWindowsCandidate(bundle, updateStart)
	if err != nil {
		return result, err
	}
	if _, err := installation.store.FetchProductionWindowsArtifact(ctx, intake); err != nil {
		return result, err
	}
	return installation.activateAccepted(ctx, intake)
}

// ApplyProductionWindowsSnapshot applies one exact LocalSystem-private
// three-file offline snapshot through the same accepted-intake transaction as
// online installation.
func ApplyProductionWindowsSnapshot(ctx context.Context, sourceDirectory string) (result WindowsInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows snapshot installation requires a context")
	}
	installation, err := ensureProductionWindowsInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	if err := installation.requireNoActivationJournal(); err != nil {
		return result, err
	}
	intake, _, err := installation.store.ImportProductionWindowsSnapshot(ctx, sourceDirectory, time.Now().UTC())
	if err != nil {
		return result, err
	}
	return installation.activateAccepted(ctx, intake)
}

// RecoverProductionWindowsInstallation resumes only durable accepted intake or
// the exact activation/rollback journal already present on disk.
func RecoverProductionWindowsInstallation(ctx context.Context) (result WindowsInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows installation recovery requires a context")
	}
	installation, err := openProductionWindowsInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	if uninstall, err := installation.store.LoadRuntimeUninstall(); err != nil {
		return result, err
	} else if uninstall != nil {
		return result, errors.New("Windows runtime uninstall is unfinished; run uninstall-runtime to resume it")
	}
	journal, err := installation.store.Load()
	if err != nil {
		return result, err
	}
	if journal != nil {
		return installation.resumeJournal(ctx, *journal)
	}
	intake, found, err := installation.store.LoadProductionWindowsIntake()
	if err != nil {
		return result, err
	}
	if found {
		return installation.activateAccepted(ctx, intake)
	}
	return result, errors.New("Windows installation has no unfinished transaction to recover")
}

// RollbackProductionWindowsInstallation switches only to the exact persisted
// previous release named by expectedInstalledID and retains authority high
// water. Retrying after response loss is an idempotent success.
func RollbackProductionWindowsInstallation(ctx context.Context, expectedInstalledID string) (result WindowsInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows rollback requires a context")
	}
	installation, err := openProductionWindowsInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	if uninstall, err := installation.store.LoadRuntimeUninstall(); err != nil {
		return result, err
	} else if uninstall != nil {
		return result, errors.New("Windows rollback cannot overlap runtime uninstall; run uninstall-runtime")
	}
	if journal, err := installation.store.Load(); err != nil {
		return result, err
	} else if journal != nil {
		return result, errors.New("Windows installation has an unfinished transaction; run recover first")
	}
	if _, found, err := installation.store.LoadProductionWindowsIntake(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Windows rollback cannot overlap an accepted release intake")
	}
	state, err := installation.store.LoadInstallState()
	if err != nil || state == nil || state.Active == nil {
		return result, errors.Join(err, errors.New("Windows rollback requires an active installation"))
	}
	if state.Active.InstalledID == expectedInstalledID {
		return installation.resultFromState(*state, WindowsOperationRollback, true)
	}
	if state.Previous == nil || state.Previous.InstalledID != expectedInstalledID {
		return result, errors.New("Windows rollback target must equal the exact persisted previous installed ID")
	}
	_, operations, err := installation.newRollbackOperations(*state)
	if err != nil {
		return result, err
	}
	completed, err := RunWindowsRollback(ctx, installation.store, operations)
	if err != nil {
		return result, err
	}
	finalized, err := installation.store.FinalizeWindowsRollback(completed)
	if err != nil {
		return result, err
	}
	return installation.resultFromState(finalized, WindowsOperationRollback, false)
}

// ActivateProductionWindowsRuntime opens the persistent runtime gate and
// starts the exact installed service after enrollment. It performs no release
// selection and is replay-safe if the process loses the success response.
func ActivateProductionWindowsRuntime(ctx context.Context) (result WindowsInstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows runtime activation requires a context")
	}
	installation, err := openProductionWindowsInstallation()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, installation.Close()) }()
	installation.store.mu.Lock()
	defer installation.store.mu.Unlock()
	lock, err := installation.store.acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := installation.store.openRoot()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, root.Close()) }()
	if err := rejectWindowsMutationDuringRuntimeUninstallLocked(root); err != nil {
		return result, err
	}
	journal, err := recoverWindowsActivationJournalLocked(root, installation.store.directory)
	if err != nil || journal != nil {
		return result, errors.Join(err, errors.New("Windows runtime activation cannot overlap an installation transaction"))
	}
	intake, err := installation.store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || intake != nil {
		return result, errors.Join(err, errors.New("Windows runtime activation cannot overlap accepted release intake"))
	}
	state, err := recoverWindowsInstallStateLocked(root, installation.store.directory)
	if err != nil || state == nil || state.Active == nil {
		return result, errors.Join(err, errors.New("Windows runtime activation requires an active release"))
	}
	controller, current, err := installation.controllerAndCurrent(*state.Active, nil)
	if err != nil {
		return result, err
	}
	if err := current.ProveSelected(); err != nil {
		return result, err
	}
	installed, err := controller.InspectInstalled()
	if err != nil || !installed {
		return result, errors.Join(err, errors.New("Windows runtime activation requires the exact installed service"))
	}
	running, err := controller.InspectRunningAndProve()
	if err != nil {
		return result, err
	}
	gateOpen, err := installation.gate.Inspect()
	if err != nil {
		return result, err
	}
	if running && !gateOpen {
		return result, errors.New("running Windows node-agent service has a closed runtime gate")
	}
	already := running && gateOpen
	if !already {
		if !gateOpen {
			if err := installation.gate.Open(); err != nil {
				return result, err
			}
		}
		if _, err := controller.StartAndProve(ctx); err != nil {
			return result, errors.Join(err, installation.gate.Close())
		}
	}
	return installation.resultFromState(*state, WindowsOperationActivate, already)
}

func ensureProductionWindowsInstallation() (*productionWindowsInstallation, error) {
	meshRoot, statePath, err := productionWindowsPaths()
	if err != nil {
		return nil, err
	}
	if err := EnsureProductionRuntimeGateDirectory(); err != nil {
		return nil, err
	}
	layout, err := EnsureReleaseLayout(meshRoot, windowssecurity.LocalSystemSID)
	if err != nil {
		return nil, err
	}
	return newProductionWindowsInstallation(meshRoot, statePath, layout)
}

func openProductionWindowsInstallation() (*productionWindowsInstallation, error) {
	meshRoot, statePath, err := productionWindowsPaths()
	if err != nil {
		return nil, err
	}
	layout, err := OpenReleaseLayout(meshRoot, windowssecurity.LocalSystemSID)
	if err != nil {
		return nil, err
	}
	return newProductionWindowsInstallation(meshRoot, statePath, layout)
}

func newProductionWindowsInstallation(meshRoot, statePath string, layout *ReleaseLayout) (*productionWindowsInstallation, error) {
	store, err := NewProductionActivationJournalStore()
	if err != nil {
		layout.Close()
		return nil, err
	}
	gate, err := NewProductionRuntimeGate()
	if err != nil {
		layout.Close()
		return nil, err
	}
	return &productionWindowsInstallation{meshRoot: meshRoot, statePath: statePath, layout: layout, store: store, gate: gate}, nil
}

func productionWindowsPaths() (meshRoot, statePath string, err error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", "", fmt.Errorf("resolve Windows ProgramData: %w", err)
	}
	meshRoot = filepath.Join(programData, "Mesh")
	statePath = filepath.Join(meshRoot, "agent", "state.json")
	if !cleanWindowsAbsolutePath(meshRoot) || !cleanWindowsAbsolutePath(statePath) {
		return "", "", errors.New("resolved Windows production paths are not canonical")
	}
	return meshRoot, statePath, nil
}

func (installation *productionWindowsInstallation) Close() error {
	if installation == nil || installation.layout == nil {
		return nil
	}
	err := installation.layout.Close()
	installation.layout = nil
	return err
}

func (installation *productionWindowsInstallation) requireNoActivationJournal() error {
	uninstall, err := installation.store.LoadRuntimeUninstall()
	if err != nil {
		return err
	}
	if uninstall != nil {
		return errors.New("Windows installation has an unfinished runtime uninstall; run uninstall-runtime")
	}
	journal, err := installation.store.Load()
	if err != nil {
		return err
	}
	if journal != nil {
		return errors.New("Windows installation has an unfinished transaction; run recover first")
	}
	return nil
}

func (installation *productionWindowsInstallation) activateAccepted(ctx context.Context, intake VerifiedWindowsIntake) (result WindowsInstallResult, returnErr error) {
	stage, authority, state, err := installation.store.PublishAcceptedWindowsIntake(installation.layout, intake)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, stage.Close()) }()
	if state.Active != nil && *state.Active == authority {
		finalized, err := installation.store.finalizeAlreadyActiveWindowsIntake(authority)
		if err != nil {
			return result, err
		}
		return installation.resultFromState(finalized, WindowsOperationActivate, true)
	}
	_, operations, err := installation.newActivationOperations(state, authority)
	if err != nil {
		return result, err
	}
	completed, err := RunWindowsActivation(ctx, installation.store, operations)
	if err != nil {
		return result, err
	}
	finalized, err := installation.store.FinalizeAcceptedWindowsActivation(completed)
	if err != nil {
		return result, err
	}
	return installation.resultFromState(finalized, WindowsOperationActivate, false)
}

func (installation *productionWindowsInstallation) newActivationOperations(state WindowsInstallState, target AuthenticatedWindowsRelease) (WindowsActivationJournal, *ActivationOperations, error) {
	if err := state.Validate(); err != nil || state.HighWater != target {
		return WindowsActivationJournal{}, nil, errors.Join(err, errors.New("Windows accepted activation target differs from install-state high water"))
	}
	current, source, targetController, installed, running, gateOpen, err := installation.observeSource(state.Active, target)
	if err != nil {
		return WindowsActivationJournal{}, nil, err
	}
	if state.Active == nil && (installed || running || gateOpen) {
		return WindowsActivationJournal{}, nil, errors.New("first Windows installation found pre-existing service or runtime-gate state")
	}
	journal, err := NewWindowsActivationJournal(state.Active, target, current.TemporaryName(), installed, running, gateOpen, running, gateOpen)
	if err != nil {
		return WindowsActivationJournal{}, nil, err
	}
	operations, err := NewActivationOperations(journal, current, installation.gate, source, targetController)
	return journal, operations, err
}

func (installation *productionWindowsInstallation) newRollbackOperations(state WindowsInstallState) (WindowsActivationJournal, *ActivationOperations, error) {
	if err := state.Validate(); err != nil || state.Active == nil || state.Previous == nil {
		return WindowsActivationJournal{}, nil, errors.Join(err, errors.New("Windows rollback requires active and previous releases"))
	}
	current, source, targetController, installed, running, gateOpen, err := installation.observeSource(state.Active, *state.Previous)
	if err != nil {
		return WindowsActivationJournal{}, nil, err
	}
	if !installed {
		return WindowsActivationJournal{}, nil, errors.New("Windows rollback source service is absent")
	}
	journal, err := NewWindowsRollbackJournal(state, current.TemporaryName(), installed, running, gateOpen, running, gateOpen)
	if err != nil {
		return WindowsActivationJournal{}, nil, err
	}
	operations, err := NewActivationOperations(journal, current, installation.gate, source, targetController)
	return journal, operations, err
}

func (installation *productionWindowsInstallation) observeSource(source *AuthenticatedWindowsRelease, target AuthenticatedWindowsRelease) (*CurrentSwitch, *NodeAgentServiceController, *NodeAgentServiceController, bool, bool, bool, error) {
	targetController, targetCurrent, err := installation.controllerAndCurrent(target, source)
	if err != nil {
		return nil, nil, nil, false, false, false, err
	}
	var sourceController *NodeAgentServiceController
	installed, running := false, false
	if source != nil {
		sourceController, _, err = installation.controllerAndCurrent(*source, nil)
		if err != nil {
			return nil, nil, nil, false, false, false, err
		}
		installed, err = sourceController.InspectInstalled()
		if err != nil || !installed {
			return nil, nil, nil, false, false, false, errors.Join(err, errors.New("Windows active source service is absent or differs from its authority"))
		}
		running, err = sourceController.InspectRunningAndProve()
		if err != nil {
			return nil, nil, nil, false, false, false, err
		}
	} else {
		installed, err = targetController.InspectInstalled()
		if err != nil {
			return nil, nil, nil, false, false, false, err
		}
	}
	gateOpen, err := installation.gate.Inspect()
	if err != nil {
		return nil, nil, nil, false, false, false, err
	}
	return targetCurrent, sourceController, targetController, installed, running, gateOpen, nil
}

func (installation *productionWindowsInstallation) controllerAndCurrent(target AuthenticatedWindowsRelease, source *AuthenticatedWindowsRelease) (*NodeAgentServiceController, *CurrentSwitch, error) {
	descriptor, err := target.CurrentDescriptor()
	if err != nil {
		return nil, nil, err
	}
	if source == nil {
		current, err := installation.layout.NewCurrentSwitch(nil, descriptor)
		if err != nil {
			return nil, nil, err
		}
		contract, err := NewNodeAgentServiceContract(filepath.Join(installation.meshRoot, "releases", target.InstalledID), installation.statePath)
		if err != nil {
			return nil, nil, err
		}
		controller, err := NewNodeAgentServiceController(contract)
		return controller, current, err
	}
	sourceDescriptor, err := source.CurrentDescriptor()
	if err != nil {
		return nil, nil, err
	}
	current, err := installation.layout.NewCurrentSwitch(&sourceDescriptor, descriptor)
	if err != nil {
		return nil, nil, err
	}
	contract, err := NewNodeAgentServiceContract(filepath.Join(installation.meshRoot, "releases", target.InstalledID), installation.statePath)
	if err != nil {
		return nil, nil, err
	}
	controller, err := NewNodeAgentServiceController(contract)
	return controller, current, err
}

func (installation *productionWindowsInstallation) resumeJournal(ctx context.Context, journal WindowsActivationJournal) (WindowsInstallResult, error) {
	current, err := installation.layout.ResumeCurrentSwitch(journal.ExpectedPrior, journal.Target, journal.CurrentTemporaryName)
	if err != nil {
		return WindowsInstallResult{}, err
	}
	targetContract, err := NewNodeAgentServiceContract(filepath.Join(installation.meshRoot, "releases", journal.Authority.InstalledID), installation.statePath)
	if err != nil {
		return WindowsInstallResult{}, err
	}
	target, err := NewNodeAgentServiceController(targetContract)
	if err != nil {
		return WindowsInstallResult{}, err
	}
	var source *NodeAgentServiceController
	if journal.SourceAuthority != nil {
		sourceContract, err := NewNodeAgentServiceContract(filepath.Join(installation.meshRoot, "releases", journal.SourceAuthority.InstalledID), installation.statePath)
		if err != nil {
			return WindowsInstallResult{}, err
		}
		source, err = NewNodeAgentServiceController(sourceContract)
		if err != nil {
			return WindowsInstallResult{}, err
		}
	}
	operations, err := NewActivationOperations(journal, current, installation.gate, source, target)
	if err != nil {
		return WindowsInstallResult{}, err
	}
	var completed WindowsActivationJournal
	switch journal.Operation {
	case WindowsOperationActivate:
		completed, err = RunWindowsActivation(ctx, installation.store, operations)
	case WindowsOperationRollback:
		completed, err = RunWindowsRollback(ctx, installation.store, operations)
	default:
		err = errors.New("Windows installation journal operation is unsupported")
	}
	if err != nil {
		return WindowsInstallResult{}, err
	}
	var state WindowsInstallState
	if journal.Operation == WindowsOperationActivate {
		state, err = installation.store.FinalizeAcceptedWindowsActivation(completed)
	} else {
		state, err = installation.store.FinalizeWindowsRollback(completed)
	}
	if err != nil {
		return WindowsInstallResult{}, err
	}
	return installation.resultFromState(state, journal.Operation, false)
}

func (installation *productionWindowsInstallation) resultFromState(state WindowsInstallState, operation WindowsActivationOperation, already bool) (WindowsInstallResult, error) {
	if err := state.Validate(); err != nil || state.Active == nil {
		return WindowsInstallResult{}, errors.Join(err, errors.New("Windows install result requires an active release"))
	}
	controller, current, err := installation.controllerAndCurrent(*state.Active, nil)
	if err != nil {
		return WindowsInstallResult{}, err
	}
	selected, err := current.InspectCurrent()
	want, descriptorErr := state.Active.CurrentDescriptor()
	if err != nil || descriptorErr != nil || selected == nil || *selected != want {
		return WindowsInstallResult{}, errors.Join(err, descriptorErr, errors.New("Windows current selector differs from finalized install state"))
	}
	if err := current.InspectTarget(want); err != nil {
		return WindowsInstallResult{}, err
	}
	installed, err := controller.InspectInstalled()
	if err != nil {
		return WindowsInstallResult{}, err
	}
	running := false
	if installed {
		running, err = controller.InspectRunningAndProve()
		if err != nil {
			return WindowsInstallResult{}, err
		}
	}
	gateOpen, err := installation.gate.Inspect()
	if err != nil {
		return WindowsInstallResult{}, err
	}
	if running && !gateOpen {
		return WindowsInstallResult{}, errors.New("Windows finalized service is running with a closed runtime gate")
	}
	return WindowsInstallResult{
		Operation: operation, Release: *state.Active, Previous: cloneAuthenticatedWindowsRelease(state.Previous),
		FirstInstall: state.Previous == nil, AlreadyActive: already,
		ServiceInstalled: installed, ServiceRunning: running, RuntimeGateOpen: gateOpen,
	}, nil
}

func (store *ActivationJournalStore) finalizeAlreadyActiveWindowsIntake(authority AuthenticatedWindowsRelease) (result WindowsInstallState, returnErr error) {
	if err := authority.Validate(); err != nil {
		return result, err
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
	journal, err := recoverWindowsActivationJournalLocked(root, store.directory)
	if err != nil || journal != nil {
		return result, errors.Join(err, errors.New("already-active Windows intake cannot overlap an activation journal"))
	}
	state, err := recoverWindowsInstallStateLocked(root, store.directory)
	if err != nil || state == nil || state.Active == nil || *state.Active != authority || state.HighWater != authority {
		return result, errors.Join(err, errors.New("already-active Windows intake differs from exact install state"))
	}
	record, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || record == nil {
		return result, errors.Join(err, errors.New("already-active Windows intake is absent"))
	}
	intake, err := record.Intake()
	if err != nil || !windowsIntakeMatchesAuthority(intake, authority) {
		return result, errors.Join(err, errors.New("already-active Windows intake differs from release authority"))
	}
	if err := discardWindowsArtifactCaptureLocked(root, intake.Candidate.Artifact); err != nil {
		return result, err
	}
	if err := root.Remove(windowsAcceptedIntakeName); err != nil {
		return result, err
	}
	remaining, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || remaining != nil {
		return result, errors.Join(err, errors.New("already-active Windows intake remained after finalization"))
	}
	return cloneWindowsInstallState(*state), nil
}
