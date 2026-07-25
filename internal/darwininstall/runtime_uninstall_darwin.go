//go:build darwin

package darwininstall

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const DarwinRuntimeUninstallResultSchema = "mesh-darwin-runtime-uninstall-result-v1"

// DarwinRuntimeUninstallResult states only reauthenticated postconditions. It
// deliberately does not infer process state from launchctl diagnostic output.
type DarwinRuntimeUninstallResult struct {
	Schema                    string                     `json:"schema"`
	Operation                 string                     `json:"operation"`
	HighWaterRetained         AuthenticatedDarwinRelease `json:"high_water_retained"`
	RuntimeDeactivated        bool                       `json:"runtime_deactivated"`
	LaunchdAbsenceProved      bool                       `json:"launchd_absence_proved"`
	LaunchdPlistInstalled     bool                       `json:"launchd_plist_installed"`
	RuntimeGateOpen           bool                       `json:"runtime_gate_open"`
	CurrentSelected           bool                       `json:"current_selected"`
	ReleaseDataRemovalApplied bool                       `json:"release_data_removal_applied"`
	AgentStateRemovalApplied  bool                       `json:"agent_state_removal_applied"`
}

type productionDarwinRuntimeUninstallOperations struct {
	source    DarwinInstallState
	state     DarwinInstallState
	layout    *ReleaseLayout
	lock      *InstallerJournalLock
	gate      *RuntimeGate
	service   LaunchdServiceController
	current   *CurrentSwitch
	publisher *LaunchdPlistPublisher
}

func (operations *productionDarwinRuntimeUninstallOperations) ValidateRuntimeUninstall(source DarwinInstallState) error {
	if operations == nil || operations.layout == nil || operations.lock == nil ||
		operations.gate == nil || operations.service == nil ||
		operations.current == nil || operations.publisher == nil {
		return errors.New("Darwin runtime-uninstall operations are incomplete")
	}
	if !sameDarwinInstallState(source, operations.source) {
		return errors.New("Darwin runtime-uninstall source differs from locked install authority")
	}
	if err := operations.layout.RejectCurrentTransactionTemporaries(); err != nil {
		return err
	}
	if _, err := operations.layout.InspectPublishedAuthority(*source.Active); err != nil {
		return fmt.Errorf("authenticate Darwin runtime-uninstall release: %w", err)
	}
	return nil
}

func (operations *productionDarwinRuntimeUninstallOperations) InspectRuntimeGate() (bool, error) {
	return operations.gate.Inspect()
}

func (operations *productionDarwinRuntimeUninstallOperations) CloseRuntimeGate() error {
	return operations.gate.Close()
}

func (operations *productionDarwinRuntimeUninstallOperations) BootoutService() error {
	return operations.service.Bootout()
}

func (operations *productionDarwinRuntimeUninstallOperations) RemoveLaunchdPlist() error {
	return operations.publisher.RemoveExact()
}

func (operations *productionDarwinRuntimeUninstallOperations) RemoveCurrentSelection() error {
	return operations.current.RemoveSelected()
}

func (operations *productionDarwinRuntimeUninstallOperations) InspectInstallState() (DarwinInstallState, error) {
	snapshot, err := operations.lock.readInstallState(darwinInstallStateName)
	if err != nil || !snapshot.found {
		return DarwinInstallState{}, errors.Join(err, errors.New("Darwin runtime uninstall lost install-state authority"))
	}
	operations.state = cloneDarwinInstallState(snapshot.state)
	return cloneDarwinInstallState(snapshot.state), nil
}

func (operations *productionDarwinRuntimeUninstallOperations) DeactivateInstallState(expected DarwinInstallState) error {
	current, err := operations.InspectInstallState()
	if err != nil || !sameDarwinInstallState(current, expected) {
		return errors.Join(err, errors.New("Darwin install state changed before exact runtime deactivation"))
	}
	next, err := expected.DeactivateRuntime()
	if err != nil {
		return err
	}
	if err := operations.lock.CommitInstallState(next); err != nil {
		return err
	}
	operations.state = next
	return nil
}

// UninstallProductionDarwinRuntime removes only the authenticated runtime
// activation surface: persistent gate, loaded launchd job, exact live plist,
// current selector, and active/previous selections. Immutable releases,
// trusted-root history, anti-rollback high water, installer files, and agent
// enrollment state are deliberately retained.
func UninstallProductionDarwinRuntime(ctx context.Context) (result DarwinRuntimeUninstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Darwin runtime uninstall requires a context")
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
		return result, errors.New("Darwin runtime uninstall cannot overlap an installer journal; run recover first")
	}
	if _, found, err := lock.LoadIntakeRecord(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("Darwin runtime uninstall cannot overlap accepted release intake")
	}
	state, found, err := lock.LoadInstallState()
	if err != nil || !found {
		return result, errors.Join(err, errors.New("Darwin runtime uninstall requires durable install-state authority"))
	}
	if state.Active == nil {
		return proveCompletedDarwinRuntimeUninstall(installation, state)
	}
	inspection, err := installation.layout.InspectPublishedAuthority(*state.Active)
	if err != nil {
		return result, err
	}
	current, err := installation.layout.NewCurrentSwitch("", state.Active.InstalledID, inspection)
	if err != nil {
		return result, err
	}
	publisher, err := NewProductionLaunchdPlistPublisher(installation.layout, state.Active.InstalledID, inspection)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, publisher.Close()) }()
	controller, err := NewProductionLaunchctlServiceController(installation.layout, state.Active.InstalledID, inspection)
	if err != nil {
		return result, err
	}
	operations := &productionDarwinRuntimeUninstallOperations{
		source: cloneDarwinInstallState(state), state: cloneDarwinInstallState(state),
		layout: installation.layout, lock: lock, gate: installation.gate,
		service: controller, current: current, publisher: publisher,
	}
	deactivated, err := deactivateDarwinRuntime(operations, state)
	if err != nil {
		return result, err
	}
	return proveCompletedDarwinRuntimeUninstall(installation, deactivated)
}

func proveCompletedDarwinRuntimeUninstall(installation *productionDarwinInstallation, state DarwinInstallState) (DarwinRuntimeUninstallResult, error) {
	if installation == nil || installation.layout == nil || installation.gate == nil {
		return DarwinRuntimeUninstallResult{}, errors.New("Darwin installation is required")
	}
	if err := state.Validate(); err != nil || state.Active != nil || state.Previous != nil {
		return DarwinRuntimeUninstallResult{}, errors.Join(err, errors.New("Darwin runtime remains active in retained install state"))
	}
	inspection, err := installation.layout.InspectPublishedAuthority(state.HighWater)
	if err != nil {
		return DarwinRuntimeUninstallResult{}, fmt.Errorf("authenticate retained Darwin high-water release: %w", err)
	}
	controller, err := NewProductionLaunchctlServiceController(installation.layout, state.HighWater.InstalledID, inspection)
	if err != nil {
		return DarwinRuntimeUninstallResult{}, err
	}
	if err := controller.Bootout(); err != nil {
		return DarwinRuntimeUninstallResult{}, fmt.Errorf("prove Darwin node-agent absence after uninstall: %w", err)
	}
	gateOpen, err := installation.gate.Inspect()
	if err != nil || gateOpen {
		return DarwinRuntimeUninstallResult{}, errors.Join(err, errors.New("Darwin runtime gate remained open after uninstall"))
	}
	if err := inspectDarwinLaunchdPlistAbsent(ProductionLaunchdDirectory); err != nil {
		return DarwinRuntimeUninstallResult{}, err
	}
	if err := installation.layout.RejectCurrentTransactionTemporaries(); err != nil {
		return DarwinRuntimeUninstallResult{}, err
	}
	installation.layout.mu.Lock()
	current, currentErr := installation.layout.readCurrentLocked()
	installation.layout.mu.Unlock()
	if currentErr != nil || current.Exists {
		return DarwinRuntimeUninstallResult{}, errors.Join(currentErr, errors.New("Darwin current selector remained after uninstall"))
	}
	return DarwinRuntimeUninstallResult{
		Schema: DarwinRuntimeUninstallResultSchema, Operation: "uninstall-runtime",
		HighWaterRetained: state.HighWater, RuntimeDeactivated: true,
		LaunchdAbsenceProved: true, LaunchdPlistInstalled: false,
		RuntimeGateOpen: false, CurrentSelected: false,
		ReleaseDataRemovalApplied: false, AgentStateRemovalApplied: false,
	}, nil
}

func inspectDarwinLaunchdPlistAbsent(directoryPath string) (returnErr error) {
	if !cleanDarwinInstallPath(directoryPath) {
		return errors.New("Darwin launchd directory must be canonical and absolute")
	}
	directory, fd, _, err := openDarwinManagedReleaseDirectory(directoryPath)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close()) }()
	for _, name := range []string{LaunchdPlistName, launchdPlistPendingName} {
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		return fmt.Errorf("Darwin launchd plist path %q remains after runtime uninstall", filepath.Join(directoryPath, name))
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}
