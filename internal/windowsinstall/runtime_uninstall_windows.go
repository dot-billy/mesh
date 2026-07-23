//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

const WindowsRuntimeUninstallResultSchema = "mesh-windows-runtime-uninstall-result-v1"

type WindowsRuntimeUninstallResult struct {
	Schema                    string                      `json:"schema"`
	Operation                 string                      `json:"operation"`
	HighWaterRetained         AuthenticatedWindowsRelease `json:"high_water_retained"`
	RuntimeDeactivated        bool                        `json:"runtime_deactivated"`
	ServiceInstalled          bool                        `json:"service_installed"`
	ServiceRunning            bool                        `json:"service_running"`
	RuntimeGateOpen           bool                        `json:"runtime_gate_open"`
	CurrentSelected           bool                        `json:"current_selected"`
	ReleaseDataRemovalApplied bool                        `json:"release_data_removal_applied"`
	AgentStateRemovalApplied  bool                        `json:"agent_state_removal_applied"`
}

type productionWindowsRuntimeUninstallOperations struct {
	journal   WindowsRuntimeUninstallJournal
	root      *os.Root
	directory string
	layout    *ReleaseLayout
	gate      *RuntimeGate
	service   *NodeAgentServiceController
}

func (operations *productionWindowsRuntimeUninstallOperations) ValidateRuntimeUninstall(journal WindowsRuntimeUninstallJournal) error {
	if operations == nil || operations.root == nil || operations.layout == nil || operations.gate == nil || operations.service == nil {
		return errors.New("Windows runtime-uninstall operations are incomplete")
	}
	if !reflect.DeepEqual(operations.journal, journal) {
		return errors.New("Windows runtime-uninstall operations differ from durable journal authority")
	}
	if err := operations.layout.RejectCurrentTransactionTemporaries(); err != nil {
		return err
	}
	if err := operations.layout.InspectPublishedRelease(journal.Current); err != nil {
		return err
	}
	state, err := recoverWindowsInstallStateLocked(operations.root, operations.directory)
	if err != nil || state == nil {
		return errors.Join(err, errors.New("Windows runtime uninstall has no durable install-state authority"))
	}
	deactivated, err := journal.Source.DeactivateRuntime()
	if err != nil {
		return err
	}
	switch journal.Phase {
	case WindowsUninstallCurrentRemoved:
		if !reflect.DeepEqual(*state, journal.Source) && !reflect.DeepEqual(*state, deactivated) {
			return errors.New("Windows install state differs from uninstall source or response-loss result")
		}
	case WindowsUninstallStateDeactivated:
		if !reflect.DeepEqual(*state, deactivated) {
			return errors.New("Windows install state differs from finalized runtime deactivation")
		}
	default:
		if !reflect.DeepEqual(*state, journal.Source) {
			return errors.New("Windows install state changed before runtime deactivation authority")
		}
	}
	return nil
}

func (operations *productionWindowsRuntimeUninstallOperations) InspectRuntimeGate() (bool, error) {
	return operations.gate.Inspect()
}

func (operations *productionWindowsRuntimeUninstallOperations) CloseRuntimeGate() error {
	return operations.gate.Close()
}

func (operations *productionWindowsRuntimeUninstallOperations) InspectService() (bool, bool, error) {
	installed, err := operations.service.InspectInstalled()
	if err != nil || !installed {
		return installed, false, err
	}
	running, err := operations.service.InspectRunningAndProve()
	return true, running, err
}

func (operations *productionWindowsRuntimeUninstallOperations) StopService(ctx context.Context) error {
	return operations.service.StopAndProve(ctx)
}

func (operations *productionWindowsRuntimeUninstallOperations) DeleteService(ctx context.Context) error {
	return operations.service.DeleteStoppedAndProve(ctx)
}

func (operations *productionWindowsRuntimeUninstallOperations) InspectCurrent() (*CurrentDescriptor, error) {
	return operations.layout.InspectCurrentSelection()
}

func (operations *productionWindowsRuntimeUninstallOperations) RemoveCurrent(expected CurrentDescriptor) error {
	return operations.layout.RemoveCurrentSelection(expected)
}

func (operations *productionWindowsRuntimeUninstallOperations) InspectInstallState() (*WindowsInstallState, error) {
	return recoverWindowsInstallStateLocked(operations.root, operations.directory)
}

func (operations *productionWindowsRuntimeUninstallOperations) DeactivateInstallState(expected WindowsInstallState) error {
	current, err := recoverWindowsInstallStateLocked(operations.root, operations.directory)
	if err != nil || current == nil || !reflect.DeepEqual(*current, expected) {
		return errors.Join(err, errors.New("Windows install state changed before exact runtime deactivation"))
	}
	next, err := expected.DeactivateRuntime()
	if err != nil {
		return err
	}
	return commitWindowsInstallStateLocked(operations.root, operations.directory, current, next)
}

// UninstallProductionWindowsRuntime removes only the runtime activation
// surface: gate, service, current selector, and active/previous state. Signed
// release trees, trusted-root history, high-water authority, installer files,
// and agent enrollment state are deliberately retained.
func UninstallProductionWindowsRuntime(ctx context.Context) (result WindowsRuntimeUninstallResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("Windows runtime uninstall requires a context")
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

	journal, err := recoverWindowsRuntimeUninstallJournalLocked(root, installation.store.directory)
	if err != nil {
		return result, err
	}
	if err := rejectWindowsRuntimeUninstallOverlapLocked(root); err != nil {
		return result, err
	}
	state, err := recoverWindowsInstallStateLocked(root, installation.store.directory)
	if err != nil || state == nil {
		return result, errors.Join(err, errors.New("Windows runtime uninstall requires durable install-state authority"))
	}
	if journal == nil && state.Active == nil {
		return proveCompletedWindowsRuntimeUninstall(installation, *state)
	}
	if journal == nil {
		prepared, err := NewWindowsRuntimeUninstallJournal(*state)
		if err != nil {
			return result, err
		}
		if err := advanceWindowsRuntimeUninstallJournalLocked(root, installation.store.directory, nil, prepared); err != nil {
			return result, err
		}
		journal = &prepared
	}
	if journal.Source.Active == nil {
		return result, errors.New("Windows runtime-uninstall journal lost its active source")
	}
	contract, err := NewNodeAgentServiceContract(
		filepath.Join(installation.meshRoot, "releases", journal.Source.Active.InstalledID),
		installation.statePath,
	)
	if err != nil {
		return result, err
	}
	controller, err := NewNodeAgentServiceController(contract)
	if err != nil {
		return result, err
	}
	operations := &productionWindowsRuntimeUninstallOperations{
		journal: *journal, root: root, directory: installation.store.directory,
		layout: installation.layout, gate: installation.gate, service: controller,
	}
	writer := &lockedWindowsRuntimeUninstallJournalWriter{root: root, directory: installation.store.directory}
	completed, err := advanceWindowsRuntimeUninstall(ctx, writer, operations, *journal)
	if err != nil {
		return result, err
	}
	if err := finalizeWindowsRuntimeUninstallLocked(root, installation.store.directory, completed); err != nil {
		return result, err
	}
	finalState, err := recoverWindowsInstallStateLocked(root, installation.store.directory)
	if err != nil || finalState == nil {
		return result, errors.Join(err, errors.New("Windows runtime uninstall lost retained install-state authority"))
	}
	return proveCompletedWindowsRuntimeUninstall(installation, *finalState)
}

func finalizeWindowsRuntimeUninstallLocked(root *os.Root, directory string, expected WindowsRuntimeUninstallJournal) error {
	if err := expected.Validate(); err != nil || expected.Phase != WindowsUninstallStateDeactivated {
		return errors.Join(err, errors.New("only a state-deactivated Windows runtime-uninstall journal can be finalized"))
	}
	live, err := recoverWindowsRuntimeUninstallJournalLocked(root, directory)
	if err != nil || live == nil || !reflect.DeepEqual(*live, expected) {
		return errors.Join(err, errors.New("Windows runtime-uninstall final journal is absent or differs"))
	}
	state, err := recoverWindowsInstallStateLocked(root, directory)
	if err != nil || state == nil {
		return errors.Join(err, errors.New("Windows install state is absent during runtime-uninstall finalization"))
	}
	want, err := expected.Source.DeactivateRuntime()
	if err != nil || !reflect.DeepEqual(*state, want) {
		return errors.Join(err, errors.New("Windows retained install state differs from exact runtime deactivation"))
	}
	if err := root.Remove(windowsRuntimeUninstallJournalName); err != nil {
		return err
	}
	if err := proveWindowsRuntimeUninstallJournal(root, nil); err != nil {
		return err
	}
	return nil
}

func proveCompletedWindowsRuntimeUninstall(installation *productionWindowsInstallation, state WindowsInstallState) (WindowsRuntimeUninstallResult, error) {
	if installation == nil {
		return WindowsRuntimeUninstallResult{}, errors.New("Windows installation is required")
	}
	if err := state.Validate(); err != nil || state.Active != nil || state.Previous != nil {
		return WindowsRuntimeUninstallResult{}, errors.Join(err, errors.New("Windows runtime remains active in retained install state"))
	}
	gateOpen, err := installation.gate.Inspect()
	if err != nil || gateOpen {
		return WindowsRuntimeUninstallResult{}, errors.Join(err, errors.New("Windows runtime gate remained open after uninstall"))
	}
	serviceAbsent, err := inspectNodeAgentServiceAbsent()
	if err != nil || !serviceAbsent {
		return WindowsRuntimeUninstallResult{}, errors.Join(err, errors.New("Windows node-agent service remained after uninstall"))
	}
	current, err := installation.layout.InspectCurrentSelection()
	if err != nil || current != nil {
		return WindowsRuntimeUninstallResult{}, errors.Join(err, errors.New("Windows current selector remained after uninstall"))
	}
	if err := installation.layout.RejectCurrentTransactionTemporaries(); err != nil {
		return WindowsRuntimeUninstallResult{}, err
	}
	return WindowsRuntimeUninstallResult{
		Schema: WindowsRuntimeUninstallResultSchema, Operation: "uninstall-runtime", HighWaterRetained: state.HighWater,
		RuntimeDeactivated: true, ServiceInstalled: false, ServiceRunning: false, RuntimeGateOpen: false,
		CurrentSelected: false, ReleaseDataRemovalApplied: false, AgentStateRemovalApplied: false,
	}, nil
}
