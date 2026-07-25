//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// ActivationOperations binds a durable journal identity to one current
// selector, runtime gate, and source/target SCM service contract. It contains
// no independent authority that could redirect recovery to another release.
type ActivationOperations struct {
	journal WindowsActivationJournal
	current *CurrentSwitch
	gate    *RuntimeGate
	source  *NodeAgentServiceController
	target  *NodeAgentServiceController
}

func NewActivationOperations(
	journal WindowsActivationJournal,
	current *CurrentSwitch,
	gate *RuntimeGate,
	source, target *NodeAgentServiceController,
) (*ActivationOperations, error) {
	if err := journal.Validate(); err != nil {
		return nil, err
	}
	if current == nil || current.layout == nil || gate == nil || target == nil {
		return nil, errors.New("Windows activation requires current, gate, and target service controllers")
	}
	current.mu.Lock()
	currentPrior := cloneCurrentDescriptor(current.expectedPrior)
	currentTarget := current.target
	currentTemporaryName := current.temporaryName
	current.mu.Unlock()
	if !descriptorEqual(currentPrior, journal.ExpectedPrior) || currentTarget != journal.Target || currentTemporaryName != journal.CurrentTemporaryName {
		return nil, errors.New("Windows activation journal differs from its current-switch authority")
	}
	targetReleaseRoot := filepath.Join(current.layout.releasesPath, journal.Target.InstalledID)
	if !serviceContractUsesRelease(target.contract, targetReleaseRoot) {
		return nil, errors.New("Windows target service contract is not bound to the journaled release")
	}
	if source != nil {
		if journal.ExpectedPrior == nil {
			return nil, errors.New("Windows source service controller requires an expected prior release")
		}
		sourceReleaseRoot := filepath.Join(current.layout.releasesPath, journal.ExpectedPrior.InstalledID)
		if !serviceContractUsesRelease(source.contract, sourceReleaseRoot) || !strings.EqualFold(source.contract.StatePath, target.contract.StatePath) {
			return nil, errors.New("Windows source service contract is not bound to the expected prior and target state")
		}
	} else if journal.SourceServiceInstalled {
		return nil, errors.New("Windows installed source service requires its exact controller")
	}
	return &ActivationOperations{journal: cloneWindowsActivationJournal(journal), current: current, gate: gate, source: source, target: target}, nil
}

func serviceContractUsesRelease(contract NodeAgentServiceContract, releaseRoot string) bool {
	want, err := NewNodeAgentServiceContract(releaseRoot, contract.StatePath)
	return err == nil && reflect.DeepEqual(contract, want)
}

func (operations *ActivationOperations) ValidateActivationJournal(journal WindowsActivationJournal) error {
	if operations == nil {
		return errors.New("Windows activation operations are required")
	}
	left := cloneWindowsActivationJournal(operations.journal)
	right := cloneWindowsActivationJournal(journal)
	left.Phase = ""
	right.Phase = ""
	if !reflect.DeepEqual(left, right) {
		return errors.New("Windows activation operations are bound to another journal identity")
	}
	return nil
}

func (operations *ActivationOperations) InspectRuntimeGate() (bool, error) {
	return operations.gate.Inspect()
}
func (operations *ActivationOperations) CloseRuntimeGate() error { return operations.gate.Close() }
func (operations *ActivationOperations) OpenRuntimeGate() error  { return operations.gate.Open() }

func (operations *ActivationOperations) QuiesceSourceService(ctx context.Context) error {
	controller, err := operations.installedController()
	if err != nil || controller == nil {
		return err
	}
	return controller.StopAndProve(ctx)
}

func (operations *ActivationOperations) SwitchCurrent() error {
	return operations.current.Execute()
}

func (operations *ActivationOperations) InstallTargetService(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	controller, err := operations.installedController()
	if err != nil {
		return err
	}
	if controller == operations.target {
		return nil
	}
	if controller != nil {
		if err := controller.StopAndProve(ctx); err != nil {
			return err
		}
		if err := controller.DeleteStopped(); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := operations.target.Install()
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) || time.Now().After(deadline) {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (operations *ActivationOperations) StartTargetService(ctx context.Context) error {
	installed, err := operations.target.InspectInstalled()
	if err != nil {
		return err
	}
	if !installed {
		return errors.New("Windows target service is absent before start")
	}
	_, err = operations.target.StartAndProve(ctx)
	return err
}

func (operations *ActivationOperations) StopTargetService(ctx context.Context) error {
	controller, err := operations.installedController()
	if err != nil || controller == nil {
		return err
	}
	return controller.StopAndProve(ctx)
}

func (operations *ActivationOperations) ProveTarget(ctx context.Context, wantRunning, wantGateOpen bool) error {
	if err := operations.current.ProveSelected(); err != nil {
		return err
	}
	gateOpen, err := operations.gate.Inspect()
	if err != nil {
		return err
	}
	if gateOpen != wantGateOpen {
		return fmt.Errorf("Windows runtime gate open state is %t, want %t", gateOpen, wantGateOpen)
	}
	installed, err := operations.target.InspectInstalled()
	if err != nil {
		return err
	}
	if !installed {
		return errors.New("Windows target service is absent during activation proof")
	}
	running, err := operations.target.InspectRunningAndProve()
	if err != nil {
		return err
	}
	if running != wantRunning {
		return fmt.Errorf("Windows target service running state is %t, want %t", running, wantRunning)
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return nil
}

func (operations *ActivationOperations) installedController() (*NodeAgentServiceController, error) {
	targetInstalled, targetErr := operations.target.InspectInstalled()
	if targetErr == nil && targetInstalled {
		return operations.target, nil
	}
	var sourceInstalled bool
	var sourceErr error
	if operations.source != nil {
		sourceInstalled, sourceErr = operations.source.InspectInstalled()
		if sourceErr == nil && sourceInstalled {
			return operations.source, nil
		}
	}
	if targetErr != nil || sourceErr != nil {
		return nil, errors.Join(targetErr, sourceErr, errors.New("installed Windows node-agent service matches neither journaled contract"))
	}
	return nil, nil
}

// ValidateSourceState re-proves the exact selector, service, and runtime-gate
// observations captured by a new journal. The transaction runner invokes it
// only before publishing the prepared phase, while holding the cross-process
// installer lock, so a caller cannot journal stale source state.
func (operations *ActivationOperations) ValidateSourceState() error {
	if operations == nil {
		return errors.New("Windows activation operations are required")
	}
	current, err := operations.current.InspectCurrent()
	if err != nil {
		return err
	}
	if !descriptorEqual(current, operations.journal.ExpectedPrior) {
		return errors.New("Windows current selector differs from the journaled source")
	}
	gateOpen, err := operations.gate.Inspect()
	if err != nil {
		return err
	}
	if gateOpen != operations.journal.SourceRuntimeGateOpen {
		return errors.New("Windows runtime gate changed before transaction journaling")
	}
	controller, err := operations.installedController()
	if err != nil {
		return err
	}
	installed := controller != nil
	if installed != operations.journal.SourceServiceInstalled {
		return errors.New("Windows node-agent service installation changed before transaction journaling")
	}
	running := false
	if controller != nil {
		running, err = controller.InspectRunningAndProve()
		if err != nil {
			return err
		}
	}
	if running != operations.journal.SourceServiceRunning {
		return errors.New("Windows node-agent service running state changed before transaction journaling")
	}
	return nil
}

// RunWindowsActivation creates the prepared journal if absent, or resumes the
// exact same transaction if a durable phase already exists. The terminal
// activated journal remains until a higher-level state/history commit proves
// it is safe to clear.
func RunWindowsActivation(ctx context.Context, store *ActivationJournalStore, operations *ActivationOperations) (result WindowsActivationJournal, returnErr error) {
	if operations == nil || operations.journal.Operation != WindowsOperationActivate {
		return result, errors.New("Windows activation runner requires an activation journal")
	}
	return runWindowsTransaction(ctx, store, operations)
}

// RunWindowsRollback uses the same fail-closed selector/service phases but
// accepts only a rollback journal derived from durable active/previous state.
func RunWindowsRollback(ctx context.Context, store *ActivationJournalStore, operations *ActivationOperations) (result WindowsActivationJournal, returnErr error) {
	if operations == nil || operations.journal.Operation != WindowsOperationRollback {
		return result, errors.New("Windows rollback runner requires a rollback journal")
	}
	return runWindowsTransaction(ctx, store, operations)
}

func runWindowsTransaction(ctx context.Context, store *ActivationJournalStore, operations *ActivationOperations) (result WindowsActivationJournal, returnErr error) {
	if store == nil || operations == nil {
		return WindowsActivationJournal{}, errors.New("Windows activation store and operations are required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	installerLock, err := store.acquireInstallerLock()
	if err != nil {
		return WindowsActivationJournal{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, installerLock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return WindowsActivationJournal{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, root.Close()) }()
	if err := rejectWindowsMutationDuringRuntimeUninstallLocked(root); err != nil {
		return WindowsActivationJournal{}, err
	}
	journal, err := recoverWindowsActivationJournalLocked(root, store.directory)
	if err != nil {
		return WindowsActivationJournal{}, err
	}
	allowConsumedIntake := journal != nil && journal.Phase == WindowsActivationActivated
	if err := validateAuthorizedWindowsTransactionLocked(root, store.directory, operations.journal, allowConsumedIntake); err != nil {
		return WindowsActivationJournal{}, err
	}
	if journal == nil {
		if err := operations.ValidateSourceState(); err != nil {
			return WindowsActivationJournal{}, err
		}
		prepared := cloneWindowsActivationJournal(operations.journal)
		prepared.Phase = WindowsActivationPrepared
		if err := advanceWindowsActivationJournalLocked(root, store.directory, nil, prepared); err != nil {
			return WindowsActivationJournal{}, err
		}
		journal = &prepared
	}
	if err := operations.ValidateActivationJournal(*journal); err != nil {
		return WindowsActivationJournal{}, err
	}
	writer := &lockedWindowsActivationJournalWriter{root: root, directory: store.directory}
	result, returnErr = advanceWindowsActivation(ctx, writer, operations, *journal)
	return result, returnErr
}
