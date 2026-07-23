//go:build linux

package linuxinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	systemctlPath         = "/usr/bin/systemctl"
	managedUnitDirectory  = "/usr/local/lib/systemd/system"
	managedReleaseRoot    = "/opt/mesh/releases"
	agentUnitName         = "mesh-agent.service"
	nebulaUnitName        = "mesh-nebula.service"
	legacyNebulaUnitName  = "nebula.service"
	maxSystemctlOutput    = 64 << 10
	systemctlTimeout      = 30 * time.Second
	minimumSystemdVersion = 249
	// The packaged lifecycle agent permits one signed-state cycle to take two
	// minutes. Leave another minute for systemd to start Nebula and for exact
	// process/provenance polling; a healthy supported cycle must not be rolled
	// back merely because the installer used a shorter readiness budget.
	serviceRestoreTimeout = 3 * time.Minute
	serviceRestorePoll    = 200 * time.Millisecond
)

var systemdProperties = []string{
	"LoadState", "FragmentPath", "DropInPaths", "TimeoutStopFailureMode", "UnitFileState",
	"ActiveState", "SubState", "MainPID", "ControlGroup",
	"WantedBy", "RequiredBy", "RequisiteOf", "UpheldBy", "BoundBy",
	"TriggeredBy", "OnFailureOf", "OnSuccessOf", "ConsistsOf", "ConflictedBy", "PropagatesReloadTo", "PropagatesStopTo",
}

var errUnexpectedManagedNebula = errors.New("managed Nebula is active when the persisted runtime snapshot requires it stopped")

var errManagedRuntimeActiveWithClosedGate = errors.New("managed runtime is active while the fixed runtime gate is closed")

var errManagedNebulaChildGateMismatch = errors.New("managed Nebula runtime does not match the agent readiness marker")

// ServiceSnapshot is persisted in the transaction journal before the fixed
// runtime gate or either managed process is changed. Unit-file topology is
// observed and preserved; the transaction never enables or disables a unit.
type ServiceSnapshot struct {
	AgentWasEnabled    bool
	AgentWasActive     bool
	NebulaWasActive    bool
	RuntimeGateWasOpen bool
}

type systemdCommandRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type managedProcessVerifier interface {
	Verify(pid uint64, expectedBinary string, expectedArgv []string, expectedControlGroup string) error
	ProveReleaseStopped(releasePath string, controlGroups []string) error
}

type systemdManager struct {
	runner         systemdCommandRunner
	processes      managedProcessVerifier
	runtimeGate    managedRuntimeGate
	childGate      childRuntimeGateInspector
	unitDirectory  string
	releaseRoot    string
	restoreTimeout time.Duration
	restorePoll    time.Duration
}

func productionSystemdManager() *systemdManager {
	return &systemdManager{
		runner:         execSystemdRunner{},
		processes:      procProcessVerifier{},
		runtimeGate:    productionRuntimeGate(),
		childGate:      productionChildRuntimeGate(),
		unitDirectory:  managedUnitDirectory,
		releaseRoot:    managedReleaseRoot,
		restoreTimeout: serviceRestoreTimeout,
		restorePoll:    serviceRestorePoll,
	}
}

// preflight proves either a completely absent first-install surface or the
// exact managed units and processes belonging to active. It never changes
// systemd state.
func (manager *systemdManager) preflight(ctx context.Context, active *ReleaseIdentity) (ServiceSnapshot, error) {
	if err := manager.validate(); err != nil {
		return ServiceSnapshot{}, err
	}
	if err := manager.requireSystemdVersion(ctx); err != nil {
		return ServiceSnapshot{}, err
	}
	if err := manager.rejectLegacyUnit(ctx); err != nil {
		return ServiceSnapshot{}, err
	}
	if active == nil {
		gateOpen, err := manager.runtimeGate.Inspect()
		if err != nil {
			return ServiceSnapshot{}, err
		}
		if gateOpen {
			return ServiceSnapshot{}, errors.New("runtime gate must be absent before first installation")
		}
		childGateOpen, err := manager.childGate.Inspect()
		if err != nil {
			return ServiceSnapshot{}, fmt.Errorf("inspect agent runtime readiness before first installation: %w", err)
		}
		if childGateOpen {
			return ServiceSnapshot{}, errors.New("agent runtime readiness marker must be absent before first installation")
		}
		if err := manager.childGate.ProveRuntimeDirectoryAbsent(); err != nil {
			return ServiceSnapshot{}, fmt.Errorf("prove agent RuntimeDirectory absent before first installation: %w", err)
		}
		for _, name := range []string{agentUnitName, nebulaUnitName} {
			unit, err := manager.inspect(ctx, name)
			if err != nil {
				return ServiceSnapshot{}, err
			}
			if err := requireAbsentUnit(name, unit); err != nil {
				return ServiceSnapshot{}, err
			}
		}
		return ServiceSnapshot{}, nil
	}
	if err := active.Validate(); err != nil {
		return ServiceSnapshot{}, fmt.Errorf("active release identity: %w", err)
	}
	agent, nebula, err := manager.inspectManaged(ctx, *active)
	if err != nil {
		return ServiceSnapshot{}, err
	}
	agentEnabled, err := managedAgentBootEnabled(agent)
	if err != nil {
		return ServiceSnapshot{}, err
	}
	gateOpen, err := manager.runtimeGate.Inspect()
	if err != nil {
		return ServiceSnapshot{}, err
	}
	if nebula.UnitFileState != "static" {
		return ServiceSnapshot{}, fmt.Errorf("%s must remain static, got %q", nebulaUnitName, nebula.UnitFileState)
	}
	if err := requireNoReverseBootDependencies(nebulaUnitName, nebula); err != nil {
		return ServiceSnapshot{}, err
	}
	agentActive, err := stableRuntime(agentUnitName, agent)
	if err != nil {
		return ServiceSnapshot{}, err
	}
	nebulaActive, err := stableRuntime(nebulaUnitName, nebula)
	if err != nil {
		return ServiceSnapshot{}, err
	}
	if nebulaActive && !agentActive {
		return ServiceSnapshot{}, errors.New("managed Nebula is active without its lifecycle agent")
	}
	if (agentActive || nebulaActive) && !gateOpen {
		return ServiceSnapshot{}, errManagedRuntimeActiveWithClosedGate
	}
	childGateOpen, err := manager.childGate.Inspect()
	if err != nil {
		return ServiceSnapshot{}, fmt.Errorf("inspect agent runtime readiness marker: %w", err)
	}
	if childGateOpen != nebulaActive {
		return ServiceSnapshot{}, fmt.Errorf("%w (marker_open=%t nebula_active=%t)", errManagedNebulaChildGateMismatch, childGateOpen, nebulaActive)
	}
	if agentActive {
		if err := manager.verifyManagedProcess(ctx, agentUnitName, agent, *active); err != nil {
			return ServiceSnapshot{}, err
		}
	}
	if nebulaActive {
		if err := manager.verifyManagedProcess(ctx, nebulaUnitName, nebula, *active); err != nil {
			return ServiceSnapshot{}, err
		}
	}
	return ServiceSnapshot{
		AgentWasEnabled: agentEnabled, AgentWasActive: agentActive,
		NebulaWasActive: nebulaActive, RuntimeGateWasOpen: gateOpen,
	}, nil
}

// quiesce durably closes the fixed runtime condition before stopping both
// managed services, then proves that neither unit has a main process. expected
// must be the exact state captured before the prepared journal was fsynced.
func (manager *systemdManager) quiesce(ctx context.Context, active *ReleaseIdentity, expected ServiceSnapshot) error {
	current, err := manager.preflight(ctx, active)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("managed service state changed after transaction preparation")
	}
	if active == nil {
		return nil
	}
	if err := manager.runtimeGate.Close(); err != nil {
		return fmt.Errorf("close fixed runtime gate: %w", err)
	}
	if _, err := manager.run(ctx, "stop", "--", agentUnitName, nebulaUnitName); err != nil {
		return fmt.Errorf("stop managed services: %w", err)
	}
	return manager.proveStopped(ctx, *active)
}

// forceQuiesce is used only after a rollback intent has been fsynced. It is
// tolerant of a partially restored gate/runtime state, but still requires
// exact unit provenance before changing anything. Unit-file state is never
// changed.
func (manager *systemdManager) forceQuiesce(ctx context.Context, active ReleaseIdentity) error {
	if err := manager.requireSystemdVersion(ctx); err != nil {
		return err
	}
	if err := active.Validate(); err != nil {
		return err
	}
	if err := manager.rejectLegacyUnit(ctx); err != nil {
		return err
	}
	agent, nebula, err := manager.inspectManaged(ctx, active)
	if err != nil {
		return err
	}
	if _, err := managedAgentBootEnabled(agent); err != nil {
		return err
	}
	if nebula.UnitFileState != "static" {
		return fmt.Errorf("%s must remain static, got %q", nebulaUnitName, nebula.UnitFileState)
	}
	if err := requireNoReverseBootDependencies(nebulaUnitName, nebula); err != nil {
		return err
	}
	if err := manager.runtimeGate.Close(); err != nil {
		return fmt.Errorf("close fixed runtime gate for rollback: %w", err)
	}
	if _, err := manager.run(ctx, "stop", "--", agentUnitName, nebulaUnitName); err != nil {
		return fmt.Errorf("stop managed services for rollback: %w", err)
	}
	return manager.proveStopped(ctx, active)
}

// reloadAndQuiesce reconciles the crash window where current was durably
// switched but systemd may still have the source unit definition cached. The
// target definitions are loaded first, then the fixed runtime gate and processes are
// forced back to a proven stopped state before recovery continues.
func (manager *systemdManager) reloadAndQuiesce(ctx context.Context, target ReleaseIdentity) error {
	if err := manager.requireSystemdVersion(ctx); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if _, err := manager.run(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("reload switched systemd units before quarantine: %w", err)
	}
	return manager.forceQuiesce(ctx, target)
}

// reloadAndRestore reloads only after current points at target. It validates
// exact fragments and the absence of drop-ins before restoring the fixed
// runtime gate, then starts only the lifecycle agent when it was active before
// the update. Existing unit-file state is observed and preserved exactly.
func (manager *systemdManager) reloadAndRestore(ctx context.Context, target ReleaseIdentity, desired ServiceSnapshot) error {
	if desired.NebulaWasActive && !desired.AgentWasActive {
		return errors.New("cannot restore active Nebula without an active lifecycle agent")
	}
	if (desired.AgentWasActive || desired.NebulaWasActive) && !desired.RuntimeGateWasOpen {
		return errors.New("cannot restore an active runtime with the fixed runtime gate closed")
	}
	if err := manager.requireSystemdVersion(ctx); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if err := manager.rejectLegacyUnit(ctx); err != nil {
		return err
	}
	if _, err := manager.run(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd units: %w", err)
	}
	agent, nebula, err := manager.inspectManaged(ctx, target)
	if err != nil {
		return err
	}
	agentEnabled, err := managedAgentBootEnabled(agent)
	if err != nil {
		return err
	}
	if agentEnabled != desired.AgentWasEnabled {
		return fmt.Errorf("agent unit-file state changed during transaction (enabled=%t, want %t)", agentEnabled, desired.AgentWasEnabled)
	}
	if nebula.UnitFileState != "static" {
		return fmt.Errorf("%s must remain static, got %q", nebulaUnitName, nebula.UnitFileState)
	}
	if err := requireNoReverseBootDependencies(nebulaUnitName, nebula); err != nil {
		return err
	}
	if _, err := stableRuntime(agentUnitName, agent); err != nil {
		return err
	}
	if _, err := stableRuntime(nebulaUnitName, nebula); err != nil {
		return err
	}
	if desired.RuntimeGateWasOpen {
		if err := manager.runtimeGate.Open(); err != nil {
			return fmt.Errorf("restore fixed runtime gate: %w", err)
		}
	} else if err := manager.runtimeGate.Close(); err != nil {
		return fmt.Errorf("keep fixed runtime gate closed: %w", err)
	}
	if desired.AgentWasActive {
		if _, err := manager.run(ctx, "start", "--", agentUnitName); err != nil {
			return fmt.Errorf("restart lifecycle agent: %w", err)
		}
	}
	err = manager.proveRestored(ctx, target, desired)
	if errors.Is(err, errUnexpectedManagedNebula) {
		cleanupContext, cancelCleanup := newInstallerCleanupContext(ctx)
		defer cancelCleanup()
		if stopErr := manager.forceQuiesce(cleanupContext, target); stopErr != nil {
			return errors.Join(err, fmt.Errorf("stop unexpected managed Nebula: %w", stopErr))
		}
		return fmt.Errorf("unexpected managed Nebula was stopped: %w", err)
	}
	return err
}

// reloadAndAssertAbsent completes first-install rollback after managed links
// and current have been safely removed by the filesystem transaction.
func (manager *systemdManager) reloadAndAssertAbsent(ctx context.Context) error {
	if err := manager.requireSystemdVersion(ctx); err != nil {
		return err
	}
	if _, err := manager.run(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd after first-install rollback: %w", err)
	}
	if err := manager.rejectLegacyUnit(ctx); err != nil {
		return err
	}
	for _, name := range []string{agentUnitName, nebulaUnitName} {
		unit, err := manager.inspect(ctx, name)
		if err != nil {
			return err
		}
		if err := requireAbsentUnit(name, unit); err != nil {
			return err
		}
	}
	gateOpen, err := manager.runtimeGate.Inspect()
	if err != nil {
		return err
	}
	if gateOpen {
		return errors.New("runtime gate remains open after first-install rollback")
	}
	childGateOpen, err := manager.childGate.Inspect()
	if err != nil {
		return fmt.Errorf("inspect agent runtime readiness after first-install rollback: %w", err)
	}
	if childGateOpen {
		return errors.New("agent runtime readiness marker remains open after first-install rollback")
	}
	if err := manager.childGate.ProveRuntimeDirectoryAbsent(); err != nil {
		return fmt.Errorf("prove agent RuntimeDirectory absent after first-install rollback: %w", err)
	}
	return nil
}

// activateEnrolled is the narrow post-enrollment transition intended for a
// future mesh-install activate command while that command holds the installer
// state lock and has audited target as the durable active release. Unlike an
// update transaction, this one-time transition deliberately establishes the
// canonical agent enablement. Any synchronous failure is quarantined by
// closing the gate before stopping both units and disabling the agent again.
func (manager *systemdManager) activateEnrolled(ctx context.Context, target ReleaseIdentity) (bool, error) {
	if ctx == nil {
		return false, errors.New("enrolled runtime activation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	before, err := manager.preflight(ctx, &target)
	want := ServiceSnapshot{
		AgentWasEnabled: true, AgentWasActive: true,
		NebulaWasActive: true, RuntimeGateWasOpen: true,
	}
	if err == nil && before == want {
		return true, nil
	}
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, errors.Join(err, ctx.Err())
		}
		if !errors.Is(err, errRuntimeGatePublicationPending) && !errors.Is(err, errManagedRuntimeActiveWithClosedGate) &&
			!errors.Is(err, errChildRuntimeGatePublicationPending) && !errors.Is(err, errManagedNebulaChildGateMismatch) {
			return false, err
		}
		// Strict preflight intentionally rejects both an interrupted gate temp
		// and an active process behind a gate already closed by a crashed
		// activation. Reconcile only after forceQuiesce has independently
		// validated exact managed-unit provenance; then require strict
		// preflight again before enabling anything.
		reconcileContext, cancelReconcile := newInstallerCleanupContext(ctx)
		reconcileErr := manager.forceQuiesce(reconcileContext, target)
		if reconcileErr == nil {
			before, reconcileErr = manager.preflight(reconcileContext, &target)
		}
		cancelReconcile()
		if reconcileErr != nil {
			return false, errors.Join(
				fmt.Errorf("strict enrolled-runtime preflight: %w", err),
				fmt.Errorf("reconcile interrupted enrolled runtime: %w", reconcileErr),
			)
		}
		// Reconciliation deliberately uses a detached cleanup context so it can
		// finish closing the gate and proving both processes stopped after an
		// interrupt. Do not reopen that gate when the caller was canceled while
		// the detached proof was running; return the proven quiesced state.
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}

	if err := manager.runtimeGate.Open(); err != nil {
		return false, manager.quarantineFailedActivation(ctx, target, fmt.Errorf("open enrolled runtime gate: %w", err))
	}
	if !before.AgentWasEnabled {
		if _, err := manager.run(ctx, "enable", "--", agentUnitName); err != nil {
			return false, manager.quarantineFailedActivation(ctx, target, fmt.Errorf("enable enrolled lifecycle agent: %w", err))
		}
	}
	agent, nebula, err := manager.inspectManaged(ctx, target)
	if err != nil {
		return false, manager.quarantineFailedActivation(ctx, target, err)
	}
	enabled, err := managedAgentBootEnabled(agent)
	if err != nil || !enabled {
		return false, manager.quarantineFailedActivation(ctx, target, errors.Join(errors.New("agent canonical enablement was not proven"), err))
	}
	if nebula.UnitFileState != "static" {
		return false, manager.quarantineFailedActivation(ctx, target, fmt.Errorf("%s must remain static, got %q", nebulaUnitName, nebula.UnitFileState))
	}
	if err := requireNoReverseBootDependencies(nebulaUnitName, nebula); err != nil {
		return false, manager.quarantineFailedActivation(ctx, target, err)
	}
	if _, err := manager.run(ctx, "start", "--", agentUnitName); err != nil {
		return false, manager.quarantineFailedActivation(ctx, target, fmt.Errorf("start enrolled lifecycle agent: %w", err))
	}
	if err := manager.proveRestored(ctx, target, want); err != nil {
		return false, manager.quarantineFailedActivation(ctx, target, fmt.Errorf("prove enrolled managed runtime: %w", err))
	}
	return false, nil
}

func (manager *systemdManager) quarantineFailedActivation(ctx context.Context, target ReleaseIdentity, activationErr error) error {
	cleanupContext, cancelCleanup := newInstallerCleanupContext(ctx)
	defer cancelCleanup()
	var cleanupFailures []error
	if err := manager.runtimeGate.Close(); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("close runtime gate after activation failure: %w", err))
	}
	if _, err := manager.run(cleanupContext, "stop", "--", agentUnitName, nebulaUnitName); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("stop managed runtime after activation failure: %w", err))
	}
	if _, err := manager.run(cleanupContext, "disable", "--", agentUnitName); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("disable lifecycle agent after activation failure: %w", err))
	}
	if err := manager.proveStopped(cleanupContext, target); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("prove failed activation cleanup: %w", err))
	}
	agent, nebula, err := manager.inspectManaged(cleanupContext, target)
	if err != nil {
		cleanupFailures = append(cleanupFailures, err)
	} else {
		enabled, enabledErr := managedAgentBootEnabled(agent)
		if enabledErr != nil || enabled {
			cleanupFailures = append(cleanupFailures, errors.Join(errors.New("failed activation did not return the agent to disabled canonical state"), enabledErr))
		}
		if nebula.UnitFileState != "static" {
			cleanupFailures = append(cleanupFailures, fmt.Errorf("failed activation changed %s unit-file state to %q", nebulaUnitName, nebula.UnitFileState))
		}
	}
	if len(cleanupFailures) != 0 {
		return errors.Join(
			fmt.Errorf("enrolled runtime activation failed: %w", activationErr),
			fmt.Errorf("activation quarantine could not be proven: %w", errors.Join(cleanupFailures...)),
		)
	}
	return fmt.Errorf("enrolled runtime activation failed and was quarantined: %w", activationErr)
}

func (manager *systemdManager) proveStopped(ctx context.Context, active ReleaseIdentity) error {
	gateOpen, err := manager.runtimeGate.Inspect()
	if err != nil {
		return err
	}
	if gateOpen {
		return errors.New("fixed runtime gate remains open while proving services stopped")
	}
	childGateOpen, err := manager.childGate.Inspect()
	if err != nil {
		return fmt.Errorf("inspect agent runtime readiness while proving services stopped: %w", err)
	}
	if childGateOpen {
		return errors.New("agent runtime readiness marker remains open while proving services stopped")
	}
	if err := manager.childGate.ProveRuntimeDirectoryAbsent(); err != nil {
		return fmt.Errorf("prove agent RuntimeDirectory absent while proving services stopped: %w", err)
	}
	controlGroups := make([]string, 0, 2)
	for _, name := range []string{agentUnitName, nebulaUnitName} {
		unit, err := manager.inspect(ctx, name)
		if err != nil {
			return err
		}
		if err := manager.validateInstalledUnit(name, unit); err != nil {
			return err
		}
		if !stoppedRuntime(unit) {
			return fmt.Errorf("%s did not reach a proven stopped state (ActiveState=%q SubState=%q MainPID=%d)", name, unit.ActiveState, unit.SubState, unit.MainPID)
		}
		controlGroups = append(controlGroups, unit.ControlGroup)
	}
	return manager.processes.ProveReleaseStopped(filepath.Join(manager.releaseRoot, active.InstalledID), controlGroups)
}

func (manager *systemdManager) proveRestored(ctx context.Context, target ReleaseIdentity, desired ServiceSnapshot) error {
	deadline := time.NewTimer(manager.restoreTimeout)
	defer deadline.Stop()
	poll := time.NewTicker(manager.restorePoll)
	defer poll.Stop()
	for {
		ready, err := manager.proveRestoredOnce(ctx, target, desired)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("managed Nebula did not become ready within %s", manager.restoreTimeout)
		case <-poll.C:
		}
	}
}

func (manager *systemdManager) proveRestoredOnce(ctx context.Context, target ReleaseIdentity, desired ServiceSnapshot) (bool, error) {
	agent, nebula, err := manager.inspectManaged(ctx, target)
	if err != nil {
		return false, err
	}
	agentEnabled, err := managedAgentBootEnabled(agent)
	if err != nil {
		return false, err
	}
	if agentEnabled != desired.AgentWasEnabled {
		return false, fmt.Errorf("agent enabled state is %t, want %t", agentEnabled, desired.AgentWasEnabled)
	}
	gateOpen, err := manager.runtimeGate.Inspect()
	if err != nil {
		return false, err
	}
	if gateOpen != desired.RuntimeGateWasOpen {
		return false, fmt.Errorf("runtime gate open state is %t, want %t", gateOpen, desired.RuntimeGateWasOpen)
	}
	if err := requireNoReverseBootDependencies(nebulaUnitName, nebula); err != nil {
		return false, err
	}
	nebulaActive, err := stableRuntime(nebulaUnitName, nebula)
	if err != nil {
		if !desired.NebulaWasActive && !stoppedRuntime(nebula) {
			return false, fmt.Errorf("%w (ActiveState=%q SubState=%q MainPID=%d)", errUnexpectedManagedNebula, nebula.ActiveState, nebula.SubState, nebula.MainPID)
		}
		if desired.NebulaWasActive && (nebula.ActiveState == "activating" || nebula.ActiveState == "deactivating") {
			return false, nil
		}
		return false, err
	}
	if !desired.NebulaWasActive && nebulaActive {
		return false, errUnexpectedManagedNebula
	}
	childGateOpen, err := manager.childGate.Inspect()
	if errors.Is(err, errChildRuntimeGatePublicationPending) {
		// The agent publishes with a durable recovery link immediately before
		// restart. A polling proof may observe that bounded intermediate state.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect restored agent runtime readiness: %w", err)
	}
	if !desired.NebulaWasActive && childGateOpen {
		return false, fmt.Errorf("%w: agent readiness is open", errUnexpectedManagedNebula)
	}
	if nebulaActive && !childGateOpen {
		return false, fmt.Errorf("%w (marker_open=false nebula_active=true)", errManagedNebulaChildGateMismatch)
	}
	agentActive, err := stableRuntime(agentUnitName, agent)
	if err != nil {
		return false, err
	}
	if agentActive != desired.AgentWasActive {
		return false, fmt.Errorf("agent active state is %t, want %t", agentActive, desired.AgentWasActive)
	}
	if agentActive {
		if err := manager.verifyManagedProcess(ctx, agentUnitName, agent, target); err != nil {
			return false, err
		}
	}
	if desired.NebulaWasActive && !nebulaActive {
		if nebula.ActiveState == "failed" {
			return false, errors.New("managed Nebula failed while restoring the previously active overlay")
		}
		return false, nil
	}
	if nebulaActive {
		if !agentActive {
			return false, errors.New("managed Nebula restarted without an active lifecycle agent")
		}
		if err := manager.verifyManagedProcess(ctx, nebulaUnitName, nebula, target); err != nil {
			return false, err
		}
	}
	gateOpenAfter, err := manager.runtimeGate.Inspect()
	if err != nil {
		return false, err
	}
	if gateOpenAfter != gateOpen {
		return false, errors.New("runtime gate changed during restored-runtime proof")
	}
	childGateOpenAfter, err := manager.childGate.Inspect()
	if errors.Is(err, errChildRuntimeGatePublicationPending) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if childGateOpenAfter != childGateOpen {
		return false, errors.New("agent runtime readiness marker changed during restored-runtime proof")
	}
	return true, nil
}

type systemdUnitState struct {
	LoadState              string
	FragmentPath           string
	DropInPaths            string
	TimeoutStopFailureMode string
	UnitFileState          string
	ActiveState            string
	SubState               string
	MainPID                uint64
	ControlGroup           string
	WantedBy               string
	RequiredBy             string
	RequisiteOf            string
	UpheldBy               string
	BoundBy                string
	TriggeredBy            string
	OnFailureOf            string
	OnSuccessOf            string
	ConsistsOf             string
	ConflictedBy           string
	PropagatesReloadTo     string
	PropagatesStopTo       string
}

func (manager *systemdManager) inspectManaged(ctx context.Context, identity ReleaseIdentity) (systemdUnitState, systemdUnitState, error) {
	if err := identity.Validate(); err != nil {
		return systemdUnitState{}, systemdUnitState{}, err
	}
	agent, err := manager.inspect(ctx, agentUnitName)
	if err != nil {
		return systemdUnitState{}, systemdUnitState{}, err
	}
	if err := manager.validateInstalledUnit(agentUnitName, agent); err != nil {
		return systemdUnitState{}, systemdUnitState{}, err
	}
	nebula, err := manager.inspect(ctx, nebulaUnitName)
	if err != nil {
		return systemdUnitState{}, systemdUnitState{}, err
	}
	if err := manager.validateInstalledUnit(nebulaUnitName, nebula); err != nil {
		return systemdUnitState{}, systemdUnitState{}, err
	}
	return agent, nebula, nil
}

func (manager *systemdManager) inspect(ctx context.Context, name string) (systemdUnitState, error) {
	propertyArgument := "--property=" + strings.Join(systemdProperties, ",")
	output, err := manager.run(ctx, "show", "--no-pager", propertyArgument, "--", name)
	if err != nil {
		return systemdUnitState{}, fmt.Errorf("inspect %s: %w", name, err)
	}
	unit, err := parseSystemdUnitState(output)
	if err != nil {
		return systemdUnitState{}, fmt.Errorf("inspect %s: %w", name, err)
	}
	return unit, nil
}

func (manager *systemdManager) validateInstalledUnit(name string, unit systemdUnitState) error {
	if unit.LoadState != "loaded" {
		return fmt.Errorf("%s is not loaded from the managed release", name)
	}
	expectedFragment := filepath.Join(manager.unitDirectory, name)
	if unit.FragmentPath != expectedFragment {
		return fmt.Errorf("%s fragment is %q, want %q", name, unit.FragmentPath, expectedFragment)
	}
	expectedDropIn := managedTimeoutAbortDropInPath(manager.unitDirectory, name)
	if unit.DropInPaths != expectedDropIn {
		return fmt.Errorf("%s has forbidden drop-ins %q; want only %q", name, unit.DropInPaths, expectedDropIn)
	}
	if unit.TimeoutStopFailureMode != "terminate" {
		return fmt.Errorf("%s has TimeoutStopFailureMode=%q, want %q", name, unit.TimeoutStopFailureMode, "terminate")
	}
	expectedContent, err := managedUnitContent(name)
	if err != nil {
		return err
	}
	if err := validateManagedUnitFragment(expectedFragment, expectedContent); err != nil {
		return fmt.Errorf("%s fixed fragment: %w", name, err)
	}
	maskContent, err := managedTopologyFileContent(filepath.Join("lib/systemd/system", name+".d", managedTimeoutAbortDropInName))
	if err != nil {
		return err
	}
	if err := validateManagedUnitFragment(expectedDropIn, maskContent); err != nil {
		return fmt.Errorf("%s fixed compatibility drop-in: %w", name, err)
	}
	return nil
}

func managedUnitContent(name string) ([]byte, error) {
	content, err := managedTopologyFileContent(filepath.Join("lib/systemd/system", name))
	if err != nil {
		return nil, fmt.Errorf("%s is not a reviewed managed unit: %w", name, err)
	}
	return content, nil
}

func managedTopologyFileContent(relative string) ([]byte, error) {
	relative = filepath.Clean(relative)
	for _, spec := range topologyFileSpecs() {
		if filepath.Clean(spec.endpointRelative()) == relative {
			return append([]byte(nil), spec.content...), nil
		}
	}
	return nil, fmt.Errorf("%q is not a reviewed managed topology file", relative)
}

func managedTimeoutAbortDropInPath(unitDirectory, name string) string {
	return filepath.Join(unitDirectory, name+".d", managedTimeoutAbortDropInName)
}

func validateManagedUnitFragment(path string, expected []byte) error {
	before, err := os.Lstat(path)
	if err != nil || !trustedExactManagedFile(before, int64(len(expected))) {
		if err != nil {
			return err
		}
		stat, _ := before.Sys().(*syscall.Stat_t)
		return fmt.Errorf("fragment is not a root-owned, single-link, mode-0444 regular file (mode=%s size=%d stat=%+v)", before.Mode(), before.Size(), stat)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return err
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return errors.New("anchor managed unit fragment")
	}
	anchored, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil ||
		!sameManagedFileObject(before, anchored) || !sameManagedFileObject(before, after) || !bytes.Equal(content, expected) {
		return errors.New("fragment changed or differs from reviewed content")
	}
	return nil
}

func (manager *systemdManager) rejectLegacyUnit(ctx context.Context) error {
	unit, err := manager.inspect(ctx, legacyNebulaUnitName)
	if err != nil {
		return err
	}
	if unit.LoadState != "not-found" || unit.FragmentPath != "" || unit.DropInPaths != "" || unit.UnitFileState != "" ||
		!reverseRelationshipsEmpty(unit) || !stoppedRuntime(unit) {
		return errors.New("competing nebula.service exists; remove it before installing Mesh")
	}
	return nil
}

func requireAbsentUnit(name string, unit systemdUnitState) error {
	if unit.LoadState != "not-found" || unit.FragmentPath != "" || unit.DropInPaths != "" || unit.UnitFileState != "" ||
		!reverseRelationshipsEmpty(unit) || !stoppedRuntime(unit) {
		return fmt.Errorf("%s conflicts with the first-install surface", name)
	}
	return nil
}

func managedAgentBootEnabled(unit systemdUnitState) (bool, error) {
	if unit.RequiredBy != "" || unit.RequisiteOf != "" || unit.UpheldBy != "" || unit.TriggeredBy != "" || unit.OnFailureOf != "" || unit.OnSuccessOf != "" ||
		unit.ConsistsOf != "" || unit.ConflictedBy != "" || unit.PropagatesReloadTo != "" || unit.PropagatesStopTo != "" ||
		unit.BoundBy != "" && unit.BoundBy != nebulaUnitName {
		return false, fmt.Errorf("%s has forbidden reverse relationships: %s", agentUnitName, reverseRelationshipSummary(unit))
	}
	switch unit.UnitFileState {
	case "disabled":
		if unit.WantedBy != "" {
			return false, fmt.Errorf("%s is disabled but still wanted by %q", agentUnitName, unit.WantedBy)
		}
		return false, nil
	case "enabled":
		if unit.WantedBy != "multi-user.target" {
			return false, fmt.Errorf("%s enabled topology is %q, want only multi-user.target", agentUnitName, unit.WantedBy)
		}
		return true, nil
	default:
		return false, fmt.Errorf("%s has unsupported boot state %q", agentUnitName, unit.UnitFileState)
	}
}

func requireNoReverseBootDependencies(name string, unit systemdUnitState) error {
	if !reverseRelationshipsEmpty(unit) {
		return fmt.Errorf("%s must not be enabled, triggered, or reverse-bound: %s", name, reverseRelationshipSummary(unit))
	}
	return nil
}

func reverseRelationshipsEmpty(unit systemdUnitState) bool {
	return unit.WantedBy == "" && unit.RequiredBy == "" && unit.RequisiteOf == "" && unit.UpheldBy == "" &&
		unit.BoundBy == "" && unit.TriggeredBy == "" && unit.OnFailureOf == "" && unit.OnSuccessOf == "" && unit.ConsistsOf == "" && unit.ConflictedBy == "" &&
		unit.PropagatesReloadTo == "" && unit.PropagatesStopTo == ""
}

func reverseRelationshipSummary(unit systemdUnitState) string {
	return fmt.Sprintf("WantedBy=%q RequiredBy=%q RequisiteOf=%q UpheldBy=%q BoundBy=%q TriggeredBy=%q OnFailureOf=%q OnSuccessOf=%q ConsistsOf=%q ConflictedBy=%q PropagatesReloadTo=%q PropagatesStopTo=%q",
		unit.WantedBy, unit.RequiredBy, unit.RequisiteOf, unit.UpheldBy, unit.BoundBy, unit.TriggeredBy,
		unit.OnFailureOf, unit.OnSuccessOf, unit.ConsistsOf, unit.ConflictedBy, unit.PropagatesReloadTo, unit.PropagatesStopTo)
}

func stableRuntime(name string, unit systemdUnitState) (bool, error) {
	if unit.ActiveState == "active" && unit.SubState == "running" && unit.MainPID > 1 {
		return true, nil
	}
	if stoppedRuntime(unit) {
		return false, nil
	}
	return false, fmt.Errorf("%s is not in a stable running or stopped state (ActiveState=%q SubState=%q MainPID=%d)", name, unit.ActiveState, unit.SubState, unit.MainPID)
}

func stoppedRuntime(unit systemdUnitState) bool {
	if unit.MainPID != 0 {
		return false
	}
	return unit.ActiveState == "inactive" && unit.SubState == "dead" ||
		unit.ActiveState == "failed" && (unit.SubState == "failed" || unit.SubState == "dead")
}

func (manager *systemdManager) verifyManagedProcess(ctx context.Context, name string, unit systemdUnitState, identity ReleaseIdentity) error {
	var binary string
	var argv []string
	switch name {
	case agentUnitName:
		binary = filepath.Join(manager.releaseRoot, identity.InstalledID, "bin/meshctl")
		argv = []string{
			"/usr/local/bin/meshctl", "agent",
			"--state", "/var/lib/mesh-agent/state.json",
			"--interval", "1m",
			"--max-config-staleness", "5m",
			"--nebula", "/usr/local/bin/nebula",
			"--nebula-cert", "/usr/local/bin/nebula-cert",
			"--restart-service", nebulaUnitName,
		}
	case nebulaUnitName:
		binary = filepath.Join(manager.releaseRoot, identity.InstalledID, "bin/nebula")
		argv = []string{"/usr/local/bin/nebula", "-config", "/var/lib/mesh-agent/nebula/current/config.yml"}
	default:
		return fmt.Errorf("unsupported managed process %q", name)
	}
	if err := manager.processes.Verify(unit.MainPID, binary, argv, unit.ControlGroup); err != nil {
		return fmt.Errorf("prove %s process: %w", name, err)
	}
	after, err := manager.inspect(ctx, name)
	if err != nil {
		return err
	}
	if after.MainPID != unit.MainPID || after.ActiveState != "active" || after.SubState != "running" {
		return fmt.Errorf("%s process changed during proof", name)
	}
	if err := manager.validateInstalledUnit(name, after); err != nil {
		return err
	}
	return nil
}

func (manager *systemdManager) validate() error {
	if manager == nil || manager.runner == nil || manager.processes == nil || manager.runtimeGate == nil || manager.childGate == nil {
		return errors.New("systemd manager is incomplete")
	}
	if !filepath.IsAbs(manager.unitDirectory) || !filepath.IsAbs(manager.releaseRoot) {
		return errors.New("systemd manager paths must be absolute")
	}
	if manager.restoreTimeout <= 0 || manager.restorePoll <= 0 || manager.restorePoll > manager.restoreTimeout {
		return errors.New("systemd manager restore bounds are invalid")
	}
	return nil
}

func (manager *systemdManager) run(ctx context.Context, args ...string) ([]byte, error) {
	if err := manager.validate(); err != nil {
		return nil, err
	}
	commandContext, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	return manager.runner.Run(commandContext, args...)
}

func (manager *systemdManager) requireSystemdVersion(ctx context.Context) error {
	output, err := manager.run(ctx, "--version")
	if err != nil {
		return fmt.Errorf("inspect systemd version: %w", err)
	}
	version, err := parseSystemdVersion(output)
	if err != nil {
		return err
	}
	if version < minimumSystemdVersion {
		return fmt.Errorf("systemd %d is unsupported; Mesh requires systemd %d or newer for managed-unit property verification", version, minimumSystemdVersion)
	}
	return nil
}

func parseSystemdVersion(output []byte) (uint64, error) {
	if len(output) == 0 || len(output) > maxSystemctlOutput || bytes.IndexByte(output, 0) >= 0 {
		return 0, errors.New("systemctl returned invalid version output")
	}
	first, _, _ := strings.Cut(strings.TrimSuffix(string(output), "\n"), "\n")
	fields := strings.Fields(first)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0, errors.New("systemctl returned noncanonical systemd version output")
	}
	version, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != fields[1] {
		return 0, errors.New("systemctl returned noncanonical systemd version number")
	}
	return version, nil
}

func parseSystemdUnitState(output []byte) (systemdUnitState, error) {
	var result systemdUnitState
	if len(output) == 0 || len(output) > maxSystemctlOutput || bytes.IndexByte(output, 0) >= 0 {
		return result, errors.New("systemd returned invalid bounded property output")
	}
	seen := make(map[string]bool, len(systemdProperties))
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || strings.ContainsAny(value, "\r\n\x00") || seen[key] {
			return result, fmt.Errorf("malformed or duplicate systemd property %q", line)
		}
		seen[key] = true
		switch key {
		case "LoadState":
			result.LoadState = value
		case "FragmentPath":
			result.FragmentPath = value
		case "DropInPaths":
			result.DropInPaths = value
		case "TimeoutStopFailureMode":
			result.TimeoutStopFailureMode = value
		case "UnitFileState":
			result.UnitFileState = value
		case "ActiveState":
			result.ActiveState = value
		case "SubState":
			result.SubState = value
		case "MainPID":
			pid, err := strconv.ParseUint(value, 10, 64)
			if err != nil || strconv.FormatUint(pid, 10) != value {
				return result, fmt.Errorf("malformed MainPID %q", value)
			}
			result.MainPID = pid
		case "ControlGroup":
			result.ControlGroup = value
		case "WantedBy":
			result.WantedBy = value
		case "RequiredBy":
			result.RequiredBy = value
		case "RequisiteOf":
			result.RequisiteOf = value
		case "UpheldBy":
			result.UpheldBy = value
		case "BoundBy":
			result.BoundBy = value
		case "TriggeredBy":
			result.TriggeredBy = value
		case "OnFailureOf":
			result.OnFailureOf = value
		case "OnSuccessOf":
			result.OnSuccessOf = value
		case "ConsistsOf":
			result.ConsistsOf = value
		case "ConflictedBy":
			result.ConflictedBy = value
		case "PropagatesReloadTo":
			result.PropagatesReloadTo = value
		case "PropagatesStopTo":
			result.PropagatesStopTo = value
		default:
			return result, fmt.Errorf("unexpected systemd property %q", key)
		}
	}
	for _, property := range systemdProperties {
		if !seen[property] {
			return result, fmt.Errorf("missing systemd property %q", property)
		}
	}
	if result.LoadState == "" || result.ActiveState == "" || result.SubState == "" {
		return result, errors.New("systemd omitted required state values")
	}
	return result, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *cappedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		buffer.overflow = true
		value = value[:remaining]
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}

type execSystemdRunner struct{}

func (execSystemdRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	binary, err := openPinnedSystemctl()
	if err != nil {
		return nil, err
	}
	defer binary.Close()
	stdout := &cappedBuffer{limit: maxSystemctlOutput}
	stderr := &cappedBuffer{limit: 8 << 10}
	// ExtraFiles maps the already-verified descriptor to fd 3 in the child.
	// Executing that descriptor through procfs prevents the Lstat-to-exec path
	// replacement race inherent in exec.Command(systemctlPath, ...).
	command := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	command.Args[0] = systemctlPath
	command.ExtraFiles = []*os.File{binary}
	command.Env = []string{
		"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TZ=UTC",
		"SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat", "SYSTEMD_PAGERSECURE=1",
	}
	input, err := os.Open("/dev/null")
	if err != nil {
		return nil, errors.New("open fixed systemctl stdin")
	}
	defer input.Close()
	command.Dir = "/"
	command.Stdin = input
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %w", systemctlAction(args), err)
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("systemctl output exceeded its security bound")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func openPinnedSystemctl() (*os.File, error) {
	if err := validateSecureAncestorChain(filepath.Dir(systemctlPath), false); err != nil {
		return nil, fmt.Errorf("systemctl ancestry: %w", err)
	}
	before, err := os.Lstat(systemctlPath)
	if err != nil || !trustedSystemctlBinary(before) {
		return nil, errors.New("systemctl must be a nonwritable root-owned regular /usr/bin/systemctl binary")
	}
	if err := rejectPOSIXACL(systemctlPath); err != nil {
		return nil, err
	}
	descriptor, err := syscall.Open(systemctlPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), systemctlPath)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("anchor systemctl binary")
	}
	anchored, statErr := file.Stat()
	after, pathErr := os.Lstat(systemctlPath)
	if statErr != nil || pathErr != nil || !sameSystemctlBinary(before, anchored) || !sameSystemctlBinary(before, after) {
		_ = file.Close()
		return nil, errors.New("systemctl binary changed while anchoring")
	}
	return file, nil
}

func trustedSystemctlBinary(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 || info.Size() <= 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 1
}

func sameSystemctlBinary(left, right os.FileInfo) bool {
	if !trustedSystemctlBinary(left) || !trustedSystemctlBinary(right) || !os.SameFile(left, right) ||
		left.Mode() != right.Mode() || left.Size() != right.Size() {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Mtim == rightStat.Mtim && leftStat.Ctim == rightStat.Ctim
}

func systemctlAction(args []string) string {
	if len(args) == 0 || args[0] == "" {
		return "systemctl command"
	}
	return "systemctl " + args[0]
}

type procProcessVerifier struct{}

func (procProcessVerifier) Verify(pid uint64, expectedBinary string, expectedArgv []string, expectedControlGroup string) error {
	if pid <= 1 || !filepath.IsAbs(expectedBinary) || len(expectedArgv) == 0 || !canonicalControlGroup(expectedControlGroup) {
		return errors.New("invalid managed process expectation")
	}
	expected, err := os.Stat(expectedBinary)
	if err != nil || !expected.Mode().IsRegular() {
		return errors.New("expected managed executable is not a regular release file")
	}
	processDirectory := filepath.Join("/proc", strconv.FormatUint(pid, 10))
	beforeProcess, err := os.Stat(processDirectory)
	if err != nil || !beforeProcess.IsDir() {
		return errors.New("managed process directory is unavailable")
	}
	processStat, ok := beforeProcess.Sys().(*syscall.Stat_t)
	if !ok || processStat.Uid != 0 {
		return errors.New("managed process must run as root")
	}
	startTimeBefore, err := readProcessStartTime(processDirectory)
	if err != nil {
		return err
	}
	executablePath := filepath.Join(processDirectory, "exe")
	executableBefore, err := os.Stat(executablePath)
	if err != nil || !os.SameFile(expected, executableBefore) {
		return errors.New("managed process executable inode differs from the active release")
	}
	commandLinePath := filepath.Join(processDirectory, "cmdline")
	commandLineFile, err := os.Open(commandLinePath)
	if err != nil {
		return err
	}
	commandLine, readErr := io.ReadAll(io.LimitReader(commandLineFile, maxSystemctlOutput+1))
	closeErr := commandLineFile.Close()
	if readErr != nil || closeErr != nil || len(commandLine) == 0 || len(commandLine) > maxSystemctlOutput || commandLine[len(commandLine)-1] != 0 {
		return errors.New("managed process command line is invalid")
	}
	parts := bytes.Split(commandLine[:len(commandLine)-1], []byte{0})
	if len(parts) != len(expectedArgv) {
		return errors.New("managed process argument count differs from the unit contract")
	}
	for index := range parts {
		if string(parts[index]) != expectedArgv[index] {
			return fmt.Errorf("managed process argument %d differs from the unit contract", index)
		}
	}
	processControlGroup, err := readProcessControlGroup(processDirectory)
	if err != nil || processControlGroup != expectedControlGroup {
		return errors.New("managed process cgroup differs from the systemd unit")
	}
	executableAfter, executableErr := os.Stat(executablePath)
	afterProcess, processErr := os.Stat(processDirectory)
	startTimeAfter, startTimeErr := readProcessStartTime(processDirectory)
	if executableErr != nil || processErr != nil || !os.SameFile(expected, executableAfter) ||
		startTimeErr != nil || startTimeBefore != startTimeAfter || !os.SameFile(executableBefore, executableAfter) ||
		!os.SameFile(beforeProcess, afterProcess) {
		return errors.New("managed process changed during executable and argument proof")
	}
	return nil
}

func (procProcessVerifier) ProveReleaseStopped(releasePath string, controlGroups []string) error {
	if !filepath.IsAbs(releasePath) {
		return errors.New("release path must be absolute")
	}
	for _, controlGroup := range controlGroups {
		if controlGroup == "" {
			continue
		}
		if !canonicalControlGroup(controlGroup) {
			return errors.New("systemd returned a noncanonical control group")
		}
		content, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(controlGroup, "/"), "cgroup.procs"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect stopped service cgroup: %w", err)
		}
		if len(content) > maxSystemctlOutput || strings.TrimSpace(string(content)) != "" {
			return errors.New("stopped service cgroup still contains processes")
		}
	}
	expected := make([]os.FileInfo, 0, 2)
	for _, name := range []string{"meshctl", "nebula"} {
		info, err := os.Stat(filepath.Join(releasePath, "bin", name))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("inspect release executable %s for stop proof", name)
		}
		expected = append(expected, info)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("scan processes for stopped release: %w", err)
	}
	if len(entries) > 1<<20 {
		return errors.New("process table exceeds the supported security bound")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !decimalPID(entry.Name()) {
			continue
		}
		executable, err := os.Stat(filepath.Join("/proc", entry.Name(), "exe"))
		if processDisappeared(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect PID %s executable during stop proof: %w", entry.Name(), err)
		}
		for _, releaseExecutable := range expected {
			if os.SameFile(executable, releaseExecutable) {
				return fmt.Errorf("release executable still runs as PID %s after systemd stop", entry.Name())
			}
		}
	}
	return nil
}

func processDisappeared(err error) bool {
	return err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH))
}

func canonicalControlGroup(value string) bool {
	return strings.HasPrefix(value, "/") && filepath.Clean(value) == value && value != "/" && !strings.ContainsAny(value, "\x00\r\n")
}

func decimalPID(value string) bool {
	if value == "" || value == "0" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func readProcessStartTime(processDirectory string) (string, error) {
	content, err := os.ReadFile(filepath.Join(processDirectory, "stat"))
	if err != nil || len(content) == 0 || len(content) > maxSystemctlOutput || bytes.IndexByte(content, 0) >= 0 {
		return "", errors.New("managed process start time is unavailable")
	}
	closing := bytes.LastIndexByte(content, ')')
	if closing < 0 || closing+2 >= len(content) {
		return "", errors.New("managed process stat is malformed")
	}
	fields := bytes.Fields(content[closing+2:])
	if len(fields) <= 19 {
		return "", errors.New("managed process stat omits start time")
	}
	startTime := string(fields[19])
	if !decimalPID(startTime) {
		return "", errors.New("managed process start time is noncanonical")
	}
	return startTime, nil
}

func readProcessControlGroup(processDirectory string) (string, error) {
	content, err := os.ReadFile(filepath.Join(processDirectory, "cgroup"))
	if err != nil || len(content) == 0 || len(content) > maxSystemctlOutput || bytes.IndexByte(content, 0) >= 0 {
		return "", errors.New("managed process cgroup is unavailable")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "0::") {
			value := strings.TrimPrefix(line, "0::")
			if canonicalControlGroup(value) {
				return value, nil
			}
		}
	}
	return "", errors.New("managed process is not in a canonical unified cgroup")
}
