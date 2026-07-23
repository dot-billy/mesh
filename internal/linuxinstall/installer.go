//go:build linux

package linuxinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/installtrust"
	"mesh/internal/linuxbundle"
)

const (
	ProductionStateDirectory = "/var/lib/mesh-installer"
	ProductionStatePath      = "/var/lib/mesh-installer/state.json"

	// Completion proof starts only after the installer journal or enrolled
	// runtime has reached its success state. Detach it from a terminal signal
	// so the CLI never reports an ambiguous failure merely because cancellation
	// landed between the durable mutation and its final readback.
	installerCompletionProofTimeout = 5 * time.Minute
)

type InstallResult struct {
	Operation            TransactionOperation `json:"operation"`
	Release              ReleaseIdentity      `json:"release"`
	Previous             *ReleaseIdentity     `json:"previous,omitempty"`
	FirstInstall         bool                 `json:"first_install"`
	AlreadyActive        bool                 `json:"already_active,omitempty"`
	RuntimeAlreadyActive bool                 `json:"runtime_already_active,omitempty"`
	AgentEnabled         bool                 `json:"agent_enabled"`
	AgentActive          bool                 `json:"agent_active"`
	NebulaActive         bool                 `json:"nebula_active"`
	RuntimeGateOpen      bool                 `json:"runtime_gate_open"`
}

type productionBoundary struct {
	build     buildinfo.Info
	bootstrap installtrust.Bootstrap
}

// ApplySnapshot verifies, stages, publishes, and activates one complete
// root-private offline release snapshot. All install destinations and trust
// inputs are compiled constants; sourceDirectory is the sole caller-selected
// path and contains only untrusted locator/content inputs.
func ApplySnapshot(ctx context.Context, sourceDirectory string) (result InstallResult, returnErr error) {
	return applySnapshotAt(ctx, sourceDirectory, time.Now().UTC())
}

func applySnapshotAt(ctx context.Context, sourceDirectory string, updateStart time.Time) (result InstallResult, returnErr error) {
	if updateStart.IsZero() {
		return result, errors.New("snapshot update start time is zero")
	}
	updateStart = updateStart.UTC()
	boundary, err := verifyProductionBoundary()
	if err != nil {
		return result, err
	}
	if err := EnsureStateDirectory(ProductionStateDirectory); err != nil {
		return result, fmt.Errorf("prepare fixed installer state directory: %w", err)
	}
	rootStore, err := NewRootStore(productionRootStoreDirectory, uint32(os.Geteuid()), boundary.bootstrap.InitialRoot)
	if err != nil {
		return result, err
	}
	store, err := NewStateStore(ProductionStatePath)
	if err != nil {
		return result, err
	}
	state, found, err := loadQuiescentSnapshotState(rootStore, store, boundary.bootstrap)
	if err != nil {
		return result, err
	}

	topology, err := NewProductionManagedLinkTopology()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, topology.Close()) }()
	services := productionSystemdManager()

	var layout *ReleaseLayout
	if found && state.Active != nil {
		layout, err = OpenReleaseLayout(ProductionMeshRoot)
		if err != nil {
			return result, err
		}
	} else {
		if err := requireUninstalledSurface(ctx, topology, services); err != nil {
			return result, err
		}
		layout, err = EnsureReleaseLayout(ProductionMeshRoot)
		if err != nil {
			return result, err
		}
	}
	defer func() { returnErr = errors.Join(returnErr, layout.Close()) }()
	if err := layout.ReconcileIntake(foundStatePointer(state, found)); err != nil {
		return result, fmt.Errorf("reconcile abandoned release intake: %w", err)
	}

	initialServices, err := auditSourceInstallation(ctx, foundStatePointer(state, found), layout, topology, services, boundary)
	if err != nil {
		return result, err
	}
	snapshot, err := OpenMetadataSnapshot(sourceDirectory)
	if err != nil {
		return result, err
	}

	// Reacquire in the global root-then-state order after all systemd preflight.
	// Trust stays locked through local artifact/package verification and the
	// prepared journal commit, but is released before any service operation.
	rootLock, err := rootStore.Acquire()
	if err != nil {
		return result, err
	}
	defer func() {
		if rootLock != nil {
			returnErr = errors.Join(returnErr, rootLock.Close())
		}
	}()
	lock, err := store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	reloaded, reloadedFound, err := lock.Load()
	if err != nil {
		return result, err
	}
	if found != reloadedFound || found && !sameStateExact(state, reloaded) {
		return result, errors.New("installer state changed during release preflight")
	}
	state, found = reloaded, reloadedFound
	if found {
		if err := validatePersistedBootstrap(state, boundary.bootstrap); err != nil {
			return result, err
		}
		if state.Pending != nil {
			return result, errors.New("an unfinished installation exists; run mesh-install recover before applying another snapshot")
		}
	}
	rootResult, err := rootLock.ApplyChain(snapshot.RootUpdates, updateStart, 0)
	if err != nil {
		return result, fmt.Errorf("authenticate and persist release-root updates: %w", err)
	}
	var prior *State
	if found {
		prior = &state
	}
	currentRoot := rootResult.Root
	candidate, err := verifySignedCandidateWithRoots(snapshot.Metadata, boundary.bootstrap, currentRoot, currentRoot, prior, updateStart, boundary.build.SecurityFloor)
	if err != nil {
		return result, fmt.Errorf("authenticate release candidate: %w", err)
	}
	if snapshot.Artifact.Identity.Size != candidate.Artifact.Size {
		return result, errors.New("observed artifact size differs from the threshold-authenticated release")
	}
	if candidate.Artifact.Size <= 0 || candidate.Artifact.Size > linuxbundle.MaxArchiveSize {
		return result, fmt.Errorf("authenticated Linux bundle size %d exceeds the installer limit %d", candidate.Artifact.Size, linuxbundle.MaxArchiveSize)
	}
	privateRoot, err := os.OpenRoot(ProductionStateDirectory)
	if err != nil {
		return result, fmt.Errorf("anchor installer private directory: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, privateRoot.Close()) }()
	captured, err := CaptureArtifact(snapshot.Artifact.Path, candidate.Artifact, privateRoot)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, captured.Close()) }()

	preservedInstalledID := migratedInstalledIDForExactCandidate(prior, candidate)
	identity, err := stageAndPublishCandidate(captured, candidate, preservedInstalledID, layout, boundary)
	if err != nil {
		return result, err
	}
	if err := rootLock.Close(); err != nil {
		return result, fmt.Errorf("release trust lock before service verification: %w", err)
	}
	rootLock = nil
	// Re-prove the source after the potentially long artifact copy and bundle
	// validation. A service/topology drift never gets journaled as desired state.
	currentServices, err := auditSourceInstallation(ctx, foundStatePointer(state, found), layout, topology, services, boundary)
	if err != nil {
		return result, err
	}
	if currentServices != initialServices {
		return result, errors.New("managed service state changed during release intake")
	}
	prepared, err := prepareRootedActivationState(prior, boundary.bootstrap, identity, currentServices, time.Now().UTC())
	if errors.Is(err, ErrReleaseAlreadyActive) {
		result = installResultFromState(OperationActivate, state, true)
		setInstallResultServices(&result, currentServices)
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if err := lock.Commit(prepared); err != nil {
		return result, &journalCommitError{cause: err}
	}
	completed, err := executePreparedTransaction(ctx, lock, prepared, layout, topology, services)
	if err != nil {
		return result, err
	}
	result = installResultFromState(OperationActivate, completed, false)
	proofContext, cancelProof := newInstallerCompletionProofContext(ctx)
	defer cancelProof()
	finalServices, err := auditSourceInstallation(proofContext, &completed, layout, topology, services, boundary)
	if err != nil {
		return result, fmt.Errorf("prove completed installation: %w", err)
	}
	setInstallResultServices(&result, finalServices)
	return result, nil
}

func loadQuiescentSnapshotState(rootStore *RootStore, store *StateStore, bootstrap installtrust.Bootstrap) (state State, found bool, returnErr error) {
	rootLock, err := rootStore.Acquire()
	if err != nil {
		return state, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, rootLock.Close()) }()
	lock, err := store.AcquireLock()
	if err != nil {
		return state, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	state, found, err = lock.Load()
	if err != nil {
		return State{}, false, err
	}
	if !found {
		return state, false, nil
	}
	if state.Schema == LegacyStateSchema {
		empty, err := rootLock.HistoryEmpty()
		if err != nil {
			return State{}, false, err
		}
		state, err = lock.MigrateV2(bootstrap, empty)
		if err != nil {
			return State{}, false, fmt.Errorf("migrate installer state to root-aware schema: %w", err)
		}
	}
	if err := validatePersistedBootstrap(state, bootstrap); err != nil {
		return State{}, false, err
	}
	if state.Pending != nil {
		return State{}, false, errors.New("an unfinished installation exists; run mesh-install recover before applying another snapshot")
	}
	return state, true, nil
}

// RecoverInstallation completes or safely compensates the one transaction
// named by the durable journal. It consumes no new release or enrollment input.
func RecoverInstallation(ctx context.Context) (result InstallResult, returnErr error) {
	boundary, err := verifyProductionBoundary()
	if err != nil {
		return result, err
	}
	if err := validatePrivateDirectory(ProductionStateDirectory); err != nil {
		return result, fmt.Errorf("open fixed installer state directory: %w", err)
	}
	store, err := NewStateStore(ProductionStatePath)
	if err != nil {
		return result, err
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	state, found, err := lock.Load()
	if err != nil {
		return result, err
	}
	if !found || state.Pending == nil {
		return result, errors.New("no unfinished installer transaction exists")
	}
	if err := validatePersistedBootstrap(state, boundary.bootstrap); err != nil {
		return result, err
	}
	layout, err := OpenReleaseLayout(ProductionMeshRoot)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, layout.Close()) }()
	if err := layout.ReconcileIntake(&state); err != nil {
		return result, fmt.Errorf("reconcile abandoned release intake: %w", err)
	}
	topology, err := NewProductionManagedLinkTopology()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, topology.Close()) }()
	if err := verifyStoredRelease(layout, state.Pending.TargetActive, boundary); err != nil {
		return result, fmt.Errorf("verify pending target release: %w", err)
	}
	if state.Pending.SourceActive != nil {
		if err := verifyStoredRelease(layout, *state.Pending.SourceActive, boundary); err != nil {
			return result, fmt.Errorf("verify pending source release: %w", err)
		}
	}
	operation := state.Pending.Operation
	completed, err := recoverPendingTransaction(ctx, lock, state, layout, topology, productionSystemdManager())
	if err != nil {
		return result, err
	}
	result = installResultFromState(operation, completed, false)
	proofContext, cancelProof := newInstallerCompletionProofContext(ctx)
	defer cancelProof()
	finalServices, err := auditSourceInstallation(proofContext, &completed, layout, topology, productionSystemdManager(), boundary)
	if err != nil {
		return result, fmt.Errorf("prove recovered installation: %w", err)
	}
	setInstallResultServices(&result, finalServices)
	return result, nil
}

// ActivateInstallation is the retry-safe post-enrollment transition. The
// signed release must already be durably installed and current; this command
// accepts no release, trust, path, or enrollment input. It establishes the
// one canonical agent boot link, opens the fixed runtime gate, starts only the
// lifecycle agent, and succeeds only after both exact managed processes are
// proven running. Interrupted partial activation is reconciled by the systemd
// manager without changing the authenticated installer state.
func ActivateInstallation(ctx context.Context) (result InstallResult, returnErr error) {
	boundary, err := verifyProductionBoundary()
	if err != nil {
		return result, err
	}
	if err := validatePrivateDirectory(ProductionStateDirectory); err != nil {
		return result, fmt.Errorf("open fixed installer state directory: %w", err)
	}
	store, err := NewStateStore(ProductionStatePath)
	if err != nil {
		return result, err
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	state, found, err := lock.Load()
	if err != nil {
		return result, err
	}
	if !found || state.Active == nil {
		return result, errors.New("Mesh is not installed")
	}
	if err := validatePersistedBootstrap(state, boundary.bootstrap); err != nil {
		return result, err
	}
	if state.Pending != nil {
		return result, errors.New("an unfinished installer transaction must be recovered before runtime activation")
	}
	layout, err := OpenReleaseLayout(ProductionMeshRoot)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, layout.Close()) }()
	if err := layout.ReconcileIntake(&state); err != nil {
		return result, fmt.Errorf("reconcile abandoned release intake: %w", err)
	}
	if err := verifyStoredRelease(layout, *state.Active, boundary); err != nil {
		return result, fmt.Errorf("verify active release: %w", err)
	}
	audit, err := layout.Audit(*state.Active)
	if err != nil {
		return result, err
	}
	if !audit.Published || !audit.Current {
		return result, errors.New("active release does not match the durable current pointer")
	}
	if state.Previous != nil {
		if err := verifyStoredRelease(layout, *state.Previous, boundary); err != nil {
			return result, fmt.Errorf("verify previous release: %w", err)
		}
	}
	topology, err := NewProductionManagedLinkTopology()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, topology.Close()) }()
	if err := topology.Audit(); err != nil {
		return result, err
	}
	services := productionSystemdManager()
	runtimeAlreadyActive, err := services.activateEnrolled(ctx, *state.Active)
	if err != nil {
		return result, err
	}
	proofContext, cancelProof := newInstallerCompletionProofContext(ctx)
	defer cancelProof()
	finalServices, err := auditSourceInstallation(proofContext, &state, layout, topology, services, boundary)
	if err != nil {
		proofErr := fmt.Errorf("prove activated enrolled runtime: %w", err)
		return result, errors.Join(proofErr, services.quarantineFailedActivation(proofContext, *state.Active, proofErr))
	}
	wantServices := ServiceSnapshot{
		AgentWasEnabled: true, AgentWasActive: true,
		NebulaWasActive: true, RuntimeGateWasOpen: true,
	}
	if finalServices != wantServices {
		proofErr := fmt.Errorf("activated enrolled runtime changed before final proof: got %+v, want %+v", finalServices, wantServices)
		return result, errors.Join(proofErr, services.quarantineFailedActivation(proofContext, *state.Active, proofErr))
	}
	result = installResultFromState(OperationActivate, state, false)
	result.RuntimeAlreadyActive = runtimeAlreadyActive
	setInstallResultServices(&result, finalServices)
	return result, nil
}

// RollbackInstallation atomically selects the recorded previous release while
// retaining the exact authenticated high-water release and security floor.
func RollbackInstallation(ctx context.Context, expectedTarget string) (result InstallResult, returnErr error) {
	boundary, err := verifyProductionBoundary()
	if err != nil {
		return result, err
	}
	if err := validatePrivateDirectory(ProductionStateDirectory); err != nil {
		return result, fmt.Errorf("open fixed installer state directory: %w", err)
	}
	store, err := NewStateStore(ProductionStatePath)
	if err != nil {
		return result, err
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	state, found, err := lock.Load()
	if err != nil {
		return result, err
	}
	if !found {
		return result, errors.New("Mesh is not installed")
	}
	if err := validatePersistedBootstrap(state, boundary.bootstrap); err != nil {
		return result, err
	}
	if state.Pending != nil {
		return result, errors.New("an unfinished transaction must be recovered before explicit rollback")
	}
	alreadyActive, err := classifyRollbackTarget(state, expectedTarget)
	if err != nil {
		return result, err
	}
	layout, err := OpenReleaseLayout(ProductionMeshRoot)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, layout.Close()) }()
	if err := layout.ReconcileIntake(&state); err != nil {
		return result, fmt.Errorf("reconcile abandoned release intake: %w", err)
	}
	topology, err := NewProductionManagedLinkTopology()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, topology.Close()) }()
	services := productionSystemdManager()
	snapshot, err := auditSourceInstallation(ctx, &state, layout, topology, services, boundary)
	if err != nil {
		return result, err
	}
	if alreadyActive {
		result = installResultFromState(OperationRollback, state, true)
		setInstallResultServices(&result, snapshot)
		return result, nil
	}
	if err := verifyStoredRelease(layout, *state.Previous, boundary); err != nil {
		return result, fmt.Errorf("verify rollback target: %w", err)
	}
	prepared, err := prepareRollbackState(state, snapshot, time.Now().UTC())
	if err != nil {
		return result, err
	}
	if err := lock.Commit(prepared); err != nil {
		return result, &journalCommitError{cause: err}
	}
	completed, err := executePreparedTransaction(ctx, lock, prepared, layout, topology, services)
	if err != nil {
		return result, err
	}
	result = installResultFromState(OperationRollback, completed, false)
	proofContext, cancelProof := newInstallerCompletionProofContext(ctx)
	defer cancelProof()
	finalServices, err := auditSourceInstallation(proofContext, &completed, layout, topology, services, boundary)
	if err != nil {
		return result, fmt.Errorf("prove completed rollback: %w", err)
	}
	setInstallResultServices(&result, finalServices)
	return result, nil
}

func classifyRollbackTarget(state State, expectedTarget string) (bool, error) {
	if !installedIDPattern.MatchString(expectedTarget) {
		return false, errors.New("rollback target must be an exact installed release ID")
	}
	if state.Active == nil {
		return false, errors.New("no active release is installed")
	}
	if state.Active.InstalledID == expectedTarget {
		return true, nil
	}
	if state.Previous == nil {
		return false, errors.New("no previous release is available for rollback")
	}
	if state.Previous.InstalledID != expectedTarget {
		return false, fmt.Errorf("rollback target %q is not the recorded previous release %q", expectedTarget, state.Previous.InstalledID)
	}
	return false, nil
}

func verifyProductionBoundary() (productionBoundary, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return productionBoundary{}, errors.New("Mesh installation is supported only on linux/amd64 and linux/arm64")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return productionBoundary{}, errors.New("mesh-install mutations require real/effective UID and GID 0")
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return productionBoundary{}, err
	}
	if build.OS != runtime.GOOS || build.Arch != runtime.GOARCH || build.SecurityFloor == 0 {
		return productionBoundary{}, errors.New("compiled installer identity differs from the running platform")
	}
	if build.AgentStateReadMin > agentstate.CurrentSchemaVersion || build.AgentStateReadMax < agentstate.CurrentSchemaVersion {
		return productionBoundary{}, fmt.Errorf("compiled installer cannot read current agent-state schema %d", agentstate.CurrentSchemaVersion)
	}
	if build.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
		return productionBoundary{}, fmt.Errorf("compiled installer writes agent-state schema %d, want %d", build.AgentStateWriteVersion, agentstate.CurrentWriteVersion)
	}
	compatibility, err := installercompat.Current()
	if err != nil {
		return productionBoundary{}, err
	}
	if !compatibility.Reads(LegacyStateSchemaVersion) || !compatibility.Reads(StateSchemaVersion) ||
		compatibility.WriteVersion != StateSchemaVersion {
		return productionBoundary{}, fmt.Errorf("compiled installer-state compatibility [%d,%d] write %d does not match implemented v2 migration and v3 writer", compatibility.ReadMinimum, compatibility.ReadMaximum, compatibility.WriteVersion)
	}
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return productionBoundary{}, err
	}
	if _, _, _, err := validateRootVerificationInputs(bootstrap, bootstrap.InitialRoot, bootstrap.InitialRoot); err != nil {
		return productionBoundary{}, fmt.Errorf("validate compiled installer bootstrap: %w", err)
	}
	return productionBoundary{build: build, bootstrap: bootstrap}, nil
}

func validatePersistedBootstrap(state State, bootstrap installtrust.Bootstrap) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if state.Schema != StateSchemaV3 {
		return errors.New("installer state must be migrated to root-aware schema v3")
	}
	if state.BootstrapTrustSHA256 != bootstrap.SHA256 || state.Channel != bootstrap.InitialRoot.Document.Channel {
		return errors.New("compiled installer bootstrap or channel differs from persisted state")
	}
	return nil
}

func foundStatePointer(state State, found bool) *State {
	if !found {
		return nil
	}
	copy := deepCopyState(state)
	return &copy
}

func newInstallerCompletionProofContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), installerCompletionProofTimeout)
}

func requireUninstalledSurface(ctx context.Context, topology *ManagedLinkTopology, services *systemdManager) error {
	if err := topology.RequireAbsent(); err != nil {
		return fmt.Errorf("first-install managed links: %w", err)
	}
	if _, err := services.preflight(ctx, nil); err != nil {
		return fmt.Errorf("first-install systemd surface: %w", err)
	}
	return nil
}

func auditSourceInstallation(ctx context.Context, state *State, layout *ReleaseLayout, topology *ManagedLinkTopology, services *systemdManager, boundary productionBoundary) (ServiceSnapshot, error) {
	if state == nil || state.Active == nil {
		current, exists, err := layout.ReadCurrent()
		if err != nil {
			return ServiceSnapshot{}, err
		}
		if exists {
			return ServiceSnapshot{}, fmt.Errorf("uninstalled state has current release %s", current.InstalledID)
		}
		if err := requireUninstalledSurface(ctx, topology, services); err != nil {
			return ServiceSnapshot{}, err
		}
		return ServiceSnapshot{}, nil
	}
	if err := verifyStoredRelease(layout, *state.Active, boundary); err != nil {
		return ServiceSnapshot{}, fmt.Errorf("verify active release: %w", err)
	}
	audit, err := layout.Audit(*state.Active)
	if err != nil || !audit.Published || !audit.Current {
		if err != nil {
			return ServiceSnapshot{}, err
		}
		return ServiceSnapshot{}, errors.New("active release does not match the durable current pointer")
	}
	if state.Previous != nil {
		if err := verifyStoredRelease(layout, *state.Previous, boundary); err != nil {
			return ServiceSnapshot{}, fmt.Errorf("verify previous release: %w", err)
		}
	}
	if err := topology.Audit(); err != nil {
		return ServiceSnapshot{}, err
	}
	return services.preflight(ctx, state.Active)
}

func stageAndPublishCandidate(archive *os.File, candidate CandidateMetadata, preservedInstalledID string, layout *ReleaseLayout, boundary productionBoundary) (identity ReleaseIdentity, returnErr error) {
	expected := linuxbundle.Expected{
		Version: candidate.Version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		MinimumSecurityFloor: candidate.MinimumSecurityFloor, InstallerBootstrapRootSHA256: boundary.bootstrap.InitialRootSHA256,
		InstallerStateSchemaVersion: StateSchemaVersion,
	}
	provisional, err := candidate.releaseIdentity(
		strings.Repeat("0", 64), boundary.bootstrap.InitialRootSHA256, candidate.MinimumSecurityFloor,
		boundary.build.AgentStateReadMin, boundary.build.AgentStateReadMax, boundary.build.AgentStateWriteVersion,
	)
	if err != nil {
		return identity, err
	}
	if preservedInstalledID != "" {
		provisional.InstalledID = preservedInstalledID
		if err := provisional.Validate(); err != nil {
			return identity, fmt.Errorf("preserve migrated release locator: %w", err)
		}
	}
	stage, err := layout.CreateStage(provisional)
	if err != nil {
		return identity, err
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			returnErr = errors.Join(returnErr, stage.Discard())
		}
		returnErr = errors.Join(returnErr, stage.Close())
	}()
	staged, err := linuxbundle.StageAuthenticated(archive, stage.Root(), expected, linuxbundle.ArtifactIdentity{
		Size: candidate.Artifact.Size, SHA256: candidate.Artifact.SHA256,
	})
	if err != nil {
		return identity, err
	}
	identity, err = candidate.releaseIdentity(
		staged.PackageJSONSHA256, boundary.bootstrap.InitialRootSHA256, staged.Package.SecurityFloor,
		staged.Package.AgentStateReadMin, staged.Package.AgentStateReadMax, staged.Package.AgentStateWriteVersion,
	)
	if err != nil {
		return ReleaseIdentity{}, err
	}
	if preservedInstalledID != "" {
		identity.InstalledID = preservedInstalledID
		if err := identity.Validate(); err != nil {
			return ReleaseIdentity{}, fmt.Errorf("preserve migrated release identity: %w", err)
		}
	}
	if err := stage.FinalizeIdentity(identity); err != nil {
		return ReleaseIdentity{}, err
	}
	verifiedStage, err := linuxbundle.VerifyStagedDirectory(stage.Path(), expected)
	if err != nil || !sameStagedRelease(staged, verifiedStage) {
		if err != nil {
			return ReleaseIdentity{}, err
		}
		return ReleaseIdentity{}, errors.New("staged release changed before publication")
	}
	exists, err := layout.InspectRelease(identity)
	if err != nil {
		return ReleaseIdentity{}, err
	}
	if exists {
		existing, err := linuxbundle.VerifyStagedDirectory(filepath.Join(layout.releasesPath, identity.InstalledID), expected)
		if err != nil || !sameStagedRelease(staged, existing) {
			if err != nil {
				return ReleaseIdentity{}, err
			}
			return ReleaseIdentity{}, errors.New("existing release directory differs from the authenticated candidate")
		}
		if err := stage.Discard(); err != nil {
			return ReleaseIdentity{}, err
		}
		cleanupStage = false
		return identity, nil
	}
	if err := stage.Publish(); err != nil {
		return ReleaseIdentity{}, err
	}
	cleanupStage = false
	installed, err := linuxbundle.VerifyStagedDirectory(filepath.Join(layout.releasesPath, identity.InstalledID), expected)
	if err != nil || !sameStagedRelease(staged, installed) {
		if err != nil {
			return ReleaseIdentity{}, err
		}
		return ReleaseIdentity{}, errors.New("published release differs from its authenticated stage")
	}
	return identity, nil
}

func migratedInstalledIDForExactCandidate(prior *State, candidate CandidateMetadata) string {
	if prior == nil || prior.Schema != StateSchemaV3 || prior.HighWater.ReleaseEpoch != candidate.ReleaseEpoch ||
		prior.HighWater.Sequence != candidate.Sequence || prior.HighWater.ChannelManifestSHA256 != candidate.ChannelManifestSHA256 ||
		prior.HighWater.ReleaseManifestSHA256 != candidate.ReleaseManifestSHA256 || prior.HighWater.ArtifactSHA256 != candidate.Artifact.SHA256 ||
		prior.HighWater.InstalledID != legacyInstalledID(prior.HighWater) {
		return ""
	}
	return prior.HighWater.InstalledID
}

func verifyStoredRelease(layout *ReleaseLayout, identity ReleaseIdentity, boundary productionBoundary) error {
	published, err := layout.InspectRelease(identity)
	if err != nil || !published {
		if err != nil {
			return err
		}
		return errors.New("authenticated release directory is missing")
	}
	expected := linuxbundle.Expected{
		Version: identity.Version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		MinimumSecurityFloor: identity.MinimumSecurityFloor, InstallerBootstrapRootSHA256: boundary.bootstrap.InitialRootSHA256,
		InstallerStateSchemaVersion: StateSchemaVersion,
	}
	verified, err := linuxbundle.VerifyStagedDirectory(filepath.Join(layout.releasesPath, identity.InstalledID), expected)
	if err != nil {
		return err
	}
	if verified.PackageJSONSHA256 != identity.BundleManifestSHA256 || verified.Package.SecurityFloor != identity.BundleSecurityFloor ||
		verified.Package.InstallerBootstrapRootSHA256 != identity.InstallerBootstrapRootSHA256 ||
		verified.Package.AgentStateReadMin != identity.AgentStateReadMin || verified.Package.AgentStateReadMax != identity.AgentStateReadMax ||
		verified.Package.AgentStateWriteVersion != identity.AgentStateWriteVersion {
		return errors.New("installed package identity differs from persisted release state")
	}
	return nil
}

func sameStagedRelease(left, right linuxbundle.StageResult) bool {
	return left.PackageJSONSHA256 == right.PackageJSONSHA256 && left.FileCount == right.FileCount &&
		left.TotalBytes == right.TotalBytes && reflect.DeepEqual(left.Package, right.Package)
}

func installResultFromState(operation TransactionOperation, state State, alreadyActive bool) InstallResult {
	result := InstallResult{Operation: operation, AlreadyActive: alreadyActive}
	if state.Active != nil {
		result.Release = *state.Active
	}
	result.Previous = deepCopyReleasePointer(state.Previous)
	if operation == OperationActivate {
		result.FirstInstall = state.Previous == nil
	}
	return result
}

func setInstallResultServices(result *InstallResult, services ServiceSnapshot) {
	result.AgentEnabled = services.AgentWasEnabled
	result.AgentActive = services.AgentWasActive
	result.NebulaActive = services.NebulaWasActive
	result.RuntimeGateOpen = services.RuntimeGateWasOpen
}
