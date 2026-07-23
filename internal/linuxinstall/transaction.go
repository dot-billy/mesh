//go:build linux

package linuxinstall

import (
	"context"
	"errors"
	"fmt"
	"time"

	"mesh/internal/installtrust"
)

var ErrReleaseAlreadyActive = errors.New("authenticated release is already active")

// A target-side rollback can require reloadAndQuiesce followed by a complete
// source reload/restore. Each systemctl call has its own 30-second bound and
// the restored runtime has a separate three-minute readiness bound; fifteen
// minutes covers the longest reviewed sequence plus filesystem and journal
// overhead.
const installerCleanupTimeout = 15 * time.Minute

type transactionJournal interface {
	Commit(State) error
}

type transactionLayout interface {
	ReadCurrent() (CurrentRelease, bool, error)
	SwitchCurrent(ReleaseIdentity) error
	ClearCurrent(ReleaseIdentity) error
	Audit(ReleaseIdentity) (ReleaseAudit, error)
}

type transactionTopology interface {
	Ensure() error
	Audit() error
	Remove() error
}

type transactionServices interface {
	quiesce(context.Context, *ReleaseIdentity, ServiceSnapshot) error
	forceQuiesce(context.Context, ReleaseIdentity) error
	reloadAndQuiesce(context.Context, ReleaseIdentity) error
	reloadAndRestore(context.Context, ReleaseIdentity, ServiceSnapshot) error
	reloadAndAssertAbsent(context.Context) error
}

type journalCommitError struct{ cause error }

func (failure *journalCommitError) Error() string {
	return "installer journal commit outcome is ambiguous; do not start another install; run mesh-install recover: " + failure.cause.Error()
}

func (failure *journalCommitError) Unwrap() error { return failure.cause }

func prepareActivationState(prior *State, policy installtrust.Policy, candidate ReleaseIdentity, services ServiceSnapshot, startedAt time.Time) (State, error) {
	if err := candidate.Validate(); err != nil {
		return State{}, err
	}
	started := startedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	if _, err := parseCanonicalTime(started); err != nil || startedAt.IsZero() {
		return State{}, errors.New("transaction start time must be nonzero")
	}
	if !channelPattern.MatchString(policy.Channel) || !lowerHex64Pattern.MatchString(policy.SHA256) {
		return State{}, errors.New("compiled installer policy identity is invalid")
	}
	var next State
	if prior == nil {
		next = State{
			Schema: LegacyStateSchema, TrustPolicySHA256: policy.SHA256, Channel: policy.Channel,
			HighWater: candidate,
		}
	} else {
		if err := prior.Validate(); err != nil {
			return State{}, err
		}
		if prior.Pending != nil {
			return State{}, errors.New("an unfinished transaction must be recovered before another activation")
		}
		if prior.TrustPolicySHA256 != policy.SHA256 || prior.Channel != policy.Channel {
			return State{}, errors.New("compiled installer policy differs from persisted state")
		}
		if prior.Active != nil && sameAuthenticatedRelease(*prior.Active, candidate) {
			return State{}, ErrReleaseAlreadyActive
		}
		if err := prior.CheckCandidate(candidate); err != nil {
			return State{}, err
		}
		next = deepCopyState(*prior)
		next.HighWater = candidate
	}
	next.Pending = &PendingTransaction{
		Operation: OperationActivate, Candidate: candidate,
		SourceActive: deepCopyReleasePointer(next.Active), SourcePrevious: deepCopyReleasePointer(next.Previous),
		TargetActive: candidate, Phase: PhasePrepared,
		AgentWasEnabled: services.AgentWasEnabled, AgentWasActive: services.AgentWasActive,
		NebulaWasActive: services.NebulaWasActive, RuntimeGateWasOpen: services.RuntimeGateWasOpen,
		StartedAt: started,
	}
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	return next, nil
}

func prepareRootedActivationState(prior *State, bootstrap installtrust.Bootstrap, candidate ReleaseIdentity, services ServiceSnapshot, startedAt time.Time) (State, error) {
	if err := candidate.validateForStateSchema(StateSchemaV3); err != nil {
		return State{}, err
	}
	started := startedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	if _, err := parseCanonicalTime(started); err != nil || startedAt.IsZero() {
		return State{}, errors.New("transaction start time must be nonzero")
	}
	if !lowerHex64Pattern.MatchString(bootstrap.SHA256) || !lowerHex64Pattern.MatchString(bootstrap.InitialRootSHA256) ||
		bootstrap.InitialRoot.Document.Version != 1 || bootstrap.InitialRoot.Document.ReleaseEpoch != 1 ||
		!channelPattern.MatchString(bootstrap.InitialRoot.Document.Channel) {
		return State{}, errors.New("compiled installer bootstrap identity is invalid")
	}
	var next State
	if prior == nil {
		next = State{
			Schema: StateSchemaV3, BootstrapTrustSHA256: bootstrap.SHA256,
			Channel: bootstrap.InitialRoot.Document.Channel, HighWater: candidate,
		}
	} else {
		if err := prior.Validate(); err != nil {
			return State{}, err
		}
		if prior.Schema != StateSchemaV3 {
			return State{}, errors.New("root-aware activation requires migrated installer state v3")
		}
		if prior.Pending != nil {
			return State{}, errors.New("an unfinished transaction must be recovered before another activation")
		}
		if prior.BootstrapTrustSHA256 != bootstrap.SHA256 || prior.Channel != bootstrap.InitialRoot.Document.Channel {
			return State{}, errors.New("compiled installer bootstrap differs from persisted state")
		}
		if prior.Active != nil && sameAuthenticatedReleaseIgnoringInstalledID(*prior.Active, candidate) {
			return State{}, ErrReleaseAlreadyActive
		}
		if err := prior.CheckCandidate(candidate); err != nil {
			return State{}, err
		}
		next = deepCopyState(*prior)
		next.HighWater = candidate
	}
	next.Pending = &PendingTransaction{
		Operation: OperationActivate, Candidate: candidate,
		SourceActive: deepCopyReleasePointer(next.Active), SourcePrevious: deepCopyReleasePointer(next.Previous),
		TargetActive: candidate, Phase: PhasePrepared,
		AgentWasEnabled: services.AgentWasEnabled, AgentWasActive: services.AgentWasActive,
		NebulaWasActive: services.NebulaWasActive, RuntimeGateWasOpen: services.RuntimeGateWasOpen,
		StartedAt: started,
	}
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	return next, nil
}

func sameAuthenticatedReleaseIgnoringInstalledID(left, right ReleaseIdentity) bool {
	left.InstalledID = ""
	right.InstalledID = ""
	return left == right
}

func prepareRollbackState(prior State, services ServiceSnapshot, startedAt time.Time) (State, error) {
	if err := prior.Validate(); err != nil {
		return State{}, err
	}
	if prior.Pending != nil {
		return State{}, errors.New("an unfinished transaction must be recovered before rollback")
	}
	if prior.Active == nil || prior.Previous == nil {
		return State{}, errors.New("rollback requires active and previous releases")
	}
	started := startedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	if _, err := parseCanonicalTime(started); err != nil || startedAt.IsZero() {
		return State{}, errors.New("transaction start time must be nonzero")
	}
	next := deepCopyState(prior)
	next.Pending = &PendingTransaction{
		Operation: OperationRollback, Candidate: next.HighWater,
		SourceActive: deepCopyReleasePointer(next.Active), SourcePrevious: deepCopyReleasePointer(next.Previous),
		TargetActive: *next.Previous, Phase: PhasePrepared,
		AgentWasEnabled: services.AgentWasEnabled, AgentWasActive: services.AgentWasActive,
		NebulaWasActive: services.NebulaWasActive, RuntimeGateWasOpen: services.RuntimeGateWasOpen,
		StartedAt: started,
	}
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	return next, nil
}

func executePreparedTransaction(ctx context.Context, journal transactionJournal, state State, layout transactionLayout, topology transactionTopology, services transactionServices) (State, error) {
	if err := validateTransactionDependencies(journal, layout, topology, services); err != nil {
		return state, err
	}
	if err := state.Validate(); err != nil || state.Pending == nil || state.Pending.Phase != PhasePrepared {
		return state, errors.New("prepared installer transaction is required")
	}
	if err := requireCurrentSource(layout, *state.Pending); err != nil {
		return state, err
	}
	desired := pendingServiceSnapshot(*state.Pending)
	if err := services.quiesce(ctx, state.Pending.SourceActive, desired); err != nil {
		return rollbackAfterOperationFailure(ctx, journal, state, layout, topology, services, fmt.Errorf("quiesce managed services: %w", err))
	}
	var err error
	state, err = commitPendingPhase(journal, state, PhaseServicesStopped)
	if err != nil {
		return state, err
	}
	if err := topology.Ensure(); err != nil {
		return rollbackAfterOperationFailure(ctx, journal, state, layout, topology, services, fmt.Errorf("establish managed links: %w", err))
	}
	if err := layout.SwitchCurrent(state.Pending.TargetActive); err != nil {
		return rollbackAfterOperationFailure(ctx, journal, state, layout, topology, services, fmt.Errorf("switch current release: %w", err))
	}
	state, err = commitPendingPhase(journal, state, PhaseCurrentSwitched)
	if err != nil {
		return state, err
	}
	if err := topology.Audit(); err != nil {
		return rollbackAfterOperationFailure(ctx, journal, state, layout, topology, services, fmt.Errorf("audit managed links after switch: %w", err))
	}
	if err := services.reloadAndRestore(ctx, state.Pending.TargetActive, desired); err != nil {
		return rollbackAfterOperationFailure(ctx, journal, state, layout, topology, services, fmt.Errorf("activate switched release: %w", err))
	}
	return completePendingTransaction(journal, state)
}

func recoverPendingTransaction(ctx context.Context, journal transactionJournal, state State, layout transactionLayout, topology transactionTopology, services transactionServices) (State, error) {
	if err := validateTransactionDependencies(journal, layout, topology, services); err != nil {
		return state, err
	}
	if err := state.Validate(); err != nil || state.Pending == nil {
		return state, errors.New("pending installer transaction is required")
	}
	if state.Pending.Phase == PhaseRollingBack {
		return rollbackPendingTransaction(ctx, journal, state, layout, topology, services)
	}
	var err error
	switch state.Pending.Phase {
	case PhasePrepared:
		role, roleErr := currentTransactionRole(layout, *state.Pending)
		if roleErr != nil {
			return state, roleErr
		}
		switch role {
		case currentIsSource:
			if state.Pending.SourceActive == nil {
				err = services.quiesce(ctx, nil, ServiceSnapshot{})
			} else {
				err = services.forceQuiesce(ctx, *state.Pending.SourceActive)
			}
		case currentIsTarget:
			if err = topology.Ensure(); err == nil {
				err = services.reloadAndQuiesce(ctx, state.Pending.TargetActive)
			}
		default:
			err = errors.New("prepared transaction current pointer is neither source nor target")
		}
		if err != nil {
			return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
		}
		state, err = commitPendingPhase(journal, state, PhaseServicesStopped)
		if err != nil {
			return state, err
		}
		if role == currentIsTarget {
			state, err = commitPendingPhase(journal, state, PhaseCurrentSwitched)
			if err != nil {
				return state, err
			}
		}
		fallthrough
	case PhaseServicesStopped:
		if state.Pending.Phase == PhaseServicesStopped {
			role, roleErr := currentTransactionRole(layout, *state.Pending)
			if roleErr != nil {
				return state, roleErr
			}
			switch role {
			case currentIsSource:
				if state.Pending.SourceActive != nil {
					err = services.forceQuiesce(ctx, *state.Pending.SourceActive)
				}
				if err == nil {
					err = topology.Ensure()
				}
				if err == nil {
					err = layout.SwitchCurrent(state.Pending.TargetActive)
				}
			case currentIsTarget:
				if err = topology.Ensure(); err == nil {
					err = services.reloadAndQuiesce(ctx, state.Pending.TargetActive)
				}
			default:
				err = errors.New("services-stopped transaction current pointer is neither source nor target")
			}
			if err != nil {
				return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
			}
			state, err = commitPendingPhase(journal, state, PhaseCurrentSwitched)
			if err != nil {
				return state, err
			}
		}
		fallthrough
	case PhaseCurrentSwitched:
		if err := requireCurrentTarget(layout, *state.Pending); err != nil {
			return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
		}
		if err := topology.Ensure(); err != nil {
			return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
		}
		if err := topology.Audit(); err != nil {
			return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
		}
		if err := services.reloadAndQuiesce(ctx, state.Pending.TargetActive); err != nil {
			return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
		}
		if err := services.reloadAndRestore(ctx, state.Pending.TargetActive, pendingServiceSnapshot(*state.Pending)); err != nil {
			return recoverOperationFailure(ctx, journal, state, layout, topology, services, err)
		}
		return completePendingTransaction(journal, state)
	default:
		return state, fmt.Errorf("unsupported recovery phase %q", state.Pending.Phase)
	}
}

func recoverOperationFailure(ctx context.Context, journal transactionJournal, state State, layout transactionLayout, topology transactionTopology, services transactionServices, cause error) (State, error) {
	rolledBack, rollbackErr := rollbackPendingTransaction(ctx, journal, state, layout, topology, services)
	if rollbackErr != nil {
		return rolledBack, errors.Join(
			fmt.Errorf("resume installer transaction: %w", cause),
			fmt.Errorf("automatic rollback is incomplete; run mesh-install recover: %w", rollbackErr),
		)
	}
	return rolledBack, fmt.Errorf("resume installer transaction failed and was rolled back: %w", cause)
}

func rollbackAfterOperationFailure(ctx context.Context, journal transactionJournal, state State, layout transactionLayout, topology transactionTopology, services transactionServices, cause error) (State, error) {
	rolledBack, rollbackErr := rollbackPendingTransaction(ctx, journal, state, layout, topology, services)
	if rollbackErr != nil {
		return rolledBack, errors.Join(cause, fmt.Errorf("automatic rollback is incomplete; run mesh-install recover: %w", rollbackErr))
	}
	return rolledBack, fmt.Errorf("installer transaction was rolled back: %w", cause)
}

func rollbackPendingTransaction(ctx context.Context, journal transactionJournal, state State, layout transactionLayout, topology transactionTopology, services transactionServices) (State, error) {
	if err := state.Validate(); err != nil || state.Pending == nil {
		return state, errors.New("pending installer transaction is required for rollback")
	}
	var err error
	if state.Pending.Phase != PhaseRollingBack {
		state, err = commitPendingPhase(journal, state, PhaseRollingBack)
		if err != nil {
			return state, err
		}
	}
	// Once rollback intent is durable, request cancellation must not strand a
	// live process behind a merely closed runtime gate. Use a fresh bounded
	// context for every stop/reload/restore proof in compensation and recovery.
	cleanupContext, cancelCleanup := newInstallerCleanupContext(ctx)
	defer cancelCleanup()
	pending := *state.Pending
	role, err := currentTransactionRole(layout, pending)
	if err != nil {
		return state, err
	}
	switch role {
	case currentIsTarget:
		if err := topology.Ensure(); err != nil {
			return state, err
		}
		if err := services.reloadAndQuiesce(cleanupContext, pending.TargetActive); err != nil {
			return state, err
		}
	case currentIsSource:
		if pending.SourceActive != nil {
			if err := services.forceQuiesce(cleanupContext, *pending.SourceActive); err != nil {
				return state, err
			}
		}
	default:
		return state, errors.New("rollback current pointer is neither transaction source nor target")
	}
	if pending.SourceActive == nil {
		if role == currentIsTarget {
			if err := layout.ClearCurrent(pending.TargetActive); err != nil {
				return state, err
			}
		}
		if err := topology.Remove(); err != nil {
			return state, err
		}
		if err := services.reloadAndAssertAbsent(cleanupContext); err != nil {
			return state, err
		}
	} else {
		if role == currentIsTarget {
			if err := layout.SwitchCurrent(*pending.SourceActive); err != nil {
				return state, err
			}
		}
		if err := topology.Audit(); err != nil {
			return state, err
		}
		if err := services.reloadAndRestore(cleanupContext, *pending.SourceActive, pendingServiceSnapshot(pending)); err != nil {
			return state, err
		}
	}
	next := deepCopyState(state)
	next.Active = deepCopyReleasePointer(pending.SourceActive)
	next.Previous = deepCopyReleasePointer(pending.SourcePrevious)
	next.Pending = nil
	if err := journal.Commit(next); err != nil {
		return state, &journalCommitError{cause: err}
	}
	return next, nil
}

func newInstallerCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), installerCleanupTimeout)
}

func commitPendingPhase(journal transactionJournal, state State, phase TransactionPhase) (State, error) {
	if state.Pending == nil {
		return state, errors.New("pending transaction is required")
	}
	next := deepCopyState(state)
	next.Pending.Phase = phase
	if err := journal.Commit(next); err != nil {
		return state, &journalCommitError{cause: err}
	}
	return next, nil
}

func completePendingTransaction(journal transactionJournal, state State) (State, error) {
	if state.Pending == nil || state.Pending.Phase != PhaseCurrentSwitched {
		return state, errors.New("current-switched transaction is required for completion")
	}
	next := deepCopyState(state)
	target := next.Pending.TargetActive
	source := deepCopyReleasePointer(next.Pending.SourceActive)
	next.Active = &target
	next.Previous = source
	next.Pending = nil
	if err := journal.Commit(next); err != nil {
		return state, &journalCommitError{cause: err}
	}
	return next, nil
}

type transactionCurrentRole uint8

const (
	currentIsUnknown transactionCurrentRole = iota
	currentIsSource
	currentIsTarget
)

func currentTransactionRole(layout transactionLayout, pending PendingTransaction) (transactionCurrentRole, error) {
	current, exists, err := layout.ReadCurrent()
	if err != nil {
		return currentIsUnknown, err
	}
	if !exists {
		if pending.SourceActive == nil {
			return currentIsSource, nil
		}
		return currentIsUnknown, nil
	}
	if current.InstalledID == pending.TargetActive.InstalledID {
		return currentIsTarget, nil
	}
	if pending.SourceActive != nil && current.InstalledID == pending.SourceActive.InstalledID {
		return currentIsSource, nil
	}
	return currentIsUnknown, nil
}

func requireCurrentSource(layout transactionLayout, pending PendingTransaction) error {
	role, err := currentTransactionRole(layout, pending)
	if err != nil {
		return err
	}
	if role != currentIsSource {
		return errors.New("prepared transaction current pointer does not match its source release")
	}
	return nil
}

func requireCurrentTarget(layout transactionLayout, pending PendingTransaction) error {
	role, err := currentTransactionRole(layout, pending)
	if err != nil {
		return err
	}
	if role != currentIsTarget {
		return errors.New("current pointer does not match the transaction target release")
	}
	return nil
}

func pendingServiceSnapshot(pending PendingTransaction) ServiceSnapshot {
	return ServiceSnapshot{
		AgentWasEnabled:    pending.AgentWasEnabled,
		AgentWasActive:     pending.AgentWasActive,
		NebulaWasActive:    pending.NebulaWasActive,
		RuntimeGateWasOpen: pending.RuntimeGateWasOpen,
	}
}

func validateTransactionDependencies(journal transactionJournal, layout transactionLayout, topology transactionTopology, services transactionServices) error {
	if journal == nil || layout == nil || topology == nil || services == nil {
		return errors.New("complete installer transaction dependencies are required")
	}
	return nil
}
