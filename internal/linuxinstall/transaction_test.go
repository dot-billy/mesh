//go:build linux

package linuxinstall

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/installtrust"
)

func TestPreparedFirstActivationCommitsCrashSafeOrder(t *testing.T) {
	candidate := testRelease(10, "a", "b", 2)
	prepared, err := prepareActivationState(nil, transactionTestPolicy(), candidate, ServiceSnapshot{}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	journal := newValidatingTransactionJournal(t, prepared)
	layout := &fakeTransactionLayout{}
	topology := &fakeTransactionTopology{}
	services := &fakeTransactionServices{}
	completed, err := executePreparedTransaction(context.Background(), journal, prepared, layout, topology, services)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Pending != nil || completed.Active == nil || *completed.Active != candidate || completed.Previous != nil {
		t.Fatalf("unexpected completed state: %+v", completed)
	}
	if got := journal.phases(); !reflect.DeepEqual(got, []TransactionPhase{PhaseServicesStopped, PhaseCurrentSwitched, ""}) {
		t.Fatalf("journal phases=%v", got)
	}
	if got := append(append([]string(nil), services.calls...), topology.calls...); len(got) == 0 {
		t.Fatal("transaction made no runtime or topology calls")
	}
	if !reflect.DeepEqual(services.calls, []string{"quiesce:none", "restore:" + candidate.InstalledID}) {
		t.Fatalf("service calls=%v", services.calls)
	}
	if !reflect.DeepEqual(topology.calls, []string{"ensure", "audit"}) || layout.current == nil || layout.current.InstalledID != candidate.InstalledID {
		t.Fatalf("topology calls=%v current=%+v", topology.calls, layout.current)
	}
}

func TestPreparedTransactionPersistsCompleteRuntimeIntent(t *testing.T) {
	candidate := testRelease(10, "a", "b", 2)
	want := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, NebulaWasActive: true, RuntimeGateWasOpen: true}
	prepared, err := prepareActivationState(nil, transactionTestPolicy(), candidate, want, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Pending == nil || !prepared.Pending.NebulaWasActive || pendingServiceSnapshot(*prepared.Pending) != want {
		t.Fatalf("runtime intent was not durably preserved: %+v", prepared.Pending)
	}
}

func TestActivationFailureAfterSwitchDurablyRollsBack(t *testing.T) {
	source := testRelease(9, "1", "2", 1)
	previous := testRelease(8, "3", "4", 1)
	prior := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: source, Active: &source, Previous: &previous,
	}
	candidate := testRelease(10, "5", "6", 2)
	prepared, err := prepareActivationState(&prior, transactionTestPolicy(), candidate, ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	journal := newValidatingTransactionJournal(t, prepared)
	layout := &fakeTransactionLayout{current: &source}
	topology := &fakeTransactionTopology{}
	services := &fakeTransactionServices{failRestoreID: candidate.InstalledID}
	rolledBack, err := executePreparedTransaction(context.Background(), journal, prepared, layout, topology, services)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("activation failure=%v", err)
	}
	if rolledBack.Pending != nil || rolledBack.Active == nil || *rolledBack.Active != source || rolledBack.Previous == nil || *rolledBack.Previous != previous {
		t.Fatalf("source state was not restored: %+v", rolledBack)
	}
	if rolledBack.HighWater != candidate {
		t.Fatal("automatic rollback lowered the authenticated high-water release")
	}
	if layout.current == nil || layout.current.InstalledID != source.InstalledID {
		t.Fatalf("current was not restored to source: %+v", layout.current)
	}
	if got := journal.phases(); !reflect.DeepEqual(got, []TransactionPhase{PhaseServicesStopped, PhaseCurrentSwitched, PhaseRollingBack, ""}) {
		t.Fatalf("journal phases=%v", got)
	}
	wantCalls := []string{
		"quiesce:" + source.InstalledID,
		"restore:" + candidate.InstalledID,
		"reload-quiesce:" + candidate.InstalledID,
		"restore:" + source.InstalledID,
	}
	if !reflect.DeepEqual(services.calls, wantCalls) {
		t.Fatalf("service calls=%v want=%v", services.calls, wantCalls)
	}
}

func TestAutomaticRollbackDetachesCanceledRequestContext(t *testing.T) {
	source := testRelease(9, "1", "2", 1)
	prior := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: source, Active: &source,
	}
	target := testRelease(10, "5", "6", 2)
	prepared, err := prepareActivationState(&prior, transactionTestPolicy(), target, ServiceSnapshot{}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	journal := newValidatingTransactionJournal(t, prepared)
	layout := &fakeTransactionLayout{current: &source}
	services := &fakeTransactionServices{failRestoreID: target.InstalledID}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executePreparedTransaction(ctx, journal, prepared, layout, &fakeTransactionTopology{}, services); err == nil {
		t.Fatal("injected activation failure was accepted")
	}
	wantCalls := []string{
		"quiesce:" + source.InstalledID,
		"restore:" + target.InstalledID,
		"reload-quiesce:" + target.InstalledID,
		"restore:" + source.InstalledID,
	}
	if !reflect.DeepEqual(services.calls, wantCalls) {
		t.Fatalf("service calls=%v want=%v", services.calls, wantCalls)
	}
	if len(services.contextErrors) != len(wantCalls) || services.contextErrors[0] == nil || services.contextErrors[1] == nil ||
		services.contextErrors[2] != nil || services.contextErrors[3] != nil {
		t.Fatalf("rollback did not detach canceled request context: %v", services.contextErrors)
	}
}

func TestRollingBackRecoveryDetachesCanceledRequestContext(t *testing.T) {
	source := testRelease(9, "1", "2", 1)
	prior := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: source, Active: &source,
	}
	target := testRelease(10, "5", "6", 2)
	state, err := prepareActivationState(&prior, transactionTestPolicy(), target, ServiceSnapshot{}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	state.Pending.Phase = PhaseRollingBack
	journal := newValidatingTransactionJournal(t, state)
	layout := &fakeTransactionLayout{current: &target}
	services := &fakeTransactionServices{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	completed, err := recoverPendingTransaction(ctx, journal, state, layout, &fakeTransactionTopology{}, services)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Pending != nil || completed.Active == nil || completed.Active.InstalledID != source.InstalledID {
		t.Fatalf("rollback recovery did not restore source: %+v", completed)
	}
	for index, contextErr := range services.contextErrors {
		if contextErr != nil {
			t.Fatalf("recovery service call %d received canceled context: %v", index, contextErr)
		}
	}
}

func TestAutomaticRollbackFailureRequiresRecoveryWithoutClaimingSuccess(t *testing.T) {
	source := testRelease(9, "1", "2", 1)
	prior := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: source, Active: &source,
	}
	target := testRelease(10, "5", "6", 2)
	prepared, err := prepareActivationState(&prior, transactionTestPolicy(), target, ServiceSnapshot{}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	services := &fakeTransactionServices{failRestoreID: target.InstalledID, failQuiesceID: target.InstalledID}
	_, err = executePreparedTransaction(context.Background(), newValidatingTransactionJournal(t, prepared), prepared,
		&fakeTransactionLayout{current: &source}, &fakeTransactionTopology{}, services)
	if err == nil || !strings.Contains(err.Error(), "automatic rollback is incomplete") ||
		!strings.Contains(err.Error(), "run mesh-install recover") || strings.Contains(err.Error(), "was rolled back") {
		t.Fatalf("incomplete rollback error=%v", err)
	}
}

func TestJournalCommitFailureStopsWithoutUnjournaledCompensation(t *testing.T) {
	candidate := testRelease(10, "a", "b", 2)
	prepared, err := prepareActivationState(nil, transactionTestPolicy(), candidate, ServiceSnapshot{}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	journal := newValidatingTransactionJournal(t, prepared)
	journal.failAt = 1
	layout := &fakeTransactionLayout{}
	topology := &fakeTransactionTopology{}
	services := &fakeTransactionServices{}
	state, err := executePreparedTransaction(context.Background(), journal, prepared, layout, topology, services)
	var commitFailure *journalCommitError
	if !errors.As(err, &commitFailure) {
		t.Fatalf("ambiguous journal failure was not surfaced: %v", err)
	}
	if !strings.Contains(err.Error(), "run mesh-install recover") || strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("ambiguous journal error made an unsupported live-state claim: %v", err)
	}
	if state.Pending == nil || state.Pending.Phase != PhasePrepared || layout.current != nil || len(topology.calls) != 0 {
		t.Fatalf("live mutation continued after journal failure: state=%+v current=%+v topology=%v", state, layout.current, topology.calls)
	}
	if !reflect.DeepEqual(services.calls, []string{"quiesce:none"}) {
		t.Fatalf("unexpected compensation after journal failure: %v", services.calls)
	}
}

func TestRecoveryRecognizesCurrentPointerAheadOfJournal(t *testing.T) {
	source := testRelease(9, "1", "2", 1)
	prior := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: source, Active: &source,
	}
	target := testRelease(10, "3", "4", 2)
	prepared, err := prepareActivationState(&prior, transactionTestPolicy(), target, ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	prepared.Pending.Phase = PhaseServicesStopped
	journal := newValidatingTransactionJournal(t, prepared)
	layout := &fakeTransactionLayout{current: &target}
	topology := &fakeTransactionTopology{}
	services := &fakeTransactionServices{}
	completed, err := recoverPendingTransaction(context.Background(), journal, prepared, layout, topology, services)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Pending != nil || completed.Active == nil || *completed.Active != target {
		t.Fatalf("recovery did not complete target: %+v", completed)
	}
	if got := journal.phases(); !reflect.DeepEqual(got, []TransactionPhase{PhaseCurrentSwitched, ""}) {
		t.Fatalf("recovery journal phases=%v", got)
	}
	want := []string{"reload-quiesce:" + target.InstalledID, "reload-quiesce:" + target.InstalledID, "restore:" + target.InstalledID}
	if !reflect.DeepEqual(services.calls, want) {
		t.Fatalf("recovery calls=%v want=%v", services.calls, want)
	}
}

func TestFirstActivationTopologyFailureRemovesOnlyManagedLinks(t *testing.T) {
	target := testRelease(10, "a", "b", 2)
	prepared, err := prepareActivationState(nil, transactionTestPolicy(), target, ServiceSnapshot{}, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	journal := newValidatingTransactionJournal(t, prepared)
	layout := &fakeTransactionLayout{}
	topology := &fakeTransactionTopology{failEnsure: errors.New("link collision")}
	services := &fakeTransactionServices{}
	rolledBack, err := executePreparedTransaction(context.Background(), journal, prepared, layout, topology, services)
	if err == nil || rolledBack.Pending != nil || rolledBack.Active != nil || rolledBack.HighWater != target {
		t.Fatalf("first activation rollback state=%+v err=%v", rolledBack, err)
	}
	if !reflect.DeepEqual(topology.calls, []string{"ensure", "remove"}) {
		t.Fatalf("first activation topology compensation=%v", topology.calls)
	}
	if !reflect.DeepEqual(services.calls, []string{"quiesce:none", "reload-absent"}) {
		t.Fatalf("first activation service compensation=%v", services.calls)
	}
}

func TestPrepareRollbackRetainsHighWaterAndExactDesiredRuntime(t *testing.T) {
	active := testRelease(12, "a", "b", 2)
	previous := testRelease(11, "c", "d", 1)
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: active, Active: &active, Previous: &previous,
	}
	services := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: false}
	prepared, err := prepareRollbackState(state, services, transactionTestTime())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.HighWater != active || prepared.Pending == nil || prepared.Pending.Operation != OperationRollback ||
		prepared.Pending.TargetActive != previous || !prepared.Pending.AgentWasEnabled || prepared.Pending.AgentWasActive {
		t.Fatalf("unexpected rollback preparation: %+v", prepared)
	}
}

type validatingTransactionJournal struct {
	t       *testing.T
	current State
	commits []State
	failAt  int
}

func newValidatingTransactionJournal(t *testing.T, initial State) *validatingTransactionJournal {
	t.Helper()
	if err := initial.Validate(); err != nil {
		t.Fatalf("invalid initial transaction state: %v", err)
	}
	return &validatingTransactionJournal{t: t, current: deepCopyState(initial)}
}

func (journal *validatingTransactionJournal) Commit(next State) error {
	if journal.failAt > 0 && len(journal.commits)+1 == journal.failAt {
		return errors.New("injected fsync ambiguity")
	}
	if err := validateCommittedTransition(stateSnapshot{found: true, state: journal.current}, next); err != nil {
		journal.t.Fatalf("invalid transaction transition: %v\ncurrent=%+v\nnext=%+v", err, journal.current, next)
	}
	journal.current = deepCopyState(next)
	journal.commits = append(journal.commits, deepCopyState(next))
	return nil
}

func (journal *validatingTransactionJournal) phases() []TransactionPhase {
	result := make([]TransactionPhase, 0, len(journal.commits))
	for _, state := range journal.commits {
		if state.Pending == nil {
			result = append(result, "")
		} else {
			result = append(result, state.Pending.Phase)
		}
	}
	return result
}

type fakeTransactionLayout struct {
	current *ReleaseIdentity
}

func (layout *fakeTransactionLayout) ReadCurrent() (CurrentRelease, bool, error) {
	if layout.current == nil {
		return CurrentRelease{}, false, nil
	}
	return CurrentRelease{InstalledID: layout.current.InstalledID, Target: "releases/" + layout.current.InstalledID}, true, nil
}

func (layout *fakeTransactionLayout) SwitchCurrent(identity ReleaseIdentity) error {
	copy := identity
	layout.current = &copy
	return nil
}

func (layout *fakeTransactionLayout) ClearCurrent(identity ReleaseIdentity) error {
	if layout.current != nil && layout.current.InstalledID != identity.InstalledID {
		return errors.New("clear mismatch")
	}
	layout.current = nil
	return nil
}

func (layout *fakeTransactionLayout) Audit(identity ReleaseIdentity) (ReleaseAudit, error) {
	return ReleaseAudit{InstalledID: identity.InstalledID, Published: true, Current: layout.current != nil && layout.current.InstalledID == identity.InstalledID}, nil
}

type fakeTransactionTopology struct {
	calls      []string
	failEnsure error
}

func (topology *fakeTransactionTopology) Ensure() error {
	topology.calls = append(topology.calls, "ensure")
	return topology.failEnsure
}

func (topology *fakeTransactionTopology) Audit() error {
	topology.calls = append(topology.calls, "audit")
	return nil
}

func (topology *fakeTransactionTopology) Remove() error {
	topology.calls = append(topology.calls, "remove")
	return nil
}

type fakeTransactionServices struct {
	calls         []string
	failRestoreID string
	failQuiesceID string
	contextErrors []error
}

func (services *fakeTransactionServices) record(ctx context.Context, call string) {
	services.calls = append(services.calls, call)
	services.contextErrors = append(services.contextErrors, ctx.Err())
}

func (services *fakeTransactionServices) quiesce(ctx context.Context, active *ReleaseIdentity, _ ServiceSnapshot) error {
	id := "none"
	if active != nil {
		id = active.InstalledID
	}
	services.record(ctx, "quiesce:"+id)
	return nil
}

func (services *fakeTransactionServices) forceQuiesce(ctx context.Context, active ReleaseIdentity) error {
	services.record(ctx, "force-quiesce:"+active.InstalledID)
	return nil
}

func (services *fakeTransactionServices) reloadAndQuiesce(ctx context.Context, active ReleaseIdentity) error {
	services.record(ctx, "reload-quiesce:"+active.InstalledID)
	if active.InstalledID == services.failQuiesceID {
		return errors.New("injected rollback quiesce failure")
	}
	return nil
}

func (services *fakeTransactionServices) reloadAndRestore(ctx context.Context, active ReleaseIdentity, _ ServiceSnapshot) error {
	services.record(ctx, "restore:"+active.InstalledID)
	if active.InstalledID == services.failRestoreID {
		return errors.New("injected start failure")
	}
	return nil
}

func (services *fakeTransactionServices) reloadAndAssertAbsent(ctx context.Context) error {
	services.record(ctx, "reload-absent")
	return nil
}

func transactionTestPolicy() installtrust.Policy {
	return installtrust.Policy{Channel: "stable", SHA256: strings.Repeat("f", 64)}
}

func transactionTestTime() time.Time {
	return time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
}

func (layout *fakeTransactionLayout) String() string {
	if layout.current == nil {
		return "none"
	}
	return fmt.Sprintf("current=%s", layout.current.InstalledID)
}
