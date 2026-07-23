package windowsinstall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testWindowsActivationJournal(t *testing.T) WindowsActivationJournal {
	t.Helper()
	authority := validAuthenticatedWindowsRelease(1, 1, 1, "a", "b")
	journal, err := NewWindowsActivationJournal(
		nil, authority, ".current-0123456789abcdef0123456789abcdef.json",
		false, false, false, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestWindowsActivationJournalCanonicalTransitions(t *testing.T) {
	journal := testWindowsActivationJournal(t)
	raw, err := MarshalWindowsActivationJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWindowsActivationJournal(raw)
	if err != nil || !reflect.DeepEqual(parsed, journal) {
		t.Fatalf("parsed=%#v error=%v", parsed, err)
	}
	quiesced, err := journal.WithPhase(WindowsActivationQuiesced)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := quiesced.WithPhase(WindowsActivationSelected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selected.WithPhase(WindowsActivationActivated); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.WithPhase(WindowsActivationSelected); err == nil {
		t.Fatal("phase skip accepted")
	}
	drifted := quiesced
	drifted.DesiredRuntimeGateOpen = false
	if err := validateWindowsActivationTransition(&journal, drifted); err == nil {
		t.Fatal("immutable desired-state drift accepted")
	}
}

func TestWindowsRollbackJournalBindsHighWaterAndPrevious(t *testing.T) {
	previous := validAuthenticatedWindowsRelease(1, 9, 1, "1", "2")
	previous.BundleSecurityFloor = 2
	active := validAuthenticatedWindowsRelease(1, 10, 2, "3", "4")
	state := validWindowsInstallState(active)
	state.Active = &active
	state.Previous = &previous
	journal, err := NewWindowsRollbackJournal(
		state, ".current-0123456789abcdef0123456789abcdef.json",
		true, true, true, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Operation != WindowsOperationRollback || journal.Authority != previous ||
		journal.SourceAuthority == nil || *journal.SourceAuthority != active || journal.HighWaterAuthority != active {
		t.Fatalf("Windows rollback journal = %+v", journal)
	}
	if finalized, err := authorizeWindowsTransactionState(state, journal); err != nil || finalized {
		t.Fatalf("Windows rollback authorization finalized=%t error=%v", finalized, err)
	}
	activatedJournal := journal
	activatedJournal.Phase = WindowsActivationActivated
	rolledBack, err := state.RollbackPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if !windowsStateReflectsFinalizedActivation(rolledBack, activatedJournal) {
		t.Fatal("committed Windows rollback was not recognized for response-loss recovery")
	}
	if windowsStateReflectsFinalizedActivation(state, activatedJournal) {
		t.Fatal("uncommitted Windows rollback was mistaken for finalized state")
	}
	if finalized, err := authorizeWindowsTransactionState(rolledBack, activatedJournal); err != nil || !finalized {
		t.Fatalf("Windows finalized rollback authorization finalized=%t error=%v", finalized, err)
	}
	wrongPrevious := state
	wrongPrevious.Previous = nil
	if _, err := authorizeWindowsTransactionState(wrongPrevious, journal); err == nil {
		t.Fatal("Windows rollback authorization accepted a missing previous target")
	}
	drifted := journal
	drifted.HighWaterAuthority = previous
	if err := drifted.Validate(); err == nil {
		t.Fatal("Windows rollback journal accepted lowered high-water authority")
	}
}

type recordingWindowsActivation struct {
	events         []string
	gateOpen       bool
	sourceStopped  bool
	selected       bool
	installed      bool
	running        bool
	failAt         string
	gateInspectErr error
}

func (operations *recordingWindowsActivation) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}
func (operations *recordingWindowsActivation) ValidateActivationJournal(WindowsActivationJournal) error {
	return operations.event("validate")
}
func (operations *recordingWindowsActivation) InspectRuntimeGate() (bool, error) {
	if err := operations.event("inspect-gate"); err != nil {
		return false, err
	}
	if operations.gateInspectErr != nil {
		return false, operations.gateInspectErr
	}
	return operations.gateOpen, nil
}
func (operations *recordingWindowsActivation) CloseRuntimeGate() error {
	if err := operations.event("close-gate"); err != nil {
		return err
	}
	operations.gateOpen = false
	operations.gateInspectErr = nil
	return nil
}
func (operations *recordingWindowsActivation) OpenRuntimeGate() error {
	if err := operations.event("open-gate"); err != nil {
		return err
	}
	operations.gateOpen = true
	return nil
}
func (operations *recordingWindowsActivation) QuiesceSourceService(context.Context) error {
	if err := operations.event("quiesce-source"); err != nil {
		return err
	}
	operations.sourceStopped = true
	return nil
}
func (operations *recordingWindowsActivation) SwitchCurrent() error {
	if err := operations.event("switch-current"); err != nil {
		return err
	}
	operations.selected = true
	return nil
}
func (operations *recordingWindowsActivation) InstallTargetService(context.Context) error {
	if err := operations.event("install-target"); err != nil {
		return err
	}
	operations.installed = true
	return nil
}
func (operations *recordingWindowsActivation) StartTargetService(context.Context) error {
	if err := operations.event("start-target"); err != nil {
		return err
	}
	operations.running = true
	return nil
}
func (operations *recordingWindowsActivation) StopTargetService(context.Context) error {
	if err := operations.event("stop-target"); err != nil {
		return err
	}
	operations.running = false
	return nil
}
func (operations *recordingWindowsActivation) ProveTarget(_ context.Context, running, gateOpen bool) error {
	if err := operations.event("prove-target"); err != nil {
		return err
	}
	if !operations.selected || !operations.installed || operations.running != running || operations.gateOpen != gateOpen {
		return errors.New("target proof mismatch")
	}
	return nil
}

type recordingWindowsJournalWriter struct {
	phases []WindowsActivationPhase
	failAt WindowsActivationPhase
}

func (writer *recordingWindowsJournalWriter) Advance(current *WindowsActivationJournal, next WindowsActivationJournal) error {
	if err := validateWindowsActivationTransition(current, next); err != nil {
		return err
	}
	if writer.failAt == next.Phase {
		return errors.New("injected journal failure")
	}
	writer.phases = append(writer.phases, next.Phase)
	return nil
}

func TestWindowsActivationOrdersGateSelectorServiceAndProof(t *testing.T) {
	journal := testWindowsActivationJournal(t)
	operations := &recordingWindowsActivation{gateOpen: true}
	writer := &recordingWindowsJournalWriter{}
	completed, err := advanceWindowsActivation(context.Background(), writer, operations, journal)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != WindowsActivationActivated || !operations.running || !operations.gateOpen {
		t.Fatalf("completion=%q operations=%+v", completed.Phase, operations)
	}
	wantPhases := []WindowsActivationPhase{WindowsActivationQuiesced, WindowsActivationSelected, WindowsActivationActivated}
	if !reflect.DeepEqual(writer.phases, wantPhases) {
		t.Fatalf("phases=%q want=%q", writer.phases, wantPhases)
	}
	closeIndex, switchIndex, openIndex, startIndex := -1, -1, -1, -1
	for index, event := range operations.events {
		switch event {
		case "close-gate":
			if closeIndex < 0 {
				closeIndex = index
			}
		case "switch-current":
			if switchIndex < 0 {
				switchIndex = index
			}
		case "open-gate":
			if openIndex < 0 {
				openIndex = index
			}
		case "start-target":
			if startIndex < 0 {
				startIndex = index
			}
		}
	}
	if !(closeIndex >= 0 && closeIndex < switchIndex && switchIndex < openIndex && openIndex < startIndex) {
		t.Fatalf("unsafe activation order: %q", operations.events)
	}
}

func TestWindowsSelectedActivationFailureQuarantinesRuntime(t *testing.T) {
	journal := testWindowsActivationJournal(t)
	journal.Phase = WindowsActivationSelected
	operations := &recordingWindowsActivation{selected: true, installed: true, failAt: "start-target"}
	_, err := advanceWindowsActivation(context.Background(), &recordingWindowsJournalWriter{}, operations, journal)
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("error=%v", err)
	}
	if operations.gateOpen || operations.running {
		t.Fatalf("failed activation was not quarantined: %+v", operations)
	}
	if got := operations.events[len(operations.events)-2:]; !reflect.DeepEqual(got, []string{"close-gate", "stop-target"}) {
		t.Fatalf("quarantine tail=%q", got)
	}
}

func TestWindowsActivationClosesInterruptedGatePublication(t *testing.T) {
	journal := testWindowsActivationJournal(t)
	operations := &recordingWindowsActivation{gateInspectErr: errWindowsRuntimeGatePublicationPending}
	completed, err := advanceWindowsActivation(context.Background(), &recordingWindowsJournalWriter{}, operations, journal)
	if err != nil || completed.Phase != WindowsActivationActivated {
		t.Fatalf("completed=%q error=%v events=%q", completed.Phase, err, operations.events)
	}
	if len(operations.events) < 2 || operations.events[0] != "validate" || operations.events[1] != "inspect-gate" {
		t.Fatalf("unexpected interrupted-gate events %q", operations.events)
	}
}

func TestWindowsActivatedJournalPublicationFailureQuarantinesRuntime(t *testing.T) {
	journal := testWindowsActivationJournal(t)
	journal.Phase = WindowsActivationSelected
	operations := &recordingWindowsActivation{selected: true, installed: true}
	writer := &recordingWindowsJournalWriter{failAt: WindowsActivationActivated}
	_, err := advanceWindowsActivation(context.Background(), writer, operations, journal)
	if err == nil || !strings.Contains(err.Error(), "journal failure") {
		t.Fatalf("error=%v", err)
	}
	if operations.gateOpen || operations.running {
		t.Fatalf("journal publication failure remained active: %+v", operations)
	}
}

func TestWindowsActivatedJournalReconcilesExactDesiredState(t *testing.T) {
	journal := testWindowsActivationJournal(t)
	journal.Phase = WindowsActivationActivated
	operations := &recordingWindowsActivation{}
	completed, err := advanceWindowsActivation(context.Background(), &recordingWindowsJournalWriter{}, operations, journal)
	if err != nil || completed.Phase != WindowsActivationActivated || !operations.running || !operations.gateOpen {
		t.Fatalf("completed=%q operations=%+v error=%v", completed.Phase, operations, err)
	}
}
