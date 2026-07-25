package windowsinstall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testWindowsRuntimeUninstallJournal(t *testing.T) WindowsRuntimeUninstallJournal {
	t.Helper()
	active := validAuthenticatedWindowsRelease(2, 7, 4, "a", "b")
	previous := validAuthenticatedWindowsRelease(2, 6, 4, "c", "d")
	state := validWindowsInstallState(active)
	state.Active = &active
	state.Previous = &previous
	journal, err := NewWindowsRuntimeUninstallJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestWindowsRuntimeUninstallJournalCanonicalTransitions(t *testing.T) {
	journal := testWindowsRuntimeUninstallJournal(t)
	raw, err := MarshalWindowsRuntimeUninstallJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWindowsRuntimeUninstallJournal(raw)
	if err != nil || !reflect.DeepEqual(parsed, journal) {
		t.Fatalf("parsed=%#v error=%v", parsed, err)
	}

	next := journal
	next.Phase = WindowsUninstallGateClosed
	if err := validateWindowsRuntimeUninstallTransition(&journal, next); err != nil {
		t.Fatal(err)
	}
	skipped := journal
	skipped.Phase = WindowsUninstallServiceStopped
	if err := validateWindowsRuntimeUninstallTransition(&journal, skipped); err == nil {
		t.Fatal("phase skip accepted")
	}
	drifted := next
	drifted.Source.HighWater.Sequence++
	if err := validateWindowsRuntimeUninstallTransition(&journal, drifted); err == nil {
		t.Fatal("immutable uninstall authority drift accepted")
	}
	if _, err := ParseWindowsRuntimeUninstallJournal(append(raw, '\n')); err == nil {
		t.Fatal("non-canonical trailing byte accepted")
	}
	unknown := strings.Replace(string(raw), `"phase":`, `"unknown":false,"phase":`, 1)
	if _, err := ParseWindowsRuntimeUninstallJournal([]byte(unknown)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

type recordingWindowsRuntimeUninstall struct {
	events           []string
	gateOpen         bool
	serviceInstalled bool
	serviceRunning   bool
	current          *CurrentDescriptor
	state            WindowsInstallState
	failAt           string
}

func (operations *recordingWindowsRuntimeUninstall) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingWindowsRuntimeUninstall) ValidateRuntimeUninstall(WindowsRuntimeUninstallJournal) error {
	return operations.event("validate")
}

func (operations *recordingWindowsRuntimeUninstall) InspectRuntimeGate() (bool, error) {
	if err := operations.event("inspect-gate"); err != nil {
		return false, err
	}
	return operations.gateOpen, nil
}

func (operations *recordingWindowsRuntimeUninstall) CloseRuntimeGate() error {
	if err := operations.event("close-gate"); err != nil {
		return err
	}
	operations.gateOpen = false
	return nil
}

func (operations *recordingWindowsRuntimeUninstall) InspectService() (bool, bool, error) {
	if err := operations.event("inspect-service"); err != nil {
		return false, false, err
	}
	return operations.serviceInstalled, operations.serviceRunning, nil
}

func (operations *recordingWindowsRuntimeUninstall) StopService(context.Context) error {
	if err := operations.event("stop-service"); err != nil {
		return err
	}
	operations.serviceRunning = false
	return nil
}

func (operations *recordingWindowsRuntimeUninstall) DeleteService(context.Context) error {
	if err := operations.event("delete-service"); err != nil {
		return err
	}
	operations.serviceInstalled = false
	operations.serviceRunning = false
	return nil
}

func (operations *recordingWindowsRuntimeUninstall) InspectCurrent() (*CurrentDescriptor, error) {
	if err := operations.event("inspect-current"); err != nil {
		return nil, err
	}
	return cloneCurrentDescriptor(operations.current), nil
}

func (operations *recordingWindowsRuntimeUninstall) RemoveCurrent(expected CurrentDescriptor) error {
	if err := operations.event("remove-current"); err != nil {
		return err
	}
	if operations.current == nil || *operations.current != expected {
		return errors.New("unexpected current")
	}
	operations.current = nil
	return nil
}

func (operations *recordingWindowsRuntimeUninstall) InspectInstallState() (*WindowsInstallState, error) {
	if err := operations.event("inspect-state"); err != nil {
		return nil, err
	}
	copy := cloneWindowsInstallState(operations.state)
	return &copy, nil
}

func (operations *recordingWindowsRuntimeUninstall) DeactivateInstallState(expected WindowsInstallState) error {
	if err := operations.event("deactivate-state"); err != nil {
		return err
	}
	if !reflect.DeepEqual(operations.state, expected) {
		return errors.New("unexpected install state")
	}
	next, err := expected.DeactivateRuntime()
	if err != nil {
		return err
	}
	operations.state = next
	return nil
}

type recordingWindowsRuntimeUninstallWriter struct {
	phases []WindowsRuntimeUninstallPhase
	failAt WindowsRuntimeUninstallPhase
}

func (writer *recordingWindowsRuntimeUninstallWriter) AdvanceRuntimeUninstall(current *WindowsRuntimeUninstallJournal, next WindowsRuntimeUninstallJournal) error {
	if err := validateWindowsRuntimeUninstallTransition(current, next); err != nil {
		return err
	}
	if writer.failAt == next.Phase {
		return errors.New("injected journal failure")
	}
	writer.phases = append(writer.phases, next.Phase)
	return nil
}

func operationsForWindowsRuntimeUninstall(journal WindowsRuntimeUninstallJournal) *recordingWindowsRuntimeUninstall {
	return &recordingWindowsRuntimeUninstall{
		gateOpen: true, serviceInstalled: true, serviceRunning: true,
		current: cloneCurrentDescriptor(&journal.Current), state: cloneWindowsInstallState(journal.Source),
	}
}

func TestWindowsRuntimeUninstallOrdersGateServiceSelectorAndState(t *testing.T) {
	journal := testWindowsRuntimeUninstallJournal(t)
	operations := operationsForWindowsRuntimeUninstall(journal)
	writer := &recordingWindowsRuntimeUninstallWriter{}
	completed, err := advanceWindowsRuntimeUninstall(context.Background(), writer, operations, journal)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != WindowsUninstallStateDeactivated || operations.gateOpen || operations.serviceInstalled || operations.current != nil || operations.state.Active != nil || operations.state.Previous != nil {
		t.Fatalf("completion=%q operations=%+v", completed.Phase, operations)
	}
	wantPhases := []WindowsRuntimeUninstallPhase{
		WindowsUninstallGateClosed, WindowsUninstallServiceStopped, WindowsUninstallServiceDeleted,
		WindowsUninstallCurrentRemoved, WindowsUninstallStateDeactivated,
	}
	if !reflect.DeepEqual(writer.phases, wantPhases) {
		t.Fatalf("phases=%q want=%q", writer.phases, wantPhases)
	}
	positions := map[string]int{}
	for index, event := range operations.events {
		if _, found := positions[event]; !found {
			positions[event] = index
		}
	}
	if !(positions["close-gate"] < positions["stop-service"] && positions["stop-service"] < positions["delete-service"] &&
		positions["delete-service"] < positions["remove-current"] && positions["remove-current"] < positions["deactivate-state"]) {
		t.Fatalf("unsafe uninstall order: %q", operations.events)
	}
}

func TestWindowsRuntimeUninstallRecoversResponseLossAtEveryJournalBoundary(t *testing.T) {
	for _, lostPhase := range []WindowsRuntimeUninstallPhase{
		WindowsUninstallGateClosed, WindowsUninstallServiceStopped, WindowsUninstallServiceDeleted,
		WindowsUninstallCurrentRemoved, WindowsUninstallStateDeactivated,
	} {
		t.Run(string(lostPhase), func(t *testing.T) {
			journal := testWindowsRuntimeUninstallJournal(t)
			operations := operationsForWindowsRuntimeUninstall(journal)
			switch lostPhase {
			case WindowsUninstallGateClosed:
				operations.gateOpen = false
			case WindowsUninstallServiceStopped:
				journal.Phase = WindowsUninstallGateClosed
				operations.gateOpen = false
				operations.serviceRunning = false
			case WindowsUninstallServiceDeleted:
				journal.Phase = WindowsUninstallServiceStopped
				operations.gateOpen = false
				operations.serviceInstalled = false
				operations.serviceRunning = false
			case WindowsUninstallCurrentRemoved:
				journal.Phase = WindowsUninstallServiceDeleted
				operations.gateOpen = false
				operations.serviceInstalled = false
				operations.serviceRunning = false
				operations.current = nil
			case WindowsUninstallStateDeactivated:
				journal.Phase = WindowsUninstallCurrentRemoved
				operations.gateOpen = false
				operations.serviceInstalled = false
				operations.serviceRunning = false
				operations.current = nil
				operations.state, _ = journal.Source.DeactivateRuntime()
			}
			completed, err := advanceWindowsRuntimeUninstall(context.Background(), &recordingWindowsRuntimeUninstallWriter{}, operations, journal)
			if err != nil || completed.Phase != WindowsUninstallStateDeactivated {
				t.Fatalf("completion=%q error=%v events=%q", completed.Phase, err, operations.events)
			}
		})
	}
}

func TestWindowsRuntimeUninstallRejectsObservedAuthorityDrift(t *testing.T) {
	journal := testWindowsRuntimeUninstallJournal(t)

	wrongCurrent := operationsForWindowsRuntimeUninstall(journal)
	journalAtCurrent := journal
	journalAtCurrent.Phase = WindowsUninstallServiceDeleted
	wrong := *wrongCurrent.current
	wrong.SecurityFloor++
	wrongCurrent.current = &wrong
	wrongCurrent.gateOpen = false
	wrongCurrent.serviceInstalled = false
	wrongCurrent.serviceRunning = false
	if _, err := advanceWindowsRuntimeUninstall(context.Background(), &recordingWindowsRuntimeUninstallWriter{}, wrongCurrent, journalAtCurrent); err == nil || !strings.Contains(err.Error(), "unexpected current") {
		t.Fatalf("unexpected current error=%v", err)
	}

	wrongState := operationsForWindowsRuntimeUninstall(journal)
	journalAtState := journal
	journalAtState.Phase = WindowsUninstallCurrentRemoved
	wrongState.gateOpen = false
	wrongState.serviceInstalled = false
	wrongState.serviceRunning = false
	wrongState.current = nil
	wrongState.state.HighWater.Sequence++
	if _, err := advanceWindowsRuntimeUninstall(context.Background(), &recordingWindowsRuntimeUninstallWriter{}, wrongState, journalAtState); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("unexpected state error=%v", err)
	}

	runningService := operationsForWindowsRuntimeUninstall(journal)
	journalAtDelete := journal
	journalAtDelete.Phase = WindowsUninstallServiceStopped
	runningService.gateOpen = false
	if _, err := advanceWindowsRuntimeUninstall(context.Background(), &recordingWindowsRuntimeUninstallWriter{}, runningService, journalAtDelete); err == nil || !strings.Contains(err.Error(), "safely stopped") {
		t.Fatalf("running service error=%v", err)
	}
}
