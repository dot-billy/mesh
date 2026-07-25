package windowsinstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingWindowsRuntimeGateOperations struct {
	events  []string
	live    windowsRuntimeGateFileState
	pending windowsRuntimeGateFileState
	failAt  string
}

func (operations *recordingWindowsRuntimeGateOperations) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingWindowsRuntimeGateOperations) InspectLive() (windowsRuntimeGateFileState, error) {
	if err := operations.event("inspect-live"); err != nil {
		return windowsRuntimeGateAbsent, err
	}
	return operations.live, nil
}
func (operations *recordingWindowsRuntimeGateOperations) InspectPending() (windowsRuntimeGateFileState, error) {
	if err := operations.event("inspect-pending"); err != nil {
		return windowsRuntimeGateAbsent, err
	}
	return operations.pending, nil
}
func (operations *recordingWindowsRuntimeGateOperations) CreatePending() error {
	if err := operations.event("create-pending"); err != nil {
		return err
	}
	operations.pending = windowsRuntimeGateComplete
	return nil
}
func (operations *recordingWindowsRuntimeGateOperations) SyncPending() error {
	return operations.event("sync-pending")
}
func (operations *recordingWindowsRuntimeGateOperations) RemoveLive() error {
	if err := operations.event("remove-live"); err != nil {
		return err
	}
	operations.live = windowsRuntimeGateAbsent
	return nil
}
func (operations *recordingWindowsRuntimeGateOperations) RemovePending() error {
	if err := operations.event("remove-pending"); err != nil {
		return err
	}
	operations.pending = windowsRuntimeGateAbsent
	return nil
}
func (operations *recordingWindowsRuntimeGateOperations) PublishPendingNoReplace() error {
	if err := operations.event("publish-pending"); err != nil {
		return err
	}
	if operations.live != windowsRuntimeGateAbsent || operations.pending != windowsRuntimeGateComplete {
		return errors.New("invalid publication state")
	}
	operations.live = windowsRuntimeGateComplete
	operations.pending = windowsRuntimeGateAbsent
	return nil
}
func (operations *recordingWindowsRuntimeGateOperations) SyncDirectory() error {
	return operations.event("sync-directory")
}

func TestWindowsRuntimeGateExactRecoveryOrder(t *testing.T) {
	operations := &recordingWindowsRuntimeGateOperations{}
	if err := openWindowsRuntimeGate(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-live", "inspect-pending", "create-pending", "sync-directory", "inspect-pending",
		"sync-pending", "publish-pending", "sync-directory", "inspect-live", "inspect-pending",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
	if err := closeWindowsRuntimeGate(operations); err != nil {
		t.Fatal(err)
	}
	if operations.live != windowsRuntimeGateAbsent || operations.pending != windowsRuntimeGateAbsent {
		t.Fatal("runtime gate remained after close")
	}
}

func TestWindowsRuntimeGateResumesCompleteAndIncompletePending(t *testing.T) {
	for _, pending := range []windowsRuntimeGateFileState{windowsRuntimeGateComplete, windowsRuntimeGateIncomplete} {
		operations := &recordingWindowsRuntimeGateOperations{pending: pending}
		if err := openWindowsRuntimeGate(operations); err != nil {
			t.Fatalf("pending %d: %v", pending, err)
		}
		if operations.live != windowsRuntimeGateComplete || operations.pending != windowsRuntimeGateAbsent {
			t.Fatalf("pending %d did not recover", pending)
		}
	}
	operations := &recordingWindowsRuntimeGateOperations{live: windowsRuntimeGateComplete, pending: windowsRuntimeGateComplete}
	if err := openWindowsRuntimeGate(operations); err == nil || !strings.Contains(err.Error(), "unexpected recovery") {
		t.Fatalf("ambiguous open state error = %v", err)
	}
}

func TestWindowsRuntimeGateStopsAtInjectedFault(t *testing.T) {
	for _, failure := range []string{"create-pending", "sync-directory", "inspect-pending", "sync-pending", "publish-pending"} {
		operations := &recordingWindowsRuntimeGateOperations{failAt: failure}
		err := openWindowsRuntimeGate(operations)
		if err == nil || operations.events[len(operations.events)-1] != failure {
			t.Fatalf("failure %q: error=%v events=%q", failure, err, operations.events)
		}
	}
}
