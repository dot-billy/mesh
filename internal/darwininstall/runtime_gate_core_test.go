package darwininstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingRuntimeGateOperations struct {
	events  []string
	live    runtimeGateFileState
	pending runtimeGateFileState
	failAt  string
}

func (operations *recordingRuntimeGateOperations) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingRuntimeGateOperations) InspectLive() (runtimeGateFileState, error) {
	if err := operations.event("inspect-live"); err != nil {
		return runtimeGateAbsent, err
	}
	return operations.live, nil
}

func (operations *recordingRuntimeGateOperations) InspectPending() (runtimeGateFileState, error) {
	if err := operations.event("inspect-pending"); err != nil {
		return runtimeGateAbsent, err
	}
	return operations.pending, nil
}

func (operations *recordingRuntimeGateOperations) CreatePending() error {
	if err := operations.event("create-pending"); err != nil {
		return err
	}
	operations.pending = runtimeGateComplete
	return nil
}

func (operations *recordingRuntimeGateOperations) SyncPending() error {
	return operations.event("sync-pending")
}

func (operations *recordingRuntimeGateOperations) RemoveLive() error {
	if err := operations.event("remove-live"); err != nil {
		return err
	}
	operations.live = runtimeGateAbsent
	return nil
}

func (operations *recordingRuntimeGateOperations) RemovePending() error {
	if err := operations.event("remove-pending"); err != nil {
		return err
	}
	operations.pending = runtimeGateAbsent
	return nil
}

func (operations *recordingRuntimeGateOperations) PublishPendingNoReplace() error {
	if err := operations.event("publish-pending"); err != nil {
		return err
	}
	if operations.live != runtimeGateAbsent || operations.pending != runtimeGateComplete {
		return errors.New("invalid publication state")
	}
	operations.live = runtimeGateComplete
	operations.pending = runtimeGateAbsent
	return nil
}

func (operations *recordingRuntimeGateOperations) SyncDirectory() error {
	return operations.event("sync-directory")
}

func TestOpenRuntimeGatePublishesInExactDurableOrder(t *testing.T) {
	operations := &recordingRuntimeGateOperations{}
	if err := openRuntimeGate(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-live", "inspect-pending", "create-pending", "sync-directory",
		"inspect-pending", "sync-pending", "publish-pending", "sync-directory",
		"inspect-live", "inspect-pending",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
	if operations.live != runtimeGateComplete || operations.pending != runtimeGateAbsent {
		t.Fatalf("state = live %d pending %d", operations.live, operations.pending)
	}
}

func TestOpenRuntimeGateResumesOnlyExactRecoveryStates(t *testing.T) {
	for _, test := range []struct {
		name       string
		live       runtimeGateFileState
		pending    runtimeGateFileState
		wantEvents []string
		want       string
	}{
		{
			name: "already open", live: runtimeGateComplete,
			wantEvents: []string{"inspect-live", "inspect-pending"},
		},
		{
			name: "complete recovery", pending: runtimeGateComplete,
			wantEvents: []string{
				"inspect-live", "inspect-pending", "sync-pending", "publish-pending",
				"sync-directory", "inspect-live", "inspect-pending",
			},
		},
		{
			name: "incomplete recovery", pending: runtimeGateIncomplete,
			wantEvents: []string{
				"inspect-live", "inspect-pending", "remove-pending", "sync-directory",
				"create-pending", "sync-directory", "inspect-pending", "sync-pending",
				"publish-pending", "sync-directory", "inspect-live", "inspect-pending",
			},
		},
		{name: "open plus recovery", live: runtimeGateComplete, pending: runtimeGateComplete, want: "unexpected recovery"},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingRuntimeGateOperations{live: test.live, pending: test.pending}
			err := openRuntimeGate(operations)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
			if test.wantEvents != nil && !reflect.DeepEqual(operations.events, test.wantEvents) {
				t.Fatalf("events = %q, want %q", operations.events, test.wantEvents)
			}
		})
	}
}

func TestCloseRuntimeGateRemovesAuthorizationBeforeRecoveryAndProvesAbsence(t *testing.T) {
	operations := &recordingRuntimeGateOperations{live: runtimeGateComplete, pending: runtimeGateIncomplete}
	if err := closeRuntimeGate(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-live", "remove-live", "sync-directory",
		"inspect-pending", "remove-pending", "sync-directory",
		"inspect-live", "inspect-pending",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestRuntimeGateFaultsNeverAdvancePastTheFailedDurabilityStep(t *testing.T) {
	for _, failure := range []string{
		"create-pending", "sync-directory", "inspect-pending", "sync-pending", "publish-pending",
	} {
		t.Run(failure, func(t *testing.T) {
			operations := &recordingRuntimeGateOperations{failAt: failure}
			err := openRuntimeGate(operations)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			failureIndex := -1
			for index, event := range operations.events {
				if event == failure {
					failureIndex = index
					break
				}
			}
			if failureIndex < 0 || failureIndex != len(operations.events)-1 {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}

func TestCloseRuntimeGateFaultsNeverAdvancePastTheFailure(t *testing.T) {
	tests := []struct {
		name    string
		live    runtimeGateFileState
		pending runtimeGateFileState
		failAt  string
	}{
		{name: "inspect live", live: runtimeGateComplete, failAt: "inspect-live"},
		{name: "remove live", live: runtimeGateComplete, failAt: "remove-live"},
		{name: "sync live removal", live: runtimeGateComplete, failAt: "sync-directory"},
		{name: "inspect recovery", pending: runtimeGateComplete, failAt: "inspect-pending"},
		{name: "remove recovery", pending: runtimeGateComplete, failAt: "remove-pending"},
		{name: "sync recovery removal", pending: runtimeGateComplete, failAt: "sync-directory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingRuntimeGateOperations{
				live: test.live, pending: test.pending, failAt: test.failAt,
			}
			err := closeRuntimeGate(operations)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			if got := operations.events[len(operations.events)-1]; got != test.failAt {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}
