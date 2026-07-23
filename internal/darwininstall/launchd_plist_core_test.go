package darwininstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingLaunchdPlistOperations struct {
	events  []string
	live    launchdPlistFileState
	pending launchdPlistFileState
	failAt  string
	noFinal bool
}

func (operations *recordingLaunchdPlistOperations) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingLaunchdPlistOperations) InspectLive() (launchdPlistFileState, error) {
	if err := operations.event("inspect-live"); err != nil {
		return launchdPlistAbsent, err
	}
	return operations.live, nil
}

func (operations *recordingLaunchdPlistOperations) InspectPending() (launchdPlistFileState, error) {
	if err := operations.event("inspect-pending"); err != nil {
		return launchdPlistAbsent, err
	}
	return operations.pending, nil
}

func (operations *recordingLaunchdPlistOperations) CreatePending() error {
	if err := operations.event("create-pending"); err != nil {
		return err
	}
	operations.pending = launchdPlistReplaceable
	return nil
}

func (operations *recordingLaunchdPlistOperations) SyncPending() error {
	return operations.event("sync-pending")
}

func (operations *recordingLaunchdPlistOperations) FinalizePending() error {
	if err := operations.event("finalize-pending"); err != nil {
		return err
	}
	if !operations.noFinal {
		operations.pending = launchdPlistComplete
	}
	return nil
}

func (operations *recordingLaunchdPlistOperations) RemovePending() error {
	if err := operations.event("remove-pending"); err != nil {
		return err
	}
	operations.pending = launchdPlistAbsent
	return nil
}

func (operations *recordingLaunchdPlistOperations) PublishPending() error {
	if err := operations.event("publish-pending"); err != nil {
		return err
	}
	if operations.pending != launchdPlistComplete {
		return errors.New("pending plist is incomplete")
	}
	operations.live = launchdPlistComplete
	operations.pending = launchdPlistAbsent
	return nil
}

func (operations *recordingLaunchdPlistOperations) SyncDirectory() error {
	return operations.event("sync-directory")
}

func TestPublishLaunchdPlistUsesDurableReplacementOrder(t *testing.T) {
	operations := &recordingLaunchdPlistOperations{live: launchdPlistReplaceable}
	if err := publishLaunchdPlist(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-live", "inspect-pending", "create-pending", "sync-pending",
		"finalize-pending", "sync-pending", "inspect-pending", "publish-pending",
		"sync-directory", "inspect-live", "inspect-pending",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestPublishLaunchdPlistRecoversOnlyRecognizedStates(t *testing.T) {
	for _, test := range []struct {
		name       string
		live       launchdPlistFileState
		pending    launchdPlistFileState
		wantEvents []string
	}{
		{
			name: "already exact", live: launchdPlistComplete,
			wantEvents: []string{"inspect-live", "inspect-pending", "sync-directory", "inspect-live", "inspect-pending"},
		},
		{
			name: "exact with stale pending", live: launchdPlistComplete, pending: launchdPlistReplaceable,
			wantEvents: []string{"inspect-live", "inspect-pending", "remove-pending", "sync-directory", "inspect-live", "inspect-pending"},
		},
		{
			name: "complete pending", pending: launchdPlistComplete,
			wantEvents: []string{
				"inspect-live", "inspect-pending", "sync-pending", "finalize-pending",
				"sync-pending", "inspect-pending", "publish-pending", "sync-directory",
				"inspect-live", "inspect-pending",
			},
		},
		{
			name: "incomplete pending", pending: launchdPlistReplaceable,
			wantEvents: []string{
				"inspect-live", "inspect-pending", "remove-pending", "sync-directory",
				"create-pending", "sync-pending", "finalize-pending", "sync-pending",
				"inspect-pending", "publish-pending", "sync-directory", "inspect-live", "inspect-pending",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingLaunchdPlistOperations{live: test.live, pending: test.pending}
			if err := publishLaunchdPlist(operations); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(operations.events, test.wantEvents) {
				t.Fatalf("events = %q, want %q", operations.events, test.wantEvents)
			}
		})
	}
}

func TestPublishLaunchdPlistNeverAdvancesPastFailure(t *testing.T) {
	for _, failure := range []string{
		"inspect-live", "inspect-pending", "create-pending", "sync-pending",
		"finalize-pending", "publish-pending", "sync-directory",
	} {
		t.Run(failure, func(t *testing.T) {
			operations := &recordingLaunchdPlistOperations{failAt: failure}
			err := publishLaunchdPlist(operations)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			if got := operations.events[len(operations.events)-1]; got != failure {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}

func TestPublishLaunchdPlistRejectsFalseFinalization(t *testing.T) {
	operations := &recordingLaunchdPlistOperations{noFinal: true}
	if err := publishLaunchdPlist(operations); err == nil || !strings.Contains(err.Error(), "not complete") {
		t.Fatalf("error = %v", err)
	}
}
