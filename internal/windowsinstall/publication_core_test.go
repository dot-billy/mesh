package windowsinstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingWindowsReleasePublication struct {
	events    []string
	stage     windowsReleaseDirectoryState
	published windowsReleaseDirectoryState
	failAt    string
}

func (operations *recordingWindowsReleasePublication) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingWindowsReleasePublication) InspectStage() (windowsReleaseDirectoryState, error) {
	if err := operations.event("inspect-stage"); err != nil {
		return windowsReleaseDirectoryAbsent, err
	}
	return operations.stage, nil
}

func (operations *recordingWindowsReleasePublication) InspectPublished() (windowsReleaseDirectoryState, error) {
	if err := operations.event("inspect-published"); err != nil {
		return windowsReleaseDirectoryAbsent, err
	}
	return operations.published, nil
}

func (operations *recordingWindowsReleasePublication) SyncStage() error {
	return operations.event("sync-stage")
}

func (operations *recordingWindowsReleasePublication) PublishNoReplace() error {
	if err := operations.event("publish-no-replace"); err != nil {
		return err
	}
	if operations.stage != windowsReleaseDirectoryFinalized || operations.published != windowsReleaseDirectoryAbsent {
		return errors.New("invalid publication state")
	}
	operations.stage = windowsReleaseDirectoryAbsent
	operations.published = windowsReleaseDirectoryFinalized
	return nil
}

func (operations *recordingWindowsReleasePublication) SyncReleases() error {
	return operations.event("sync-releases")
}

func TestPublishWindowsFinalizedReleaseUsesExactDurableOrder(t *testing.T) {
	operations := &recordingWindowsReleasePublication{stage: windowsReleaseDirectoryFinalized}
	if err := publishWindowsFinalizedRelease(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-stage", "inspect-published", "sync-stage", "publish-no-replace",
		"sync-releases", "inspect-stage", "inspect-published",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestPublishWindowsFinalizedReleaseResumesPostRename(t *testing.T) {
	operations := &recordingWindowsReleasePublication{published: windowsReleaseDirectoryFinalized}
	if err := publishWindowsFinalizedRelease(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-stage", "inspect-published", "sync-releases",
		"inspect-stage", "inspect-published",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestPublishWindowsFinalizedReleaseRejectsAmbiguousState(t *testing.T) {
	for _, test := range []struct {
		name      string
		stage     windowsReleaseDirectoryState
		published windowsReleaseDirectoryState
	}{
		{name: "both absent"},
		{name: "private stage", stage: windowsReleaseDirectoryPrivate},
		{name: "private published", stage: windowsReleaseDirectoryFinalized, published: windowsReleaseDirectoryPrivate},
		{name: "both finalized", stage: windowsReleaseDirectoryFinalized, published: windowsReleaseDirectoryFinalized},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingWindowsReleasePublication{stage: test.stage, published: test.published}
			if err := publishWindowsFinalizedRelease(operations); err == nil || !strings.Contains(err.Error(), "resumable") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPublishWindowsFinalizedReleaseStopsAtFailure(t *testing.T) {
	for _, failure := range []string{
		"inspect-stage", "inspect-published", "sync-stage", "publish-no-replace", "sync-releases",
	} {
		t.Run(failure, func(t *testing.T) {
			operations := &recordingWindowsReleasePublication{stage: windowsReleaseDirectoryFinalized, failAt: failure}
			err := publishWindowsFinalizedRelease(operations)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			if got := operations.events[len(operations.events)-1]; got != failure {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}
