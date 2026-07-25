package darwininstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingReleasePublication struct {
	events    []string
	stage     releaseDirectoryState
	published releaseDirectoryState
	failAt    string
}

func (operations *recordingReleasePublication) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingReleasePublication) InspectStage() (releaseDirectoryState, error) {
	if err := operations.event("inspect-stage"); err != nil {
		return releaseDirectoryAbsent, err
	}
	return operations.stage, nil
}

func (operations *recordingReleasePublication) InspectPublished() (releaseDirectoryState, error) {
	if err := operations.event("inspect-published"); err != nil {
		return releaseDirectoryAbsent, err
	}
	return operations.published, nil
}

func (operations *recordingReleasePublication) SyncStage() error {
	return operations.event("sync-stage")
}

func (operations *recordingReleasePublication) PublishNoReplace() error {
	if err := operations.event("publish-no-replace"); err != nil {
		return err
	}
	if operations.stage != releaseDirectoryFinalized || operations.published != releaseDirectoryAbsent {
		return errors.New("invalid publication state")
	}
	operations.stage = releaseDirectoryAbsent
	operations.published = releaseDirectoryFinalized
	return nil
}

func (operations *recordingReleasePublication) SyncReleases() error {
	return operations.event("sync-releases")
}

func TestPublishFinalizedReleaseUsesExactDurableOrder(t *testing.T) {
	operations := &recordingReleasePublication{stage: releaseDirectoryFinalized}
	if err := publishFinalizedRelease(operations); err != nil {
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

func TestPublishFinalizedReleaseResumesPostRenameBeforeDurability(t *testing.T) {
	operations := &recordingReleasePublication{published: releaseDirectoryFinalized}
	if err := publishFinalizedRelease(operations); err != nil {
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

func TestPublishFinalizedReleaseRejectsEveryAmbiguousState(t *testing.T) {
	for _, test := range []struct {
		name      string
		stage     releaseDirectoryState
		published releaseDirectoryState
	}{
		{name: "both absent"},
		{name: "private stage", stage: releaseDirectoryPrivate},
		{name: "unexpected published", stage: releaseDirectoryFinalized, published: releaseDirectoryPrivate},
		{name: "both finalized", stage: releaseDirectoryFinalized, published: releaseDirectoryFinalized},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingReleasePublication{stage: test.stage, published: test.published}
			if err := publishFinalizedRelease(operations); err == nil || !strings.Contains(err.Error(), "resumable") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPublishFinalizedReleaseNeverAdvancesPastFailure(t *testing.T) {
	for _, failure := range []string{
		"inspect-stage", "inspect-published", "sync-stage", "publish-no-replace", "sync-releases",
	} {
		t.Run(failure, func(t *testing.T) {
			operations := &recordingReleasePublication{stage: releaseDirectoryFinalized, failAt: failure}
			err := publishFinalizedRelease(operations)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			if got := operations.events[len(operations.events)-1]; got != failure {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}
