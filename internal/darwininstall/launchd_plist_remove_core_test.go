package darwininstall

import (
	"reflect"
	"testing"
)

type recordingLaunchdPlistRemoval struct {
	events  []string
	live    launchdPlistFileState
	pending launchdPlistFileState
}

func (operations *recordingLaunchdPlistRemoval) InspectLive() (launchdPlistFileState, error) {
	operations.events = append(operations.events, "inspect-live")
	return operations.live, nil
}

func (operations *recordingLaunchdPlistRemoval) InspectPending() (launchdPlistFileState, error) {
	operations.events = append(operations.events, "inspect-pending")
	return operations.pending, nil
}

func (operations *recordingLaunchdPlistRemoval) RemoveLive() error {
	operations.events = append(operations.events, "remove-live")
	operations.live = launchdPlistAbsent
	return nil
}

func (operations *recordingLaunchdPlistRemoval) SyncDirectory() error {
	operations.events = append(operations.events, "sync-directory")
	return nil
}

func TestDarwinLaunchdPlistRemovalRequiresExactLiveContent(t *testing.T) {
	operations := &recordingLaunchdPlistRemoval{live: launchdPlistComplete}
	if err := removeLaunchdPlist(operations); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-live", "inspect-pending", "remove-live", "sync-directory",
		"inspect-live", "inspect-pending",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("Darwin plist removal events = %q, want %q", operations.events, want)
	}
	if err := removeLaunchdPlist(operations); err != nil {
		t.Fatalf("Darwin plist removal response-loss replay: %v", err)
	}
}

func TestDarwinLaunchdPlistRemovalRejectsRecoveryAndUnexpectedContent(t *testing.T) {
	for name, operations := range map[string]*recordingLaunchdPlistRemoval{
		"pending": {
			live: launchdPlistComplete, pending: launchdPlistReplaceable,
		},
		"replaceable live": {
			live: launchdPlistReplaceable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := removeLaunchdPlist(operations); err == nil {
				t.Fatal("unsafe Darwin launchd plist removal was accepted")
			}
			for _, event := range operations.events {
				if event == "remove-live" {
					t.Fatal("unsafe Darwin launchd plist was removed")
				}
			}
		})
	}
}
