package darwininstall

import (
	"errors"
	"reflect"
	"testing"
)

type recordingCurrentRemoval struct {
	events    []string
	targetOK  bool
	current   currentReleaseSelection
	temporary bool
}

func (operations *recordingCurrentRemoval) InspectTarget() error {
	operations.events = append(operations.events, "inspect-target")
	if !operations.targetOK {
		return errors.New("target failed authentication")
	}
	return nil
}

func (operations *recordingCurrentRemoval) InspectCurrent() (currentReleaseSelection, error) {
	operations.events = append(operations.events, "inspect-current")
	return operations.current, nil
}

func (operations *recordingCurrentRemoval) InspectTemporary() (bool, error) {
	operations.events = append(operations.events, "inspect-temporary")
	return operations.temporary, nil
}

func (operations *recordingCurrentRemoval) RemoveCurrent() error {
	operations.events = append(operations.events, "remove-current")
	operations.current = currentReleaseSelection{}
	return nil
}

func (operations *recordingCurrentRemoval) SyncRoot() error {
	operations.events = append(operations.events, "sync-root")
	return nil
}

func TestDarwinCurrentRemovalRequiresExactSelectionAndDurableAbsence(t *testing.T) {
	operations := &recordingCurrentRemoval{
		targetOK: true,
		current: currentReleaseSelection{
			InstalledID: "exact",
			Exists:      true,
		},
	}
	if err := removeDarwinCurrentSelection(operations, "exact"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-target", "inspect-temporary", "inspect-current",
		"remove-current", "sync-root", "inspect-target", "inspect-current",
		"inspect-temporary",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("Darwin current removal events = %q, want %q", operations.events, want)
	}
	if err := removeDarwinCurrentSelection(operations, "exact"); err != nil {
		t.Fatalf("Darwin current removal response-loss replay: %v", err)
	}
}

func TestDarwinCurrentRemovalRejectsAuthorityDriftAndTemporary(t *testing.T) {
	for name, operations := range map[string]*recordingCurrentRemoval{
		"wrong current": {
			targetOK: true,
			current:  currentReleaseSelection{InstalledID: "other", Exists: true},
		},
		"temporary": {
			targetOK:  true,
			current:   currentReleaseSelection{InstalledID: "exact", Exists: true},
			temporary: true,
		},
		"target": {
			current: currentReleaseSelection{InstalledID: "exact", Exists: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := removeDarwinCurrentSelection(operations, "exact"); err == nil {
				t.Fatal("unsafe Darwin current removal was accepted")
			}
			for _, event := range operations.events {
				if event == "remove-current" {
					t.Fatal("unsafe Darwin current selection was removed")
				}
			}
		})
	}
}
