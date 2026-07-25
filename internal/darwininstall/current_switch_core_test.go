package darwininstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingCurrentSwitch struct {
	events    []string
	current   string
	temporary bool
	targetOK  bool
	target    string
	failAt    string
}

func (operations *recordingCurrentSwitch) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingCurrentSwitch) InspectTarget() error {
	if err := operations.event("inspect-target"); err != nil {
		return err
	}
	if !operations.targetOK {
		return errors.New("target is not published")
	}
	return nil
}

func (operations *recordingCurrentSwitch) InspectCurrent() (currentReleaseSelection, error) {
	if err := operations.event("inspect-current"); err != nil {
		return currentReleaseSelection{}, err
	}
	return currentReleaseSelection{InstalledID: operations.current, Exists: operations.current != ""}, nil
}

func (operations *recordingCurrentSwitch) InspectTemporary() (bool, error) {
	if err := operations.event("inspect-temporary"); err != nil {
		return false, err
	}
	return operations.temporary, nil
}

func (operations *recordingCurrentSwitch) CreateTemporary() error {
	if err := operations.event("create-temporary"); err != nil {
		return err
	}
	operations.temporary = true
	return nil
}

func (operations *recordingCurrentSwitch) RemoveTemporary() error {
	if err := operations.event("remove-temporary"); err != nil {
		return err
	}
	operations.temporary = false
	return nil
}

func (operations *recordingCurrentSwitch) SyncRoot() error {
	return operations.event("sync-root")
}

func (operations *recordingCurrentSwitch) ReplaceCurrent() error {
	if err := operations.event("replace-current"); err != nil {
		return err
	}
	if !operations.temporary {
		return errors.New("temporary is absent")
	}
	operations.temporary = false
	operations.current = operations.target
	return nil
}

func TestSwitchCurrentReleaseUsesExactFirstSelectionOrder(t *testing.T) {
	operations := &recordingCurrentSwitch{targetOK: true, target: "target"}
	if err := switchCurrentRelease(operations, "", "target"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-target", "inspect-current", "inspect-temporary", "create-temporary", "sync-root",
		"inspect-current", "inspect-temporary", "replace-current", "sync-root",
		"inspect-target", "inspect-current", "inspect-temporary",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestSwitchCurrentReleaseResumesEveryRecognizedCrashState(t *testing.T) {
	for _, test := range []struct {
		name      string
		current   string
		temporary bool
		want      []string
	}{
		{
			name: "temporary published", current: "prior", temporary: true,
			want: []string{
				"inspect-target", "inspect-current", "inspect-temporary", "sync-root",
				"inspect-current", "inspect-temporary", "replace-current", "sync-root",
				"inspect-target", "inspect-current", "inspect-temporary",
			},
		},
		{
			name: "rename before sync", current: "target",
			want: []string{
				"inspect-target", "inspect-current", "inspect-temporary", "sync-root",
				"inspect-target", "inspect-current", "inspect-temporary",
			},
		},
		{
			name: "rename plus leftover", current: "target", temporary: true,
			want: []string{
				"inspect-target", "inspect-current", "inspect-temporary", "remove-temporary", "sync-root",
				"inspect-target", "inspect-current", "inspect-temporary",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingCurrentSwitch{
				targetOK: true, target: "target", current: test.current, temporary: test.temporary,
			}
			if err := switchCurrentRelease(operations, "prior", "target"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(operations.events, test.want) {
				t.Fatalf("events = %q, want %q", operations.events, test.want)
			}
		})
	}
}

func TestSwitchCurrentReleaseRejectsStaleTransactionWithoutMutation(t *testing.T) {
	operations := &recordingCurrentSwitch{targetOK: true, target: "target", current: "newer"}
	err := switchCurrentRelease(operations, "prior", "target")
	if err == nil || !strings.Contains(err.Error(), "expected prior") {
		t.Fatalf("error = %v", err)
	}
	want := []string{"inspect-target", "inspect-current", "inspect-temporary"}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestSwitchCurrentReleaseNeverAdvancesPastFailure(t *testing.T) {
	for _, failure := range []string{
		"inspect-target", "inspect-current", "inspect-temporary", "create-temporary", "sync-root", "replace-current",
	} {
		t.Run(failure, func(t *testing.T) {
			operations := &recordingCurrentSwitch{targetOK: true, target: "target", failAt: failure}
			err := switchCurrentRelease(operations, "", "target")
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			if got := operations.events[len(operations.events)-1]; got != failure {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}
