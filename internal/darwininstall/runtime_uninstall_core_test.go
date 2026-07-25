package darwininstall

import (
	"errors"
	"reflect"
	"testing"
)

type recordingDarwinRuntimeUninstall struct {
	events        []string
	gateOpen      bool
	serviceLoaded bool
	plistPresent  bool
	current       bool
	state         DarwinInstallState
	failAt        string
}

func (operations *recordingDarwinRuntimeUninstall) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingDarwinRuntimeUninstall) ValidateRuntimeUninstall(DarwinInstallState) error {
	return operations.event("validate")
}

func (operations *recordingDarwinRuntimeUninstall) InspectRuntimeGate() (bool, error) {
	if err := operations.event("inspect-gate"); err != nil {
		return false, err
	}
	return operations.gateOpen, nil
}

func (operations *recordingDarwinRuntimeUninstall) CloseRuntimeGate() error {
	if err := operations.event("close-gate"); err != nil {
		return err
	}
	operations.gateOpen = false
	return nil
}

func (operations *recordingDarwinRuntimeUninstall) BootoutService() error {
	if err := operations.event("bootout-service"); err != nil {
		return err
	}
	operations.serviceLoaded = false
	return nil
}

func (operations *recordingDarwinRuntimeUninstall) RemoveLaunchdPlist() error {
	if err := operations.event("remove-plist"); err != nil {
		return err
	}
	operations.plistPresent = false
	return nil
}

func (operations *recordingDarwinRuntimeUninstall) RemoveCurrentSelection() error {
	if err := operations.event("remove-current"); err != nil {
		return err
	}
	operations.current = false
	return nil
}

func (operations *recordingDarwinRuntimeUninstall) InspectInstallState() (DarwinInstallState, error) {
	if err := operations.event("inspect-state"); err != nil {
		return DarwinInstallState{}, err
	}
	return cloneDarwinInstallState(operations.state), nil
}

func (operations *recordingDarwinRuntimeUninstall) DeactivateInstallState(expected DarwinInstallState) error {
	if err := operations.event("deactivate-state"); err != nil {
		return err
	}
	if !sameDarwinInstallState(operations.state, expected) {
		return errors.New("unexpected Darwin install state")
	}
	next, err := expected.DeactivateRuntime()
	if err != nil {
		return err
	}
	operations.state = next
	return nil
}

func darwinRuntimeUninstallFixture(t *testing.T) (DarwinInstallState, *recordingDarwinRuntimeUninstall) {
	t.Helper()
	active := validAuthenticatedDarwinRelease(2, 7, 4, "a", "b")
	previous := validAuthenticatedDarwinRelease(2, 6, 4, "c", "d")
	state := validDarwinInstallState(active)
	state.Active, state.Previous = &active, &previous
	return state, &recordingDarwinRuntimeUninstall{
		gateOpen: true, serviceLoaded: true, plistPresent: true, current: true,
		state: cloneDarwinInstallState(state),
	}
}

func TestDarwinRuntimeUninstallOrdersActivationRemovalBeforeState(t *testing.T) {
	source, operations := darwinRuntimeUninstallFixture(t)
	completed, err := deactivateDarwinRuntime(operations, source)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Active != nil || completed.Previous != nil ||
		completed.HighWater != source.HighWater ||
		operations.gateOpen || operations.serviceLoaded ||
		operations.plistPresent || operations.current {
		t.Fatalf("Darwin runtime uninstall = state %+v operations %+v", completed, operations)
	}
	positions := map[string]int{}
	for index, event := range operations.events {
		if _, found := positions[event]; !found {
			positions[event] = index
		}
	}
	if !(positions["close-gate"] < positions["bootout-service"] &&
		positions["bootout-service"] < positions["remove-plist"] &&
		positions["remove-plist"] < positions["remove-current"] &&
		positions["remove-current"] < positions["deactivate-state"]) {
		t.Fatalf("unsafe Darwin runtime-uninstall order: %q", operations.events)
	}
}

func TestDarwinRuntimeUninstallRecoversResponseLoss(t *testing.T) {
	source, operations := darwinRuntimeUninstallFixture(t)
	operations.gateOpen = false
	operations.serviceLoaded = false
	operations.plistPresent = false
	operations.current = false
	deactivated, err := source.DeactivateRuntime()
	if err != nil {
		t.Fatal(err)
	}
	operations.state = deactivated
	completed, err := deactivateDarwinRuntime(operations, source)
	if err != nil || !reflect.DeepEqual(completed, deactivated) {
		t.Fatalf("Darwin runtime-uninstall response-loss recovery = %+v, %v", completed, err)
	}
	for _, event := range operations.events {
		if event == "deactivate-state" {
			t.Fatal("terminal Darwin runtime-uninstall replay rewrote state")
		}
	}
}

func TestDarwinRuntimeUninstallRetainsSourceOnActivationRemovalFailure(t *testing.T) {
	for _, failure := range []string{
		"close-gate", "bootout-service", "remove-plist", "remove-current",
	} {
		t.Run(failure, func(t *testing.T) {
			source, operations := darwinRuntimeUninstallFixture(t)
			operations.failAt = failure
			if _, err := deactivateDarwinRuntime(operations, source); err == nil {
				t.Fatal("injected Darwin runtime-uninstall failure was ignored")
			}
			if !sameDarwinInstallState(operations.state, source) {
				t.Fatal("Darwin runtime-uninstall changed state before activation removal completed")
			}
		})
	}
}
