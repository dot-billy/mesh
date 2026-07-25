package windowsinstall

import (
	"reflect"
	"strings"
	"testing"
)

func TestWindowsInstallStateCanonicalRoundTrip(t *testing.T) {
	state := validWindowsInstallState(validAuthenticatedWindowsRelease(1, 4, 2, "a", "b"))
	raw, err := MarshalWindowsInstallState(state)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWindowsInstallState(raw)
	if err != nil || !reflect.DeepEqual(parsed, state) {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	for _, mutation := range [][]byte{
		append([]byte(" "), raw...), append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.Replace(string(raw), `"schema":`, `"unknown":1,"schema":`, 1)),
	} {
		if _, err := ParseWindowsInstallState(mutation); err == nil {
			t.Fatalf("noncanonical Windows install state accepted: %q", mutation)
		}
	}
}

func TestWindowsInstallStateTransitionAllowsOnlySeparateAuthorityAndActivationSteps(t *testing.T) {
	first := validAuthenticatedWindowsRelease(1, 4, 1, "a", "b")
	initial := validWindowsInstallState(first)
	if err := validateWindowsInstallStateTransition(nil, initial); err != nil {
		t.Fatal(err)
	}
	active, err := initial.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsInstallStateTransition(&initial, active); err != nil {
		t.Fatal(err)
	}
	second := validAuthenticatedWindowsRelease(1, 5, 2, "c", "d")
	advanced, err := active.AdvanceHighWater(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsInstallStateTransition(&active, advanced); err != nil {
		t.Fatal(err)
	}
	combined, err := advanced.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsInstallStateTransition(&active, combined); err == nil {
		t.Fatal("combined Windows high-water and activation transition was accepted")
	}
	if err := validateWindowsInstallStateTransition(&advanced, combined); err != nil {
		t.Fatal(err)
	}
	deactivated, err := combined.DeactivateRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsInstallStateTransition(&combined, deactivated); err != nil {
		t.Fatalf("exact runtime deactivation rejected: %v", err)
	}
	driftedDeactivation := deactivated
	driftedDeactivation.HighWater = active.HighWater
	if err := validateWindowsInstallStateTransition(&combined, driftedDeactivation); err == nil {
		t.Fatal("runtime deactivation that changed high water accepted")
	}
}
