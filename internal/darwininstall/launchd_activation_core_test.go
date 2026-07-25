package darwininstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingLaunchdActivation struct {
	events        []string
	gate          bool
	loaded        bool
	switched      bool
	plist         bool
	closeNoop     bool
	bootoutNoop   bool
	bootstrapNoop bool
	openNoop      bool
	failAt        string
}

func (operations *recordingLaunchdActivation) event(name string) error {
	operations.events = append(operations.events, name)
	if operations.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (operations *recordingLaunchdActivation) InspectRuntimeGate() (bool, error) {
	if err := operations.event("inspect-gate"); err != nil {
		return false, err
	}
	return operations.gate, nil
}

func (operations *recordingLaunchdActivation) CloseRuntimeGate() error {
	if err := operations.event("close-gate"); err != nil {
		return err
	}
	if !operations.closeNoop {
		operations.gate = false
	}
	return nil
}

func (operations *recordingLaunchdActivation) BootoutService() error {
	if err := operations.event("bootout-service"); err != nil {
		return err
	}
	if operations.bootoutNoop {
		return errors.New("launchd bootout did not prove absence")
	}
	operations.loaded = false
	return nil
}

func (operations *recordingLaunchdActivation) SwitchCurrent() error {
	if err := operations.event("switch-current"); err != nil {
		return err
	}
	if operations.gate || operations.loaded {
		return errors.New("release switched before runtime quiescence")
	}
	operations.switched = true
	return nil
}

func (operations *recordingLaunchdActivation) PublishPlist() error {
	if err := operations.event("publish-plist"); err != nil {
		return err
	}
	if !operations.switched || operations.loaded {
		return errors.New("plist published outside the quiesced selected release")
	}
	operations.plist = true
	return nil
}

func (operations *recordingLaunchdActivation) BootstrapService() error {
	if err := operations.event("bootstrap-service"); err != nil {
		return err
	}
	if !operations.plist || operations.gate {
		return errors.New("service bootstrapped before exact plist publication or with an open gate")
	}
	if operations.bootstrapNoop {
		return errors.New("launchd bootstrap did not prove loading")
	}
	operations.loaded = true
	return nil
}

func (operations *recordingLaunchdActivation) OpenRuntimeGate() error {
	if err := operations.event("open-gate"); err != nil {
		return err
	}
	if !operations.loaded {
		return errors.New("runtime gate opened before launchd bootstrap")
	}
	if !operations.openNoop {
		operations.gate = true
	}
	return nil
}

func (operations *recordingLaunchdActivation) InspectTarget() error {
	if err := operations.event("inspect-target"); err != nil {
		return err
	}
	if !operations.switched || !operations.plist {
		return errors.New("Darwin activation target or plist is not exact")
	}
	return nil
}

func TestActivateLaunchdReleaseUsesFailClosedUpgradeOrder(t *testing.T) {
	operations := &recordingLaunchdActivation{gate: true, loaded: true}
	if err := activateLaunchdRelease(operations, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-gate", "close-gate", "inspect-gate",
		"bootout-service", "switch-current", "publish-plist", "bootstrap-service",
		"inspect-gate", "open-gate", "inspect-target", "inspect-gate",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestActivateLaunchdReleaseKeepsFirstInstallGateClosed(t *testing.T) {
	operations := &recordingLaunchdActivation{}
	if err := activateLaunchdRelease(operations, false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inspect-gate", "inspect-gate", "bootout-service",
		"switch-current", "publish-plist", "bootstrap-service",
		"inspect-gate", "inspect-target", "inspect-gate",
	}
	if !reflect.DeepEqual(operations.events, want) {
		t.Fatalf("events = %q, want %q", operations.events, want)
	}
}

func TestActivateLaunchdReleaseResumesAlreadyBootstrappedTarget(t *testing.T) {
	operations := &recordingLaunchdActivation{switched: true, plist: true}
	if err := activateLaunchdRelease(operations, false); err != nil {
		t.Fatal(err)
	}
	if !operations.switched || !operations.plist || !operations.loaded || operations.gate {
		t.Fatalf("resumed activation state = %+v", operations)
	}
}

func TestActivateLaunchdReleaseNeverAdvancesPastFailure(t *testing.T) {
	for _, failure := range []string{
		"inspect-gate", "close-gate", "bootout-service",
		"switch-current", "publish-plist", "bootstrap-service", "open-gate",
		"inspect-target",
	} {
		t.Run(failure, func(t *testing.T) {
			operations := &recordingLaunchdActivation{gate: true, loaded: true, failAt: failure}
			err := activateLaunchdRelease(operations, true)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v", err)
			}
			if got := operations.events[len(operations.events)-1]; got != failure {
				t.Fatalf("events continued after failure: %q", operations.events)
			}
		})
	}
}

func TestActivateLaunchdReleaseRejectsFalseQuiescenceAndProof(t *testing.T) {
	for name, operations := range map[string]*recordingLaunchdActivation{
		"gate remains open":        {gate: true, closeNoop: true},
		"service remains loaded":   {loaded: true, bootoutNoop: true},
		"bootstrap remains absent": {bootstrapNoop: true},
		"gate restore is false":    {openNoop: true},
	} {
		t.Run(name, func(t *testing.T) {
			wantGate := name == "gate restore is false"
			if err := activateLaunchdRelease(operations, wantGate); err == nil {
				t.Fatal("false quiescence was accepted")
			}
		})
	}
}
