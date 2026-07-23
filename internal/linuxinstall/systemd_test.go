//go:build linux

package linuxinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseSystemdUnitStateRequiresExactBoundedProperties(t *testing.T) {
	raw := renderSystemdUnit(systemdUnitState{
		LoadState: "loaded", FragmentPath: "/usr/local/lib/systemd/system/mesh-agent.service",
		DropInPaths: "/usr/local/lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf", TimeoutStopFailureMode: "terminate",
		UnitFileState: "enabled", ActiveState: "active", SubState: "running",
		MainPID: 42, ControlGroup: "/system.slice/mesh-agent.service",
	})
	parsed, err := parseSystemdUnitState(raw)
	if err != nil || parsed.MainPID != 42 || parsed.UnitFileState != "enabled" || parsed.TimeoutStopFailureMode != "terminate" {
		t.Fatalf("parse=%+v err=%v", parsed, err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"empty":     func([]byte) []byte { return nil },
		"NUL":       func(value []byte) []byte { return append(value, 0) },
		"duplicate": func(value []byte) []byte { return append(value, []byte("MainPID=42\n")...) },
		"missing": func(value []byte) []byte {
			return []byte(strings.Replace(string(value), "ControlGroup=/system.slice/mesh-agent.service\n", "", 1))
		},
		"bad PID": func(value []byte) []byte {
			return []byte(strings.Replace(string(value), "MainPID=42", "MainPID=042", 1))
		},
		"unknown":  func(value []byte) []byte { return append(value, []byte("Environment=evil\n")...) },
		"oversize": func([]byte) []byte { return []byte(strings.Repeat("x", maxSystemctlOutput+1)) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSystemdUnitState(mutate(append([]byte(nil), raw...))); err == nil {
				t.Fatal("invalid systemd property output accepted")
			}
		})
	}
}

func TestSystemdPreflightRequiresAbsentFirstInstallSurface(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager := testSystemdManager(t, runner, &fakeProcessVerifier{})
	snapshot, err := manager.preflight(context.Background(), nil)
	if err != nil || snapshot != (ServiceSnapshot{}) {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	testRuntimeGate(t, manager).open = true
	if _, err := manager.preflight(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "before first installation") {
		t.Fatalf("open first-install runtime gate accepted: %v", err)
	}
	testRuntimeGate(t, manager).open = false
	childOpen := true
	testChildRuntimeGate(t, manager).open = &childOpen
	if _, err := manager.preflight(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "readiness marker") {
		t.Fatalf("open first-install child runtime gate accepted: %v", err)
	}
	testChildRuntimeGate(t, manager).open = nil
	runner.units[legacyNebulaUnitName] = stoppedLoadedUnit("/usr/lib/systemd/system/nebula.service", "disabled")
	if _, err := manager.preflight(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "competing") {
		t.Fatalf("competing legacy unit accepted: %v", err)
	}
	delete(runner.units, legacyNebulaUnitName)
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	if _, err := manager.preflight(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "first-install surface") {
		t.Fatalf("preexisting managed unit accepted: %v", err)
	}
}

func TestSystemdPreflightRequiresNebulaAndChildReadinessToMatch(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	testRuntimeGate(t, manager).open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 151)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 152)

	closed := false
	testChildRuntimeGate(t, manager).open = &closed
	if _, err := manager.preflight(context.Background(), &identity); !errors.Is(err, errManagedNebulaChildGateMismatch) {
		t.Fatalf("active Nebula without readiness marker error=%v", err)
	}

	open := true
	testChildRuntimeGate(t, manager).open = &open
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	if _, err := manager.preflight(context.Background(), &identity); !errors.Is(err, errManagedNebulaChildGateMismatch) {
		t.Fatalf("readiness marker without active Nebula error=%v", err)
	}
}

func TestSystemdStoppedProofRequiresChildReadinessAbsent(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	open := true
	testChildRuntimeGate(t, manager).open = &open
	if err := manager.proveStopped(context.Background(), identity); err == nil || !strings.Contains(err.Error(), "readiness marker remains open") {
		t.Fatalf("stopped proof accepted open child readiness: %v", err)
	}
}

func TestSystemdStoppedProofRequiresAgentRuntimeDirectoryAbsent(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	present := true
	testChildRuntimeGate(t, manager).directoryPresent = &present
	if err := manager.proveStopped(context.Background(), identity); err == nil || !strings.Contains(err.Error(), "RuntimeDirectory absent") {
		t.Fatalf("stopped proof accepted lingering agent RuntimeDirectory: %v", err)
	}
}

func TestSystemdPreflightBindsFragmentsDropinsAndRunningProcesses(t *testing.T) {
	runner := newFakeSystemdRunner()
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	testRuntimeGate(t, manager).open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 101)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 102)

	snapshot, err := manager.preflight(context.Background(), &identity)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot != (ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, NebulaWasActive: true, RuntimeGateWasOpen: true}) {
		t.Fatalf("unexpected service snapshot: %+v", snapshot)
	}
	if len(processes.verified) != 2 || processes.verified[0].pid != 101 || processes.verified[1].pid != 102 {
		t.Fatalf("running process proofs=%+v", processes.verified)
	}
	custom := runner.units[agentUnitName]
	custom.WantedBy = "multi-user.target rescue.target"
	runner.units[agentUnitName] = custom
	if _, err := manager.preflight(context.Background(), &identity); err == nil || !strings.Contains(err.Error(), "enabled topology") {
		t.Fatalf("custom enable topology accepted: %v", err)
	}
	custom.WantedBy = "multi-user.target"
	runner.units[agentUnitName] = custom
	triggered := runner.units[agentUnitName]
	triggered.TriggeredBy = "mesh-agent.socket"
	runner.units[agentUnitName] = triggered
	if _, err := manager.preflight(context.Background(), &identity); err == nil || !strings.Contains(err.Error(), "forbidden reverse") {
		t.Fatalf("alternate activation trigger accepted: %v", err)
	}
	triggered.TriggeredBy = ""
	runner.units[agentUnitName] = triggered
	changed := runner.units[agentUnitName]
	changed.DropInPaths = "/etc/systemd/system/mesh-agent.service.d/override.conf"
	runner.units[agentUnitName] = changed
	if _, err := manager.preflight(context.Background(), &identity); err == nil || !strings.Contains(err.Error(), "forbidden drop-ins") {
		t.Fatalf("unit drop-in accepted: %v", err)
	}
	for _, extra := range []string{
		"/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
		"/etc/systemd/system/mesh-agent.service.d/operator.conf",
	} {
		changed.DropInPaths = managedTimeoutAbortDropInPath(manager.unitDirectory, agentUnitName) + " " + extra
		runner.units[agentUnitName] = changed
		if _, err := manager.preflight(context.Background(), &identity); err == nil || !strings.Contains(err.Error(), "forbidden drop-ins") {
			t.Fatalf("additional drop-in %q accepted: %v", extra, err)
		}
	}
	changed.DropInPaths = managedTimeoutAbortDropInPath(manager.unitDirectory, agentUnitName)
	changed.TimeoutStopFailureMode = "abort"
	runner.units[agentUnitName] = changed
	if _, err := manager.preflight(context.Background(), &identity); err == nil || !strings.Contains(err.Error(), "TimeoutStopFailureMode") {
		t.Fatalf("nondefault timeout failure mode accepted: %v", err)
	}
}

func TestSystemdPreflightRequiresExactCompatibilityMaskFile(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	if _, err := manager.preflight(context.Background(), &identity); err != nil {
		t.Fatalf("exact compatibility masks were rejected: %v", err)
	}
	maskPath := managedTimeoutAbortDropInPath(manager.unitDirectory, nebulaUnitName)
	if err := os.Chmod(maskPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maskPath, []byte("# tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(maskPath, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.preflight(context.Background(), &identity); err == nil || !strings.Contains(err.Error(), "fixed compatibility drop-in") {
		t.Fatalf("tampered compatibility mask was accepted: %v", err)
	}
}

func TestSystemdQuiesceClosesGateBeforeStopAndPreservesUnitFileState(t *testing.T) {
	runner := newFakeSystemdRunner()
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	gate := testRuntimeGate(t, manager)
	gate.open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 201)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 202)

	want := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, NebulaWasActive: true, RuntimeGateWasOpen: true}
	if err := manager.quiesce(context.Background(), &identity, want); err != nil {
		t.Fatal(err)
	}
	if runner.units[agentUnitName].UnitFileState != "enabled" || gate.open || !stoppedRuntime(runner.units[agentUnitName]) || !stoppedRuntime(runner.units[nebulaUnitName]) {
		t.Fatalf("services not quiesced: agent=%+v nebula=%+v", runner.units[agentUnitName], runner.units[nebulaUnitName])
	}
	if len(processes.stopped) != 1 || processes.stopped[0] != filepath.Join(manager.releaseRoot, identity.InstalledID) {
		t.Fatalf("release stop proofs=%v", processes.stopped)
	}
	actions := runner.mutatingActions()
	if !reflect.DeepEqual(actions, []string{"stop"}) {
		t.Fatalf("mutating systemctl order=%v", actions)
	}
	if closeIndex, stopIndex := eventIndex(runner.events, "gate:close"), eventIndex(runner.events, "systemctl:stop"); closeIndex < 0 || stopIndex < 0 || closeIndex > stopIndex {
		t.Fatalf("runtime gate was not closed before stop: %v", runner.events)
	}
}

func TestSystemdReloadRestoresOnlyAgentBootAndRuntime(t *testing.T) {
	runner := newFakeSystemdRunner()
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	gate := testRuntimeGate(t, manager)
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")

	desired := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true}
	if err := manager.reloadAndRestore(context.Background(), identity, desired); err != nil {
		t.Fatal(err)
	}
	if runner.units[agentUnitName].UnitFileState != "enabled" || !gate.open || !unitRunning(runner.units[agentUnitName]) {
		t.Fatalf("agent was not restored: %+v", runner.units[agentUnitName])
	}
	if runner.units[nebulaUnitName].UnitFileState != "static" || !stoppedRuntime(runner.units[nebulaUnitName]) {
		t.Fatalf("Nebula was directly enabled or started: %+v", runner.units[nebulaUnitName])
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"daemon-reload", "start"}) {
		t.Fatalf("mutating systemctl order=%v", actions)
	}
	if len(processes.verified) != 1 || processes.verified[0].pid == 0 || !strings.HasSuffix(processes.verified[0].binary, "/bin/meshctl") {
		t.Fatalf("restored process proof=%+v", processes.verified)
	}
}

func TestSystemdRestoreWaitsForPreviouslyActiveNebula(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.startNebulaWithAgent = true
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	desired := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, NebulaWasActive: true, RuntimeGateWasOpen: true}
	if err := manager.reloadAndRestore(context.Background(), identity, desired); err != nil {
		t.Fatal(err)
	}
	if !unitRunning(runner.units[nebulaUnitName]) || len(processes.verified) < 2 {
		t.Fatalf("previously active Nebula was not proven restored: unit=%+v proofs=%+v", runner.units[nebulaUnitName], processes.verified)
	}
}

func TestSystemdReloadAndQuiesceClosesSwitchedUnitCacheWindow(t *testing.T) {
	runner := newFakeSystemdRunner()
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	testRuntimeGate(t, manager).open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 301)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 302)
	if err := manager.reloadAndQuiesce(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"daemon-reload", "stop"}) {
		t.Fatalf("switched quarantine order=%v", actions)
	}
	if len(processes.stopped) != 1 {
		t.Fatalf("release stop proof count=%d", len(processes.stopped))
	}
}

func TestSystemdReloadKeepsFirstInstallDisabledAndStopped(t *testing.T) {
	runner := newFakeSystemdRunner()
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	if err := manager.reloadAndRestore(context.Background(), identity, ServiceSnapshot{}); err != nil {
		t.Fatal(err)
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"daemon-reload"}) {
		t.Fatalf("first install changed boot/runtime state: %v", actions)
	}
	if len(processes.verified) != 0 {
		t.Fatal("stopped first install claimed a running process proof")
	}
}

func TestSystemdRestoreReopensPreviouslyOpenGateWithoutStartingStoppedAgent(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	desired := ServiceSnapshot{AgentWasEnabled: true, RuntimeGateWasOpen: true}
	if err := manager.reloadAndRestore(context.Background(), identity, desired); err != nil {
		t.Fatal(err)
	}
	if !testRuntimeGate(t, manager).open {
		t.Fatal("previously open gate was not restored")
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"daemon-reload"}) {
		t.Fatalf("stopped agent was unexpectedly started or topology changed: %v", actions)
	}
}

func TestSystemdQuiesceGateFailurePreventsStop(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	gate := testRuntimeGate(t, manager)
	gate.open = true
	gate.closeErr = errors.New("injected gate fsync failure")
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 901)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 902)
	want := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, NebulaWasActive: true, RuntimeGateWasOpen: true}
	if err := manager.quiesce(context.Background(), &identity, want); err == nil || !strings.Contains(err.Error(), "gate") {
		t.Fatalf("gate failure did not stop quiesce: %v", err)
	}
	if actions := runner.mutatingActions(); len(actions) != 0 {
		t.Fatalf("systemctl mutated after ambiguous gate close: %v", actions)
	}
}

func TestActivateEnrolledRuntimeIsIdempotentAndProvesBothProcesses(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.startNebulaWithAgent = true
	processes := &fakeProcessVerifier{}
	manager, identity := testInstalledSystemdManager(t, runner, processes)
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	if already, err := manager.activateEnrolled(context.Background(), identity); err != nil || already {
		t.Fatal(err)
	}
	if !testRuntimeGate(t, manager).open || len(processes.verified) < 2 {
		t.Fatalf("runtime gate/processes were not proven: gate=%t proofs=%+v", testRuntimeGate(t, manager).open, processes.verified)
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"enable", "start"}) {
		t.Fatalf("activation actions=%v", actions)
	}
	before := len(runner.mutatingActions())
	if already, err := manager.activateEnrolled(context.Background(), identity); err != nil || !already {
		t.Fatalf("idempotent activation: %v", err)
	}
	if after := len(runner.mutatingActions()); after != before {
		t.Fatalf("idempotent activation mutated systemd again: before=%d after=%d", before, after)
	}
}

func TestActivateEnrolledRuntimeSynchronousFailureQuarantines(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.failAction = map[string]error{"start": errors.New("injected start failure")}
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	if _, err := manager.activateEnrolled(context.Background(), identity); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("activation failure=%v", err)
	}
	if testRuntimeGate(t, manager).open || runner.units[agentUnitName].UnitFileState != "disabled" ||
		!stoppedRuntime(runner.units[agentUnitName]) || !stoppedRuntime(runner.units[nebulaUnitName]) {
		t.Fatalf("failed activation not quarantined: gate=%t agent=%+v nebula=%+v", testRuntimeGate(t, manager).open, runner.units[agentUnitName], runner.units[nebulaUnitName])
	}
	want := []string{"enable", "start", "stop", "disable"}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, want) {
		t.Fatalf("failure compensation actions=%v want=%v", actions, want)
	}
	if closeIndex, stopIndex := eventIndex(runner.events, "gate:close"), eventIndex(runner.events, "systemctl:stop"); closeIndex < 0 || stopIndex < 0 || closeIndex > stopIndex {
		t.Fatalf("failed activation was not gated before stop: %v", runner.events)
	}
}

func TestActivateEnrolledRuntimeCancellationDuringFailureStillQuarantines(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.failAction = map[string]error{"start": errors.New("injected start failure")}
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	ctx, cancel := context.WithCancel(context.Background())
	runner.onAction = map[string]func(){"start": cancel}
	if _, err := manager.activateEnrolled(ctx, identity); err == nil || !strings.Contains(err.Error(), "was quarantined") {
		t.Fatalf("canceled activation was not proven quarantined: %v", err)
	}
	for _, action := range []string{"stop", "disable"} {
		observed := runner.contextErrors[action]
		if len(observed) == 0 || observed[len(observed)-1] != nil {
			t.Fatalf("%s did not receive a detached live cleanup context: %v", action, observed)
		}
	}
	if testRuntimeGate(t, manager).open || !stoppedRuntime(runner.units[agentUnitName]) || runner.units[agentUnitName].UnitFileState != "disabled" {
		t.Fatalf("canceled activation left runtime reachable: gate=%t agent=%+v", testRuntimeGate(t, manager).open, runner.units[agentUnitName])
	}
}

func TestActivateEnrolledCanceledPreflightDoesNotQuiesceHealthyRuntime(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.honorCanceledContext = true
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	gate := testRuntimeGate(t, manager)
	gate.open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 1201)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 1202)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.activateEnrolled(ctx, identity); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preflight error=%v", err)
	}
	if actions := runner.mutatingActions(); len(actions) != 0 {
		t.Fatalf("canceled preflight mutated healthy runtime: %v", actions)
	}
	if !gate.open || !unitRunning(runner.units[agentUnitName]) || !unitRunning(runner.units[nebulaUnitName]) {
		t.Fatalf("canceled preflight disrupted healthy runtime: gate=%t agent=%+v nebula=%+v", gate.open, runner.units[agentUnitName], runner.units[nebulaUnitName])
	}
}

func TestActivateEnrolledDoesNotReconcileArbitraryPreflightFailure(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.failAction = map[string]error{"show": errors.New("transient systemd query failure")}
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	gate := testRuntimeGate(t, manager)
	gate.open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 1301)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 1302)
	if _, err := manager.activateEnrolled(context.Background(), identity); err == nil || !strings.Contains(err.Error(), "query failure") {
		t.Fatalf("arbitrary preflight failure=%v", err)
	}
	if actions := runner.mutatingActions(); len(actions) != 0 {
		t.Fatalf("arbitrary preflight failure triggered reconciliation: %v", actions)
	}
	if !gate.open || !unitRunning(runner.units[agentUnitName]) || !unitRunning(runner.units[nebulaUnitName]) {
		t.Fatal("arbitrary preflight failure disrupted healthy runtime")
	}
}

func TestActivateEnrolledDoesNotClaimFailedQuarantineProof(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.failAction = map[string]error{
		"start": errors.New("injected start failure"),
		"stop":  errors.New("injected stop failure"),
	}
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	_, err := manager.activateEnrolled(context.Background(), identity)
	if err == nil || !strings.Contains(err.Error(), "could not be proven") || strings.Contains(err.Error(), "was quarantined") {
		t.Fatalf("unproven quarantine error=%v", err)
	}
}

func TestActivateEnrolledRuntimeRetriesInterruptedGatePublication(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.startNebulaWithAgent = true
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	gate := testRuntimeGate(t, manager)
	gate.pending = true
	runner.units[agentUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "disabled")
	runner.units[nebulaUnitName] = stoppedLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static")
	if already, err := manager.activateEnrolled(context.Background(), identity); err != nil || already {
		t.Fatalf("interrupted gate publication was not recovered: %v", err)
	}
	if gate.pending || !gate.open {
		t.Fatalf("gate recovery state pending=%t open=%t", gate.pending, gate.open)
	}
	want := []string{"stop", "enable", "start"}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, want) {
		t.Fatalf("gate retry actions=%v want=%v", actions, want)
	}
}

func TestActivateEnrolledCancellationDuringCrashReconcileLeavesRuntimeQuiesced(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	gate := testRuntimeGate(t, manager)
	gate.pending = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 1401)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 1402)
	ctx, cancel := context.WithCancel(context.Background())
	runner.onAction = map[string]func(){"stop": cancel}

	if _, err := manager.activateEnrolled(ctx, identity); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("crash-reconciliation cancellation error=%v", err)
	}
	if gate.open || gate.pending || !stoppedRuntime(runner.units[agentUnitName]) || !stoppedRuntime(runner.units[nebulaUnitName]) {
		t.Fatalf("canceled reconciliation was not left proven quiesced: gate=(open=%t pending=%t) agent=%+v nebula=%+v", gate.open, gate.pending, runner.units[agentUnitName], runner.units[nebulaUnitName])
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"stop"}) {
		t.Fatalf("canceled reconciliation reopened or restarted runtime: %v", actions)
	}
	if eventIndex(runner.events, "gate:open") >= 0 {
		t.Fatalf("canceled reconciliation reopened runtime gate: %v", runner.events)
	}
}

func TestActivateEnrolledRuntimeRetriesActiveProcessBehindClosedGate(t *testing.T) {
	runner := newFakeSystemdRunner()
	runner.startNebulaWithAgent = true
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 1001)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 1002)
	if already, err := manager.activateEnrolled(context.Background(), identity); err != nil || already {
		t.Fatalf("closed-gate active crash state was not recovered: %v", err)
	}
	if !testRuntimeGate(t, manager).open || !unitRunning(runner.units[agentUnitName]) || !unitRunning(runner.units[nebulaUnitName]) {
		t.Fatalf("runtime was not restored: gate=%t agent=%+v nebula=%+v", testRuntimeGate(t, manager).open, runner.units[agentUnitName], runner.units[nebulaUnitName])
	}
	want := []string{"stop", "start"}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, want) {
		t.Fatalf("closed-gate retry actions=%v want=%v", actions, want)
	}
}

func TestSystemdRestoreStopsUnexpectedActiveNebula(t *testing.T) {
	runner := newFakeSystemdRunner()
	manager, identity := testInstalledSystemdManager(t, runner, &fakeProcessVerifier{})
	gate := testRuntimeGate(t, manager)
	gate.open = true
	runner.units[agentUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, agentUnitName), "enabled", 1101)
	runner.units[nebulaUnitName] = runningLoadedUnit(filepath.Join(manager.unitDirectory, nebulaUnitName), "static", 1102)
	desired := ServiceSnapshot{AgentWasEnabled: true, AgentWasActive: true, RuntimeGateWasOpen: true}
	if err := manager.reloadAndRestore(context.Background(), identity, desired); err == nil || !strings.Contains(err.Error(), "was stopped") {
		t.Fatalf("unexpected live Nebula was accepted: %v", err)
	}
	if gate.open || !stoppedRuntime(runner.units[agentUnitName]) || !stoppedRuntime(runner.units[nebulaUnitName]) {
		t.Fatalf("unexpected Nebula was not quarantined: gate=%t agent=%+v nebula=%+v", gate.open, runner.units[agentUnitName], runner.units[nebulaUnitName])
	}
	if actions := runner.mutatingActions(); !reflect.DeepEqual(actions, []string{"daemon-reload", "start", "stop"}) {
		t.Fatalf("unexpected Nebula quarantine actions=%v", actions)
	}
}

func TestStableManagedUnitEnableDoesNotPinVersionedRelease(t *testing.T) {
	if _, err := os.Stat(systemctlPath); err != nil {
		t.Skipf("systemctl unavailable: %v", err)
	}
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "usr/local/lib/systemd/system")
	if err := os.MkdirAll(unitDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	content, err := managedUnitContent(agentUnitName)
	if err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(unitDirectory, agentUnitName)
	if err := os.WriteFile(unitPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unitPath, 0o444); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(systemctlPath, "--root="+root, "enable", agentUnitName)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("systemctl --root enable: %v: %s", err, output)
	}
	gate := filepath.Join(root, "etc/systemd/system/multi-user.target.wants", agentUnitName)
	target, err := os.Readlink(gate)
	if err != nil || target != "/usr/local/lib/systemd/system/"+agentUnitName {
		t.Fatalf("boot gate target=%q err=%v", target, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/systemd/system", agentUnitName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enable created a shadowing unit alias: %v", err)
	}
}

func TestExecSystemdRunnerExecutesPinnedTrustedBinary(t *testing.T) {
	output, err := (execSystemdRunner{}).Run(context.Background(), "--version")
	if err != nil {
		t.Fatalf("pinned systemctl execution failed: %v", err)
	}
	if !bytes.Contains(output, []byte("systemd")) {
		t.Fatalf("unexpected systemctl version output %q", output)
	}
}

func TestProcessProofParsersUseStableKernelFields(t *testing.T) {
	processDirectory := filepath.Join("/proc", strconv.Itoa(os.Getpid()))
	startTime, err := readProcessStartTime(processDirectory)
	if err != nil || !decimalPID(startTime) {
		t.Fatalf("start time=%q err=%v", startTime, err)
	}
	controlGroup, err := readProcessControlGroup(processDirectory)
	if err != nil || !canonicalControlGroup(controlGroup) {
		t.Fatalf("control group=%q err=%v", controlGroup, err)
	}
	for _, bad := range []string{"", "/", "relative", "/a/../b", "/a\n"} {
		if canonicalControlGroup(bad) {
			t.Fatalf("noncanonical control group %q accepted", bad)
		}
	}
}

type fakeSystemdRunner struct {
	units                map[string]systemdUnitState
	commands             [][]string
	nextPID              uint64
	startNebulaWithAgent bool
	events               []string
	failAction           map[string]error
	contextErrors        map[string][]error
	honorCanceledContext bool
	onAction             map[string]func()
}

func newFakeSystemdRunner() *fakeSystemdRunner {
	return &fakeSystemdRunner{units: make(map[string]systemdUnitState), nextPID: 500}
}

func (runner *fakeSystemdRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	runner.commands = append(runner.commands, append([]string(nil), args...))
	if len(args) == 0 {
		return nil, errors.New("missing systemctl action")
	}
	if runner.contextErrors == nil {
		runner.contextErrors = make(map[string][]error)
	}
	runner.contextErrors[args[0]] = append(runner.contextErrors[args[0]], ctx.Err())
	if callback := runner.onAction[args[0]]; callback != nil {
		callback()
	}
	if runner.honorCanceledContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch args[0] {
	case "--version":
		return []byte("systemd 259 (259.1-1)\n"), nil
	case "show":
		if err := runner.failAction["show"]; err != nil {
			return nil, err
		}
		name := args[len(args)-1]
		unit, found := runner.units[name]
		if !found {
			unit = absentSystemdUnit()
		}
		return renderSystemdUnit(unit), nil
	case "disable":
		runner.events = append(runner.events, "systemctl:disable")
		if err := runner.failAction["disable"]; err != nil {
			return nil, err
		}
		unit := runner.units[agentUnitName]
		unit.UnitFileState = "disabled"
		unit.WantedBy = ""
		runner.units[agentUnitName] = unit
	case "enable":
		runner.events = append(runner.events, "systemctl:enable")
		if err := runner.failAction["enable"]; err != nil {
			return nil, err
		}
		unit := runner.units[agentUnitName]
		unit.UnitFileState = "enabled"
		unit.WantedBy = "multi-user.target"
		runner.units[agentUnitName] = unit
	case "stop":
		runner.events = append(runner.events, "systemctl:stop")
		if err := runner.failAction["stop"]; err != nil {
			return nil, err
		}
		for _, name := range []string{agentUnitName, nebulaUnitName} {
			unit := runner.units[name]
			unit.ActiveState, unit.SubState, unit.MainPID, unit.ControlGroup = "inactive", "dead", 0, ""
			runner.units[name] = unit
		}
	case "start":
		runner.events = append(runner.events, "systemctl:start")
		if err := runner.failAction["start"]; err != nil {
			return nil, err
		}
		runner.nextPID++
		unit := runner.units[agentUnitName]
		unit.ActiveState, unit.SubState, unit.MainPID = "active", "running", runner.nextPID
		unit.ControlGroup = "/system.slice/mesh-agent.service"
		runner.units[agentUnitName] = unit
		if runner.startNebulaWithAgent {
			runner.nextPID++
			nebula := runner.units[nebulaUnitName]
			nebula.ActiveState, nebula.SubState, nebula.MainPID = "active", "running", runner.nextPID
			nebula.ControlGroup = "/system.slice/mesh-nebula.service"
			runner.units[nebulaUnitName] = nebula
		}
	case "daemon-reload":
		runner.events = append(runner.events, "systemctl:daemon-reload")
	default:
		return nil, fmt.Errorf("unexpected systemctl action %q", args[0])
	}
	return nil, nil
}

func (runner *fakeSystemdRunner) mutatingActions() []string {
	var actions []string
	for _, command := range runner.commands {
		if len(command) > 0 && command[0] != "show" && command[0] != "--version" {
			actions = append(actions, command[0])
		}
	}
	return actions
}

func TestParseSystemdVersionRequiresAuditableMinimum(t *testing.T) {
	for _, test := range []struct {
		value string
		want  uint64
	}{
		{value: "systemd 249 (249.11-0ubuntu3)\n+PAM\n", want: 249},
		{value: "systemd 259\n", want: 259},
	} {
		got, err := parseSystemdVersion([]byte(test.value))
		if err != nil || got != test.want {
			t.Fatalf("parse %q = %d, %v", test.value, got, err)
		}
	}
	for _, bad := range []string{"", "systemd\n", "systemd 0249\n", "systemd unknown\n", "other 259\n", "systemd 249\x00\n"} {
		if _, err := parseSystemdVersion([]byte(bad)); err == nil {
			t.Fatalf("invalid version %q accepted", bad)
		}
	}
}

type processProofCall struct {
	pid          uint64
	binary       string
	argv         []string
	controlGroup string
}

type fakeProcessVerifier struct {
	verified []processProofCall
	stopped  []string
	err      error
}

type fakeRuntimeGate struct {
	open       bool
	pending    bool
	inspectErr error
	openErr    error
	closeErr   error
	calls      []string
	events     *[]string
}

type fakeChildRuntimeGate struct {
	runner           *fakeSystemdRunner
	open             *bool
	directoryPresent *bool
	inspectErr       error
	calls            int
}

func (gate *fakeChildRuntimeGate) ProveRuntimeDirectoryAbsent() error {
	present := false
	if gate.directoryPresent != nil {
		present = *gate.directoryPresent
	} else if gate.runner != nil {
		present = unitRunning(gate.runner.units[agentUnitName])
	}
	if present {
		return errors.New("agent RuntimeDirectory remains present")
	}
	return nil
}

func (gate *fakeChildRuntimeGate) Inspect() (bool, error) {
	gate.calls++
	if gate.inspectErr != nil {
		return false, gate.inspectErr
	}
	if gate.open != nil {
		return *gate.open, nil
	}
	if gate.runner == nil {
		return false, nil
	}
	return unitRunning(gate.runner.units[nebulaUnitName]), nil
}

func (gate *fakeRuntimeGate) record(action string) {
	gate.calls = append(gate.calls, action)
	if gate.events != nil {
		*gate.events = append(*gate.events, "gate:"+action)
	}
}

func (gate *fakeRuntimeGate) Inspect() (bool, error) {
	gate.record("inspect")
	if gate.pending {
		return false, errRuntimeGatePublicationPending
	}
	return gate.open, gate.inspectErr
}

func (gate *fakeRuntimeGate) Open() error {
	gate.record("open")
	if gate.openErr != nil {
		return gate.openErr
	}
	gate.pending = false
	gate.open = true
	return nil
}

func (gate *fakeRuntimeGate) Close() error {
	gate.record("close")
	if gate.closeErr != nil {
		return gate.closeErr
	}
	gate.pending = false
	gate.open = false
	return nil
}

func (verifier *fakeProcessVerifier) Verify(pid uint64, expectedBinary string, expectedArgv []string, expectedControlGroup string) error {
	verifier.verified = append(verifier.verified, processProofCall{
		pid: pid, binary: expectedBinary, argv: append([]string(nil), expectedArgv...), controlGroup: expectedControlGroup,
	})
	return verifier.err
}

func (verifier *fakeProcessVerifier) ProveReleaseStopped(releasePath string, _ []string) error {
	verifier.stopped = append(verifier.stopped, releasePath)
	return verifier.err
}

func testSystemdManager(t *testing.T, runner systemdCommandRunner, processes managedProcessVerifier) *systemdManager {
	t.Helper()
	root := t.TempDir()
	gate := &fakeRuntimeGate{}
	childGate := &fakeChildRuntimeGate{}
	if fake, ok := runner.(*fakeSystemdRunner); ok {
		gate.events = &fake.events
		childGate.runner = fake
	}
	return &systemdManager{
		runner: runner, processes: processes, runtimeGate: gate, childGate: childGate,
		unitDirectory: filepath.Join(root, "units"), releaseRoot: filepath.Join(root, "releases"),
		restoreTimeout: 50 * time.Millisecond, restorePoll: time.Millisecond,
	}
}

func testChildRuntimeGate(t *testing.T, manager *systemdManager) *fakeChildRuntimeGate {
	t.Helper()
	gate, ok := manager.childGate.(*fakeChildRuntimeGate)
	if !ok {
		t.Fatal("test manager does not use a fake child runtime gate")
	}
	return gate
}

func testRuntimeGate(t *testing.T, manager *systemdManager) *fakeRuntimeGate {
	t.Helper()
	gate, ok := manager.runtimeGate.(*fakeRuntimeGate)
	if !ok {
		t.Fatal("test manager does not use a fake runtime gate")
	}
	return gate
}

func eventIndex(events []string, want string) int {
	for index, event := range events {
		if event == want {
			return index
		}
	}
	return -1
}

func testInstalledSystemdManager(t *testing.T, runner systemdCommandRunner, processes managedProcessVerifier) (*systemdManager, ReleaseIdentity) {
	t.Helper()
	manager := testSystemdManager(t, runner, processes)
	identity := testRelease(12, "a", "b", 2)
	release := filepath.Join(manager.releaseRoot, identity.InstalledID)
	for _, directory := range []string{manager.unitDirectory, filepath.Join(release, "lib/systemd/system"), filepath.Join(release, "bin")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range topologyFileSpecs() {
		source := filepath.Join(release, spec.endpointRelative())
		if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, spec.content, 0o444); err != nil {
			t.Fatal(err)
		}
		relative, found := strings.CutPrefix(filepath.ToSlash(spec.endpointRelative()), "lib/systemd/system/")
		if !found {
			t.Fatalf("managed systemd topology file is outside the fixed unit tree: %q", spec.endpointRelative())
		}
		fixed := filepath.Join(manager.unitDirectory, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(fixed), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixed, spec.content, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixed, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"meshctl", "nebula"} {
		if err := os.WriteFile(filepath.Join(release, "bin", name), []byte(name), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	return manager, identity
}

func absentSystemdUnit() systemdUnitState {
	return systemdUnitState{LoadState: "not-found", ActiveState: "inactive", SubState: "dead"}
}

func stoppedLoadedUnit(fragment, unitFileState string) systemdUnitState {
	unit := systemdUnitState{
		LoadState: "loaded", FragmentPath: fragment,
		DropInPaths: managedTimeoutAbortDropInPath(filepath.Dir(fragment), filepath.Base(fragment)), TimeoutStopFailureMode: "terminate",
		UnitFileState: unitFileState,
		ActiveState:   "inactive", SubState: "dead",
	}
	if unitFileState == "enabled" {
		unit.WantedBy = "multi-user.target"
	}
	return unit
}

func runningLoadedUnit(fragment, unitFileState string, pid uint64) systemdUnitState {
	unit := systemdUnitState{
		LoadState: "loaded", FragmentPath: fragment,
		DropInPaths: managedTimeoutAbortDropInPath(filepath.Dir(fragment), filepath.Base(fragment)), TimeoutStopFailureMode: "terminate",
		UnitFileState: unitFileState,
		ActiveState:   "active", SubState: "running", MainPID: pid,
		ControlGroup: "/system.slice/" + filepath.Base(fragment),
	}
	if unitFileState == "enabled" {
		unit.WantedBy = "multi-user.target"
	}
	return unit
}

func unitRunning(unit systemdUnitState) bool {
	return unit.ActiveState == "active" && unit.SubState == "running" && unit.MainPID > 1
}

func renderSystemdUnit(unit systemdUnitState) []byte {
	return []byte(fmt.Sprintf(
		"LoadState=%s\nFragmentPath=%s\nDropInPaths=%s\nTimeoutStopFailureMode=%s\nUnitFileState=%s\nActiveState=%s\nSubState=%s\nMainPID=%d\nControlGroup=%s\nWantedBy=%s\nRequiredBy=%s\nRequisiteOf=%s\nUpheldBy=%s\nBoundBy=%s\nTriggeredBy=%s\nOnFailureOf=%s\nOnSuccessOf=%s\nConsistsOf=%s\nConflictedBy=%s\nPropagatesReloadTo=%s\nPropagatesStopTo=%s\n",
		unit.LoadState, unit.FragmentPath, unit.DropInPaths, unit.TimeoutStopFailureMode, unit.UnitFileState,
		unit.ActiveState, unit.SubState, unit.MainPID, unit.ControlGroup,
		unit.WantedBy, unit.RequiredBy, unit.RequisiteOf, unit.UpheldBy, unit.BoundBy,
		unit.TriggeredBy, unit.OnFailureOf, unit.OnSuccessOf, unit.ConsistsOf, unit.ConflictedBy, unit.PropagatesReloadTo, unit.PropagatesStopTo,
	))
}
