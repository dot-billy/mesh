package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"mesh/internal/supervisedchild"
)

type recordingPersistentRuntimeGate struct {
	events *[]string
	open   bool
	err    error
}

func (gate recordingPersistentRuntimeGate) Inspect() (bool, error) {
	*gate.events = append(*gate.events, "inspect-persistent-gate")
	return gate.open, gate.err
}

func TestAuthorizeSupervisedRuntimeRequiresPersistentGateBeforeAdapter(t *testing.T) {
	for _, test := range []struct {
		name          string
		open          bool
		gateErr       error
		wantConstruct bool
		want          string
	}{
		{name: "open", open: true, wantConstruct: true},
		{name: "closed", want: "closed"},
		{name: "inspection-error", gateErr: errors.New("unsafe ACL"), want: "unsafe ACL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			construct := func() (runtimeController, error) {
				events = append(events, "construct-process-adapter")
				return noReloadRuntime{}, nil
			}
			_, err := authorizeSupervisedRuntime(recordingPersistentRuntimeGate{events: &events, open: test.open, err: test.gateErr}, construct)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("authorization error = %v, want text %q", err, test.want)
			}
			wantEvents := []string{"inspect-persistent-gate"}
			if test.wantConstruct {
				wantEvents = append(wantEvents, "construct-process-adapter")
			}
			if !reflect.DeepEqual(events, wantEvents) {
				t.Fatalf("authorization events = %v, want %v", events, wantEvents)
			}
		})
	}
}

type recordingSupervisedChild struct {
	events        *[]string
	observation   supervisedchild.Observation
	reloadErr     error
	observeErr    error
	quarantineErr error
}

func (child *recordingSupervisedChild) Reload(context.Context) error {
	*child.events = append(*child.events, "child.reload")
	return child.reloadErr
}

func (child *recordingSupervisedChild) Observe(context.Context) (supervisedchild.Observation, error) {
	*child.events = append(*child.events, "child.observe")
	return child.observation, child.observeErr
}

func (child *recordingSupervisedChild) Quarantine(context.Context) error {
	*child.events = append(*child.events, "child.quarantine")
	return child.quarantineErr
}

func TestSupervisedRuntimeRechecksPersistentGateBeforeEveryChildOperation(t *testing.T) {
	events := []string{}
	gate := recordingPersistentRuntimeGate{events: &events, open: true}
	child := &recordingSupervisedChild{
		events: &events, observation: supervisedchild.Observation{Healthy: true},
	}
	runtime := &supervisedNebulaRuntime{persistent: gate, child: child}

	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observation != (runtimeObservation{HeartbeatAllowed: true, NebulaRunning: true, Status: "healthy"}) {
		t.Fatalf("observation = %+v", observation)
	}
	want := []string{
		"inspect-persistent-gate", "child.reload",
		"inspect-persistent-gate", "child.observe",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}
}

func TestSupervisedRuntimePersistentGateFailureQuarantinesWithoutChildOperation(t *testing.T) {
	for _, test := range []struct {
		name          string
		gateErr       error
		quarantineErr error
		want          []string
	}{
		{name: "closed", want: []string{"closed"}},
		{name: "inspection error", gateErr: errors.New("unsafe ACL"), want: []string{"unsafe ACL"}},
		{
			name: "cleanup failure", gateErr: errors.New("unstable gate"),
			quarantineErr: errors.New("child remained live"), want: []string{"unstable gate", "child remained live"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			gate := recordingPersistentRuntimeGate{events: &events, err: test.gateErr}
			child := &recordingSupervisedChild{events: &events, quarantineErr: test.quarantineErr}
			runtime := &supervisedNebulaRuntime{persistent: gate, child: child}
			err := runtime.Reload(context.Background())
			for _, want := range test.want {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("Reload() error = %v, want text %q", err, want)
				}
			}
			wantEvents := []string{"inspect-persistent-gate", "child.quarantine"}
			if !reflect.DeepEqual(events, wantEvents) {
				t.Fatalf("events = %q, want %q", events, wantEvents)
			}
		})
	}
}

func TestSupervisedRuntimeRejectsUnhealthyObservationAndTeardownQuarantines(t *testing.T) {
	events := []string{}
	runtime := &supervisedNebulaRuntime{
		persistent: recordingPersistentRuntimeGate{events: &events, open: true},
		child:      &recordingSupervisedChild{events: &events},
	}
	if observation, err := runtime.Observe(context.Background()); err == nil || observation != (runtimeObservation{}) {
		t.Fatalf("Observe() = %+v, %v; want zero observation and error", observation, err)
	}
	if err := runtime.CloseReadinessMarker(); err != nil {
		t.Fatal(err)
	}
	want := []string{"inspect-persistent-gate", "child.observe", "child.quarantine"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}
}

func TestAgentCycleAuthorizesPersistentGateBeforeLoadingStateOrPolling(t *testing.T) {
	events := []string{}
	child := &recordingSupervisedChild{events: &events}
	runtime := &supervisedNebulaRuntime{
		persistent: recordingPersistentRuntimeGate{events: &events},
		child:      child,
	}
	agent := &recordingLifecycleAgent{events: &events}
	runner := &agentRunner{agent: agent, runtime: runtime}
	if _, err := runner.cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "persistent runtime gate is closed") {
		t.Fatalf("cycle error = %v", err)
	}
	want := []string{"inspect-persistent-gate", "child.quarantine"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}
}
