//go:build linux

package supervisedchild

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testBinary = "/opt/mesh/current/bin/nebula"
	testConfig = "/var/db/mesh-agent/runtime/current/config.yml"
)

func TestNewRequiresExactAbsoluteBinaryAndConfig(t *testing.T) {
	starter := &fakeStarter{}
	gate := &fakeGate{}
	tests := []struct {
		name   string
		binary string
		config string
	}{
		{name: "relative binary", binary: "nebula", config: testConfig},
		{name: "unclean binary", binary: "/opt/mesh/current/../current/bin/nebula", config: testConfig},
		{name: "root binary", binary: "/", config: testConfig},
		{name: "relative config", binary: testBinary, config: "config.yml"},
		{name: "unclean config", binary: testBinary, config: "/var/db/mesh-agent/./runtime/config.yml"},
		{name: "NUL config", binary: testBinary, config: "/var/db/mesh-agent/config.yml\x00ignored"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.binary, test.config, starter, gate); err == nil {
				t.Fatal("unsafe path contract was accepted")
			}
		})
	}
}

func TestReloadStartsAndAcknowledgesOnlyExactProvenChild(t *testing.T) {
	events := []string{}
	gate := &fakeGate{events: &events}
	process := &fakeProcess{events: &events}
	starter := &fakeStarter{events: &events, process: process}
	supervisor := mustSupervisor(t, starter, gate)

	if err := supervisor.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantStartArgs := []string{"-config", testConfig}
	if starter.binary != testBinary || !reflect.DeepEqual(starter.args, wantStartArgs) {
		t.Fatalf("started (%q, %q); want (%q, %q)", starter.binary, starter.args, testBinary, wantStartArgs)
	}
	if process.proveBinary != testBinary || !reflect.DeepEqual(process.proveArgs, wantStartArgs) {
		t.Fatalf("proved (%q, %q); want (%q, %q)", process.proveBinary, process.proveArgs, testBinary, wantStartArgs)
	}
	if got, want := events, []string{"gate.close", "gate.inspect", "gate.open", "start", "gate.inspect", "process.prove"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("reload events = %q; want %q", got, want)
	}

	observation, err := supervisor.Observe(context.Background())
	if err != nil || !observation.Healthy {
		t.Fatalf("Observe() = %+v, %v; want healthy", observation, err)
	}
}

func TestReloadProofFailureClosesBeforeTerminateAndWaits(t *testing.T) {
	events := []string{}
	gate := &fakeGate{events: &events}
	process := &fakeProcess{events: &events, proveErr: errors.New("wrong executable")}
	starter := &fakeStarter{events: &events, process: process}
	supervisor := mustSupervisor(t, starter, gate)

	err := supervisor.Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "wrong executable") {
		t.Fatalf("Reload() error = %v; want proof failure", err)
	}
	want := []string{
		"gate.close", "gate.inspect", "gate.open", "start", "gate.inspect", "process.prove",
		"gate.close", "process.terminate", "process.wait", "gate.inspect",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("failure events = %q; want %q", events, want)
	}
	if observation, observeErr := supervisor.Observe(context.Background()); observeErr == nil || observation.Healthy {
		t.Fatalf("Observe() after cleanup = %+v, %v; want unhealthy error", observation, observeErr)
	}
}

func TestReloadGateOpenFailureProvesPartialPublicationClosedWithoutStarting(t *testing.T) {
	events := []string{}
	gate := &fakeGate{
		events: &events, openErr: errors.New("publication sync failed"),
		openOnError: true,
	}
	starter := &fakeStarter{events: &events, process: &fakeProcess{events: &events}}
	supervisor := mustSupervisor(t, starter, gate)

	err := supervisor.Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "publication sync failed") {
		t.Fatalf("Reload() error = %v; want gate publication failure", err)
	}
	if got, want := events, []string{
		"gate.close", "gate.inspect", "gate.open", "gate.close", "gate.inspect",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("gate-open failure events = %q; want %q", got, want)
	}
	if starter.binary != "" || len(starter.args) != 0 {
		t.Fatalf("gate-open failure unexpectedly started %q %q", starter.binary, starter.args)
	}
	if gate.open {
		t.Fatal("partial gate publication remained open after failed reload")
	}
}

func TestQuarantineAttemptsCloseBeforeTerminateAndRequiresWaitProof(t *testing.T) {
	events := []string{}
	gate := &fakeGate{events: &events}
	process := &fakeProcess{events: &events}
	starter := &fakeStarter{events: &events, process: process}
	supervisor := mustSupervisor(t, starter, gate)
	if err := supervisor.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	events = events[:0]
	gate.events = &events
	process.events = &events
	gate.closeErr = errors.New("sync failed")
	process.terminateErr = errors.New("signal failed")
	process.waitErr = errors.New("exit unproven")

	err := supervisor.Quarantine(context.Background())
	for _, want := range []string{"sync failed", "signal failed", "exit unproven"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Quarantine() error = %v; want joined %q", err, want)
		}
	}
	if got, want := events, []string{"gate.close", "process.terminate", "process.wait", "gate.inspect"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("quarantine events = %q; want %q", got, want)
	}

	// An unproven wait retains the exact child so a later cleanup retries it.
	events = events[:0]
	gate.closeErr = nil
	process.terminateErr = nil
	process.waitErr = nil
	if err := supervisor.Quarantine(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := events, []string{"gate.close", "process.terminate", "process.wait", "gate.inspect"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry events = %q; want %q", got, want)
	}
}

func TestObserveNeverAcknowledgesUnprovenChild(t *testing.T) {
	events := []string{}
	gate := &fakeGate{events: &events, open: true}
	process := &fakeProcess{events: &events, proveErr: errors.New("pid identity mismatch")}
	supervisor := mustSupervisor(t, &fakeStarter{process: process}, gate)
	supervisor.child = process

	observation, err := supervisor.Observe(context.Background())
	if err == nil || observation.Healthy {
		t.Fatalf("Observe() = %+v, %v; unproven child must not be healthy", observation, err)
	}
	if got, want := events, []string{"gate.inspect", "process.prove"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observe events = %q; want %q", got, want)
	}
}

func TestCanceledReloadStillQuarantinesWithBoundedDetachedWaitAndDoesNotRestart(t *testing.T) {
	events := []string{}
	gate := &fakeGate{events: &events, open: true}
	process := &fakeProcess{events: &events}
	starter := &fakeStarter{events: &events, process: &fakeProcess{events: &events}}
	supervisor := mustSupervisor(t, starter, gate)
	supervisor.cleanupTimeout = time.Minute
	supervisor.child = process

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := supervisor.Reload(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Reload() error = %v; want context cancellation after quarantine", err)
	}
	if got, want := events, []string{"gate.close", "process.terminate", "process.wait", "gate.inspect"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("canceled reload events = %q; want %q", got, want)
	}
	if starter.binary != "" || len(starter.args) != 0 {
		t.Fatalf("canceled reload unexpectedly started %q %q", starter.binary, starter.args)
	}
	if process.waitContextErr != nil {
		t.Fatalf("cleanup wait inherited caller cancellation: %v", process.waitContextErr)
	}
	if !process.waitHadDeadline {
		t.Fatal("cleanup wait was detached but not bounded by a deadline")
	}
}

func mustSupervisor(t *testing.T, starter Starter, gate Gate) *Supervisor {
	t.Helper()
	supervisor, err := New(testBinary, testConfig, starter, gate)
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

type fakeGate struct {
	events      *[]string
	open        bool
	openErr     error
	openOnError bool
	closeErr    error
	inspectErr  error
}

func (g *fakeGate) record(event string) {
	if g.events != nil {
		*g.events = append(*g.events, event)
	}
}

func (g *fakeGate) Open() error {
	g.record("gate.open")
	if g.openErr == nil || g.openOnError {
		g.open = true
	}
	return g.openErr
}

func (g *fakeGate) Close() error {
	g.record("gate.close")
	g.open = false
	return g.closeErr
}

func (g *fakeGate) Inspect() (bool, error) {
	g.record("gate.inspect")
	return g.open, g.inspectErr
}

type fakeStarter struct {
	events  *[]string
	process Process
	err     error
	binary  string
	args    []string
}

func (s *fakeStarter) Start(_ context.Context, binary string, args []string) (Process, error) {
	if s.events != nil {
		*s.events = append(*s.events, "start")
	}
	s.binary = binary
	s.args = append([]string(nil), args...)
	return s.process, s.err
}

type fakeProcess struct {
	events          *[]string
	proveErr        error
	terminateErr    error
	waitErr         error
	proveBinary     string
	proveArgs       []string
	waitContextErr  error
	waitHadDeadline bool
}

func (p *fakeProcess) record(event string) {
	if p.events != nil {
		*p.events = append(*p.events, event)
	}
}

func (p *fakeProcess) Prove(_ context.Context, binary string, args []string) error {
	p.record("process.prove")
	p.proveBinary = binary
	p.proveArgs = append([]string(nil), args...)
	return p.proveErr
}

func (p *fakeProcess) Terminate() error {
	p.record("process.terminate")
	return p.terminateErr
}

func (p *fakeProcess) Wait(ctx context.Context) error {
	p.record("process.wait")
	p.waitContextErr = ctx.Err()
	_, p.waitHadDeadline = ctx.Deadline()
	return p.waitErr
}
