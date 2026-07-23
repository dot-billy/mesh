//go:build !windows && !darwin

package nodeagent

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"mesh/internal/runtimetelemetry"
)

type recordingActiveProbeExecutor struct {
	supported bool
	result    runtimetelemetry.ActiveProbeResult
	calls     int
	before    func()
}

func (executor *recordingActiveProbeExecutor) Supported() bool { return executor.supported }

func (executor *recordingActiveProbeExecutor) Probe(context.Context, activeProbePlan) runtimetelemetry.ActiveProbeResult {
	executor.calls++
	if executor.before != nil {
		executor.before()
	}
	return runtimetelemetry.CloneActiveProbe(executor.result)
}

func eligibleActiveProbeBundle(t *testing.T, targets ...string) Bundle {
	t.Helper()
	return runtimeTelemetryBundle(
		t,
		probePrefixes("10.42.0.9/24"),
		activeProbeConfig(targets, targets, []string{probeFirewallRule("icmp", "host: any")}, nil),
	)
}

func probePrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		result[index] = netip.MustParsePrefix(value)
	}
	return result
}

func attemptedActiveProbeResult() runtimetelemetry.ActiveProbeResult {
	age := uint64(0)
	return runtimetelemetry.ActiveProbeResult{
		Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
		SampleAgeMS: &age, Attempted: 1, Replied: 1, DurationMS: 3,
	}
}

func newActiveProbeOrchestrationStore(t *testing.T) *StateStore {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStateStore(filepath.Join(directory, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestAgentActiveProbeSkipsJournalAndExecutorWhenDeniedOrUnsupported(t *testing.T) {
	now := time.Date(2026, 7, 20, 21, 0, 0, 0, time.UTC)
	t.Run("denied", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
		agent := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor}
		bundle := runtimeTelemetryBundle(
			t,
			[]netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")},
			activeProbeConfig([]string{"10.42.0.1"}, []string{"10.42.0.1"}, []string{probeFirewallRule("tcp", "host: any")}, nil),
		)
		result := agent.resolveActiveProbe(context.Background(), bundle)
		if result.State != runtimetelemetry.ProbeNotEligible || executor.calls != 0 {
			t.Fatalf("denied result = %#v calls=%d", result, executor.calls)
		}
		if _, err := store.LoadActiveProbeJournal(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("denied plan touched journal: %v", err)
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		executor := &recordingActiveProbeExecutor{supported: false}
		agent := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor}
		result := agent.resolveActiveProbe(context.Background(), eligibleActiveProbeBundle(t, "10.42.0.1"))
		if result != runtimetelemetry.UnsupportedActiveProbe() || executor.calls != 0 {
			t.Fatalf("unsupported result = %#v calls=%d", result, executor.calls)
		}
		if _, err := store.LoadActiveProbeJournal(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsupported platform touched journal: %v", err)
		}
	})
}

func TestAgentActiveProbeReservesCachesChangesPlanAndSurvivesRestart(t *testing.T) {
	store := newActiveProbeOrchestrationStore(t)
	now := time.Date(2026, 7, 20, 21, 5, 0, 0, time.UTC)
	executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
	agent := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor}
	firstBundle := eligibleActiveProbeBundle(t, "10.42.0.1")
	executor.before = func() {
		journal, err := store.LoadActiveProbeJournal()
		if err != nil || journal.Result != runtimetelemetry.UnavailableActiveProbe() || !journal.ReservedAt.Equal(now) {
			t.Fatalf("reservation before executor = %#v err=%v", journal, err)
		}
	}
	first := agent.resolveActiveProbe(context.Background(), firstBundle)
	if first.State != runtimetelemetry.ProbeAttempted || executor.calls != 1 {
		t.Fatalf("first result = %#v calls=%d", first, executor.calls)
	}
	journal, err := store.LoadActiveProbeJournal()
	if err != nil || journal.Result.State != runtimetelemetry.ProbeAttempted || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(journal.PlanSHA256) {
		t.Fatalf("completed journal = %#v err=%v", journal, err)
	}
	firstHash := journal.PlanSHA256

	now = now.Add(10 * time.Second)
	cached := agent.resolveActiveProbe(context.Background(), firstBundle)
	if cached.State != runtimetelemetry.ProbeAttempted || cached.SampleAgeMS == nil || *cached.SampleAgeMS != 10_000 || executor.calls != 1 {
		t.Fatalf("cached result = %#v calls=%d", cached, executor.calls)
	}

	changedBundle := eligibleActiveProbeBundle(t, "10.42.0.2")
	changed := agent.resolveActiveProbe(context.Background(), changedBundle)
	if changed != runtimetelemetry.UnavailableActiveProbe() || executor.calls != 1 {
		t.Fatalf("changed-plan result = %#v calls=%d", changed, executor.calls)
	}

	now = now.Add(20 * time.Second)
	executor.before = nil
	due := agent.resolveActiveProbe(context.Background(), changedBundle)
	if due.State != runtimetelemetry.ProbeAttempted || executor.calls != 2 {
		t.Fatalf("due result = %#v calls=%d", due, executor.calls)
	}
	journal, err = store.LoadActiveProbeJournal()
	if err != nil || journal.PlanSHA256 == firstHash || !journal.ReservedAt.Equal(now) {
		t.Fatalf("changed-plan journal = %#v err=%v", journal, err)
	}

	now = now.Add(10 * time.Second)
	restartedExecutor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
	restarted := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: restartedExecutor}
	reused := restarted.resolveActiveProbe(context.Background(), changedBundle)
	if reused.State != runtimetelemetry.ProbeAttempted || reused.SampleAgeMS == nil || *reused.SampleAgeMS != 10_000 || restartedExecutor.calls != 0 {
		t.Fatalf("restart reuse = %#v calls=%d", reused, restartedExecutor.calls)
	}
}

func TestAgentActiveProbeFailsClosedForClockCorruptionAndJournalWrites(t *testing.T) {
	now := time.Date(2026, 7, 20, 21, 10, 0, 0, time.UTC)
	bundle := eligibleActiveProbeBundle(t, "10.42.0.1")

	t.Run("future reservation", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		plan, err := activeProbePlanFromVerifiedBundle(bundle)
		if err != nil {
			t.Fatal(err)
		}
		journal := activeProbeJournal{
			Schema: activeProbeJournalSchemaV1, PlanSHA256: activeProbePlanSHA256(plan),
			ReservedAt: now.Add(time.Second), Result: attemptedActiveProbeResult(),
		}
		if err := store.SaveActiveProbeJournal(journal); err != nil {
			t.Fatal(err)
		}
		executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
		agent := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor}
		if result := agent.resolveActiveProbe(context.Background(), bundle); result != runtimetelemetry.UnavailableActiveProbe() || executor.calls != 0 {
			t.Fatalf("future result = %#v calls=%d", result, executor.calls)
		}
	})

	t.Run("corrupt journal", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		path := store.Path() + ".runtime-probe.json"
		before := []byte("corrupt\n")
		if err := os.WriteFile(path, before, 0o600); err != nil {
			t.Fatal(err)
		}
		executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
		agent := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor}
		if result := agent.resolveActiveProbe(context.Background(), bundle); result != runtimetelemetry.UnavailableActiveProbe() || executor.calls != 0 {
			t.Fatalf("corrupt result = %#v calls=%d", result, executor.calls)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatalf("corrupt journal changed: %q", after)
		}
	})

	t.Run("reservation write", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
		agent := &Agent{
			Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor,
			saveActiveProbeJournal: func(activeProbeJournal) error { return errors.New("reservation write failed") },
		}
		if result := agent.resolveActiveProbe(context.Background(), bundle); result != runtimetelemetry.UnavailableActiveProbe() || executor.calls != 0 {
			t.Fatalf("reservation failure = %#v calls=%d", result, executor.calls)
		}
	})

	t.Run("final write", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
		saves := 0
		agent := &Agent{
			Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor,
			saveActiveProbeJournal: func(journal activeProbeJournal) error {
				saves++
				if saves == 2 {
					return errors.New("final write failed")
				}
				return store.SaveActiveProbeJournal(journal)
			},
		}
		if result := agent.resolveActiveProbe(context.Background(), bundle); result != runtimetelemetry.UnavailableActiveProbe() || executor.calls != 1 {
			t.Fatalf("final failure = %#v calls=%d", result, executor.calls)
		}
		journal, err := store.LoadActiveProbeJournal()
		if err != nil || journal.Result != runtimetelemetry.UnavailableActiveProbe() {
			t.Fatalf("reservation not retained = %#v err=%v", journal, err)
		}
	})

	t.Run("canceled", func(t *testing.T) {
		store := newActiveProbeOrchestrationStore(t)
		executor := &recordingActiveProbeExecutor{supported: true, result: attemptedActiveProbeResult()}
		agent := &Agent{Store: store, Now: func() time.Time { return now }, activeProbeExecutor: executor}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if result := agent.resolveActiveProbe(ctx, bundle); result != runtimetelemetry.UnavailableActiveProbe() || executor.calls != 0 {
			t.Fatalf("canceled result = %#v calls=%d", result, executor.calls)
		}
	})
}

func TestAgentActiveProbePlanHashIsDomainSeparatedAndOrderSensitive(t *testing.T) {
	first := activeProbeTestPlan("10.42.0.1", "10.42.0.2")
	second := activeProbeTestPlan("10.42.0.2", "10.42.0.1")
	firstHash := activeProbePlanSHA256(first)
	if firstHash == activeProbePlanSHA256(second) || firstHash == strings.Repeat("0", 64) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(firstHash) {
		t.Fatalf("plan hashes first=%q second=%q", firstHash, activeProbePlanSHA256(second))
	}
}
