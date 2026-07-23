package runtimetelemetry

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreSequenceIdempotencyAndUnknownReplacement(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	observed := validObservation()
	record, changed, err := store.Put("node_b", 7, now, observed, UnsupportedActiveProbe())
	if err != nil || !changed || record.HeartbeatSequence != 7 {
		t.Fatalf("initial put = %+v, %t, %v", record, changed, err)
	}
	// Mutating caller-owned pointers must not alter the accepted record.
	*observed.Snapshot.Handshakes.MostRecentCompletionAgeMS = 999
	stored, found, err := store.Get("node_b")
	if err != nil || !found || *stored.Observation.Snapshot.Handshakes.MostRecentCompletionAgeMS != 500 {
		t.Fatalf("stored clone = %+v, %t, %v", stored, found, err)
	}
	original := validObservation()
	if _, changed, err := store.Put("node_b", 7, now.Add(time.Minute), original, UnsupportedActiveProbe()); err != nil || changed {
		t.Fatalf("idempotent retry changed=%t err=%v", changed, err)
	}
	conflict := validObservation()
	conflict.Snapshot.SampleSequence++
	if _, _, err := store.Put("node_b", 7, now, conflict, UnsupportedActiveProbe()); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-sequence conflict returned %v", err)
	}
	if _, _, err := store.Put("node_b", 6, now, original, UnsupportedActiveProbe()); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay returned %v", err)
	}
	unknown := Observation{Version: VersionV1, State: StateUnknown}
	if _, changed, err := store.Put("node_b", 8, now.Add(time.Minute), unknown, UnsupportedActiveProbe()); err != nil || !changed {
		t.Fatalf("unknown replacement changed=%t err=%v", changed, err)
	}
	stored, _, _ = store.Get("node_b")
	if stored.Observation.State != StateUnknown || stored.Observation.Snapshot != nil {
		t.Fatalf("unknown replacement retained snapshot: %+v", stored)
	}
}

func TestMemoryStoreOrderingDeleteAndClose(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	for _, nodeID := range []string{"node_b", "node_a"} {
		if _, _, err := store.Put(nodeID, 1, now, Observation{Version: VersionV1, State: StateUnknown}, UnsupportedActiveProbe()); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.List()
	if err != nil || len(records) != 2 || records[0].NodeID != "node_a" || records[1].NodeID != "node_b" {
		t.Fatalf("ordered list = %+v, %v", records, err)
	}
	if deleted, err := store.Delete("node_a"); err != nil || !deleted {
		t.Fatalf("delete = %t, %v", deleted, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReadiness(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed readiness returned %v", err)
	}
}

func TestMemoryStoreClassifiesProcessContinuity(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	first := validObservation()
	record, changed, err := store.Put("node_a", 1, now, first, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("first record = %+v, changed=%t, err=%v", record, changed, err)
	}

	continuous := cloneObservation(first)
	continuous.Snapshot.SampleSequence++
	continuous.Snapshot.ProcessUptimeMS += 1_000
	continuous.Snapshot.Handshakes.CompletedTotal++
	record, changed, err = store.Put("node_a", 2, now.Add(time.Minute), continuous, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityContinuous {
		t.Fatalf("continuous record = %+v, changed=%t, err=%v", record, changed, err)
	}

	restarted := cloneObservation(continuous)
	restarted.Snapshot.ProcessInstanceID = "fedcba9876543210fedcba9876543210"
	restarted.Snapshot.SampleSequence = 1
	restarted.Snapshot.ProcessUptimeMS = 1_000
	restarted.Snapshot.Handshakes.CompletedTotal = 2
	restarted.Snapshot.Handshakes.TimedOutTotal = 0
	record, changed, err = store.Put("node_a", 3, now.Add(2*time.Minute), restarted, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityRestarted {
		t.Fatalf("restarted record = %+v, changed=%t, err=%v", record, changed, err)
	}

	unknown := Observation{Version: VersionV2, State: StateUnknown}
	record, changed, err = store.Put("node_a", 4, now.Add(3*time.Minute), unknown, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityUnavailable {
		t.Fatalf("unknown record = %+v, changed=%t, err=%v", record, changed, err)
	}
	record, changed, err = store.Put("node_a", 5, now.Add(4*time.Minute), validObservation(), UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("post-unknown record = %+v, changed=%t, err=%v", record, changed, err)
	}
	retry, changed, err := store.Put("node_a", 5, now.Add(5*time.Minute), validObservation(), UnsupportedActiveProbe())
	if err != nil || changed || retry.ProcessContinuity != ContinuityUnclassified || !retry.ReceivedAt.Equal(record.ReceivedAt) {
		t.Fatalf("idempotent retry = %+v, changed=%t, err=%v", retry, changed, err)
	}
}

func TestMemoryStoreRejectsSameProcessContinuityRollback(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Observation)
		want   error
	}{
		{name: "repeated sample sequence", mutate: func(*Observation) {}, want: ErrReplay},
		{name: "decreased sample sequence", mutate: func(value *Observation) { value.Snapshot.SampleSequence-- }, want: ErrReplay},
		{name: "version switch", mutate: func(value *Observation) {
			value.Version = VersionV1
			value.Snapshot.SampleSequence++
			value.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = nil
		}, want: ErrConflict},
		{name: "uptime rollback", mutate: func(value *Observation) {
			value.Snapshot.SampleSequence++
			value.Snapshot.ProcessUptimeMS--
		}, want: ErrConflict},
		{name: "completed counter rollback", mutate: func(value *Observation) {
			value.Snapshot.SampleSequence++
			value.Snapshot.ProcessUptimeMS++
			value.Snapshot.Handshakes.CompletedTotal--
		}, want: ErrConflict},
		{name: "timeout counter rollback", mutate: func(value *Observation) {
			value.Snapshot.SampleSequence++
			value.Snapshot.ProcessUptimeMS++
			value.Snapshot.Handshakes.TimedOutTotal--
		}, want: ErrConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore()
			if _, _, err := store.Put("node_a", 1, now, validObservation(), UnsupportedActiveProbe()); err != nil {
				t.Fatal(err)
			}
			candidate := validObservation()
			test.mutate(&candidate)
			if _, _, err := store.Put("node_a", 2, now.Add(time.Minute), candidate, UnsupportedActiveProbe()); !errors.Is(err, test.want) {
				t.Fatalf("rollback returned %v, want %v", err, test.want)
			}
			stored, found, err := store.Get("node_a")
			if err != nil || !found || stored.HeartbeatSequence != 1 || stored.ProcessContinuity != ContinuityUnclassified {
				t.Fatalf("rejected rollback changed state: %+v, found=%t, err=%v", stored, found, err)
			}
		})
	}
}
