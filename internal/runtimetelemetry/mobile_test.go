package runtimetelemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validMobileRuntimeInput() MobileRuntimeReportInput {
	read, written := uint64(11), uint64(7)
	return MobileRuntimeReportInput{
		Version:                MobileRuntimeVersionV1,
		InstanceGeneration:     3,
		Sequence:               4,
		State:                  MobileStateTunnelRunning,
		ConfigRevision:         8,
		ConfigSHA256:           string(bytes.Repeat([]byte{'a'}, 64)),
		CertificateFingerprint: string(bytes.Repeat([]byte{'b'}, 64)),
		CertificateGeneration:  2,
		EngineIdentity:         string(bytes.Repeat([]byte{'c'}, 64)),
		RuntimeUptimeMS:        90_000,
		PacketsRead:            &read,
		PacketsWritten:         &written,
	}
}

func TestDecodeMobileRuntimeReportIsStrictAndBounded(t *testing.T) {
	valid, err := json.Marshal(validMobileRuntimeInput())
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeMobileRuntimeReportInput(valid); err != nil ||
		decoded.State != MobileStateTunnelRunning {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	tests := [][]byte{
		[]byte(`{"version":1,"version":1}`),
		append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unknown":true}`)...),
		append(append([]byte(nil), valid...), []byte(`{}`)...),
		bytes.Repeat([]byte{'x'}, MaxMobileRuntimeReportBytes+1),
		[]byte{0xff},
	}
	for _, raw := range tests {
		if _, err := DecodeMobileRuntimeReportInput(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid mobile report returned %v", err)
		}
	}
}

func TestMobileRuntimeStoreTransitionsAreMonotonicAndIdempotent(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	input := validMobileRuntimeInput()
	record, changed, err := store.PutMobile("node_mobile", now, input)
	if err != nil || !changed || record.Sequence != input.Sequence {
		t.Fatalf("record=%#v changed=%t err=%v", record, changed, err)
	}
	// Caller-owned packet counters cannot mutate persisted evidence.
	*input.PacketsRead = 99
	stored, found, err := store.GetMobile("node_mobile")
	if err != nil || !found || *stored.PacketsRead != 11 {
		t.Fatalf("stored=%#v found=%t err=%v", stored, found, err)
	}
	retry := validMobileRuntimeInput()
	if accepted, changed, err := store.PutMobile(
		"node_mobile",
		now.Add(time.Minute),
		retry,
	); err != nil || changed || !accepted.ReceivedAt.Equal(now) {
		t.Fatalf("retry=%#v changed=%t err=%v", accepted, changed, err)
	}
	conflict := validMobileRuntimeInput()
	*conflict.PacketsRead = 12
	if _, _, err := store.PutMobile("node_mobile", now, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-sequence conflict returned %v", err)
	}
	replay := validMobileRuntimeInput()
	replay.Sequence--
	if _, _, err := store.PutMobile("node_mobile", now, replay); !errors.Is(err, ErrReplay) {
		t.Fatalf("sequence replay returned %v", err)
	}
	next := validMobileRuntimeInput()
	next.Sequence++
	next.RuntimeUptimeMS++
	*next.PacketsRead = 12
	if _, changed, err := store.PutMobile(
		"node_mobile",
		now.Add(time.Minute),
		next,
	); err != nil || !changed {
		t.Fatalf("next changed=%t err=%v", changed, err)
	}
	restarted := validMobileRuntimeInput()
	restarted.InstanceGeneration++
	restarted.Sequence = 1
	restarted.RuntimeUptimeMS = 0
	*restarted.PacketsRead = 0
	*restarted.PacketsWritten = 0
	if _, changed, err := store.PutMobile(
		"node_mobile",
		now.Add(2*time.Minute),
		restarted,
	); err != nil || !changed {
		t.Fatalf("new instance changed=%t err=%v", changed, err)
	}
}

func TestMobileRuntimeProjectionSeparatesSuspensionStalenessAndRevocation(
	t *testing.T,
) {
	now := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	record, err := newMobileRuntimeRecord(
		"node_mobile",
		now,
		validMobileRuntimeInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := ProjectMobileRuntime(record, now.Add(time.Minute), false)
	if err != nil ||
		!fresh.Fresh ||
		fresh.ServerState != MobileStateTunnelRunning {
		t.Fatalf("fresh=%#v err=%v", fresh, err)
	}
	stale, err := ProjectMobileRuntime(
		record,
		now.Add(MobileRuntimeFreshnessBound),
		false,
	)
	if err != nil || stale.Fresh || stale.ServerState != "stale" {
		t.Fatalf("stale=%#v err=%v", stale, err)
	}
	suspendedInput := validMobileRuntimeInput()
	suspendedInput.State = MobileStateSuspended
	suspendedInput.PacketsRead = nil
	suspendedInput.PacketsWritten = nil
	suspended, err := newMobileRuntimeRecord(
		"node_mobile",
		now,
		suspendedInput,
	)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectMobileRuntime(
		suspended,
		now.Add(10*time.Minute),
		false,
	)
	if err != nil || !projected.Fresh || projected.ServerState != MobileStateSuspended {
		t.Fatalf("suspended=%#v err=%v", projected, err)
	}
	revoked, err := ProjectMobileRuntime(record, now.Add(time.Minute), true)
	if err != nil || revoked.Fresh || revoked.ServerState != "revoked" {
		t.Fatalf("revoked=%#v err=%v", revoked, err)
	}
}

func TestStateDocumentMigratesV7AndPersistsMobileRecords(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v7","records":[]}`)
	migrated, err := DecodeState(legacy)
	if err != nil ||
		migrated.Schema != StateSchemaV8 ||
		len(migrated.MobileRecords) != 0 {
		t.Fatalf("migrated=%#v err=%v", migrated, err)
	}
	record, err := newMobileRuntimeRecord(
		"node_mobile",
		time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC),
		validMobileRuntimeInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	state := EmptyState()
	state.MobileRecords = []MobileRuntimeRecord{record}
	raw, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(raw)
	if err != nil ||
		len(decoded.MobileRecords) != 1 ||
		decoded.MobileRecords[0].NodeID != "node_mobile" {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
}
