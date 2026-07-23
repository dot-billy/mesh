package runtimetelemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"mesh/internal/postgresstore"
)

type memoryPostgresRepository struct {
	document postgresstore.Document
}

func (r *memoryPostgresRepository) Initialize(_ context.Context, domain postgresstore.Domain, body []byte) (postgresstore.WriteResult, error) {
	if domain != postgresstore.DomainRuntimeTelemetry {
		return postgresstore.WriteResult{}, postgresstore.ErrInvalidDomain
	}
	if r.document.Revision != 0 {
		if bytes.Equal(r.document.Bytes, body) {
			return postgresstore.WriteResult{Document: r.document}, nil
		}
		return postgresstore.WriteResult{}, postgresstore.ErrAlreadyInitialized
	}
	r.document = postgresstore.Document{Domain: domain, Revision: 1, Bytes: bytes.Clone(body), SHA256: sha256.Sum256(body), LastWriteID: "init", UpdatedAt: time.Now().UTC()}
	return postgresstore.WriteResult{Changed: true, Document: r.document}, nil
}

func (r *memoryPostgresRepository) Read(_ context.Context, domain postgresstore.Domain) (postgresstore.Document, error) {
	if domain != postgresstore.DomainRuntimeTelemetry || r.document.Revision == 0 {
		return postgresstore.Document{}, postgresstore.ErrNotInitialized
	}
	copy := r.document
	copy.Bytes = bytes.Clone(copy.Bytes)
	return copy, nil
}

func (r *memoryPostgresRepository) Update(_ context.Context, domain postgresstore.Domain, operation string, mutate func([]byte) ([]byte, error)) (postgresstore.WriteResult, error) {
	if domain != postgresstore.DomainRuntimeTelemetry || (operation != postgresUpdateOperation && operation != postgresMigrateOperation) || r.document.Revision == 0 {
		return postgresstore.WriteResult{}, postgresstore.ErrNotInitialized
	}
	next, err := mutate(bytes.Clone(r.document.Bytes))
	if err != nil {
		return postgresstore.WriteResult{}, err
	}
	if bytes.Equal(next, r.document.Bytes) {
		return postgresstore.WriteResult{Document: r.document}, nil
	}
	r.document.Revision++
	r.document.Bytes = bytes.Clone(next)
	r.document.SHA256 = sha256.Sum256(next)
	r.document.LastWriteID = "update"
	r.document.UpdatedAt = time.Now().UTC()
	return postgresstore.WriteResult{Changed: true, Document: r.document}, nil
}

func (*memoryPostgresRepository) CheckReadiness(context.Context) error { return nil }

func TestPostgresStoreInitializeTransitionsAndClose(t *testing.T) {
	repository := &memoryPostgresRepository{}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("idempotent initialize: %v", err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	accepted, changed, err := store.Put("node_a", 4, now, validObservation(), UnsupportedActiveProbe())
	if err != nil || !changed || accepted.HeartbeatSequence != 4 || accepted.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("put=%+v changed=%t err=%v", accepted, changed, err)
	}
	retry, changed, err := store.Put("node_a", 4, now.Add(time.Minute), validObservation(), UnsupportedActiveProbe())
	if err != nil || changed || !retry.ReceivedAt.Equal(now) {
		t.Fatalf("retry=%+v changed=%t err=%v", retry, changed, err)
	}
	if _, _, err := store.Put("node_a", 3, now, validObservation(), UnsupportedActiveProbe()); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay returned %v", err)
	}
	if records, err := store.List(); err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if deleted, err := store.Delete("node_a"); err != nil || !deleted {
		t.Fatalf("delete=%t err=%v", deleted, err)
	}
	if err := store.CheckReadiness(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed list returned %v", err)
	}
}

func TestPostgresStorePersistsConfigBoundProbeDegradation(t *testing.T) {
	repository := &memoryPostgresRepository{}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 21, 19, 30, 0, 0, time.UTC)
	digest := string(bytes.Repeat([]byte{'f'}, 64))
	observation := validObservation()
	if _, _, err := store.PutWithConfig("node_a", 1, now, observation, transitionProbe(2, 2), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest); err != nil {
		t.Fatal(err)
	}
	observation = nextTransitionObservation(observation)
	degraded, changed, err := store.PutWithConfig("node_a", 2, now.Add(time.Second), observation, transitionProbe(2, 1), UnsupportedRouteOverlap(), UnsupportedEndpointDNS(), digest)
	if err != nil || !changed || degraded.ProbeTransition != ProbeTransitionDegraded {
		t.Fatalf("degraded=%#v changed=%t err=%v", degraded, changed, err)
	}
	reopened, found, err := store.Get("node_a")
	if err != nil || !found || reopened.AppliedConfigSHA256 != digest || reopened.ProbeTransition != ProbeTransitionDegraded {
		t.Fatalf("reopened=%#v found=%t err=%v", reopened, found, err)
	}
}

func TestPostgresStoreClassifiesContinuityAndRejectsRollback(t *testing.T) {
	repository := &memoryPostgresRepository{}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	if record, _, err := store.Put("node_a", 1, now, validObservation(), UnsupportedActiveProbe()); err != nil || record.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("first record=%+v err=%v", record, err)
	}
	continuous := validObservation()
	continuous.Snapshot.SampleSequence++
	continuous.Snapshot.ProcessUptimeMS++
	record, changed, err := store.Put("node_a", 2, now.Add(time.Minute), continuous, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityContinuous {
		t.Fatalf("continuous record=%+v changed=%t err=%v", record, changed, err)
	}
	restarted := cloneObservation(continuous)
	restarted.Snapshot.ProcessInstanceID = "fedcba9876543210fedcba9876543210"
	restarted.Snapshot.SampleSequence = 1
	restarted.Snapshot.ProcessUptimeMS = 1_000
	record, changed, err = store.Put("node_a", 3, now.Add(2*time.Minute), restarted, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityRestarted {
		t.Fatalf("restarted record=%+v changed=%t err=%v", record, changed, err)
	}
	unknown := Observation{Version: VersionV2, State: StateUnknown}
	record, changed, err = store.Put("node_a", 4, now.Add(3*time.Minute), unknown, UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityUnavailable {
		t.Fatalf("unknown record=%+v changed=%t err=%v", record, changed, err)
	}
	record, changed, err = store.Put("node_a", 5, now.Add(4*time.Minute), validObservation(), UnsupportedActiveProbe())
	if err != nil || !changed || record.ProcessContinuity != ContinuityUnclassified {
		t.Fatalf("post-unknown record=%+v changed=%t err=%v", record, changed, err)
	}
	before := bytes.Clone(repository.document.Bytes)
	if _, _, err := store.Put("node_a", 6, now.Add(5*time.Minute), validObservation(), UnsupportedActiveProbe()); !errors.Is(err, ErrReplay) {
		t.Fatalf("same-process repeat returned %v", err)
	}
	rollback := validObservation()
	rollback.Snapshot.SampleSequence++
	rollback.Snapshot.ProcessUptimeMS--
	if _, _, err := store.Put("node_a", 6, now.Add(5*time.Minute), rollback, UnsupportedActiveProbe()); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-process uptime rollback returned %v", err)
	}
	if !bytes.Equal(before, repository.document.Bytes) {
		t.Fatalf("rejected PostgreSQL rollback changed exact document")
	}
}

func TestPostgresStoreEnsureInitializedMigratesV1Document(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v1","records":[]}`)
	repository := &memoryPostgresRepository{document: postgresstore.Document{
		Domain: postgresstore.DomainRuntimeTelemetry, Revision: 4, Bytes: bytes.Clone(legacy), SHA256: sha256.Sum256(legacy),
		LastWriteID: "legacy", UpdatedAt: time.Now().UTC(),
	}}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("EnsureInitialized legacy v1: %v", err)
	}
	if repository.document.Revision != 5 || string(repository.document.Bytes) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy PostgreSQL document was not migrated: revision=%d body=%s", repository.document.Revision, repository.document.Bytes)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("idempotent migrated EnsureInitialized: %v", err)
	}
	if repository.document.Revision != 5 {
		t.Fatalf("idempotent migration changed revision to %d", repository.document.Revision)
	}
}

func TestPostgresStoreEnsureInitializedMigratesV2Document(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v2","records":[]}`)
	repository := &memoryPostgresRepository{document: postgresstore.Document{
		Domain: postgresstore.DomainRuntimeTelemetry, Revision: 4, Bytes: bytes.Clone(legacy), SHA256: sha256.Sum256(legacy),
		LastWriteID: "legacy", UpdatedAt: time.Now().UTC(),
	}}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("EnsureInitialized legacy v2: %v", err)
	}
	if repository.document.Revision != 5 || string(repository.document.Bytes) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy v2 PostgreSQL document was not migrated: revision=%d body=%s", repository.document.Revision, repository.document.Bytes)
	}
}

func TestPostgresStoreEnsureInitializedMigratesV4Document(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v4","records":[]}`)
	repository := &memoryPostgresRepository{document: postgresstore.Document{
		Domain: postgresstore.DomainRuntimeTelemetry, Revision: 4, Bytes: bytes.Clone(legacy), SHA256: sha256.Sum256(legacy),
		LastWriteID: "legacy", UpdatedAt: time.Now().UTC(),
	}}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("EnsureInitialized legacy v4: %v", err)
	}
	if repository.document.Revision != 5 || string(repository.document.Bytes) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy v4 PostgreSQL document was not migrated: revision=%d body=%s", repository.document.Revision, repository.document.Bytes)
	}
}

func TestPostgresStoreEnsureInitializedMigratesV6Document(t *testing.T) {
	legacy := []byte(`{"schema":"mesh-runtime-telemetry-state-v6","records":[]}`)
	repository := &memoryPostgresRepository{document: postgresstore.Document{
		Domain: postgresstore.DomainRuntimeTelemetry, Revision: 4, Bytes: bytes.Clone(legacy), SHA256: sha256.Sum256(legacy),
		LastWriteID: "legacy", UpdatedAt: time.Now().UTC(),
	}}
	store, err := newPostgresStore(repository, PostgresStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("EnsureInitialized legacy v6: %v", err)
	}
	if repository.document.Revision != 5 || string(repository.document.Bytes) != `{"schema":"mesh-runtime-telemetry-state-v7","records":[]}` {
		t.Fatalf("legacy v6 PostgreSQL document was not migrated: revision=%d body=%s", repository.document.Revision, repository.document.Bytes)
	}
}
