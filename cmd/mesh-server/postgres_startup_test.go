package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/postgresstore"
)

type fakePostgresStartupStore struct {
	documents   map[postgresstore.Domain]postgresstore.Document
	importErr   error
	pairErr     error
	importCalls int
	pairCalls   int
	returned    map[postgresstore.Domain][]byte
}

func (store *fakePostgresStartupStore) CheckImportReadiness(ctx context.Context) error {
	store.importCalls++
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.importErr
}

func (store *fakePostgresStartupStore) ReadPair(ctx context.Context) (postgresstore.Document, postgresstore.Document, error) {
	if err := ctx.Err(); err != nil {
		return postgresstore.Document{}, postgresstore.Document{}, err
	}
	store.pairCalls++
	controlDocument, controlOK := store.documents[postgresstore.DomainControl]
	identityDocument, identityOK := store.documents[postgresstore.DomainIdentity]
	if !controlOK || !identityOK {
		return postgresstore.Document{}, postgresstore.Document{}, postgresstore.ErrNotInitialized
	}
	controlDocument.Bytes = bytes.Clone(controlDocument.Bytes)
	identityDocument.Bytes = bytes.Clone(identityDocument.Bytes)
	if store.returned == nil {
		store.returned = make(map[postgresstore.Domain][]byte)
	}
	store.returned[postgresstore.DomainControl] = controlDocument.Bytes
	store.returned[postgresstore.DomainIdentity] = identityDocument.Bytes
	if store.pairErr != nil {
		return controlDocument, identityDocument, store.pairErr
	}
	return controlDocument, identityDocument, nil
}

type fakeContextReadiness struct {
	err   error
	calls int
}

func (check *fakeContextReadiness) CheckReadiness(ctx context.Context) error {
	check.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	return check.err
}

type fakeRecoveryBinding struct {
	err            error
	calls          int
	masterVerifier string
	adminVerifier  string
}

func (check *fakeRecoveryBinding) CheckCurrentRecoveryCredentialBinding(masterVerifier, adminVerifier string) error {
	check.calls++
	check.masterVerifier = masterVerifier
	check.adminVerifier = adminVerifier
	return check.err
}

func TestValidatePostgresRecoveryDocumentsAuthenticatesExactImportedState(t *testing.T) {
	documents, box, masterKey, adminToken := postgresRecoveryFixture(t)
	defer clearPostgresRecoveryDocuments(&documents)
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, adminToken, true); err != nil {
		t.Fatalf("valid imported documents rejected: %v", err)
	}
	wrongAdmin := bytes.Repeat([]byte{'B'}, 43)
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, wrongAdmin, true); err == nil {
		t.Fatal("wrong configured administrator token authenticated")
	}
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, wrongAdmin, false); err != nil {
		t.Fatalf("explicit rotation preflight did not retain master-key cryptographic validation: %v", err)
	}
	corruptIdentity := documents
	corruptIdentity.identity.Bytes = []byte(`{"schema":"identity-state-v2","sessions":[`)
	if err := validatePostgresRecoveryDocuments(corruptIdentity, box, masterKey, adminToken, true); err == nil {
		t.Fatal("corrupt identity document passed recovery validation")
	}
}

func TestClearPostgresRecoveryDocumentsZeroesAliasesAfterSuccessAndFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		corrupt bool
	}{
		{name: "successful validation"},
		{name: "failed validation", corrupt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			documents, box, masterKey, adminToken := postgresRecoveryFixture(t)
			if test.corrupt {
				documents.identity.Bytes[0] ^= 0xff
			}
			controlAlias := documents.control.Bytes
			identityAlias := documents.identity.Bytes
			err := validatePostgresRecoveryDocuments(documents, box, masterKey, adminToken, true)
			if test.corrupt && err == nil {
				t.Fatal("corrupt documents unexpectedly validated")
			}
			if !test.corrupt && err != nil {
				t.Fatalf("valid documents failed validation: %v", err)
			}
			clearPostgresRecoveryDocuments(&documents)
			if documents.control.Bytes != nil || documents.identity.Bytes != nil {
				t.Fatal("cleared recovery document retained a byte slice")
			}
			if !allZero(controlAlias) || !allZero(identityAlias) {
				t.Fatal("clearing recovery documents did not zero an existing alias")
			}
		})
	}
}

func TestPostgresAdministratorRotationRequiresFinalConfiguredCredential(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x52}, 32)
	oldAdmin := bytes.Repeat([]byte{'O'}, 43)
	newAdmin := bytes.Repeat([]byte{'N'}, 43)
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	controlStore, err := control.OpenStore(filepath.Join(directory, "rotation-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlStore.Close() })
	service := control.NewService(controlStore, box, control.NebulaIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	oldVerifier, err := control.DeriveAdminCredentialVerifier(masterKey, oldAdmin)
	if err != nil {
		t.Fatal(err)
	}
	newVerifier, err := control.DeriveAdminCredentialVerifier(masterKey, newAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, oldVerifier, false); err != nil {
		t.Fatal(err)
	}
	controlBytes, err := controlStore.ExportRecoverySnapshot(context.Background(), box)
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(directory, "rotation-identity.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	identityBytes, err := identityStore.ExportRecoverySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	documents := postgresRecoveryDocuments{
		control:  postgresstore.Document{Domain: postgresstore.DomainControl, Revision: 1, Bytes: controlBytes, SHA256: sha256.Sum256(controlBytes)},
		identity: postgresstore.Document{Domain: postgresstore.DomainIdentity, Revision: 1, Bytes: identityBytes, SHA256: sha256.Sum256(identityBytes)},
	}
	defer clearPostgresRecoveryDocuments(&documents)
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, newAdmin, false); err != nil {
		t.Fatalf("rotation preflight did not authenticate existing key material: %v", err)
	}
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, newAdmin, true); err == nil {
		t.Fatal("new administrator credential authenticated before rotation committed")
	}
	if err := service.CheckRecoveryCredentialBinding(masterVerifier, newVerifier, true); err != nil {
		t.Fatalf("authorized rotation preflight failed: %v", err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, newVerifier, true); err != nil {
		t.Fatalf("authorized rotation commit failed: %v", err)
	}
	rotatedControl, err := controlStore.ExportRecoverySnapshot(context.Background(), box)
	if err != nil {
		t.Fatal(err)
	}
	clear(documents.control.Bytes)
	documents.control.Bytes = rotatedControl
	documents.control.Revision++
	documents.control.SHA256 = sha256.Sum256(rotatedControl)
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, newAdmin, true); err != nil {
		t.Fatalf("new administrator credential did not authenticate final exact document: %v", err)
	}
	if err := validatePostgresRecoveryDocuments(documents, box, masterKey, oldAdmin, true); err == nil {
		t.Fatal("old administrator credential authenticated after rotation committed")
	}
}

func TestReadPostgresRecoveryDocumentsRequiresBothExactDomains(t *testing.T) {
	documents, _, _, _ := postgresRecoveryFixture(t)
	store := newFakePostgresStartupStore(documents)
	read, err := readPostgresRecoveryDocuments(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if read.control.Domain != postgresstore.DomainControl || read.identity.Domain != postgresstore.DomainIdentity {
		t.Fatalf("unexpected domains: %q %q", read.control.Domain, read.identity.Domain)
	}
	if store.pairCalls != 1 {
		t.Fatalf("paired recovery reads = %d, want 1", store.pairCalls)
	}
	clearPostgresRecoveryDocuments(&read)

	store.documents[postgresstore.DomainIdentity] = postgresstore.Document{Domain: postgresstore.DomainControl, Revision: 1, Bytes: []byte("not identity")}
	if _, err := readPostgresRecoveryDocuments(context.Background(), store); err == nil {
		t.Fatal("mislabeled identity document was accepted")
	}
}

func TestReadPostgresRecoveryDocumentsClearsDetachedBytesOnPairedReadError(t *testing.T) {
	documents, _, _, _ := postgresRecoveryFixture(t)
	store := newFakePostgresStartupStore(documents)
	store.pairErr = errors.New("paired read failed")
	if _, err := readPostgresRecoveryDocuments(context.Background(), store); err == nil {
		t.Fatal("paired read failure was accepted")
	}
	if !allZero(store.returned[postgresstore.DomainControl]) || !allZero(store.returned[postgresstore.DomainIdentity]) {
		t.Fatal("recovery read failure did not zero all detached document aliases")
	}
}

func TestPostgresRuntimeReadinessChecksProvenanceAdaptersBindingsAndRecovery(t *testing.T) {
	documents, box, _, _ := postgresRecoveryFixture(t)
	store := newFakePostgresStartupStore(documents)
	controlReady := &fakeContextReadiness{}
	identityReady := &fakeContextReadiness{}
	binding := &fakeRecoveryBinding{}
	recovery := &postgresRecoveryValidator{reader: store, box: box}
	check := postgresRuntimeReadinessCheck(store, controlReady, identityReady, binding, recovery, "master-verifier", "admin-verifier")
	if err := check(context.Background()); err != nil {
		t.Fatalf("valid PostgreSQL runtime was not ready: %v", err)
	}
	if store.importCalls != 1 || controlReady.calls != 1 || identityReady.calls != 1 || binding.calls != 1 {
		t.Fatalf("readiness call counts = import:%d control:%d identity:%d binding:%d", store.importCalls, controlReady.calls, identityReady.calls, binding.calls)
	}
	if binding.masterVerifier != "master-verifier" || binding.adminVerifier != "admin-verifier" {
		t.Fatalf("binding verifiers = %q %q", binding.masterVerifier, binding.adminVerifier)
	}

	provenanceFailure := errors.New("provenance failure")
	store.importErr = provenanceFailure
	if err := check(context.Background()); !errors.Is(err, provenanceFailure) {
		t.Fatalf("provenance failure = %v", err)
	}
	if controlReady.calls != 1 || identityReady.calls != 1 || binding.calls != 1 {
		t.Fatal("readiness continued after import provenance failed")
	}
	store.importErr = nil
	staleHash := store.documents[postgresstore.DomainControl]
	staleHash.Bytes = []byte(`{"version":2}`)
	store.documents[postgresstore.DomainControl] = staleHash
	if err := check(context.Background()); err == nil {
		t.Fatal("changed control bytes with a stale cached hash passed readiness")
	}

	corrupt := store.documents[postgresstore.DomainControl]
	corrupt.Revision++
	corrupt.Bytes = []byte(`{"version":2}`)
	corrupt.SHA256 = sha256.Sum256(corrupt.Bytes)
	store.documents[postgresstore.DomainControl] = corrupt
	if err := check(context.Background()); err == nil {
		t.Fatal("changed corrupt control document passed recovery-grade readiness")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := check(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness = %v", err)
	}
}

func TestPostgresRuntimeReadinessRejectsMissingDependencies(t *testing.T) {
	if err := postgresRuntimeReadinessCheck(nil, nil, nil, nil, nil, "", "")(context.Background()); err == nil {
		t.Fatal("missing PostgreSQL runtime dependencies were ready")
	}
}

func postgresRecoveryFixture(t *testing.T) (postgresRecoveryDocuments, *control.SecretBox, []byte, []byte) {
	t.Helper()
	masterKey := bytes.Repeat([]byte{0x51}, 32)
	adminToken := bytes.Repeat([]byte{'A'}, 43)
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	controlStore, err := control.OpenStore(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlStore.Close() })
	service := control.NewService(controlStore, box, control.NebulaIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(masterKey, adminToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	controlBytes, err := controlStore.ExportRecoverySnapshot(context.Background(), box)
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(directory, "identity-state.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	identityBytes, err := identityStore.ExportRecoverySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	controlHash := sha256.Sum256(controlBytes)
	identityHash := sha256.Sum256(identityBytes)
	return postgresRecoveryDocuments{
		control:  postgresstore.Document{Domain: postgresstore.DomainControl, Revision: 1, Bytes: controlBytes, SHA256: controlHash},
		identity: postgresstore.Document{Domain: postgresstore.DomainIdentity, Revision: 1, Bytes: identityBytes, SHA256: identityHash},
	}, box, bytes.Clone(masterKey), bytes.Clone(adminToken)
}

func newFakePostgresStartupStore(documents postgresRecoveryDocuments) *fakePostgresStartupStore {
	return &fakePostgresStartupStore{documents: map[postgresstore.Domain]postgresstore.Document{
		postgresstore.DomainControl:  documents.control,
		postgresstore.DomainIdentity: documents.identity,
	}}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
