package postgresstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestImportSourceValidationFailsBeforeDatabaseAccess(t *testing.T) {
	valid := testImportSource()
	tests := []struct {
		name   string
		mutate func(*ImportSource)
	}{
		{name: "empty control", mutate: func(s *ImportSource) { s.ControlBytes = nil }},
		{name: "empty identity", mutate: func(s *ImportSource) { s.IdentityBytes = nil }},
		{name: "source format", mutate: func(s *ImportSource) { s.SourceFormat = "json" }},
		{name: "control version", mutate: func(s *ImportSource) { s.ControlVersion = 1 }},
		{name: "future control version", mutate: func(s *ImportSource) { s.ControlVersion = ImportControlVersionMax + 1 }},
		{name: "identity schema", mutate: func(s *ImportSource) { s.IdentitySchema = "identity-state-v1" }},
		{name: "short backup id", mutate: func(s *ImportSource) { s.AuthenticatedBackupID = strings.Repeat("a", 31) }},
		{name: "uppercase backup id", mutate: func(s *ImportSource) { s.AuthenticatedBackupID = strings.Repeat("A", 32) }},
		{name: "nonhex backup id", mutate: func(s *ImportSource) { s.AuthenticatedBackupID = strings.Repeat("z", 32) }},
		{name: "empty importer build", mutate: func(s *ImportSource) { s.ImporterBuild = "" }},
		{name: "spaced importer build", mutate: func(s *ImportSource) { s.ImporterBuild = " build" }},
		{name: "oversized importer build", mutate: func(s *ImportSource) { s.ImporterBuild = "a" + strings.Repeat("b", MaxImporterBuildBytes) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := valid
			source.ControlBytes = append([]byte(nil), valid.ControlBytes...)
			source.IdentityBytes = append([]byte(nil), valid.IdentityBytes...)
			test.mutate(&source)
			db := &fakeDatabase{}
			store := testStore(t, db)
			if _, err := store.Import(context.Background(), source); !errors.Is(err, ErrInvalidImportSource) {
				t.Fatalf("error = %v, want ErrInvalidImportSource", err)
			}
			if db.begins.Load() != 0 {
				t.Fatalf("invalid source began %d transactions", db.begins.Load())
			}
		})
	}
}

func TestImportSourceAcceptsAuthenticatedControlVersionsTwoThroughFive(t *testing.T) {
	for _, version := range []int{2, 3, 4, 5} {
		source := testImportSource()
		source.ControlVersion = version
		if err := validateImportSource(source); err != nil {
			t.Fatalf("control version %d was rejected: %v", version, err)
		}
	}
}

func TestImportSourceDomainSizeBounds(t *testing.T) {
	tests := []struct {
		name   string
		domain Domain
		size   int
	}{
		{name: "control", domain: DomainControl, size: MaxControlDocumentBytes + 1},
		{name: "identity", domain: DomainIdentity, size: MaxIdentityDocumentBytes + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := testImportSource()
			if test.domain == DomainControl {
				source.ControlBytes = make([]byte, test.size)
			} else {
				source.IdentityBytes = make([]byte, test.size)
			}
			db := &fakeDatabase{}
			store := testStore(t, db)
			if _, err := store.Import(context.Background(), source); !errors.Is(err, ErrInvalidImportSource) {
				t.Fatalf("error = %v, want ErrInvalidImportSource", err)
			}
			if db.begins.Load() != 0 {
				t.Fatal("oversized source reached database")
			}
		})
	}
}

func TestMatchImportExpectationChecksEveryBinding(t *testing.T) {
	expected := testImportExpectation()
	actual := importProvenance{
		importID:       expected.result.ImportID,
		receiptID:      expected.result.ReceiptID,
		sourceFormat:   expected.sourceFormat,
		controlHash:    expected.controlHash,
		identityHash:   expected.identityHash,
		controlBytes:   expected.controlBytes,
		identityBytes:  expected.identityBytes,
		controlVersion: expected.controlVersion,
		identitySchema: expected.identitySchema,
		backupID:       expected.backupID,
		importedAt:     expected.result.ImportedAt,
		importerBuild:  expected.importerBuild,
	}
	if err := matchImportExpectation(actual, expected); err != nil {
		t.Fatal(err)
	}
	actual.backupID = strings.Repeat("b", 32)
	if err := matchImportExpectation(actual, expected); err == nil {
		t.Fatal("mismatched authenticated backup ID was accepted")
	}
}

func TestUnresolvedImportCommitGatesProcess(t *testing.T) {
	expected := testImportExpectation()
	commitTx := &fakeTransaction{commitErr: errors.New("connection lost during import commit")}
	resolutionTx := &fakeTransaction{queryRowFn: func(context.Context, string, ...any) rowScanner {
		return rowFunc(func(...any) error { return errors.New("authoritative database unavailable") })
	}}
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return resolutionTx, nil }}
	store := testStore(t, db)
	if err := store.commitImport(context.Background(), commitTx, expected); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("error = %v, want ErrUncertainCommit", err)
	}
	uncertain, exists := store.UncertainWrite()
	if !exists || uncertain.ReceiptID != expected.result.ReceiptID || uncertain.OperationClass != OperationImport {
		t.Fatalf("unexpected uncertain import: %+v exists=%v", uncertain, exists)
	}
	beginCount := db.begins.Load()
	if _, err := store.Import(context.Background(), testImportSource()); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("subsequent import error = %v, want ErrUncertainCommit", err)
	}
	if err := store.CheckImportReadiness(context.Background()); !errors.Is(err, ErrUncertainCommit) {
		t.Fatalf("import readiness error = %v, want ErrUncertainCommit", err)
	}
	if db.begins.Load() != beginCount {
		t.Fatal("fail-closed import operation reached database")
	}
}

func TestAmbiguousImportCommitResolvesOnlyExactProvenance(t *testing.T) {
	expected := testImportExpectation()
	commitTx := &fakeTransaction{commitErr: errors.New("connection lost after import commit")}
	resolutionTx := importResolutionTransaction(expected)
	db := &fakeDatabase{beginFn: func(context.Context) (transaction, error) { return resolutionTx, nil }}
	store := testStore(t, db)
	if err := store.commitImport(context.Background(), commitTx, expected); err != nil {
		t.Fatal(err)
	}
	if _, uncertain := store.UncertainWrite(); uncertain {
		t.Fatal("exact two-document provenance did not resolve ambiguous commit")
	}
}

func testImportSource() ImportSource {
	return ImportSource{
		ControlBytes:          []byte(`{"version":2}`),
		IdentityBytes:         []byte(`{"schema":"identity-state-v2"}`),
		SourceFormat:          ImportSourceFormat,
		ControlVersion:        ImportControlVersion,
		IdentitySchema:        ImportIdentitySchema,
		AuthenticatedBackupID: strings.Repeat("a", 32),
		ImporterBuild:         "mesh-import/v1.0.0+test",
	}
}

func testImportExpectation() importExpectation {
	source := testImportSource()
	controlHash := sha256.Sum256(source.ControlBytes)
	identityHash := sha256.Sum256(source.IdentityBytes)
	return importExpectation{
		result: ImportResult{
			ImportID:   "223e4567-e89b-42d3-a456-426614174000",
			ReceiptID:  testWriteID,
			ImportedAt: testCommittedAt,
		},
		sourceFormat:   source.SourceFormat,
		controlHash:    controlHash,
		identityHash:   identityHash,
		controlBytes:   int64(len(source.ControlBytes)),
		identityBytes:  int64(len(source.IdentityBytes)),
		controlVersion: source.ControlVersion,
		identitySchema: source.IdentitySchema,
		backupID:       source.AuthenticatedBackupID,
		importerBuild:  source.ImporterBuild,
	}
}

func importResolutionTransaction(expected importExpectation) *fakeTransaction {
	var queryRows int
	return &fakeTransaction{
		queryRowFn: func(context.Context, string, ...any) rowScanner {
			queryRows++
			switch queryRows {
			case 1:
				return valuesRow(int64(1))
			case 2:
				return valuesRow(
					expected.result.ImportID,
					expected.result.ReceiptID,
					expected.sourceFormat,
					expected.controlHash[:],
					expected.identityHash[:],
					expected.controlBytes,
					expected.identityBytes,
					expected.controlVersion,
					expected.identitySchema,
					expected.backupID,
					expected.result.ImportedAt,
					expected.importerBuild,
				)
			case 3:
				return valuesRow(OperationImport, expected.result.ImportedAt)
			default:
				return rowFunc(func(...any) error { return errors.New("unexpected import resolution QueryRow") })
			}
		},
		queryFn: func(context.Context, string, ...any) (rowsScanner, error) {
			return &fakeRows{rows: [][]any{
				{string(DomainControl), int64(0), int64(1), expected.controlHash[:]},
				{string(DomainIdentity), int64(0), int64(1), expected.identityHash[:]},
			}}, nil
		},
	}
}
