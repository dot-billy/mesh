// mesh-storage is the offline PostgreSQL migration, import, and recovery
// verification utility. It accepts all credentials only through private files
// and emits provenance metadata, never state or secret material.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"mesh/internal/backupio"
	"mesh/internal/buildinfo"
	"mesh/internal/postgresruntime"
	"mesh/internal/postgresstore"
	"mesh/internal/runtimetelemetry"
)

const (
	resultSchema            = "mesh-storage-command-result-v1"
	defaultOperationTimeout = 10 * time.Minute
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, productionDependencies()); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-storage:", err)
		os.Exit(1)
	}
}

type storage interface {
	Migrate(context.Context) error
	CheckSchemaReadiness(context.Context) error
	Import(context.Context, postgresstore.ImportSource) (postgresstore.ImportResult, error)
	Initialize(context.Context, postgresstore.Domain, []byte) (postgresstore.WriteResult, error)
	Read(context.Context, postgresstore.Domain) (postgresstore.Document, error)
	ReadPair(context.Context) (postgresstore.Document, postgresstore.Document, error)
	CheckImportReadiness(context.Context) error
}

var errImportVerifyRequired = errors.New("PostgreSQL backup import may be durable; run mesh-storage verify offline with all Mesh writers stopped before retrying")

type openedStorage struct {
	store storage
	close func() error
}

type archive interface {
	controlBytes() []byte
	identityBytes() []byte
	metadata() backupio.ImportArchiveMetadata
	ValidateExactDocuments(context.Context, []byte, []byte) error
	Clear()
}

type dependencies struct {
	openStorage func(context.Context, storageOpenOptions) (*openedStorage, error)
	openArchive func(context.Context, backupio.ImportArchiveOptions) (archive, error)
	build       func() (string, error)
	now         func() time.Time
}

type storageOpenOptions struct {
	dsnFile             string
	allowLocalPlaintext bool
	build               string
}

type productionArchive struct {
	*backupio.ValidatedImportArchive
}

func (archive *productionArchive) controlBytes() []byte {
	return archive.ControlBytes
}

func (archive *productionArchive) identityBytes() []byte {
	return archive.IdentityBytes
}

func (archive *productionArchive) metadata() backupio.ImportArchiveMetadata {
	return archive.Metadata
}

func productionDependencies() dependencies {
	return dependencies{
		openStorage: func(ctx context.Context, options storageOpenOptions) (*openedStorage, error) {
			runtime, err := postgresruntime.Open(ctx, postgresruntime.Options{
				DSNFile:             options.dsnFile,
				AllowLocalPlaintext: options.allowLocalPlaintext,
				StoreOptions:        postgresstore.Options{MigrationBuild: options.build},
			})
			if err != nil {
				return nil, err
			}
			return &openedStorage{store: runtime.Store(), close: runtime.Close}, nil
		},
		openArchive: func(ctx context.Context, options backupio.ImportArchiveOptions) (archive, error) {
			validated, err := backupio.OpenValidatedImportArchive(ctx, options)
			if err != nil {
				return nil, err
			}
			return &productionArchive{ValidatedImportArchive: validated}, nil
		},
		build: importerBuild,
		now:   time.Now,
	}
}

func importerBuild() (string, error) {
	info, err := buildinfo.Current()
	if err != nil {
		return "", err
	}
	value := "mesh-storage/" + info.Version + "@" + info.Commit
	if len(value) == 0 || len(value) > postgresstore.MaxImporterBuildBytes {
		return "", errors.New("compiled Mesh build identity is too long for PostgreSQL provenance")
	}
	return value, nil
}

func run(ctx context.Context, args []string, output io.Writer, deps dependencies) error {
	if ctx == nil {
		return errors.New("storage command context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) == 0 || output == nil || deps.openStorage == nil || deps.openArchive == nil || deps.build == nil || deps.now == nil {
		return usageError()
	}

	var result commandResult
	var err error
	switch args[0] {
	case "migrate":
		result, err = migrate(ctx, args[1:], deps)
	case "import-backup":
		result, err = importBackup(ctx, args[1:], deps)
	case "initialize-runtime-telemetry":
		result, err = initializeRuntimeTelemetry(ctx, args[1:], deps)
	case "verify":
		result, err = verify(ctx, args[1:], deps)
	default:
		return usageError()
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return errors.New("write storage command result failed")
	}
	return nil
}

func usageError() error {
	return errors.New("usage: mesh-storage <migrate|import-backup|initialize-runtime-telemetry|verify> [flags]")
}

type commonFlags struct {
	dsnFile             string
	allowLocalPlaintext bool
}

type backupFlags struct {
	commonFlags
	keyFile          string
	archivePath      string
	expectedBackupID string
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func parseCommonFlags(command string, args []string) (commonFlags, error) {
	set := newFlagSet(command)
	dsnFile := set.String("postgres-dsn-file", "", "private PostgreSQL DSN file")
	allowLocal := set.Bool("allow-local-plaintext-postgres", false, "allow plaintext only for numeric loopback or an absolute Unix socket")
	if err := set.Parse(args); err != nil {
		return commonFlags{}, fmt.Errorf("%s flags are invalid", command)
	}
	if set.NArg() != 0 {
		return commonFlags{}, fmt.Errorf("%s does not accept positional arguments", command)
	}
	if strings.TrimSpace(*dsnFile) == "" {
		return commonFlags{}, errors.New("--postgres-dsn-file is required")
	}
	return commonFlags{dsnFile: *dsnFile, allowLocalPlaintext: *allowLocal}, nil
}

func parseBackupFlags(command string, args []string) (backupFlags, error) {
	set := newFlagSet(command)
	dsnFile := set.String("postgres-dsn-file", "", "private PostgreSQL DSN file")
	allowLocal := set.Bool("allow-local-plaintext-postgres", false, "allow plaintext only for numeric loopback or an absolute Unix socket")
	keyFile := set.String("backup-key-file", "", "private backup root-key file")
	archivePath := set.String("backup-archive", "", "encrypted Mesh backup archive")
	expectedID := set.String("expect-backup-id", "", "exact authenticated backup ID")
	if err := set.Parse(args); err != nil {
		return backupFlags{}, fmt.Errorf("%s flags are invalid", command)
	}
	if set.NArg() != 0 {
		return backupFlags{}, fmt.Errorf("%s does not accept positional arguments", command)
	}
	for _, required := range []struct {
		name  string
		value string
	}{
		{"postgres-dsn-file", *dsnFile},
		{"backup-key-file", *keyFile},
		{"backup-archive", *archivePath},
		{"expect-backup-id", *expectedID},
	} {
		if strings.TrimSpace(required.value) == "" {
			return backupFlags{}, fmt.Errorf("--%s is required", required.name)
		}
	}
	return backupFlags{
		commonFlags: commonFlags{dsnFile: *dsnFile, allowLocalPlaintext: *allowLocal},
		keyFile:     *keyFile, archivePath: *archivePath, expectedBackupID: *expectedID,
	}, nil
}

func openStorage(ctx context.Context, flags commonFlags, deps dependencies, build string) (*openedStorage, error) {
	opened, err := deps.openStorage(ctx, storageOpenOptions{
		dsnFile: flags.dsnFile, allowLocalPlaintext: flags.allowLocalPlaintext, build: build,
	})
	if err != nil {
		return nil, err
	}
	if opened == nil || opened.store == nil || opened.close == nil {
		if opened != nil && opened.close != nil {
			_ = opened.close()
		}
		return nil, errors.New("PostgreSQL storage dependency is unavailable")
	}
	return opened, nil
}

func closeStorage(opened *openedStorage, resultErr *error) {
	if opened == nil || opened.close == nil {
		return
	}
	*resultErr = errors.Join(*resultErr, opened.close())
}

func migrate(ctx context.Context, args []string, deps dependencies) (result commandResult, resultErr error) {
	flags, err := parseCommonFlags("migrate", args)
	if err != nil {
		return commandResult{}, err
	}
	build, err := deps.build()
	if err != nil {
		return commandResult{}, err
	}
	opened, err := openStorage(ctx, flags, deps, build)
	if err != nil {
		return commandResult{}, err
	}
	defer closeStorage(opened, &resultErr)
	if err := opened.store.Migrate(ctx); err != nil {
		return commandResult{}, err
	}
	if err := opened.store.CheckSchemaReadiness(ctx); err != nil {
		return commandResult{}, err
	}
	verifiedAt, err := safeCommandTime(deps.now())
	if err != nil {
		return commandResult{}, err
	}
	return commandResult{
		Schema: resultSchema, Status: "migrated", VerifiedAt: verifiedAt,
	}, nil
}

func importBackup(ctx context.Context, args []string, deps dependencies) (result commandResult, resultErr error) {
	flags, err := parseBackupFlags("import-backup", args)
	if err != nil {
		return commandResult{}, err
	}
	validated, err := deps.openArchive(ctx, backupio.ImportArchiveOptions{
		KeyFile: flags.keyFile, ArchivePath: flags.archivePath, ExpectedBackupID: flags.expectedBackupID,
	})
	if err != nil {
		return commandResult{}, err
	}
	if validated == nil {
		return commandResult{}, errors.New("validated backup archive dependency is unavailable")
	}
	defer validated.Clear()
	metadata := validated.metadata()
	if _, err := safeCommandTime(metadata.CapturedAt); err != nil {
		return commandResult{}, errors.New("authenticated backup capture time is invalid")
	}
	build, err := deps.build()
	if err != nil {
		return commandResult{}, err
	}
	opened, err := openStorage(ctx, flags.commonFlags, deps, build)
	if err != nil {
		return commandResult{}, err
	}
	importCommitted := false
	defer func() {
		closeErr := opened.close()
		if closeErr != nil && importCommitted {
			closeErr = requireImportVerification(closeErr)
		}
		resultErr = errors.Join(resultErr, closeErr)
	}()

	// Import intentionally never migrates. This forces privilege and change
	// control separation between schema setup and state installation.
	if err := opened.store.CheckSchemaReadiness(ctx); err != nil {
		return commandResult{}, err
	}
	imported, err := opened.store.Import(ctx, postgresstore.ImportSource{
		ControlBytes:          validated.controlBytes(),
		IdentityBytes:         validated.identityBytes(),
		SourceFormat:          postgresstore.ImportSourceFormat,
		ControlVersion:        metadata.ControlVersion,
		IdentitySchema:        metadata.IdentitySchema,
		AuthenticatedBackupID: metadata.BackupID,
		ImporterBuild:         build,
	})
	if err != nil {
		if errors.Is(err, postgresstore.ErrUncertainCommit) {
			return commandResult{}, requireImportVerification(err)
		}
		return commandResult{}, err
	}
	importCommitted = true
	defer clearImportResult(&imported)
	controlDocument, identityDocument, err := readDocuments(ctx, opened.store)
	if err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	defer clearDocument(&controlDocument)
	defer clearDocument(&identityDocument)
	if !sameDocument(imported.Control, controlDocument) || !sameDocument(imported.Identity, identityDocument) {
		return commandResult{}, requireImportVerification(errors.New("PostgreSQL import result does not match authoritative reread"))
	}
	if controlDocument.Revision != 1 || identityDocument.Revision != 1 {
		return commandResult{}, requireImportVerification(errors.New("PostgreSQL backup import did not create exact revision-one documents"))
	}
	if err := validated.ValidateExactDocuments(ctx, controlDocument.Bytes, identityDocument.Bytes); err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	if err := opened.store.CheckImportReadiness(ctx); err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	if err := ensureRuntimeTelemetryState(ctx, opened.store); err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	confirmedControl, confirmedIdentity, err := readDocuments(ctx, opened.store)
	if err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	defer clearDocument(&confirmedControl)
	defer clearDocument(&confirmedIdentity)
	if !sameDocument(controlDocument, confirmedControl) || !sameDocument(identityDocument, confirmedIdentity) {
		return commandResult{}, requireImportVerification(errors.New("PostgreSQL documents changed during post-import verification"))
	}
	if err := validated.ValidateExactDocuments(ctx, confirmedControl.Bytes, confirmedIdentity.Bytes); err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	if err := checkRuntimeTelemetryState(ctx, opened.store); err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	importedAt, err := safeCommandTime(imported.ImportedAt)
	if err != nil {
		return commandResult{}, requireImportVerification(errors.New("PostgreSQL import timestamp is invalid"))
	}
	verifiedAt, err := safeCommandTime(deps.now())
	if err != nil {
		return commandResult{}, requireImportVerification(err)
	}
	return commandResult{
		Schema: resultSchema, Status: "imported", BackupID: metadata.BackupID,
		ImportID: imported.ImportID, ReceiptID: imported.ReceiptID,
		CapturedAt: timePointer(metadata.CapturedAt), ImportedAt: timePointer(importedAt),
		ControlRevision: confirmedControl.Revision, IdentityRevision: confirmedIdentity.Revision,
		VerifiedAt: verifiedAt,
	}, nil
}

func initializeRuntimeTelemetry(ctx context.Context, args []string, deps dependencies) (result commandResult, resultErr error) {
	flags, err := parseCommonFlags("initialize-runtime-telemetry", args)
	if err != nil {
		return commandResult{}, err
	}
	build, err := deps.build()
	if err != nil {
		return commandResult{}, err
	}
	opened, err := openStorage(ctx, flags, deps, build)
	if err != nil {
		return commandResult{}, err
	}
	defer closeStorage(opened, &resultErr)
	// This command intentionally requires the authenticated authoritative pair
	// and immutable import provenance before creating the reconstructible third
	// document. It is safe to rerun and never overwrites existing telemetry.
	if err := opened.store.CheckImportReadiness(ctx); err != nil {
		return commandResult{}, err
	}
	if err := ensureRuntimeTelemetryState(ctx, opened.store); err != nil {
		return commandResult{}, err
	}
	if err := opened.store.CheckImportReadiness(ctx); err != nil {
		return commandResult{}, err
	}
	if err := checkRuntimeTelemetryState(ctx, opened.store); err != nil {
		return commandResult{}, err
	}
	verifiedAt, err := safeCommandTime(deps.now())
	if err != nil {
		return commandResult{}, err
	}
	return commandResult{Schema: resultSchema, Status: "runtime-telemetry-initialized", VerifiedAt: verifiedAt}, nil
}

func verify(ctx context.Context, args []string, deps dependencies) (result commandResult, resultErr error) {
	flags, err := parseBackupFlags("verify", args)
	if err != nil {
		return commandResult{}, err
	}
	validated, err := deps.openArchive(ctx, backupio.ImportArchiveOptions{
		KeyFile: flags.keyFile, ArchivePath: flags.archivePath, ExpectedBackupID: flags.expectedBackupID,
	})
	if err != nil {
		return commandResult{}, err
	}
	if validated == nil {
		return commandResult{}, errors.New("validated backup archive dependency is unavailable")
	}
	defer validated.Clear()
	metadata := validated.metadata()
	if _, err := safeCommandTime(metadata.CapturedAt); err != nil {
		return commandResult{}, errors.New("authenticated backup capture time is invalid")
	}
	build, err := deps.build()
	if err != nil {
		return commandResult{}, err
	}
	opened, err := openStorage(ctx, flags.commonFlags, deps, build)
	if err != nil {
		return commandResult{}, err
	}
	defer closeStorage(opened, &resultErr)
	if err := opened.store.CheckImportReadiness(ctx); err != nil {
		return commandResult{}, err
	}
	controlDocument, identityDocument, err := readDocuments(ctx, opened.store)
	if err != nil {
		return commandResult{}, err
	}
	defer clearDocument(&controlDocument)
	defer clearDocument(&identityDocument)
	if err := validated.ValidateExactDocuments(ctx, controlDocument.Bytes, identityDocument.Bytes); err != nil {
		return commandResult{}, err
	}
	if err := opened.store.CheckImportReadiness(ctx); err != nil {
		return commandResult{}, err
	}
	confirmedControl, confirmedIdentity, err := readDocuments(ctx, opened.store)
	if err != nil {
		return commandResult{}, err
	}
	defer clearDocument(&confirmedControl)
	defer clearDocument(&confirmedIdentity)
	if !sameDocument(controlDocument, confirmedControl) || !sameDocument(identityDocument, confirmedIdentity) {
		return commandResult{}, errors.New("PostgreSQL documents changed during verification; repeat offline verification")
	}
	if err := validated.ValidateExactDocuments(ctx, confirmedControl.Bytes, confirmedIdentity.Bytes); err != nil {
		return commandResult{}, err
	}
	if err := checkRuntimeTelemetryState(ctx, opened.store); err != nil {
		return commandResult{}, err
	}
	verifiedAt, err := safeCommandTime(deps.now())
	if err != nil {
		return commandResult{}, err
	}
	return commandResult{
		Schema: resultSchema, Status: "verified", BackupID: metadata.BackupID,
		CapturedAt:      timePointer(metadata.CapturedAt),
		ControlRevision: confirmedControl.Revision, IdentityRevision: confirmedIdentity.Revision,
		VerifiedAt: verifiedAt,
	}, nil
}

func readDocuments(ctx context.Context, store storage) (postgresstore.Document, postgresstore.Document, error) {
	return store.ReadPair(ctx)
}

func ensureRuntimeTelemetryState(ctx context.Context, store storage) error {
	if store == nil {
		return errors.New("PostgreSQL storage dependency is unavailable")
	}
	raw, err := runtimetelemetry.EncodeState(runtimetelemetry.EmptyState())
	if err != nil {
		return err
	}
	defer clear(raw)
	_, err = store.Initialize(ctx, postgresstore.DomainRuntimeTelemetry, raw)
	if err != nil && !errors.Is(err, postgresstore.ErrAlreadyInitialized) {
		return fmt.Errorf("initialize PostgreSQL runtime telemetry document: %w", err)
	}
	return checkRuntimeTelemetryState(ctx, store)
}

func checkRuntimeTelemetryState(ctx context.Context, store storage) error {
	if store == nil {
		return errors.New("PostgreSQL storage dependency is unavailable")
	}
	document, err := store.Read(ctx, postgresstore.DomainRuntimeTelemetry)
	if err != nil {
		return fmt.Errorf("read PostgreSQL runtime telemetry document: %w", err)
	}
	defer clearDocument(&document)
	actualHash := sha256.Sum256(document.Bytes)
	if document.Domain != postgresstore.DomainRuntimeTelemetry || document.Revision < 1 || len(document.Bytes) < 1 || len(document.Bytes) > postgresstore.MaxRuntimeTelemetryDocumentBytes || actualHash != document.SHA256 {
		return errors.New("PostgreSQL runtime telemetry document metadata is invalid")
	}
	if _, err := runtimetelemetry.DecodeState(document.Bytes); err != nil {
		return fmt.Errorf("validate PostgreSQL runtime telemetry document: %w", err)
	}
	return nil
}

func sameDocument(left, right postgresstore.Document) bool {
	leftHash := sha256.Sum256(left.Bytes)
	rightHash := sha256.Sum256(right.Bytes)
	return left.Domain == right.Domain &&
		left.Revision == right.Revision &&
		left.LastWriteID == right.LastWriteID &&
		left.UpdatedAt.Equal(right.UpdatedAt) &&
		subtle.ConstantTimeCompare(left.SHA256[:], right.SHA256[:]) == 1 &&
		subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1 &&
		subtle.ConstantTimeCompare(left.Bytes, right.Bytes) == 1
}

func clearDocument(document *postgresstore.Document) {
	if document == nil {
		return
	}
	clear(document.Bytes)
	document.Bytes = nil
}

func clearImportResult(result *postgresstore.ImportResult) {
	if result == nil {
		return
	}
	clearDocument(&result.Control)
	clearDocument(&result.Identity)
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

func safeCommandTime(value time.Time) (time.Time, error) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, errors.New("storage command clock returned an invalid time")
	}
	return value.UTC(), nil
}

func requireImportVerification(cause error) error {
	if cause == nil {
		cause = errors.New("post-import verification did not complete")
	}
	return fmt.Errorf("%w: %w", errImportVerifyRequired, cause)
}

type commandResult struct {
	Schema           string     `json:"schema"`
	Status           string     `json:"status"`
	BackupID         string     `json:"backup_id,omitempty"`
	ImportID         string     `json:"import_id,omitempty"`
	ReceiptID        string     `json:"receipt_id,omitempty"`
	CapturedAt       *time.Time `json:"captured_at,omitempty"`
	ImportedAt       *time.Time `json:"imported_at,omitempty"`
	ControlRevision  int64      `json:"control_revision,omitempty"`
	IdentityRevision int64      `json:"identity_revision,omitempty"`
	VerifiedAt       time.Time  `json:"verified_at"`
}
