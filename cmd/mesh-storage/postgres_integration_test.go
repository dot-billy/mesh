//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"mesh/internal/backupio"
	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/postgresstore"
)

// Set MESH_STORAGE_POSTGRES_TEST_DSN to a strict local-plaintext DSN for a
// disposable empty database. This exercises the production DSN-file loader,
// migration, authenticated backup reader, atomic import, coherent reread, and
// offline verification command path. It creates and drops only schema mesh.
func TestMeshStoragePostgresIntegration(t *testing.T) {
	dsn := os.Getenv("MESH_STORAGE_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("MESH_STORAGE_POSTGRES_TEST_DSN is not set")
	}
	clearPostgresEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open disposable PostgreSQL database")
	}
	defer adminPool.Close()
	var schemaExists bool
	if err := adminPool.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace('mesh') IS NOT NULL`).Scan(&schemaExists); err != nil {
		t.Fatal("inspect disposable PostgreSQL database")
	}
	if schemaExists {
		t.Fatal("refusing integration test because schema mesh already exists")
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS mesh CASCADE`); err != nil {
			t.Errorf("drop disposable mesh schema: %v", err)
		}
	}()

	root := t.TempDir()
	dsnPath := filepath.Join(root, "postgres.dsn")
	if err := os.WriteFile(dsnPath, []byte(dsn+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(root, "keys")
	archiveDir := filepath.Join(root, "archives")
	dataDir := filepath.Join(root, "data")
	for _, directory := range []string{keyDir, archiveDir, dataDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, "backup.key")
	archivePath := filepath.Join(archiveDir, "source.meshbackup")
	backupID := createIntegrationBackup(t, ctx, dataDir, keyPath, archivePath)

	deps := productionDependencies()
	var migrated bytes.Buffer
	if err := run(ctx, []string{
		"migrate", "--postgres-dsn-file", dsnPath, "--allow-local-plaintext-postgres",
	}, &migrated, deps); err != nil {
		t.Fatalf("migrate command: %v", err)
	}
	var migratedResult commandResult
	if err := json.Unmarshal(migrated.Bytes(), &migratedResult); err != nil || migratedResult.Status != "migrated" {
		t.Fatalf("migrate result=%q err=%v", migrated.String(), err)
	}

	commandArgs := []string{
		"--postgres-dsn-file", dsnPath,
		"--backup-key-file", keyPath,
		"--backup-archive", archivePath,
		"--expect-backup-id", backupID,
		"--allow-local-plaintext-postgres",
	}
	var imported bytes.Buffer
	if err := run(ctx, append([]string{"import-backup"}, commandArgs...), &imported, deps); err != nil {
		t.Fatalf("import command: %v", err)
	}
	var importedResult commandResult
	if err := json.Unmarshal(imported.Bytes(), &importedResult); err != nil || importedResult.Status != "imported" || importedResult.BackupID != backupID || importedResult.ControlRevision != 1 || importedResult.IdentityRevision != 1 {
		t.Fatalf("import result=%q err=%v", imported.String(), err)
	}

	var verified bytes.Buffer
	if err := run(ctx, append([]string{"verify"}, commandArgs...), &verified, deps); err != nil {
		t.Fatalf("verify command: %v", err)
	}
	var verifiedResult commandResult
	if err := json.Unmarshal(verified.Bytes(), &verifiedResult); err != nil || verifiedResult.Status != "verified" || verifiedResult.BackupID != backupID || verifiedResult.ControlRevision != 1 || verifiedResult.IdentityRevision != 1 {
		t.Fatalf("verify result=%q err=%v", verified.String(), err)
	}
	for _, output := range []string{migrated.String(), imported.String(), verified.String()} {
		for _, forbidden := range []string{integrationMasterText(), strings.Repeat("A", 43), dsn, keyPath, archivePath, dataDir} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("command output leaked sensitive input: %q", output)
			}
		}
	}

	var duplicate bytes.Buffer
	err = run(ctx, append([]string{"import-backup"}, commandArgs...), &duplicate, deps)
	if !errors.Is(err, postgresstore.ErrAlreadyImported) || duplicate.Len() != 0 {
		t.Fatalf("duplicate import err=%v output=%q", err, duplicate.String())
	}
}

func clearPostgresEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLCERT", "PGSSLKEY",
		"PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLSNI", "PGSSLNEGOTIATION",
		"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGTARGETSESSIONATTRS", "PGTZ",
		"PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION",
		"PGCHANNELBINDING", "PGREQUIREAUTH",
	} {
		t.Setenv(key, "")
	}
}

func createIntegrationBackup(t *testing.T, ctx context.Context, dataDir, keyPath, archivePath string) string {
	t.Helper()
	master := bytes.Repeat([]byte{0x31}, 32)
	defer clear(master)
	masterText := base64.RawURLEncoding.EncodeToString(master)
	adminToken := []byte(strings.Repeat("A", 43))
	defer clear(adminToken)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	controlStore, err := control.OpenStore(filepath.Join(dataDir, backupio.ControlStateName))
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, adminToken)
	if err != nil {
		t.Fatal(err)
	}
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.NewService(controlStore, box, control.NebulaIssuer{}).EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.Close(); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(dataDir, backupio.IdentityStateName), box)
	if err != nil {
		t.Fatal(err)
	}
	if err := identityStore.Close(); err != nil {
		t.Fatal(err)
	}
	operations := backupio.New()
	if _, err := operations.Keygen(backupio.KeygenOptions{OutputPath: keyPath}); err != nil {
		t.Fatal(err)
	}
	created, err := operations.Create(ctx, backupio.CreateOptions{
		DataDir: dataDir, KeyFile: keyPath, OutputPath: archivePath,
		MasterKey: masterText, AdminToken: string(adminToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.BackupID
}

func integrationMasterText() string {
	master := bytes.Repeat([]byte{0x31}, 32)
	defer clear(master)
	return base64.RawURLEncoding.EncodeToString(master)
}
