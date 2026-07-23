//go:build linux

package postgresruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/postgresconfig"
)

func writePrivateDSN(t *testing.T, dsn string) string {
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
	path := filepath.Join(t.TempDir(), "postgres.dsn")
	if err := os.WriteFile(path, []byte(dsn+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigForcesCatalogSearchPath(t *testing.T) {
	path := writePrivateDSN(t, "postgres://mesh:secret@127.0.0.1:5432/mesh?sslmode=disable&connect_timeout=1&pool_max_conns=1&target_session_attrs=read-write")
	config, err := loadConfig(path, postgresconfig.Options{Transport: postgresconfig.AllowLocalPlaintext})
	if err != nil {
		t.Fatal(err)
	}
	if got := config.ConnConfig.RuntimeParams["search_path"]; got != "pg_catalog" {
		t.Fatalf("search_path=%q, want pg_catalog", got)
	}
}

func TestOpenSanitizesConnectionFailure(t *testing.T) {
	secret := "runtime-super-secret"
	dsn := "postgres://mesh:" + secret + "@127.0.0.1:1/mesh?sslmode=disable&connect_timeout=1&pool_max_conns=1&target_session_attrs=read-write"
	path := writePrivateDSN(t, dsn)
	runtime, err := Open(context.Background(), Options{DSNFile: path, AllowLocalPlaintext: true})
	if runtime != nil {
		runtime.Close()
		t.Fatal("unexpected runtime for unreachable PostgreSQL endpoint")
	}
	if err == nil {
		t.Fatal("unreachable PostgreSQL endpoint was accepted")
	}
	for _, forbidden := range []string{secret, dsn, path, "127.0.0.1"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("connection error leaked %q: %q", forbidden, err)
		}
	}
}

func TestOpenRejectsNilAndCanceledContext(t *testing.T) {
	if runtime, err := Open(nil, Options{}); runtime != nil || err == nil {
		t.Fatalf("nil context returned runtime=%v err=%v", runtime != nil, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime, err := Open(ctx, Options{}); runtime != nil || err != context.Canceled {
		t.Fatalf("canceled context returned runtime=%v err=%v", runtime != nil, err)
	}
}
