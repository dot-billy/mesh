//go:build linux || darwin

package postgresconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validTLSDsn = "postgres://mesh:correct-horse@db.example.com:5432/mesh?sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=8"

func clearPGEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range postgresEnvironmentKeys {
		t.Setenv(key, "")
	}
}

func writeDSNFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "postgres.dsn")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireStage(t *testing.T, err error, want Stage) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error", want)
	}
	var configErr *Error
	if !errors.As(err, &configErr) {
		t.Fatalf("expected typed Error, got %T: %v", err, err)
	}
	if configErr.Stage != want {
		t.Fatalf("got stage %q, want %q", configErr.Stage, want)
	}
}

func TestLoadFileValidTLSURL(t *testing.T) {
	clearPGEnvironment(t)
	path := writeDSNFile(t, validTLSDsn+"\n", 0o400)

	config, err := LoadFile(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.Host != "db.example.com" {
		t.Fatalf("unexpected host %q", config.ConnConfig.Host)
	}
	if config.ConnConfig.Password != "correct-horse" {
		t.Fatal("password was not parsed from the private DSN")
	}
	if config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("authenticated TLS was not preserved")
	}
	if config.ConnConfig.TLSConfig.ServerName != "db.example.com" {
		t.Fatalf("unexpected TLS server name %q", config.ConnConfig.TLSConfig.ServerName)
	}
	if config.ConnConfig.TLSConfig.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Fatalf("unexpected TLS minimum version %#x", config.ConnConfig.TLSConfig.MinVersion)
	}
	if config.PingTimeout != defaultPingTimeout {
		t.Fatalf("unexpected ping timeout %s", config.PingTimeout)
	}
	if config.ConnConfig.ValidateConnect == nil {
		t.Fatal("read-write target routing was not installed")
	}
	if len(config.ConnConfig.RuntimeParams) != 0 {
		t.Fatalf("unexpected runtime parameters: %#v", config.ConnConfig.RuntimeParams)
	}
}

func TestLoadFileValidKeywordDSN(t *testing.T) {
	clearPGEnvironment(t)
	path := writeDSNFile(t, "host=db.example.com port=5432 dbname=mesh user=mesh password='two words' sslmode=verify-full sslrootcert=system target_session_attrs=read-write connect_timeout=5 pool_max_conns=4", 0o600)

	config, err := LoadFile(path, Options{PingTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.Password != "two words" {
		t.Fatal("quoted password was not parsed consistently")
	}
	if config.PingTimeout != 3*time.Second {
		t.Fatalf("unexpected ping timeout %s", config.PingTimeout)
	}
}

func TestLoadFileDoesNotLeakPasswordOrDSN(t *testing.T) {
	clearPGEnvironment(t)
	secret := "do-not-ever-print-this-password"
	dsn := "postgres://mesh:" + secret + "@db.example.com:notaport/mesh?sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&connect_timeout=5"
	path := writeDSNFile(t, dsn, 0o600)

	_, err := LoadFile(path, Options{})
	requireStage(t, err, StageParse)
	message := err.Error()
	for _, forbidden := range []string{secret, dsn, path, "notaport"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error leaked sensitive input %q: %q", forbidden, message)
		}
	}
}

func TestLoadFileRejectsAmbientPostgresEnvironment(t *testing.T) {
	clearPGEnvironment(t)
	t.Setenv("PGPASSWORD", "ambient-secret")
	path := writeDSNFile(t, validTLSDsn, 0o600)

	_, err := LoadFile(path, Options{})
	requireStage(t, err, StageEnvironment)
	if strings.Contains(err.Error(), "ambient-secret") {
		t.Fatal("environment secret leaked in error")
	}
}

func TestLoadFileRejectsIndirectConfigBeforeParsing(t *testing.T) {
	clearPGEnvironment(t)
	for _, key := range []string{"service=production servicefile=/does/not/exist", "passfile=/does/not/exist"} {
		t.Run(strings.Fields(key)[0], func(t *testing.T) {
			dsn := "host=db.example.com dbname=mesh user=mesh password=secret sslmode=verify-full sslrootcert=system target_session_attrs=read-write connect_timeout=5 " + key
			path := writeDSNFile(t, dsn, 0o600)
			_, err := LoadFile(path, Options{})
			requireStage(t, err, StageParse)
		})
	}
}

func TestLoadFileRejectsTrustPathsAndSessionOverrides(t *testing.T) {
	clearPGEnvironment(t)
	tests := []struct {
		name  string
		extra string
	}{
		{"custom root path", "sslrootcert=/tmp/untrusted-root.pem"},
		{"client certificate", "sslcert=/tmp/client.pem&sslkey=/tmp/client.key"},
		{"libpq options", "options=-csearch_path%3Devil"},
		{"search path", "search_path=evil"},
		{"role", "role=superuser"},
		{"session authorization", "session_authorization=superuser"},
		{"arbitrary runtime parameter", "application_name=untrusted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dsn := "postgres://mesh:secret@db.example.com:5432/mesh?sslmode=verify-full&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4&" + tc.extra
			_, err := LoadFile(writeDSNFile(t, dsn, 0o600), Options{})
			requireStage(t, err, StageParse)
		})
	}
}

func TestLoadFileRejectsEncodedControlsAndAmbiguity(t *testing.T) {
	clearPGEnvironment(t)
	tests := []string{
		"postgres://mesh:line%0Abreak@db.example.com:5432/mesh?sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&connect_timeout=5",
		"postgres://mesh:secret@db.example.com:5432/mesh?sslmode=verify-full&sslmode=disable&sslrootcert=system&target_session_attrs=read-write&connect_timeout=5",
		"host=db.example.com host=other.example.com dbname=mesh user=mesh password=secret sslmode=verify-full sslrootcert=system target_session_attrs=read-write connect_timeout=5",
		validTLSDsn + "#ignored-trailer",
	}
	for _, dsn := range tests {
		_, err := LoadFile(writeDSNFile(t, dsn, 0o600), Options{})
		requireStage(t, err, StageParse)
	}
}

func TestLoadFileRequiresReadWriteTargetRouting(t *testing.T) {
	clearPGEnvironment(t)
	for _, target := range []string{"", "any", "primary", "standby", "read-only"} {
		t.Run("target "+target, func(t *testing.T) {
			targetQuery := ""
			if target != "" {
				targetQuery = "&target_session_attrs=" + target
			}
			dsn := "postgres://mesh:secret@db.example.com:5432/mesh?sslmode=verify-full&sslrootcert=system&connect_timeout=5&pool_max_conns=4" + targetQuery
			_, err := LoadFile(writeDSNFile(t, dsn, 0o600), Options{})
			requireStage(t, err, StageParse)
		})
	}
}

func TestTransportPolicies(t *testing.T) {
	clearPGEnvironment(t)
	t.Run("production multi-host TLS", func(t *testing.T) {
		dsn := "postgres://mesh:secret@db-a.example.com:5432,db-b.example.com:5433/mesh?sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=8"
		config, err := LoadFile(writeDSNFile(t, dsn, 0o600), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(config.ConnConfig.Fallbacks) != 1 {
			t.Fatalf("got %d fallbacks, want 1", len(config.ConnConfig.Fallbacks))
		}
		if config.ConnConfig.TLSConfig.ServerName != "db-a.example.com" || config.ConnConfig.Fallbacks[0].TLSConfig.ServerName != "db-b.example.com" {
			t.Fatal("each route did not retain its own authenticated server name")
		}
	})

	for _, mode := range []string{"disable", "allow", "prefer", "require", "verify-ca"} {
		t.Run("production rejects "+mode, func(t *testing.T) {
			rootSetting := "&sslrootcert=system"
			if mode == "disable" {
				rootSetting = ""
			}
			dsn := "postgres://mesh:secret@db.example.com:5432/mesh?sslmode=" + mode + rootSetting + "&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=8"
			_, err := LoadFile(writeDSNFile(t, dsn, 0o600), Options{})
			requireStage(t, err, StageTransport)
		})
	}

	localCases := []struct {
		name string
		dsn  string
		ok   bool
	}{
		{"IPv4 loopback", "postgres://mesh:secret@127.0.0.1:5432/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4", true},
		{"IPv6 loopback", "postgres://mesh:secret@[::1]:5432/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4", true},
		{"Unix socket", "host=/tmp port=5432 dbname=mesh user=mesh password=secret sslmode=disable target_session_attrs=read-write connect_timeout=5 pool_max_conns=4", true},
		{"localhost hostname", "postgres://mesh:secret@localhost:5432/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4", false},
		{"private network", "postgres://mesh:secret@10.0.0.8:5432/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4", false},
		{"mixed fallback", "postgres://mesh:secret@127.0.0.1:5432,10.0.0.8:5432/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4", false},
	}
	for _, tc := range localCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFile(writeDSNFile(t, tc.dsn, 0o600), Options{Transport: AllowLocalPlaintext})
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok {
				requireStage(t, err, StageTransport)
			}
		})
	}
}

func TestPoolBounds(t *testing.T) {
	clearPGEnvironment(t)
	cases := []struct {
		name  string
		query string
	}{
		{"zero connect timeout", "connect_timeout=0&pool_max_conns=8"},
		{"long connect timeout", "connect_timeout=31&pool_max_conns=8"},
		{"too many connections", "connect_timeout=5&pool_max_conns=129"},
		{"negative minimum", "connect_timeout=5&pool_max_conns=8&pool_min_conns=-1"},
		{"minimum above maximum", "connect_timeout=5&pool_max_conns=8&pool_min_conns=9"},
		{"zero lifetime", "connect_timeout=5&pool_max_conns=8&pool_max_conn_lifetime=0s"},
		{"short lifetime", "connect_timeout=5&pool_max_conns=8&pool_max_conn_lifetime=30s"},
		{"long lifetime", "connect_timeout=5&pool_max_conns=8&pool_max_conn_lifetime=25h"},
		{"zero idle timeout", "connect_timeout=5&pool_max_conns=8&pool_max_conn_idle_time=0s"},
		{"long idle timeout", "connect_timeout=5&pool_max_conns=8&pool_max_conn_idle_time=3h"},
		{"zero health period", "connect_timeout=5&pool_max_conns=8&pool_health_check_period=0s"},
		{"long health period", "connect_timeout=5&pool_max_conns=8&pool_health_check_period=6m"},
		{"negative jitter", "connect_timeout=5&pool_max_conns=8&pool_max_conn_lifetime_jitter=-1s"},
		{"long jitter", "connect_timeout=5&pool_max_conns=8&pool_max_conn_lifetime_jitter=2h"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dsn := "postgres://mesh:secret@db.example.com:5432/mesh?sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&" + tc.query
			_, err := LoadFile(writeDSNFile(t, dsn, 0o600), Options{})
			if err == nil {
				t.Fatal("unsafe pool configuration was accepted")
			}
			var configErr *Error
			if !errors.As(err, &configErr) || (configErr.Stage != StagePool && configErr.Stage != StageParse) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestTypedOptionsAreValidated(t *testing.T) {
	clearPGEnvironment(t)
	path := writeDSNFile(t, validTLSDsn, 0o600)
	for _, opts := range []Options{
		{Transport: TransportPolicy(255)},
		{PingTimeout: 50 * time.Millisecond},
		{PingTimeout: time.Minute},
	} {
		_, err := LoadFile(path, opts)
		requireStage(t, err, StageOptions)
	}
}
