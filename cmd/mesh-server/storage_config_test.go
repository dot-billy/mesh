package main

import (
	"path/filepath"
	"testing"
)

func TestParseServerConfigStorageIsolation(t *testing.T) {
	absoluteDSN := filepath.Join(t.TempDir(), "postgres.dsn")
	tests := []struct {
		name      string
		arguments []string
		backend   string
		wantError bool
	}{
		{name: "default JSON", backend: storageBackendJSON},
		{name: "explicit JSON", arguments: []string{"--storage-backend=json"}, backend: storageBackendJSON},
		{name: "JSON rejects DSN", arguments: []string{"--postgres-dsn-file=" + absoluteDSN}, wantError: true},
		{name: "JSON rejects explicit empty DSN", arguments: []string{"--postgres-dsn-file="}, wantError: true},
		{name: "JSON rejects plaintext exception", arguments: []string{"--allow-local-plaintext-postgres"}, wantError: true},
		{name: "JSON rejects explicit false plaintext exception", arguments: []string{"--allow-local-plaintext-postgres=false"}, wantError: true},
		{name: "PostgreSQL", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=" + absoluteDSN}, backend: storageBackendPostgres},
		{name: "PostgreSQL local plaintext", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=" + absoluteDSN, "--allow-local-plaintext-postgres"}, backend: storageBackendPostgres},
		{name: "PostgreSQL missing DSN", arguments: []string{"--storage-backend=postgres"}, wantError: true},
		{name: "PostgreSQL relative DSN", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=postgres.dsn"}, wantError: true},
		{name: "PostgreSQL unclean DSN", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=" + filepath.Dir(absoluteDSN) + "/nested/../postgres.dsn"}, wantError: true},
		{name: "PostgreSQL rejects development", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=" + absoluteDSN, "--dev"}, wantError: true},
		{name: "PostgreSQL rejects explicit default data dir", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=" + absoluteDSN, "--data-dir=./data"}, wantError: true},
		{name: "PostgreSQL permits explicit rotation", arguments: []string{"--storage-backend=postgres", "--postgres-dsn-file=" + absoluteDSN, "--rotate-admin-token"}, backend: storageBackendPostgres},
		{name: "unknown backend", arguments: []string{"--storage-backend=sqlite"}, wantError: true},
		{name: "whitespace backend", arguments: []string{"--storage-backend= postgres"}, wantError: true},
		{name: "positional argument", arguments: []string{"unexpected"}, wantError: true},
		{name: "unknown flag", arguments: []string{"--unknown"}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := parseServerConfig(test.arguments)
			if (err != nil) != test.wantError {
				t.Fatalf("parseServerConfig(%q) error = %v, wantError %v", test.arguments, err, test.wantError)
			}
			if err == nil && config.storageBackend != test.backend {
				t.Fatalf("storageBackend = %q, want %q", config.storageBackend, test.backend)
			}
		})
	}
}

func TestParseServerConfigLinuxInstallBundleURL(t *testing.T) {
	want := "https://releases.example/channels/stable/bundle.json"
	handoff := "https://releases.example/bootstrap/stable/bootstrap-handoff.json"
	config, err := parseServerConfig([]string{"--linux-install-bundle-url", want, "--linux-bootstrap-handoff-url", handoff})
	if err != nil {
		t.Fatal(err)
	}
	if config.linuxInstallBundleURL != want || config.linuxBootstrapHandoffURL != handoff {
		t.Fatalf("URLs = (%q, %q), want (%q, %q)", config.linuxInstallBundleURL, config.linuxBootstrapHandoffURL, want, handoff)
	}
	empty, err := parseServerConfig(nil)
	if err != nil || empty.linuxInstallBundleURL != "" || empty.linuxBootstrapHandoffURL != "" {
		t.Fatalf("optional URL defaults = (%q, %q), %v", empty.linuxInstallBundleURL, empty.linuxBootstrapHandoffURL, err)
	}
	for _, value := range []string{
		"http://releases.example/bundle.json",
		"https://releases.example/bundle.json?x=1",
		"https://RELEASES.example/bundle.json",
		"https://releases.example/a/../bundle.json",
		" https://releases.example/bundle.json",
	} {
		if _, err := parseServerConfig([]string{"--linux-install-bundle-url", value}); err == nil {
			t.Fatalf("invalid URL accepted: %q", value)
		}
		if _, err := parseServerConfig([]string{"--linux-bootstrap-handoff-url", value}); err == nil {
			t.Fatalf("invalid handoff URL accepted: %q", value)
		}
	}
}

func TestParseServerConfigCredentialFiles(t *testing.T) {
	root := t.TempDir()
	adminPath := filepath.Join(root, "admin.token")
	masterPath := filepath.Join(root, "master.key")
	config, err := parseServerConfig([]string{"--admin-token-file", adminPath, "--master-key-file", masterPath})
	if err != nil {
		t.Fatal(err)
	}
	if config.adminTokenFile != adminPath || config.masterKeyFile != masterPath {
		t.Fatalf("credential paths = (%q, %q), want (%q, %q)", config.adminTokenFile, config.masterKeyFile, adminPath, masterPath)
	}
	for _, arguments := range [][]string{
		{"--admin-token-file", "admin.token"},
		{"--master-key-file", root + "/nested/../master.key"},
		{"--dev", "--admin-token-file", adminPath},
		{"--dev", "--master-key-file", masterPath},
	} {
		if _, err := parseServerConfig(arguments); err == nil {
			t.Fatalf("invalid credential-file arguments accepted: %q", arguments)
		}
	}
}
