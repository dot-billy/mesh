package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"mesh/internal/onlinerelease"
)

const (
	storageBackendJSON     = "json"
	storageBackendPostgres = "postgres"
)

type serverConfig struct {
	listen                      string
	dataDir                     string
	tlsCert                     string
	tlsKey                      string
	publicURL                   string
	linuxInstallBundleURL       string
	linuxBootstrapHandoffURL    string
	identityConfigPath          string
	adminTokenFile              string
	masterKeyFile               string
	storageBackend              string
	postgresDSNFile             string
	dev                         bool
	behindTLSProxy              bool
	allowInsecureHTTP           bool
	rotateAdminToken            bool
	allowLocalPlaintextPostgres bool
	dataDirExplicit             bool
	postgresDSNFileExplicit     bool
	postgresPlaintextExplicit   bool
}

func parseServerConfig(arguments []string) (serverConfig, error) {
	var config serverConfig
	flags := flag.NewFlagSet("mesh-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	flags.StringVar(&config.dataDir, "data-dir", "./data", "persistent data directory (JSON storage only)")
	flags.StringVar(&config.tlsCert, "tls-cert", "", "TLS certificate path")
	flags.StringVar(&config.tlsKey, "tls-key", "", "TLS private key path")
	flags.StringVar(&config.publicURL, "public-url", "", "canonical browser origin (required behind a TLS proxy or for non-loopback listeners)")
	flags.StringVar(&config.linuxInstallBundleURL, "linux-install-bundle-url", "", "canonical public HTTPS URL for the signed Linux online release bundle")
	flags.StringVar(&config.linuxBootstrapHandoffURL, "linux-bootstrap-handoff-url", "", "canonical public HTTPS courier URL for the unsigned bootstrap handoff")
	flags.StringVar(&config.identityConfigPath, "identity-config", "", "absolute path to a private mesh-identity-v2 or mesh-hybrid-identity-v1 JSON policy")
	flags.StringVar(&config.adminTokenFile, "admin-token-file", "", "absolute path to a private administrator token file")
	flags.StringVar(&config.masterKeyFile, "master-key-file", "", "absolute path to a private canonical master-key file")
	flags.StringVar(&config.storageBackend, "storage-backend", storageBackendJSON, "state storage backend: json or postgres")
	flags.StringVar(&config.postgresDSNFile, "postgres-dsn-file", "", "absolute path to a private PostgreSQL DSN file")
	flags.BoolVar(&config.dev, "dev", false, "generate and persist local development secrets")
	flags.BoolVar(&config.behindTLSProxy, "behind-tls-proxy", false, "trust TLS termination in front of this listener and force Secure cookies")
	flags.BoolVar(&config.allowInsecureHTTP, "allow-insecure-http", false, "deprecated unsafe mode (rejected; use loopback HTTP or HTTPS)")
	flags.BoolVar(&config.rotateAdminToken, "rotate-admin-token", false, "authorize this startup to replace an existing administrator-token binding")
	flags.BoolVar(&config.allowLocalPlaintextPostgres, "allow-local-plaintext-postgres", false, "allow plaintext PostgreSQL only over a numeric loopback address or absolute Unix socket")
	if err := flags.Parse(arguments); err != nil {
		return serverConfig{}, errors.New("invalid command-line configuration")
	}
	if flags.NArg() != 0 {
		return serverConfig{}, errors.New("positional arguments are not supported")
	}
	flags.Visit(func(item *flag.Flag) {
		switch item.Name {
		case "data-dir":
			config.dataDirExplicit = true
		case "postgres-dsn-file":
			config.postgresDSNFileExplicit = true
		case "allow-local-plaintext-postgres":
			config.postgresPlaintextExplicit = true
		}
	})
	if config.linuxInstallBundleURL != "" {
		canonical, err := onlinerelease.CanonicalBundleURL(config.linuxInstallBundleURL)
		if err != nil || canonical != config.linuxInstallBundleURL {
			return serverConfig{}, errors.New("--linux-install-bundle-url must be one canonical public HTTPS object URL")
		}
	}
	if config.linuxBootstrapHandoffURL != "" {
		canonical, err := onlinerelease.CanonicalBundleURL(config.linuxBootstrapHandoffURL)
		if err != nil || canonical != config.linuxBootstrapHandoffURL {
			return serverConfig{}, errors.New("--linux-bootstrap-handoff-url must be one canonical public HTTPS object URL")
		}
	}
	for name, path := range map[string]string{
		"--admin-token-file": config.adminTokenFile,
		"--master-key-file":  config.masterKeyFile,
	} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator)) {
			return serverConfig{}, fmt.Errorf("%s must be a clean absolute file path", name)
		}
	}
	if config.dev && (config.adminTokenFile != "" || config.masterKeyFile != "") {
		return serverConfig{}, errors.New("credential file flags cannot be combined with --dev")
	}
	if err := validateStorageConfiguration(config); err != nil {
		return serverConfig{}, err
	}
	return config, nil
}

func validateStorageConfiguration(config serverConfig) error {
	if config.storageBackend != strings.TrimSpace(config.storageBackend) {
		return errors.New("--storage-backend must be exactly json or postgres")
	}
	switch config.storageBackend {
	case storageBackendJSON:
		if config.postgresDSNFileExplicit || config.postgresPlaintextExplicit {
			return errors.New("PostgreSQL flags require --storage-backend=postgres")
		}
	case storageBackendPostgres:
		if config.dev {
			return errors.New("--storage-backend=postgres cannot be combined with --dev")
		}
		if config.dataDirExplicit {
			return errors.New("--data-dir is not used with --storage-backend=postgres")
		}
		if config.postgresDSNFile == "" || !filepath.IsAbs(config.postgresDSNFile) || filepath.Clean(config.postgresDSNFile) != config.postgresDSNFile {
			return errors.New("--storage-backend=postgres requires a clean absolute --postgres-dsn-file path")
		}
	default:
		return errors.New("--storage-backend must be exactly json or postgres")
	}
	return nil
}
