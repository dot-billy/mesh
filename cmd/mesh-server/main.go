package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mesh/internal/backupio"
	"mesh/internal/control"
	"mesh/internal/httpapi"
	"mesh/internal/identity"
	"mesh/internal/postgresruntime"
	"mesh/internal/runtimetelemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := parseServerConfig(os.Args[1:])
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	if config.dev && config.rotateAdminToken && strings.TrimSpace(os.Getenv("MESH_ADMIN_TOKEN")) != "" {
		logger.Error("configuration error", "error", "--dev --rotate-admin-token requires replacing the private data-dir/admin.token file first; a one-run environment override would not survive restart")
		os.Exit(1)
	}
	if err := validateTransport(config.listen, config.tlsCert, config.tlsKey, config.dev, config.behindTLSProxy, config.allowInsecureHTTP); err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	publicURL, secureCookies, err := resolvePublicURL(config.publicURL, config.listen, nativeTLSEnabled(config.tlsCert, config.tlsKey), config.behindTLSProxy)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	identityValidation := identity.ValidationOptions{AllowInsecureLoopback: !secureCookies}
	if config.identityConfigPath != "" && !secureCookies {
		logger.Error("identity configuration error", "error", "hybrid OIDC requires an HTTPS public URL and native TLS or --behind-tls-proxy")
		os.Exit(1)
	}
	identityConfig, err := loadIdentityConfiguration(config.identityConfigPath, publicURL, identityValidation)
	if err != nil {
		logger.Error("identity configuration error", "error", err)
		os.Exit(1)
	}
	policyFingerprint, err := identityConfig.PolicyFingerprint(identityValidation)
	if err != nil {
		logger.Error("identity configuration error", "error", err)
		os.Exit(1)
	}
	dataDir := ""
	var fileControlStore *control.Store
	if config.storageBackend == storageBackendJSON {
		dataDir, err = filepath.Abs(config.dataDir)
		if err != nil {
			logger.Error("resolve data directory", "error", err)
			os.Exit(1)
		}
		// The parent-directory fence is held across both marker checks and
		// creation and locking of the control store. A restore takes the same
		// fence, so neither side can win only half of the startup race.
		fileControlStore, err = openFencedControlStore(dataDir)
		if err != nil {
			logger.Error("open fenced state", "error", err)
			os.Exit(1)
		}
		defer fileControlStore.Close()
	}
	adminToken, masterKey, err := secrets(dataDir, config.dev, config.adminTokenFile, config.masterKeyFile)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	defer clear(masterKey)
	box, boxErr := control.NewSecretBox(masterKey)
	masterKeyVerifier, masterKeyVerifierErr := control.DeriveMasterKeyVerifier(masterKey)
	adminTokenBytes := []byte(adminToken)
	adminCredentialVerifier, adminCredentialVerifierErr := control.DeriveAdminCredentialVerifier(masterKey, adminTokenBytes)
	clear(adminTokenBytes)
	legacyCredentialBinding := ""
	var bindingErr error
	if identityConfig.LegacyBrowserLogin {
		legacyCredentialBinding, bindingErr = httpapi.DeriveLegacyCredentialBinding(masterKey, adminToken)
	}
	if boxErr != nil {
		logger.Error("initialize encryption", "error", boxErr)
		os.Exit(1)
	}
	if masterKeyVerifierErr != nil {
		logger.Error("initialize master-key verifier", "error", masterKeyVerifierErr)
		os.Exit(1)
	}
	if adminCredentialVerifierErr != nil {
		logger.Error("initialize administrator credential verifier", "error", adminCredentialVerifierErr)
		os.Exit(1)
	}
	if bindingErr != nil {
		logger.Error("initialize legacy session binding", "error", bindingErr)
		os.Exit(1)
	}
	if config.storageBackend == storageBackendJSON {
		// The file-backed path no longer needs the raw key after constructing
		// the purpose-bound box and verifier material.
		clear(masterKey)
	}
	issuer := control.NebulaIssuer{Binary: os.Getenv("NEBULA_CERT_BINARY")}
	var service *control.Service
	var identityStore identity.SessionStore
	var runtimeTelemetryStore runtimetelemetry.Store
	var readinessCheck func(context.Context) error
	var finalStorageValidation func() error
	if config.storageBackend == storageBackendJSON {
		service = control.NewService(fileControlStore, box, issuer)
		if err := service.CheckRecoveryCredentialBinding(masterKeyVerifier, adminCredentialVerifier, config.rotateAdminToken); err != nil {
			logger.Error("check recovery credential binding", "error", err)
			os.Exit(1)
		}
		identityPath, err := filepath.Abs(filepath.Join(dataDir, "identity-state.json"))
		if err != nil {
			logger.Error("resolve identity state path", "error", err)
			os.Exit(1)
		}
		fileIdentityStore, openErr := identity.OpenFileStore(identityPath, box)
		if openErr != nil {
			logger.Error("open identity state", "error", openErr)
			os.Exit(1)
		}
		identityStore = fileIdentityStore
		telemetryPath, pathErr := filepath.Abs(filepath.Join(dataDir, "runtime-telemetry.json"))
		if pathErr != nil {
			logger.Error("resolve runtime telemetry state path", "error", pathErr)
			os.Exit(1)
		}
		fileRuntimeTelemetryStore, openErr := runtimetelemetry.OpenFileStore(telemetryPath)
		if openErr != nil {
			logger.Error("open runtime telemetry state", "error", openErr)
			os.Exit(1)
		}
		runtimeTelemetryStore = fileRuntimeTelemetryStore
		readinessCheck = runtimeTelemetryReadinessCheck(
			runtimeReadinessCheck(fileControlStore, fileIdentityStore, service, masterKeyVerifier, adminCredentialVerifier),
			fileRuntimeTelemetryStore,
		)
	} else {
		startupCtx, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
		postgresRuntime, openErr := postgresruntime.Open(startupCtx, postgresruntime.Options{
			DSNFile:             config.postgresDSNFile,
			AllowLocalPlaintext: config.allowLocalPlaintextPostgres,
		})
		cancelStartup()
		if openErr != nil {
			// Never place a connection-boundary diagnostic in a server log. The
			// operator command provides staged, credential-free diagnostics.
			logger.Error("PostgreSQL startup failed", "stage", "connection")
			os.Exit(1)
		}
		defer postgresRuntime.Close()

		preflightCtx, cancelPreflight := context.WithTimeout(context.Background(), 30*time.Second)
		if err := postgresRuntime.Store().CheckImportReadiness(preflightCtx); err != nil {
			cancelPreflight()
			logger.Error("PostgreSQL startup preflight failed", "stage", "import provenance")
			os.Exit(1)
		}
		validationErr := validatePostgresStartupRecovery(preflightCtx, postgresRuntime.Store(), box, masterKey, adminToken, !config.rotateAdminToken)
		cancelPreflight()
		if validationErr != nil {
			logger.Error("PostgreSQL startup preflight failed", "stage", "cryptographic validation")
			os.Exit(1)
		}

		postgresControlStore, adapterErr := control.NewPostgresStateStore(postgresRuntime.Store(), control.PostgresStateStoreOptions{})
		if adapterErr != nil {
			logger.Error("PostgreSQL startup failed", "stage", "control adapter")
			os.Exit(1)
		}
		service, adapterErr = control.NewServiceWithStateStore(postgresControlStore, box, issuer)
		if adapterErr != nil {
			logger.Error("PostgreSQL startup failed", "stage", "control service")
			os.Exit(1)
		}
		if err := service.CheckRecoveryCredentialBinding(masterKeyVerifier, adminCredentialVerifier, config.rotateAdminToken); err != nil {
			logger.Error("PostgreSQL startup preflight failed", "stage", "credential binding")
			os.Exit(1)
		}
		postgresIdentityStore, adapterErr := identity.NewPostgresStore(postgresRuntime.Store(), box, identity.PostgresStoreOptions{})
		if adapterErr != nil {
			logger.Error("PostgreSQL startup failed", "stage", "identity adapter")
			os.Exit(1)
		}
		identityStore = postgresIdentityStore
		postgresRuntimeTelemetryStore, adapterErr := runtimetelemetry.NewPostgresStore(postgresRuntime.Store(), runtimetelemetry.PostgresStoreOptions{})
		if adapterErr != nil {
			logger.Error("PostgreSQL startup failed", "stage", "runtime telemetry adapter")
			os.Exit(1)
		}
		runtimeTelemetryStore = postgresRuntimeTelemetryStore
		readinessCheck = runtimeTelemetryReadinessCheck(postgresRuntimeReadinessCheck(
			postgresRuntime.Store(), postgresControlStore, postgresIdentityStore, service,
			&postgresRecoveryValidator{reader: postgresRuntime.Store(), box: box},
			masterKeyVerifier, adminCredentialVerifier,
		), postgresRuntimeTelemetryStore)
		finalStorageValidation = func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := postgresRuntime.Store().CheckImportReadiness(ctx); err != nil {
				return err
			}
			return validatePostgresStartupRecovery(ctx, postgresRuntime.Store(), box, masterKey, adminToken, true)
		}
	}
	defer identityStore.Close()
	defer runtimeTelemetryStore.Close()
	var oidcAuthenticator httpapi.OIDCAuthenticator
	if identityConfig.OIDC != nil {
		oidcAuthenticator, err = identity.NewOIDCFlow(identityConfig, identityStore, identity.OIDCFlowOptions{})
		if err != nil {
			logger.Error("initialize OIDC", "error", err)
			os.Exit(1)
		}
	}
	if err := service.EnsureManagedNetworks(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "managed network initialization")
		} else {
			logger.Error("initialize managed network signing keys", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterKeyVerifier, adminCredentialVerifier, config.rotateAdminToken); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "credential binding persistence")
		} else {
			logger.Error("persist recovery credential binding", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "topology schema migration")
		} else {
			logger.Error("migrate topology schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "network DNS schema migration")
		} else {
			logger.Error("migrate network DNS schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "network relay schema migration")
		} else {
			logger.Error("migrate network relay schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureCARotationSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "CA rotation schema migration")
		} else {
			logger.Error("migrate CA rotation schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "firewall rollout schema migration")
		} else {
			logger.Error("migrate firewall rollout schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "firewall pause schema migration")
		} else {
			logger.Error("migrate firewall pause schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "route transfer schema migration")
		} else {
			logger.Error("migrate route transfer schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "route profile edit schema migration")
		} else {
			logger.Error("migrate route profile edit schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "route policy schema migration")
		} else {
			logger.Error("migrate route policy schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "native DNS schema migration")
		} else {
			logger.Error("migrate native DNS schema", "error", err)
		}
		os.Exit(1)
	}
	if err := service.EnsureFirewallScopeSchema(); err != nil {
		if config.storageBackend == storageBackendPostgres {
			logger.Error("PostgreSQL startup failed", "stage", "firewall scope schema migration")
		} else {
			logger.Error("migrate firewall scope schema", "error", err)
		}
		os.Exit(1)
	}
	if config.storageBackend == storageBackendPostgres {
		// A rotation is authorized only for the transition above. Before serving,
		// reread the authoritative bytes and require the configured credential
		// against the committed credential binding and current control schema.
		if finalStorageValidation == nil {
			logger.Error("PostgreSQL startup validation failed", "stage", "recovery credentials")
			os.Exit(1)
		}
		finalValidationErr := finalStorageValidation()
		finalStorageValidation = nil
		if finalValidationErr != nil {
			logger.Error("PostgreSQL startup validation failed", "stage", "recovery credentials")
			os.Exit(1)
		}
		if err := runtimeTelemetryStore.CheckReadiness(); err != nil {
			logger.Error("PostgreSQL startup validation failed", "stage", "runtime telemetry")
			os.Exit(1)
		}
		readinessCtx, cancelReadiness := context.WithTimeout(context.Background(), 30*time.Second)
		readinessErr := readinessCheck(readinessCtx)
		cancelReadiness()
		if readinessErr != nil {
			logger.Error("PostgreSQL startup validation failed", "stage", "runtime readiness")
			os.Exit(1)
		}
	}
	clear(masterKey)
	httpAdminToken := adminToken
	if !identityConfig.LegacyBearer && !identityConfig.LegacyBrowserLogin {
		httpAdminToken = ""
	}
	api, err := httpapi.New(service, httpapi.Options{
		IdentityConfig: identityConfig, ValidationOptions: identityValidation,
		PolicyFingerprint: policyFingerprint, LegacyCredentialBinding: legacyCredentialBinding, SessionStore: identityStore,
		OIDCAuthenticator: oidcAuthenticator, AdminToken: httpAdminToken, SecureCookies: secureCookies, Logger: logger,
		ReadinessCheck: readinessCheck, RuntimeTelemetryStore: runtimeTelemetryStore,
		LinuxInstallBundleURL:    config.linuxInstallBundleURL,
		LinuxBootstrapHandoffURL: config.linuxBootstrapHandoffURL,
	})
	if err != nil {
		logger.Error("initialize HTTP API", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Addr: config.listen, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	logger.Info("mesh control plane started", "listen", config.listen, "public_url", publicURL, "tls", secureCookies, "identity_mode", identityConfig.Mode, "storage_backend", config.storageBackend)
	if config.dev {
		logger.Warn("development mode enabled", "admin_token_file", filepath.Join(dataDir, "admin.token"))
	}
	if nativeTLSEnabled(config.tlsCert, config.tlsKey) {
		err = server.ListenAndServeTLS(config.tlsCert, config.tlsKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func runtimeReadinessCheck(controlStore *control.Store, identityStore *identity.FileStore, service *control.Service, masterVerifier, adminVerifier string) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if controlStore == nil || identityStore == nil || service == nil {
			return errors.New("runtime dependency is unavailable")
		}
		if err := controlStore.CheckReadiness(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := identityStore.CheckReadiness(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return service.CheckCurrentRecoveryCredentialBinding(masterVerifier, adminVerifier)
	}
}

type runtimeTelemetryReadiness interface {
	CheckReadiness() error
}

func runtimeTelemetryReadinessCheck(base func(context.Context) error, telemetry runtimeTelemetryReadiness) func(context.Context) error {
	return func(ctx context.Context) error {
		if ctx == nil {
			return errors.New("runtime readiness context is unavailable")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if base == nil || telemetry == nil {
			return errors.New("runtime telemetry dependency is unavailable")
		}
		if err := base(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return telemetry.CheckReadiness()
	}
}

func openFencedControlStore(dataDir string) (store *control.Store, resultErr error) {
	fence, err := backupio.AcquireStartupFence(dataDir)
	if err != nil {
		return nil, fmt.Errorf("acquire restore/startup fence: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, fence.Close())
		if resultErr != nil && store != nil {
			resultErr = errors.Join(resultErr, store.Close())
			store = nil
		}
	}()
	if err := fence.Check(); err != nil {
		return nil, fmt.Errorf("pre-open incomplete-restore check: %w", err)
	}
	store, err = control.OpenStore(filepath.Join(dataDir, backupio.ControlStateName))
	if err != nil {
		return nil, fmt.Errorf("open state: %w", err)
	}
	if err := fence.Check(); err != nil {
		return nil, fmt.Errorf("post-open incomplete-restore check: %w", err)
	}
	return store, nil
}

func nativeTLSEnabled(certPath, keyPath string) bool {
	return certPath != "" && keyPath != ""
}

func resolvePublicURL(configured, listen string, nativeTLS, behindTLSProxy bool) (string, bool, error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		if behindTLSProxy {
			return "", false, errors.New("--public-url is required with --behind-tls-proxy because the external origin cannot be derived from the private listener")
		}
		host, port, err := net.SplitHostPort(listen)
		if err != nil || host == "" {
			return "", false, errors.New("--public-url is required when the listen address is ambiguous")
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() || strings.Contains(host, "%") {
			return "", false, errors.New("--public-url is required unless the listener uses an explicit loopback IP address")
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", false, errors.New("--public-url is required when the listener does not use a fixed numeric port")
		}
		scheme := "http"
		if nativeTLS {
			scheme = "https"
		}
		return scheme + "://" + net.JoinHostPort(host, port), nativeTLS, nil
	}
	parsed, err := url.Parse(configured)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false, errors.New("--public-url must be an absolute origin")
	}
	secure := parsed.Scheme == "https"
	if (nativeTLS || behindTLSProxy) && !secure {
		return "", false, errors.New("--public-url must use https when TLS is enabled locally or at the trusted proxy")
	}
	if secure && !nativeTLS && !behindTLSProxy {
		return "", false, errors.New("an https --public-url requires local TLS or --behind-tls-proxy")
	}
	return configured, secure, nil
}

func validateTransport(listen, tlsCert, tlsKey string, dev, behindTLSProxy, allowInsecureHTTP bool) error {
	if (tlsCert == "") != (tlsKey == "") {
		return errors.New("both --tls-cert and --tls-key are required together")
	}
	// Proxy mode changes browser trust decisions: it enables Secure cookies,
	// HSTS, and assumes the request already crossed an authenticated TLS edge.
	// Without trusted-proxy address parsing, a non-loopback bind would let a
	// direct client bypass that edge while still receiving proxy-trusted
	// treatment. Keep the backend unreachable off-host by construction.
	if behindTLSProxy && !loopbackListen(listen) {
		return errors.New("--behind-tls-proxy requires a loopback listener; bind the TLS proxy and keep the Mesh backend local")
	}
	if allowInsecureHTTP {
		return errors.New("--allow-insecure-http is no longer supported; browser identity permits cleartext only on an explicit loopback origin")
	}
	if tlsCert == "" && !loopbackListen(listen) && !behindTLSProxy {
		return errors.New("refusing non-loopback cleartext HTTP; configure TLS or a loopback --behind-tls-proxy listener")
	}
	return nil
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func secrets(dataDir string, dev bool, adminTokenFile, masterKeyFile string) (string, []byte, error) {
	admin := strings.TrimSpace(os.Getenv("MESH_ADMIN_TOKEN"))
	masterEncoded := strings.TrimSpace(os.Getenv("MESH_MASTER_KEY"))
	if !dev {
		var err error
		admin, err = resolveProductionCredential("--admin-token-file", adminTokenFile, "MESH_ADMIN_TOKEN")
		if err != nil {
			return "", nil, err
		}
		masterEncoded, err = resolveProductionCredential("--master-key-file", masterKeyFile, "MESH_MASTER_KEY")
		if err != nil {
			return "", nil, err
		}
		if len(admin) < 32 {
			return "", nil, fmt.Errorf("administrator token must contain at least 32 characters")
		}
		key, err := httpapi.DecodeMasterKey(masterEncoded)
		return admin, key, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(dataDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !secretPathPrivate(info) {
		return "", nil, errors.New("development secret directory must be a real private directory (0700)")
	}
	if admin == "" {
		var err error
		admin, err = loadOrCreate(filepath.Join(dataDir, "admin.token"), 32)
		if err != nil {
			return "", nil, err
		}
	}
	if masterEncoded == "" {
		var err error
		masterEncoded, err = loadOrCreate(filepath.Join(dataDir, "master.key"), 32)
		if err != nil {
			return "", nil, err
		}
	}
	key, err := httpapi.DecodeMasterKey(masterEncoded)
	return admin, key, err
}

func loadOrCreate(path string, size int) (string, error) {
	if before, err := os.Lstat(path); err == nil {
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || !secretPathPrivate(before) || before.Size() > 4096 {
			return "", errors.New("development secret must be a bounded private regular file (0600)")
		}
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		after, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, after) {
			_ = file.Close()
			return "", errors.New("development secret changed while opening")
		}
		b, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		if len(b) > 4096 {
			return "", errors.New("development secret exceeds size limit")
		}
		value := strings.TrimSpace(string(b))
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(value)
		if decodeErr != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
			return "", errors.New("development secret must be canonical unpadded base64url of the configured size")
		}
		clear(decoded)
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	random := make([]byte, size)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(random)
	clear(random)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreate(path, size)
	}
	if err != nil {
		return "", err
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(value + "\n"); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	removePartial = false
	if err := syncSecretDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	return value, nil
}
