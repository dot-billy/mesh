//go:build darwin

// Command desktop-e2e-fixture runs a disposable real Mesh HTTP API for the
// cross-language desktop integration test. It is test infrastructure only:
// it binds an ephemeral IPv4 loopback port, uses private temporary file stores,
// and requires an unguessable fixture token for its non-production helpers.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"

	"mesh/internal/control"
	"mesh/internal/httpapi"
	"mesh/internal/identity"
	"mesh/internal/runtimetelemetry"
)

const (
	fixtureSchema = "mesh-desktop-real-control-plane-fixture-v1"
	maxHelperBody = 8 * 1024
)

type fixtureClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *fixtureClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *fixtureClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type unavailableOIDC struct{}

func (unavailableOIDC) Start(context.Context, string) (identity.OIDCStartResult, error) {
	return identity.OIDCStartResult{}, identity.ErrOIDCUnavailable
}

func (unavailableOIDC) Complete(context.Context, string, string, string) (identity.OIDCCompleteResult, error) {
	return identity.OIDCCompleteResult{}, identity.ErrOIDCUnavailable
}

func (unavailableOIDC) ConsumeAuthorizationError(context.Context, string, string) (string, error) {
	return "", identity.ErrOIDCUnavailable
}

type fixture struct {
	origin            string
	fixtureToken      string
	adminToken        string
	policyFingerprint string
	identityConfig    identity.IdentityConfig
	identityStore     identity.SessionStore
	service           *control.Service
	api               http.Handler
	clock             *fixtureClock
	browserClient     *http.Client
}

type startupDocument struct {
	Schema       string `json:"schema"`
	Origin       string `json:"origin"`
	AdminToken   string `json:"admin_token"`
	FixtureToken string `json:"fixture_token"`
}

type desktopDecisionInput struct {
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
}

type enrollInput struct {
	EnrollmentToken string `json:"enrollment_token"`
}

type viewerSessionDocument struct {
	Schema       string `json:"schema"`
	SessionID    string `json:"session_id"`
	SessionToken string `json:"session_token"`
	CSRFToken    string `json:"csrf_token"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "desktop E2E fixture:", err)
		os.Exit(1)
	}
}

func run() error {
	createdRoot, err := os.MkdirTemp("", "mesh-desktop-e2e-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(createdRoot)
	root, err := filepath.EvalSymlinks(createdRoot)
	if err != nil {
		return err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()

	adminToken, err := identity.NewOpaqueToken()
	if err != nil {
		return err
	}
	fixtureToken, err := identity.NewOpaqueToken()
	if err != nil {
		return err
	}
	clock := &fixtureClock{now: time.Now().UTC().Truncate(time.Second)}
	serverFixture, cleanup, err := newFixture(root, origin, adminToken, fixtureToken, clock)
	if err != nil {
		return err
	}
	defer cleanup()

	server := &http.Server{
		Handler:           serverFixture.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	serveErrors := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- err
		}
		close(serveErrors)
	}()

	startup := startupDocument{
		Schema:       fixtureSchema,
		Origin:       origin,
		AdminToken:   adminToken,
		FixtureToken: fixtureToken,
	}
	if err := json.NewEncoder(os.Stdout).Encode(startup); err != nil {
		return err
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	stdinClosed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdinClosed)
	}()

	select {
	case err := <-serveErrors:
		if err != nil {
			return err
		}
	case <-stdinClosed:
	case <-stop:
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownContext)
}

func newFixture(root, origin, adminToken, fixtureToken string, clock *fixtureClock) (*fixture, func(), error) {
	masterKey := bytes.Repeat([]byte{0x5d}, 32)
	controlStore, err := control.OpenStore(filepath.Join(root, "control-state.json"))
	if err != nil {
		return nil, func() {}, err
	}
	closeControl := true
	defer func() {
		if closeControl {
			_ = controlStore.Close()
		}
	}()
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		return nil, func() {}, err
	}
	nebulaCert, err := pinnedNebulaCert()
	if err != nil {
		return nil, func() {}, err
	}
	service := control.NewService(
		controlStore,
		box,
		control.NebulaIssuer{Binary: nebulaCert},
	)

	masterVerifier, err := control.DeriveMasterKeyVerifier(masterKey)
	if err != nil {
		return nil, func() {}, err
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(masterKey, []byte(adminToken))
	if err != nil {
		return nil, func() {}, err
	}
	initializers := []func() error{
		service.EnsureManagedNetworks,
		func() error {
			return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false)
		},
		service.EnsureTopologySchema,
		service.EnsureNetworkDNSSchema,
		service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema,
		service.EnsureFirewallRolloutSchema,
		service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema,
		service.EnsureRouteProfileEditSchema,
		service.EnsureRoutePolicySchema,
		service.EnsureNativeDNSSchema,
		service.EnsureFirewallScopeSchema,
	}
	for _, initialize := range initializers {
		if err := initialize(); err != nil {
			return nil, func() {}, err
		}
	}

	identityConfig, err := (identity.IdentityConfig{
		Mode:               identity.ModeHybrid,
		PublicURL:          origin,
		LegacyBearer:       true,
		LegacyBrowserLogin: true,
		BreakGlass: identity.BreakGlassConfig{
			Enabled:            true,
			MinimumUsableCodes: identity.MinBreakGlassUsableCodes,
		},
		OIDC: &identity.OIDCConfig{
			Issuer:           "https://id.example.test/desktop-e2e",
			ClientID:         "mesh-desktop-e2e",
			ClientSecretFile: filepath.Join(root, "unused-oidc-client-secret"),
			Scopes:           []string{"openid"},
			GroupsClaim:      "groups",
			AllowedSigningAlgs: []string{
				"RS256",
			},
			Admins: []identity.AdminSelector{
				{Kind: "group", Value: "mesh-admins"},
			},
			RoleBindings: []identity.RoleBinding{
				{
					Role: identity.RoleViewer,
					Selector: identity.AdminSelector{
						Kind:  "group",
						Value: "mesh-viewers",
					},
				},
			},
			RequiredAMRAll:       []string{"otp"},
			MaxAuthenticationAge: 15 * time.Minute,
		},
	}).Normalized(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		return nil, func() {}, err
	}
	fingerprint, err := identityConfig.PolicyFingerprint(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		return nil, func() {}, err
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(root, "identity-state.json"), box)
	if err != nil {
		return nil, func() {}, err
	}
	closeIdentity := true
	defer func() {
		if closeIdentity {
			_ = identityStore.Close()
		}
	}()
	credentialBinding, err := httpapi.DeriveLegacyCredentialBinding(masterKey, adminToken)
	if err != nil {
		return nil, func() {}, err
	}
	sessionPolicyDigest := sha256.Sum256([]byte(
		"mesh-legacy-session-policy-v1\x00" +
			fingerprint +
			"\x00" +
			credentialBinding,
	))
	sessionPolicyFingerprint := hex.EncodeToString(sessionPolicyDigest[:])
	telemetry := runtimetelemetry.NewMemoryStore()
	apiServer, err := httpapi.New(service, httpapi.Options{
		IdentityConfig:          identityConfig,
		ValidationOptions:       identity.ValidationOptions{AllowInsecureLoopback: true},
		PolicyFingerprint:       fingerprint,
		LegacyCredentialBinding: credentialBinding,
		SessionStore:            identityStore,
		OIDCAuthenticator:       unavailableOIDC{},
		AdminToken:              adminToken,
		SecureCookies:           false,
		Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:                     clock.Now,
		RuntimeTelemetryStore:   telemetry,
	})
	if err != nil {
		return nil, func() {}, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, func() {}, err
	}
	closeControl = false
	closeIdentity = false
	value := &fixture{
		origin: origin, fixtureToken: fixtureToken, adminToken: adminToken,
		policyFingerprint: sessionPolicyFingerprint, identityConfig: identityConfig,
		identityStore: identityStore, service: service, api: apiServer.Handler(),
		clock: clock, browserClient: &http.Client{Jar: jar, Timeout: 10 * time.Second},
	}
	cleanup := func() {
		_ = telemetry.Close()
		_ = identityStore.Close()
		_ = controlStore.Close()
	}
	return value, cleanup, nil
}

func pinnedNebulaCert() (string, error) {
	command := exec.Command("go", "tool", "-n", "nebula-cert")
	rawPath, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve pinned nebula-cert: %w", err)
	}
	path := strings.TrimSpace(string(rawPath))
	info, err := os.Stat(path)
	if err != nil || !filepath.IsAbs(path) || !info.Mode().IsRegular() {
		return "", errors.New("pinned nebula-cert did not resolve to a physical executable")
	}
	version, err := exec.Command(path, "-version").CombinedOutput()
	if err != nil || string(version) != "Version: 1.10.3\n" {
		return "", errors.New("desktop E2E requires exact nebula-cert 1.10.3")
	}
	return path, nil
}

func (f *fixture) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__fixture/desktop-decision", f.desktopDecision)
	mux.HandleFunc("POST /__fixture/enroll", f.enroll)
	mux.HandleFunc("POST /__fixture/viewer-session", f.viewerSession)
	mux.Handle("/", f.api)
	return mux
}

func (f *fixture) authorizedHelper(response http.ResponseWriter, request *http.Request) bool {
	provided := request.Header.Get("X-Mesh-Fixture-Token")
	if len(provided) != len(f.fixtureToken) ||
		subtle.ConstantTimeCompare([]byte(provided), []byte(f.fixtureToken)) != 1 {
		http.Error(response, "fixture authorization required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (f *fixture) desktopDecision(response http.ResponseWriter, request *http.Request) {
	if !f.authorizedHelper(response, request) {
		return
	}
	var input desktopDecisionInput
	if err := decodeHelper(request, &input); err != nil ||
		!strings.HasPrefix(input.RequestID, "desktop_") ||
		(input.Decision != "approve" && input.Decision != "deny") {
		http.Error(response, "invalid fixture decision", http.StatusBadRequest)
		return
	}
	if err := f.ensureBrowserSession(request.Context()); err != nil {
		http.Error(response, "fixture browser session failed", http.StatusInternalServerError)
		return
	}
	f.clock.Advance(5 * time.Second)
	body, _ := json.Marshal(map[string]string{"decision": input.Decision})
	decision, err := http.NewRequestWithContext(
		request.Context(),
		http.MethodPost,
		f.origin+"/api/v1/auth/desktop/"+input.RequestID+"/decision",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Error(response, "fixture decision failed", http.StatusInternalServerError)
		return
	}
	decision.Header.Set("Content-Type", "application/json")
	decision.Header.Set("Origin", f.origin)
	decision.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, cookie := range f.browserClient.Jar.Cookies(decision.URL) {
		if cookie.Name == "mesh_csrf" {
			decision.Header.Set("X-Mesh-CSRF", cookie.Value)
		}
	}
	upstream, err := f.browserClient.Do(decision)
	if err != nil {
		http.Error(response, "fixture decision failed", http.StatusInternalServerError)
		return
	}
	defer upstream.Body.Close()
	if upstream.StatusCode != http.StatusNoContent {
		http.Error(response, "fixture decision was rejected", http.StatusBadGateway)
		return
	}
	writeHelperJSON(response, map[string]any{"status": upstream.StatusCode})
}

func (f *fixture) ensureBrowserSession(ctx context.Context) error {
	target, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		f.origin+"/api/v1/session",
		strings.NewReader(`{"token":"`+f.adminToken+`"}`),
	)
	if err != nil {
		return err
	}
	target.Header.Set("Content-Type", "application/json")
	target.Header.Set("Origin", f.origin)
	target.Header.Set("Sec-Fetch-Site", "same-origin")
	result, err := f.browserClient.Do(target)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		return fmt.Errorf("browser login returned %d", result.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(result.Body, maxHelperBody))
	return err
}

func (f *fixture) enroll(response http.ResponseWriter, request *http.Request) {
	if !f.authorizedHelper(response, request) {
		return
	}
	var input enrollInput
	if err := decodeHelper(request, &input); err != nil || !control.ValidBearerToken(input.EnrollmentToken) {
		http.Error(response, "invalid fixture enrollment", http.StatusBadRequest)
		return
	}
	agentToken, err := identity.NewOpaqueToken()
	if err != nil {
		http.Error(response, "fixture enrollment failed", http.StatusInternalServerError)
		return
	}
	publicKey := string(nebulacert.MarshalPublicKeyToPEM(
		nebulacert.Curve_CURVE25519,
		bytes.Repeat([]byte{'E'}, 32),
	))
	enrolled, err := f.service.Enroll(
		request.Context(),
		input.EnrollmentToken,
		publicKey,
		control.HashToken(agentToken),
	)
	if err != nil {
		http.Error(response, "fixture enrollment failed", http.StatusConflict)
		return
	}
	if _, err := f.service.IssueAgentRecovery(enrolled.NodeID); err != nil {
		http.Error(response, "fixture recovery setup failed", http.StatusInternalServerError)
		return
	}
	writeHelperJSON(response, map[string]any{"node_id": enrolled.NodeID})
}

func (f *fixture) viewerSession(response http.ResponseWriter, request *http.Request) {
	if !f.authorizedHelper(response, request) {
		return
	}
	if err := decodeHelper(request, &struct{}{}); err != nil {
		http.Error(response, "invalid fixture session request", http.StatusBadRequest)
		return
	}
	now := f.clock.Now()
	principal, err := identity.NewOIDCPrincipal(
		f.identityConfig.OIDC.Issuer,
		"desktop-viewer-subject",
		"Desktop Viewer",
		"",
		[]string{"mesh-viewers"},
		"mfa",
		[]string{"otp"},
		now,
	)
	if err != nil {
		http.Error(response, "fixture viewer failed", http.StatusInternalServerError)
		return
	}
	idToken, err := identity.NewOpaqueToken()
	if err != nil {
		http.Error(response, "fixture viewer failed", http.StatusInternalServerError)
		return
	}
	sessionToken, err := identity.NewOpaqueToken()
	if err != nil {
		http.Error(response, "fixture viewer failed", http.StatusInternalServerError)
		return
	}
	csrfToken, err := identity.NewOpaqueToken()
	if err != nil {
		http.Error(response, "fixture viewer failed", http.StatusInternalServerError)
		return
	}
	sessionID := "session_" + idToken
	_, err = f.identityStore.CreateSession(request.Context(), identity.CreateSessionInput{
		ID: sessionID, Token: sessionToken, CSRFToken: csrfToken, Principal: principal,
		PolicyFingerprint: f.policyFingerprint, AuthMethod: "oidc",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		http.Error(response, "fixture viewer failed", http.StatusInternalServerError)
		return
	}
	if _, err := f.identityStore.AuthenticateSession(
		request.Context(),
		sessionToken,
		f.policyFingerprint,
		now,
	); err != nil {
		http.Error(response, "fixture viewer authentication failed", http.StatusInternalServerError)
		return
	}
	probe, err := http.NewRequestWithContext(
		request.Context(),
		http.MethodGet,
		f.origin+"/api/v1/session",
		nil,
	)
	if err != nil {
		http.Error(response, "fixture viewer authentication failed", http.StatusInternalServerError)
		return
	}
	probe.AddCookie(&http.Cookie{Name: "mesh_session", Value: sessionToken})
	probeResponse, err := http.DefaultClient.Do(probe)
	if err != nil {
		http.Error(response, "fixture viewer authentication failed", http.StatusInternalServerError)
		return
	}
	probeBody, readErr := io.ReadAll(io.LimitReader(probeResponse.Body, maxHelperBody))
	_ = probeResponse.Body.Close()
	if readErr != nil {
		http.Error(response, "fixture viewer authentication failed", http.StatusInternalServerError)
		return
	}
	if probeResponse.StatusCode != http.StatusOK {
		http.Error(
			response,
			fmt.Sprintf(
				"fixture viewer authentication failed: status=%d body=%s",
				probeResponse.StatusCode,
				probeBody,
			),
			http.StatusInternalServerError,
		)
		return
	}
	writeHelperJSON(response, viewerSessionDocument{
		Schema: fixtureSchema, SessionID: sessionID,
		SessionToken: sessionToken, CSRFToken: csrfToken,
	})
}

func decodeHelper(request *http.Request, target any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("helper request must be JSON")
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maxHelperBody+1))
	if err != nil || len(raw) > maxHelperBody {
		return errors.New("helper request exceeds its size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("helper request must contain one JSON value")
	}
	return nil
}

func writeHelperJSON(response http.ResponseWriter, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(value)
}
