package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/onlinerelease"
	"mesh/internal/runtimetelemetry"
)

//go:embed web/*
var webFiles embed.FS

const (
	maxOIDCCallbackQueryBytes = 16 << 10
	maxOIDCAuthorizationURL   = 16 << 10
	maxOIDCTransactionAge     = 5 * time.Minute
	// Fleet projections clone or decode the complete bounded control document
	// and derive exact configuration evidence. Two concurrent reads preserve
	// normal browser/API overlap without allowing parallel requests to amplify
	// that work without bound.
	maxConcurrentFleetHealthRequests = 2
	// Readiness can spend up to three seconds in bounded DNS resolution. Keep
	// that work separate from fleet-health slots so an administrator running
	// endpoint checks cannot starve the dashboard's authoritative refresh.
	maxConcurrentNetworkReadinessRequests = 2
	breakGlassIdleTTL                     = 5 * time.Minute
	breakGlassAbsoluteTTL                 = 15 * time.Minute
)

// OIDCAuthenticator is the browser-facing subset of the identity OIDC flow.
// Keeping the HTTP boundary narrow makes callback consumption semantics
// explicit and lets tests prove that malformed or wrong-state callbacks never
// burn a legitimate login attempt.
type OIDCAuthenticator interface {
	Start(context.Context, string) (identity.OIDCStartResult, error)
	Complete(context.Context, string, string, string) (identity.OIDCCompleteResult, error)
	ConsumeAuthorizationError(context.Context, string, string) (string, error)
}

type Server struct {
	service                  *control.Service
	identityConfig           identity.IdentityConfig
	policyFingerprint        string
	sessions                 identity.SessionStore
	identityAudit            identity.IdentityAuditStore
	breakGlass               identity.BreakGlassStore
	runtimeTelemetry         runtimetelemetry.Store
	linuxInstallBundleURL    string
	linuxBootstrapHandoffURL string
	oidc                     OIDCAuthenticator
	adminHash                [32]byte
	secure                   bool
	logger                   *slog.Logger
	now                      func() time.Time
	readinessCheck           func(context.Context) error
	sessionCookie            string
	csrfCookie               string
	oidcCookie               string
	loginSlots               chan struct{}
	agentSlots               chan struct{}
	agentRate                *tokenBucket
	fleetHealthSlots         chan struct{}
	networkReadinessSlots    chan struct{}
	oidcStartSlots           chan struct{}
	oidcCallbackSlots        chan struct{}
	oidcStartRate            *tokenBucket
	oidcCallbackRate         *tokenBucket
	oidcStartClients         *clientRateLimiter
	oidcCallbackClients      *clientRateLimiter
}

// Options is the complete browser and direct-administrator authentication
// contract. IdentityConfig must already be normalized and PolicyFingerprint
// must have been computed from that exact value. SessionStore is always
// required so no browser path can fall back to placing the administrator
// credential in a cookie.
type Options struct {
	IdentityConfig          identity.IdentityConfig
	ValidationOptions       identity.ValidationOptions
	PolicyFingerprint       string
	LegacyCredentialBinding string
	SessionStore            identity.SessionStore
	// RuntimeTelemetryStore is a separately versioned observation plane. Nil
	// preserves mixed-version compatibility by leaving its endpoint absent.
	RuntimeTelemetryStore runtimetelemetry.Store
	// LinuxInstallBundleURL is informational browser guidance only. Empty
	// preserves the external-install workflow; nonempty values must already be
	// canonical public HTTPS object URLs.
	LinuxInstallBundleURL string
	// LinuxBootstrapHandoffURL is untrusted courier location guidance only.
	// The browser and control plane never present it as authentication; the
	// exact handoff digest must arrive through an independent operator channel.
	LinuxBootstrapHandoffURL string
	OIDCAuthenticator        OIDCAuthenticator
	AdminToken               string
	SecureCookies            bool
	Logger                   *slog.Logger
	// ReadinessCheck proves that runtime dependencies are safe to serve. A nil
	// callback fails closed at /readyz while preserving /healthz as process-only
	// liveness.
	ReadinessCheck func(context.Context) error
	// Now exists for deterministic expiry and concurrency tests. Production
	// callers should leave it nil.
	Now func() time.Time
}

func New(service *control.Service, options Options) (*Server, error) {
	if service == nil || options.SessionStore == nil || options.Logger == nil {
		return nil, errors.New("HTTP API requires service, identity session store, and logger")
	}
	identityAudit, ok := options.SessionStore.(identity.IdentityAuditStore)
	if !ok || nilInterface(identityAudit) {
		return nil, errors.New("HTTP API requires an identity session store with durable identity audit support")
	}
	linuxInstallBundleURL := ""
	if options.LinuxInstallBundleURL != "" {
		canonical, err := onlinerelease.CanonicalBundleURL(options.LinuxInstallBundleURL)
		if err != nil || canonical != options.LinuxInstallBundleURL {
			return nil, errors.New("Linux install bundle URL must be one canonical public HTTPS object URL")
		}
		linuxInstallBundleURL = canonical
	}
	linuxBootstrapHandoffURL := ""
	if options.LinuxBootstrapHandoffURL != "" {
		canonical, err := onlinerelease.CanonicalBundleURL(options.LinuxBootstrapHandoffURL)
		if err != nil || canonical != options.LinuxBootstrapHandoffURL {
			return nil, errors.New("Linux bootstrap handoff URL must be one canonical public HTTPS object URL")
		}
		linuxBootstrapHandoffURL = canonical
	}
	normalized, err := options.IdentityConfig.Normalized(options.ValidationOptions)
	if err != nil {
		return nil, fmt.Errorf("validate identity configuration: %w", err)
	}
	if !reflect.DeepEqual(normalized, options.IdentityConfig) {
		return nil, errors.New("HTTP API requires a normalized identity configuration")
	}
	var breakGlass identity.BreakGlassStore
	if normalized.BreakGlass.Enabled {
		var ok bool
		breakGlass, ok = options.SessionStore.(identity.BreakGlassStore)
		if !ok || nilInterface(breakGlass) {
			return nil, errors.New("break-glass recovery requires an identity store with recovery-code lifecycle support")
		}
	}
	oidcConfigured := normalized.OIDC != nil
	oidcSupplied := !nilInterface(options.OIDCAuthenticator)
	if oidcConfigured != oidcSupplied {
		if oidcConfigured {
			return nil, errors.New("OIDC identity configuration requires an OIDC authenticator")
		}
		return nil, errors.New("OIDC authenticator supplied while OIDC authentication is disabled")
	}
	fingerprint, err := normalized.PolicyFingerprint(options.ValidationOptions)
	if err != nil {
		return nil, fmt.Errorf("fingerprint identity configuration: %w", err)
	}
	if options.PolicyFingerprint == "" || subtle.ConstantTimeCompare([]byte(fingerprint), []byte(options.PolicyFingerprint)) != 1 {
		return nil, errors.New("identity policy fingerprint does not match the normalized configuration")
	}
	legacyEnabled := normalized.LegacyBearer || normalized.LegacyBrowserLogin
	if legacyEnabled && !validAdminCredential(options.AdminToken) {
		return nil, errors.New("legacy authentication requires a bounded administrator token of at least 32 characters")
	}
	if !legacyEnabled && options.AdminToken != "" {
		return nil, errors.New("administrator token supplied while legacy authentication is disabled")
	}
	if normalized.LegacyBrowserLogin && !validCredentialBinding(options.LegacyCredentialBinding) {
		return nil, errors.New("legacy browser login requires a master-key-bound credential binding")
	}
	if !normalized.LegacyBrowserLogin && options.LegacyCredentialBinding != "" {
		return nil, errors.New("legacy credential binding supplied while browser login is disabled")
	}
	sessionPolicyFingerprint := fingerprint
	if normalized.LegacyBrowserLogin {
		digest := sha256.Sum256([]byte("mesh-legacy-session-policy-v1\x00" + fingerprint + "\x00" + options.LegacyCredentialBinding))
		sessionPolicyFingerprint = hex.EncodeToString(digest[:])
	}
	parsedPublicURL, err := url.Parse(normalized.PublicURL)
	if err != nil {
		return nil, errors.New("normalized public URL is invalid")
	}
	if options.SecureCookies != (parsedPublicURL.Scheme == "https") {
		return nil, errors.New("secure-cookie setting must match the public URL scheme")
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if normalized.Mode == identity.ModeOIDC {
		checkContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		usable, countErr := breakGlass.CountUsableBreakGlassCodes(checkContext, now().UTC())
		cancel()
		if countErr != nil {
			return nil, errors.New("could not verify usable break-glass recovery inventory")
		}
		if usable < normalized.BreakGlass.MinimumUsableCodes {
			return nil, fmt.Errorf("OIDC-only mode requires at least %d usable break-glass recovery codes", normalized.BreakGlass.MinimumUsableCodes)
		}
	}
	sessionCookie, csrfCookie, oidcCookie := "mesh_session", "mesh_csrf", "mesh_oidc"
	if options.SecureCookies {
		sessionCookie, csrfCookie, oidcCookie = "__Host-mesh_session", "__Host-mesh_csrf", "__Host-mesh_oidc"
	}
	return &Server{
		service: service, identityConfig: normalized, policyFingerprint: sessionPolicyFingerprint, sessions: options.SessionStore,
		identityAudit: identityAudit, breakGlass: breakGlass, runtimeTelemetry: options.RuntimeTelemetryStore, linuxInstallBundleURL: linuxInstallBundleURL,
		linuxBootstrapHandoffURL: linuxBootstrapHandoffURL,
		oidc:                     options.OIDCAuthenticator,
		adminHash:                sha256.Sum256([]byte(options.AdminToken)), secure: options.SecureCookies, logger: options.Logger, now: now,
		readinessCheck: options.ReadinessCheck,
		sessionCookie:  sessionCookie, csrfCookie: csrfCookie, oidcCookie: oidcCookie,
		loginSlots: make(chan struct{}, 8), agentSlots: make(chan struct{}, 32), agentRate: newTokenBucket(50, 100),
		fleetHealthSlots:      make(chan struct{}, maxConcurrentFleetHealthRequests),
		networkReadinessSlots: make(chan struct{}, maxConcurrentNetworkReadinessRequests),
		oidcStartSlots:        make(chan struct{}, 4), oidcCallbackSlots: make(chan struct{}, 8),
		oidcStartRate: newTokenBucket(1, 8), oidcCallbackRate: newTokenBucket(10, 40),
		oidcStartClients: newClientRateLimiter(0.5, 4, 1024), oidcCallbackClients: newClientRateLimiter(4, 20, 1024),
	}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// DeriveLegacyCredentialBinding binds browser sessions to both the master key
// and the shared legacy credential. The HMAC result can be folded into the
// public configuration fingerprint without turning persisted state into an
// offline oracle for a weak administrator token.
func DeriveLegacyCredentialBinding(masterKey []byte, adminToken string) (string, error) {
	if len(masterKey) != 32 {
		return "", errors.New("legacy credential binding requires a 32-byte master key")
	}
	if !validAdminCredential(adminToken) {
		return "", errors.New("legacy credential binding requires a valid administrator token")
	}
	keyDerivation := hmac.New(sha256.New, masterKey)
	_, _ = keyDerivation.Write([]byte("mesh-legacy-browser-binding-subkey-v1"))
	subkey := keyDerivation.Sum(nil)
	defer clear(subkey)
	mac := hmac.New(sha256.New, subkey)
	_, _ = mac.Write([]byte("mesh-legacy-browser-credential-v1\x00"))
	_, _ = mac.Write([]byte(adminToken))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validCredentialBinding(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("HEAD /readyz", s.ready)
	mux.HandleFunc("GET /openapi.json", serveOpenAPI)
	mux.HandleFunc("GET /api/v1/auth/methods", s.authMethods)
	mux.Handle("POST /api/v1/auth/desktop/start", s.oidcLimited(s.oidcStartSlots, s.oidcStartRate, s.oidcStartClients, http.HandlerFunc(s.desktopAuthorizationStart)))
	mux.Handle("POST /api/v1/auth/desktop/complete", s.oidcLimited(s.oidcCallbackSlots, s.oidcCallbackRate, s.oidcCallbackClients, http.HandlerFunc(s.desktopAuthorizationComplete)))
	mux.Handle("POST /api/v1/auth/desktop/{requestID}/decision", s.admin(http.HandlerFunc(s.desktopAuthorizationDecision)))
	if s.oidc != nil {
		mux.Handle("POST /api/v1/auth/oidc/start", s.oidcLimited(s.oidcStartSlots, s.oidcStartRate, s.oidcStartClients, http.HandlerFunc(s.oidcStart)))
		mux.Handle("GET /api/v1/auth/oidc/callback", s.oidcLimited(s.oidcCallbackSlots, s.oidcCallbackRate, s.oidcCallbackClients, http.HandlerFunc(s.oidcCallback)))
	}
	if !nilInterface(s.breakGlass) {
		mux.HandleFunc("POST /api/v1/auth/break-glass", s.breakGlassLogin)
		mux.Handle("GET /api/v1/break-glass-codes", s.authorized(identity.PermissionIdentityManage, http.HandlerFunc(s.listBreakGlassCodes)))
		mux.Handle("POST /api/v1/break-glass-codes", s.authorized(identity.PermissionIdentityManage, http.HandlerFunc(s.registerBreakGlassCode)))
		mux.Handle("DELETE /api/v1/break-glass-codes/{codeID}", s.authorized(identity.PermissionIdentityManage, http.HandlerFunc(s.revokeBreakGlassCode)))
	}
	mux.HandleFunc("POST /api/v1/session", s.login)
	mux.Handle("DELETE /api/v1/session", s.admin(http.HandlerFunc(s.logout)))
	mux.Handle("POST /api/v1/enroll/preflight", s.agentLimited(http.HandlerFunc(s.enrollmentPreflight)))
	mux.Handle("POST /api/v1/enroll", s.agentLimited(http.HandlerFunc(s.enroll)))
	mux.Handle("POST /api/v1/agent/recover", s.agentLimited(http.HandlerFunc(s.agentRecover)))
	mux.Handle("GET /api/v1/agent/config", s.agentLimited(http.HandlerFunc(s.agentConfig)))
	mux.Handle("GET /api/v1/agent/bootstrap", s.agentLimited(http.HandlerFunc(s.agentBootstrap)))
	mux.Handle("POST /api/v1/agent/heartbeat", s.agentLimited(http.HandlerFunc(s.agentHeartbeat)))
	mux.Handle("POST /api/v1/agent/config-apply-failure", s.agentLimited(http.HandlerFunc(s.agentConfigApplyFailure)))
	if !nilInterface(s.runtimeTelemetry) {
		mux.Handle("POST /api/v1/agent/runtime-telemetry", s.agentLimited(http.HandlerFunc(s.agentRuntimeTelemetry)))
		mux.Handle("GET /api/v1/fleet/runtime-telemetry", s.authorized(identity.PermissionNetworksRead, s.fleetHealthLimited(http.HandlerFunc(s.getRuntimeTelemetryCollection))))
	}
	mux.Handle("POST /api/v1/agent/certificate/renew", s.agentLimited(http.HandlerFunc(s.agentRenew)))
	mux.Handle("POST /api/v1/agent/credentials/rotate", s.agentLimited(http.HandlerFunc(s.agentRotateCredential)))
	mux.Handle("GET /api/v1/session", s.admin(http.HandlerFunc(s.session)))
	mux.Handle("GET /api/v1/sessions", s.authorized(identity.PermissionIdentityManage, http.HandlerFunc(s.listSessions)))
	mux.Handle("DELETE /api/v1/sessions/{sessionID}", s.authorized(identity.PermissionIdentityManage, http.HandlerFunc(s.revokeSession)))
	mux.Handle("GET /api/v1/install-guide", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.installGuide)))
	mux.Handle("GET /api/v1/fleet/health", s.authorized(identity.PermissionNetworksRead, s.fleetHealthLimited(http.HandlerFunc(s.getFleetHealthCollection))))
	mux.Handle("GET /api/v1/networks", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.listNetworks)))
	mux.Handle("POST /api/v1/networks", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.createNetwork)))
	mux.Handle("POST /api/v1/networks/{networkID}/retire", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.retireNetwork)))
	mux.Handle("GET /api/v1/networks/{networkID}/health", s.authorized(identity.PermissionNetworksRead, s.fleetHealthLimited(http.HandlerFunc(s.getFleetHealth))))
	mux.Handle("GET /api/v1/networks/{networkID}/readiness", s.authorized(identity.PermissionNetworksRead, s.networkReadinessLimited(http.HandlerFunc(s.getNetworkReadiness))))
	mux.Handle("GET /api/v1/networks/{networkID}/dns", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNetworkDNS)))
	mux.Handle("PUT /api/v1/networks/{networkID}/dns", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.updateNetworkDNS)))
	mux.Handle("GET /api/v1/networks/{networkID}/relays", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNetworkRelays)))
	mux.Handle("PUT /api/v1/networks/{networkID}/relays", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.updateNetworkRelays)))
	mux.Handle("GET /api/v1/networks/{networkID}/ca-rotation", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNetworkCARotation)))
	mux.Handle("POST /api/v1/networks/{networkID}/ca-rotation", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.updateNetworkCARotation)))
	mux.Handle("GET /api/v1/networks/{networkID}/firewall-rollout", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNetworkFirewallRollout)))
	mux.Handle("POST /api/v1/networks/{networkID}/firewall-rollout", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.updateNetworkFirewallRollout)))
	mux.Handle("GET /api/v1/networks/{networkID}/route-transfer", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNetworkRouteTransfer)))
	mux.Handle("POST /api/v1/networks/{networkID}/route-transfer", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.startNetworkRouteTransfer)))
	mux.Handle("POST /api/v1/networks/{networkID}/route-transfer/advance", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.advanceNetworkRouteTransfer)))
	mux.Handle("POST /api/v1/networks/{networkID}/route-transfer/cancel", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.cancelNetworkRouteTransfer)))
	mux.Handle("GET /api/v1/networks/{networkID}/route-policies", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNetworkRoutePolicies)))
	mux.Handle("POST /api/v1/networks/{networkID}/route-policies", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.updateNetworkRoutePolicy)))
	mux.Handle("GET /api/v1/networks/{networkID}/firewall", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getFirewallPolicy)))
	mux.Handle("PUT /api/v1/networks/{networkID}/firewall/preview", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.previewFirewallPolicy)))
	mux.Handle("PUT /api/v1/networks/{networkID}/firewall", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.updateFirewallPolicy)))
	mux.Handle("GET /api/v1/networks/{networkID}/nodes", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.listNodes)))
	mux.Handle("POST /api/v1/networks/{networkID}/nodes", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.createNode)))
	mux.Handle("GET /api/v1/nodes/{nodeID}/route-profile", s.authorized(identity.PermissionNetworksRead, http.HandlerFunc(s.getNodeRouteProfileEdit)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/route-profile", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.startNodeRouteProfileEdit)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/route-profile/advance", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.advanceNodeRouteProfileEdit)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/route-profile/cancel", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.cancelNodeRouteProfileEdit)))
	mux.Handle("PUT /api/v1/nodes/{nodeID}/topology", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.updateNodeTopology)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/enrollment/reissue", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.reissueEnrollment)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/enrollment/cancel", s.authorized(identity.PermissionNetworksWrite, http.HandlerFunc(s.cancelPendingEnrollment)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/agent-recovery", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.issueAgentRecovery)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/replace", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.replaceNode)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/revoke", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.revokeNode)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/revocation", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.revokeNodeWithReceipt)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/certificate/rotate", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.rotateNodeCertificate)))
	mux.Handle("PUT /api/v1/nodes/{nodeID}/groups", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.updateNodeGroups)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/archive", s.authorized(identity.PermissionNetworksSecurity, http.HandlerFunc(s.archiveNode)))
	mux.Handle("GET /api/v1/audit", s.authorized(identity.PermissionAuditRead, http.HandlerFunc(s.audit)))
	assets, _ := fs.Sub(webFiles, "web")
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	return s.securityHeaders(s.recoverer(s.requestLog(mux)))
}

// agentLimited bounds unauthenticated work before a token lookup reaches the
// single-writer JSON store. It is deliberately global and memory-bounded; an
// edge proxy should add distributed/per-source limits for internet exposure.
func (s *Server) agentLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.agentRate.Allow(time.Now()) {
			w.Header().Set("Retry-After", "1")
			writeError(w, control.ErrRateLimited)
			return
		}
		select {
		case s.agentSlots <- struct{}{}:
			defer func() { <-s.agentSlots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			writeError(w, control.ErrRateLimited)
		}
	})
}

// fleetHealthLimited is shared by collection and per-network projections so
// either route consumes the same bounded resource. It is intentionally placed
// inside administrator authentication: rejected credentials cannot occupy a
// projection slot, while saturation remains a generic, secret-free response.
func (s *Server) fleetHealthLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.fleetHealthSlots <- struct{}{}:
			defer func() { <-s.fleetHealthSlots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "fleet health is temporarily unavailable"})
		}
	})
}

// networkReadinessLimited bounds control-plane DNS work independently from
// health projections. It sits inside administrator authentication so rejected
// credentials cannot consume a DNS worker slot.
func (s *Server) networkReadinessLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.networkReadinessSlots <- struct{}{}:
			defer func() { <-s.networkReadinessSlots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "deployment readiness is temporarily unavailable"})
		}
	})
}

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// clientRateLimiter is a memory-bounded token bucket set keyed only from the
// TCP peer address. Forwarding headers are intentionally ignored here because
// trusting them belongs at a configured edge proxy, not at this application
// boundary. IPv6 peers share a /64 bucket to prevent cheap source rotation.
type clientRateLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxEntries int
	entries    map[string]clientRateEntry
}

type clientRateEntry struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst}
}

func newClientRateLimiter(rate, burst float64, maxEntries int) *clientRateLimiter {
	return &clientRateLimiter{rate: rate, burst: burst, maxEntries: maxEntries, entries: make(map[string]clientRateEntry)}
}

func (b *tokenBucket) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.last = now
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *clientRateLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, found := l.entries[key]
	if !found {
		if len(l.entries) >= l.maxEntries {
			oldestKey := ""
			var oldest time.Time
			for candidate, value := range l.entries {
				if oldestKey == "" || value.seen.Before(oldest) {
					oldestKey, oldest = candidate, value.seen
				}
			}
			delete(l.entries, oldestKey)
		}
		entry = clientRateEntry{tokens: l.burst, last: now}
	} else if elapsed := now.Sub(entry.last).Seconds(); elapsed > 0 {
		entry.tokens += elapsed * l.rate
		if entry.tokens > l.burst {
			entry.tokens = l.burst
		}
		entry.last = now
	}
	entry.seen = now
	allowed := entry.tokens >= 1
	if allowed {
		entry.tokens--
	}
	l.entries[key] = entry
	return allowed
}

func requestClientRateKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	address = address.Unmap()
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String()
	}
	return address.String()
}

func (s *Server) oidcLimited(slots chan struct{}, global *tokenBucket, clients *clientRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		now := s.currentTime()
		if !global.Allow(now) || !clients.Allow(requestClientRateKey(r), now) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "single sign-on is temporarily unavailable"})
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "single sign-on is temporarily unavailable"})
		}
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	statusCode, status := http.StatusServiceUnavailable, "unavailable"
	if s.readinessSucceeded(r.Context()) {
		statusCode, status = http.StatusOK, "ready"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(statusCode)
		return
	}
	writeJSON(w, statusCode, struct {
		Status string `json:"status"`
	}{Status: status})
}

func (s *Server) readinessSucceeded(ctx context.Context) (ready bool) {
	if s.readinessCheck == nil {
		return false
	}
	// A dependency panic is a failed check, not a reason for an orchestrator to
	// receive a different response shape or an internal diagnostic.
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return s.readinessCheck(ctx) == nil
}

func (s *Server) authMethods(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct {
		OIDC               bool `json:"oidc"`
		LegacyBrowserLogin bool `json:"legacy_browser_login"`
		BreakGlass         bool `json:"break_glass"`
	}{OIDC: s.oidc != nil, LegacyBrowserLogin: s.identityConfig.LegacyBrowserLogin, BreakGlass: !nilInterface(s.breakGlass)})
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.validSameOriginJSON(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "single sign-on request was rejected"})
		return
	}
	returnPath, err := decodeOIDCStartJSON(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if !validOIDCReturnPath(returnPath) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "single sign-on request was rejected"})
		return
	}
	result, err := s.oidc.Start(r.Context(), returnPath)
	if err != nil {
		writeOIDCFailure(w, http.StatusServiceUnavailable)
		return
	}
	if !identity.ValidOpaqueToken(result.TransactionToken) || !s.validOIDCAuthorizationURL(result.AuthorizationURL) {
		writeOIDCFailure(w, http.StatusInternalServerError)
		return
	}
	now := s.currentTime()
	s.setOIDCTransactionCookie(w, result.TransactionToken, now)
	writeJSON(w, http.StatusOK, struct {
		AuthorizationURL string `json:"authorization_url"`
	}{AuthorizationURL: result.AuthorizationURL})
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	callback, err := s.parseOIDCCallback(r)
	if err != nil {
		writeOIDCFailure(w, http.StatusBadRequest)
		return
	}
	transaction, ok := singleCookie(r, s.oidcCookie)
	if !ok || !identity.ValidOpaqueToken(transaction.Value) {
		writeOIDCFailure(w, http.StatusUnauthorized)
		return
	}
	if callback.Error != "" {
		returnPath, consumeErr := s.oidc.ConsumeAuthorizationError(r.Context(), transaction.Value, callback.State)
		if consumeErr != nil {
			writeOIDCFailure(w, oidcFailureStatus(consumeErr))
			return
		}
		s.clearOIDCTransactionCookie(w)
		s.redirectOIDCFailure(w, returnPath)
		return
	}
	result, completeErr := s.oidc.Complete(r.Context(), transaction.Value, callback.State, callback.Code)
	if completeErr != nil {
		if result.AttemptConsumed {
			s.clearOIDCTransactionCookie(w)
			s.redirectOIDCFailure(w, result.ReturnPath)
			return
		}
		writeOIDCFailure(w, oidcFailureStatus(completeErr))
		return
	}
	if !result.AttemptConsumed || !validOIDCReturnPath(result.ReturnPath) || result.Principal.Kind != identity.PrincipalOIDCAdmin || result.Principal.Validate() != nil {
		if result.AttemptConsumed {
			s.clearOIDCTransactionCookie(w)
		}
		writeOIDCFailure(w, http.StatusInternalServerError)
		return
	}
	now := s.currentTime()
	session, sessionToken, csrfToken, createErr := s.createSession(r.Context(), result.Principal, now)
	if createErr != nil {
		s.clearOIDCTransactionCookie(w)
		s.redirectOIDCFailure(w, result.ReturnPath)
		return
	}
	s.setSessionCookies(w, sessionToken, csrfToken, session.AbsoluteExpiresAt, now)
	s.clearOIDCTransactionCookie(w)
	w.Header().Set("Location", result.ReturnPath)
	w.WriteHeader(http.StatusSeeOther)
}

type oidcCallbackValues struct {
	State string
	Code  string
	Error string
}

func (s *Server) parseOIDCCallback(r *http.Request) (oidcCallbackValues, error) {
	if len(r.URL.RawQuery) < 1 || len(r.URL.RawQuery) > maxOIDCCallbackQueryBytes {
		return oidcCallbackValues{}, errors.New("invalid OIDC callback query size")
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return oidcCallbackValues{}, errors.New("invalid OIDC callback query")
	}
	allowed := map[string]bool{
		"code": true, "state": true, "error": true, "error_description": true,
		"error_uri": true, "iss": true, "session_state": true,
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return oidcCallbackValues{}, errors.New("unsupported or repeated OIDC callback parameter")
		}
	}
	state, ok := singleQueryValue(values, "state")
	if !ok || !identity.ValidOpaqueToken(state) {
		return oidcCallbackValues{}, errors.New("invalid OIDC callback state")
	}
	code, codePresent := singleQueryValue(values, "code")
	providerError, errorPresent := singleQueryValue(values, "error")
	if codePresent == errorPresent {
		return oidcCallbackValues{}, errors.New("OIDC callback must contain exactly one result")
	}
	if codePresent {
		if !validOIDCCode(code) || values.Has("error_description") || values.Has("error_uri") {
			return oidcCallbackValues{}, errors.New("invalid OIDC authorization code callback")
		}
	} else if !validOAuthErrorValue(providerError, 128) {
		return oidcCallbackValues{}, errors.New("invalid OIDC authorization error")
	}
	if description, present := singleQueryValue(values, "error_description"); present {
		if !errorPresent || !validOAuthErrorValue(description, 1024) {
			return oidcCallbackValues{}, errors.New("invalid OIDC authorization error description")
		}
	}
	if errorURI, present := singleQueryValue(values, "error_uri"); present {
		if !errorPresent || !validOIDCErrorURI(errorURI) {
			return oidcCallbackValues{}, errors.New("invalid OIDC authorization error URI")
		}
	}
	if issuer, present := singleQueryValue(values, "iss"); present {
		if s.identityConfig.OIDC == nil || !constantTimeStringEqual(issuer, s.identityConfig.OIDC.Issuer) {
			return oidcCallbackValues{}, errors.New("OIDC callback issuer mismatch")
		}
	}
	if sessionState, present := singleQueryValue(values, "session_state"); present && !validCallbackText(sessionState, 1, 1024) {
		return oidcCallbackValues{}, errors.New("invalid OIDC session state")
	}
	return oidcCallbackValues{State: state, Code: code, Error: providerError}, nil
}

func singleQueryValue(values url.Values, key string) (string, bool) {
	entries, ok := values[key]
	if !ok || len(entries) != 1 {
		return "", false
	}
	return entries[0], true
}

func decodeOIDCStartJSON(r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 4<<10)
	decoder := json.NewDecoder(r.Body)
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", fmt.Errorf("%w: malformed single sign-on request", control.ErrInvalid)
	}
	returnPath := ""
	seenReturnPath := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return "", fmt.Errorf("%w: malformed single sign-on request", control.ErrInvalid)
		}
		name, ok := key.(string)
		if !ok || name != "return_path" || seenReturnPath {
			return "", fmt.Errorf("%w: single sign-on request must contain exactly one return_path", control.ErrInvalid)
		}
		if err := decoder.Decode(&returnPath); err != nil {
			return "", fmt.Errorf("%w: malformed single sign-on return_path", control.ErrInvalid)
		}
		seenReturnPath = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seenReturnPath {
		return "", fmt.Errorf("%w: single sign-on request must contain exactly one return_path", control.ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: single sign-on request must contain one JSON object", control.ErrInvalid)
	}
	return returnPath, nil
}

func (s *Server) validSameOriginJSON(r *http.Request) bool {
	origin, originOK := singleHeader(r, "Origin")
	contentType, contentTypeOK := singleHeader(r, "Content-Type")
	if !originOK || !constantTimeStringEqual(origin, s.identityConfig.PublicURL) || !contentTypeOK || contentType != "application/json" {
		return false
	}
	if values := r.Header.Values("Sec-Fetch-Site"); len(values) != 0 && (len(values) != 1 || values[0] != "same-origin") {
		return false
	}
	return true
}

func (s *Server) validOIDCAuthorizationURL(raw string) bool {
	if len(raw) < 1 || len(raw) > maxOIDCAuthorizationURL || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return !s.secure && parsed.Scheme == "http"
}

func validOIDCReturnPath(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\r\n\\") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return false
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || strings.HasPrefix(decodedPath, "//") || containsUnsafeCallbackText(decodedPath) {
		return false
	}
	decodedQuery, err := url.QueryUnescape(parsed.RawQuery)
	return err == nil && !containsUnsafeCallbackText(decodedQuery)
}

func validOIDCCode(value string) bool {
	if len(value) < 1 || len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validOAuthErrorValue(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if !((character >= 0x20 && character <= 0x21) || (character >= 0x23 && character <= 0x5b) || (character >= 0x5d && character <= 0x7e)) {
			return false
		}
	}
	return true
}

func validOIDCErrorURI(value string) bool {
	if !validOAuthErrorValue(value, 2048) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.User == nil && (parsed.Scheme == "https" || parsed.Scheme == "http")
}

func validCallbackText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return !containsUnsafeCallbackText(value)
}

func containsUnsafeCallbackText(value string) bool {
	if strings.ContainsRune(value, '\\') {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func oidcFailureStatus(err error) int {
	if errors.Is(err, identity.ErrOIDCUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return http.StatusServiceUnavailable
	}
	return http.StatusUnauthorized
}

func writeOIDCFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": "single sign-on could not be completed"})
}

func (s *Server) redirectOIDCFailure(w http.ResponseWriter, returnPath string) {
	if !validOIDCReturnPath(returnPath) {
		writeOIDCFailure(w, http.StatusInternalServerError)
		return
	}
	parsed, err := url.ParseRequestURI(returnPath)
	if err != nil {
		writeOIDCFailure(w, http.StatusInternalServerError)
		return
	}
	query := parsed.Query()
	query.Set("mesh_auth_error", "oidc")
	parsed.RawQuery = query.Encode()
	w.Header().Set("Location", parsed.RequestURI())
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) setOIDCTransactionCookie(w http.ResponseWriter, token string, now time.Time) {
	lifetime := min(s.identityConfig.Sessions.LoginAttemptTTL, maxOIDCTransactionAge)
	expiresAt := now.Add(lifetime)
	http.SetCookie(w, &http.Cookie{
		Name: s.oidcCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(lifetime / time.Second), Expires: expiresAt.UTC(),
	})
}

func (s *Server) clearOIDCTransactionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.oidcCookie, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC(),
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	origin, originOK := singleHeader(r, "Origin")
	contentType, contentTypeOK := singleHeader(r, "Content-Type")
	fetchSiteOK := true
	if values := r.Header.Values("Sec-Fetch-Site"); len(values) != 0 {
		fetchSiteOK = len(values) == 1 && values[0] == "same-origin"
	}
	if !originOK || !constantTimeStringEqual(origin, s.identityConfig.PublicURL) || !contentTypeOK || contentType != "application/json" || !fetchSiteOK {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "login origin or content type check failed"})
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	if !s.identityConfig.LegacyBrowserLogin || !s.validToken(body.Token) {
		s.throttledLoginFailure(w)
		return
	}
	now := s.currentTime()
	principal, err := identity.NewLegacyPrincipal(now)
	if err != nil {
		writeError(w, err)
		return
	}
	session, sessionToken, csrfToken, err := s.createSession(r.Context(), principal, now)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	s.setSessionCookies(w, sessionToken, csrfToken, session.AbsoluteExpiresAt, now)
	response, err := s.newSessionResponse(session)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) breakGlassLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.validSameOriginJSON(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "recovery login was rejected"})
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.throttledLoginFailure(w)
		return
	}
	credential, err := identity.ParseBreakGlassCredential(body.Code)
	if err != nil {
		s.throttledLoginFailure(w)
		return
	}
	now := s.currentTime()
	consumed, err := s.breakGlass.ConsumeBreakGlassCodeAs(r.Context(), credential.ID, credential.Token, now)
	if err != nil {
		s.throttledLoginFailure(w)
		return
	}
	principal, err := identity.NewBreakGlassPrincipal(consumed.ID, now)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	session, sessionToken, csrfToken, err := s.createSession(r.Context(), principal, now)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	s.setSessionCookies(w, sessionToken, csrfToken, session.AbsoluteExpiresAt, now)
	response, err := s.newSessionResponse(session)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) listBreakGlassCodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: recovery-code inventory does not accept query parameters", control.ErrInvalid))
		return
	}
	if !s.canManageBreakGlass(r) {
		writeIdentityError(w, identity.ErrUnauthorized)
		return
	}
	codes, err := s.breakGlass.ListBreakGlassCodes(r.Context(), s.currentTime())
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	if codes == nil {
		codes = []identity.BreakGlassCodeSummary{}
	}
	usable := 0
	for _, code := range codes {
		if code.State == identity.BreakGlassCodeUsable {
			usable++
		}
	}
	writeJSON(w, http.StatusOK, breakGlassInventoryResponse{
		MinimumUsableCodes: s.identityConfig.BreakGlass.MinimumUsableCodes,
		UsableCodes:        usable,
		Codes:              codes,
	})
}

type breakGlassInventoryResponse struct {
	MinimumUsableCodes int                              `json:"minimum_usable_codes"`
	UsableCodes        int                              `json:"usable_codes"`
	Codes              []identity.BreakGlassCodeSummary `json:"codes"`
}

func (s *Server) registerBreakGlassCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: recovery-code registration does not accept query parameters", control.ErrInvalid))
		return
	}
	actor, ok := s.breakGlassManagerActor(r)
	if !ok {
		writeIdentityError(w, identity.ErrUnauthorized)
		return
	}
	var body struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	credential, err := identity.ParseBreakGlassCredential(body.Code)
	if err != nil {
		writeError(w, fmt.Errorf("%w: recovery code is invalid", control.ErrInvalid))
		return
	}
	now := s.currentTime()
	expiresAt := body.ExpiresAt.UTC()
	if body.ExpiresAt.IsZero() || expiresAt.Sub(now) < identity.MinBreakGlassCodeLifetime || expiresAt.Sub(now) > identity.MaxBreakGlassCodeLifetime {
		writeError(w, fmt.Errorf("%w: recovery code expiry must be between %s and %s from now", control.ErrInvalid, identity.MinBreakGlassCodeLifetime, identity.MaxBreakGlassCodeLifetime))
		return
	}
	summary, created, err := s.breakGlass.RegisterBreakGlassCodeAs(r.Context(), actor, identity.BreakGlassCodeInput{
		ID: credential.ID, Token: credential.Token, CreatedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, summary)
}

func (s *Server) revokeBreakGlassCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: recovery-code revocation does not accept query parameters", control.ErrInvalid))
		return
	}
	actor, ok := s.breakGlassManagerActor(r)
	if !ok {
		writeIdentityError(w, identity.ErrUnauthorized)
		return
	}
	codeID := r.PathValue("codeID")
	if !validRecordID(codeID) || !strings.HasPrefix(codeID, "bg_") {
		writeError(w, fmt.Errorf("%w: recovery code ID is invalid", control.ErrInvalid))
		return
	}
	if _, err := s.breakGlass.RevokeBreakGlassCodeAs(r.Context(), actor, codeID, s.currentTime()); err != nil {
		writeIdentityError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) canManageBreakGlass(r *http.Request) bool {
	auth, ok := requestAuthentication(r.Context())
	return ok && auth.principal.Kind != identity.PrincipalBreakGlass
}

func (s *Server) breakGlassManagerActor(r *http.Request) (identity.Actor, bool) {
	auth, ok := requestAuthentication(r.Context())
	if !ok || auth.principal.Kind == identity.PrincipalBreakGlass {
		return identity.Actor{}, false
	}
	var actor identity.Actor
	var err error
	if auth.session != nil {
		actor, err = auth.session.Actor()
	} else {
		actor, err = auth.principal.Actor("")
	}
	return actor, err == nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth, ok := requestAuthentication(r.Context())
	if !ok || auth.session == nil {
		writeError(w, fmt.Errorf("%w: no browser session is active", control.ErrInvalid))
		return
	}
	if _, err := s.sessions.RevokeSession(r.Context(), auth.session.ID, s.currentTime(), "user logout"); err != nil {
		writeIdentityError(w, err)
		return
	}
	s.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth, ok := requestAuthentication(r.Context())
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	if auth.session != nil {
		writeJSON(w, http.StatusOK, sessionResponseForAccess(*auth.session, auth.role, auth.permissions))
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{
		Authenticated: true,
		Principal:     auth.principal,
		AuthMethod:    "legacy_bearer",
		Role:          auth.role,
		Permissions:   auth.permissions,
	})
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > identity.MaxSessionListLimit {
			writeError(w, fmt.Errorf("%w: session limit must be between 1 and %d", control.ErrInvalid, identity.MaxSessionListLimit))
			return
		}
		limit = parsed
	}
	includeRevoked := false
	if raw := r.URL.Query().Get("include_revoked"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil || (raw != "true" && raw != "false") {
			writeError(w, fmt.Errorf("%w: include_revoked must be true or false", control.ErrInvalid))
			return
		}
		includeRevoked = parsed
	}
	if len(r.URL.Query()) > 2 || (r.URL.Query().Has("limit") && len(r.URL.Query()["limit"]) != 1) || (r.URL.Query().Has("include_revoked") && len(r.URL.Query()["include_revoked"]) != 1) {
		writeError(w, fmt.Errorf("%w: unsupported or repeated session query parameter", control.ErrInvalid))
		return
	}
	for key := range r.URL.Query() {
		if key != "limit" && key != "include_revoked" {
			writeError(w, fmt.Errorf("%w: unsupported session query parameter", control.ErrInvalid))
			return
		}
	}
	summaries, err := s.sessions.ListSessions(r.Context(), identity.SessionListFilter{IncludeRevoked: includeRevoked, Limit: limit})
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	if summaries == nil {
		summaries = []identity.SessionSummary{}
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	targetID := r.PathValue("sessionID")
	if !validRecordID(targetID) {
		writeError(w, fmt.Errorf("%w: session ID is invalid", control.ErrInvalid))
		return
	}
	auth, ok := requestAuthentication(r.Context())
	if !ok {
		panic("session revocation reached handler without request authentication")
	}
	var actor identity.Actor
	var err error
	if auth.session != nil {
		actor, err = auth.session.Actor()
	} else {
		actor, err = auth.principal.Actor("")
	}
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	if _, err := s.identityAudit.RevokeSessionAs(r.Context(), actor, targetID, s.currentTime(), "administrator revocation"); err != nil {
		// Once revoked, DELETE remains a successful terminal operation even
		// when the original reason or timestamp differs.
		if !errors.Is(err, identity.ErrConflict) {
			writeIdentityError(w, err)
			return
		}
	}
	if auth, ok := requestAuthentication(r.Context()); ok && auth.session != nil && auth.session.ID == targetID {
		s.clearSessionCookies(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

type sessionResponse struct {
	Authenticated     bool                  `json:"authenticated"`
	SessionID         string                `json:"session_id,omitempty"`
	Principal         identity.Principal    `json:"principal"`
	AuthMethod        string                `json:"auth_method"`
	Role              identity.Role         `json:"role"`
	Permissions       []identity.Permission `json:"permissions"`
	CreatedAt         *time.Time            `json:"created_at,omitempty"`
	LastSeenAt        *time.Time            `json:"last_seen_at,omitempty"`
	IdleExpiresAt     *time.Time            `json:"idle_expires_at,omitempty"`
	AbsoluteExpiresAt *time.Time            `json:"absolute_expires_at,omitempty"`
}

func (s *Server) newSessionResponse(session identity.Session) (sessionResponse, error) {
	role, permissions, err := s.accessForPrincipal(session.Principal)
	if err != nil {
		return sessionResponse{}, err
	}
	return sessionResponseForAccess(session, role, permissions), nil
}

func sessionResponseForAccess(session identity.Session, role identity.Role, permissions []identity.Permission) sessionResponse {
	createdAt, lastSeenAt := session.CreatedAt, session.LastSeenAt
	idleExpiresAt, absoluteExpiresAt := session.IdleExpiresAt, session.AbsoluteExpiresAt
	return sessionResponse{
		Authenticated: true, SessionID: session.ID, Principal: session.Principal, AuthMethod: session.AuthMethod,
		Role: role, Permissions: append([]identity.Permission(nil), permissions...),
		CreatedAt: &createdAt, LastSeenAt: &lastSeenAt, IdleExpiresAt: &idleExpiresAt, AbsoluteExpiresAt: &absoluteExpiresAt,
	}
}

func (s *Server) listNetworks(w http.ResponseWriter, _ *http.Request) {
	networks, err := s.service.Networks()
	if err != nil {
		writeError(w, err)
		return
	}
	if networks == nil {
		networks = []control.NetworkSummary{}
	}
	writeJSON(w, http.StatusOK, networks)
}

func (s *Server) getFleetHealthCollection(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: fleet health does not accept query parameters", control.ErrInvalid))
		return
	}
	collection, err := s.service.FleetHealthAll()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, collection)
}

func (s *Server) getRuntimeTelemetryCollection(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: runtime telemetry does not accept query parameters", control.ErrInvalid))
		return
	}
	records, err := s.runtimeTelemetry.List()
	if err != nil {
		writeError(w, err)
		return
	}
	projection, err := runtimetelemetry.BuildFleetProjection(records, s.now().UTC())
	if err != nil {
		// Invalid repository data or a regressed server clock is an internal
		// failure, never an administrator request error.
		writeError(w, errors.New("runtime telemetry projection is unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, projection)
}

func (s *Server) createNetwork(w http.ResponseWriter, r *http.Request) {
	var input control.CreateNetworkInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	network, err := s.service.CreateNetworkAs(r.Context(), mustRequestActor(r), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, network)
}

type retiredNetworkResponse struct {
	control.RetiredNetwork
	RuntimeTelemetryRecordsRemoved  int  `json:"runtime_telemetry_records_removed"`
	RuntimeTelemetryCleanupComplete bool `json:"runtime_telemetry_cleanup_complete"`
}

func (s *Server) retireNetwork(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network retirement does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.RetireNetworkInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	retired, err := s.service.RetireNetworkAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	response := retiredNetworkResponse{RetiredNetwork: retired, RuntimeTelemetryCleanupComplete: true}
	if !nilInterface(s.runtimeTelemetry) {
		for _, nodeID := range retired.NodeIDs {
			removed, deleteErr := s.runtimeTelemetry.Delete(nodeID)
			if deleteErr != nil {
				response.RuntimeTelemetryCleanupComplete = false
				s.logger.Error("retired network runtime telemetry cleanup failed", "network_id", retired.NetworkID, "node_id", nodeID, "error", deleteErr)
				continue
			}
			if removed {
				response.RuntimeTelemetryRecordsRemoved++
			}
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) getFleetHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: fleet health does not accept query parameters", control.ErrInvalid))
		return
	}
	report, err := s.service.FleetHealth(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) getNetworkReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network readiness does not accept query parameters", control.ErrInvalid))
		return
	}
	var (
		report control.NetworkReadinessReport
		err    error
	)
	if !nilInterface(s.runtimeTelemetry) {
		// Read observations before taking the authoritative control snapshot.
		// A heartbeat accepted between the reads changes its sequence and makes
		// the older observation ineligible instead of accidentally extending it.
		records, listErr := s.runtimeTelemetry.List()
		if listErr == nil {
			report, err = s.service.NetworkReadinessWithRuntime(r.Context(), r.PathValue("networkID"), records)
		} else {
			s.logger.Warn("network readiness runtime evidence unavailable")
			report, err = s.service.NetworkReadiness(r.Context(), r.PathValue("networkID"))
		}
	} else {
		report, err = s.service.NetworkReadiness(r.Context(), r.PathValue("networkID"))
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) getNetworkDNS(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network DNS does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NetworkDNS(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getNetworkRoutePolicies(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network route policies do not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NetworkRoutePolicies(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) updateNetworkRoutePolicy(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network route policies do not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateNetworkRoutePolicyInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.UpdateNetworkRoutePolicyAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) updateNetworkDNS(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network DNS does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateNetworkDNSInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.UpdateNetworkDNSAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getNetworkRelays(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network relays do not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NetworkRelays(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) updateNetworkRelays(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network relays do not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateNetworkRelaysInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.UpdateNetworkRelaysAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getNetworkCARotation(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network CA rotation does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NetworkCARotation(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) updateNetworkCARotation(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network CA rotation does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateNetworkCARotationInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.UpdateNetworkCARotationAs(r.Context(), mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getNetworkFirewallRollout(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network firewall rollout does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NetworkFirewallRollout(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) updateNetworkFirewallRollout(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network firewall rollout does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateNetworkFirewallRolloutInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.UpdateNetworkFirewallRolloutAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getNetworkRouteTransfer(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network route transfer does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NetworkRouteTransfer(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) startNetworkRouteTransfer(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network route transfer does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.StartRouteTransferInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.StartRouteTransferAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, document)
}

func (s *Server) advanceNetworkRouteTransfer(w http.ResponseWriter, r *http.Request) {
	s.updateNetworkRouteTransfer(w, r, false)
}

func (s *Server) cancelNetworkRouteTransfer(w http.ResponseWriter, r *http.Request) {
	s.updateNetworkRouteTransfer(w, r, true)
}

func (s *Server) updateNetworkRouteTransfer(w http.ResponseWriter, r *http.Request, cancel bool) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: network route transfer does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateRouteTransferInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	var document control.NetworkRouteTransferDocument
	var err error
	if cancel {
		document, err = s.service.CancelRouteTransferAs(mustRequestActor(r), r.PathValue("networkID"), input)
	} else {
		document, err = s.service.AdvanceRouteTransferAs(mustRequestActor(r), r.PathValue("networkID"), input)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getNodeRouteProfileEdit(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: node route profile does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	document, err := s.service.NodeRouteProfileEdit(r.PathValue("nodeID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) startNodeRouteProfileEdit(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: node route profile does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.StartRouteProfileEditInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	document, err := s.service.StartRouteProfileEditAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, document)
}

func (s *Server) advanceNodeRouteProfileEdit(w http.ResponseWriter, r *http.Request) {
	s.updateNodeRouteProfileEdit(w, r, false)
}

func (s *Server) cancelNodeRouteProfileEdit(w http.ResponseWriter, r *http.Request) {
	s.updateNodeRouteProfileEdit(w, r, true)
}

func (s *Server) updateNodeRouteProfileEdit(w http.ResponseWriter, r *http.Request, cancel bool) {
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: node route profile does not accept query parameters", control.ErrInvalid))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateRouteProfileEditInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	var document control.NodeRouteProfileEditDocument
	var err error
	if cancel {
		document, err = s.service.CancelRouteProfileEditAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	} else {
		document, err = s.service.AdvanceRouteProfileEditAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getFirewallPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	policy, err := s.service.GetFirewallPolicy(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) previewFirewallPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input control.FirewallPolicyInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	preview, err := s.service.PreviewFirewallPolicy(r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) updateFirewallPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateFirewallPolicyInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	policy, err := s.service.UpdateFirewallPolicyAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.service.Nodes(r.PathValue("networkID"))
	if err != nil {
		writeError(w, err)
		return
	}
	if nodes == nil {
		nodes = []control.Node{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var input control.CreateNodeInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	created, err := s.service.CreateNodeAs(mustRequestActor(r), r.PathValue("networkID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateNodeTopology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input control.UpdateNodeTopologyInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	updated, err := s.service.UpdateNodeTopologyAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) reissueEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	issued, err := s.service.ReissueEnrollmentAs(mustRequestActor(r), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, issued)
}

func (s *Server) cancelPendingEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: pending enrollment cancellation does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.CancelPendingNodeInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	receipt, err := s.service.CancelPendingNodeAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) enrollmentPreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: enrollment preflight does not accept query parameters", control.ErrInvalid))
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	plan, err := s.service.PreflightEnrollment(input.Token)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) issueAgentRecovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	issued, err := s.service.IssueAgentRecoveryAs(mustRequestActor(r), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, issued)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token          string `json:"token"`
		PublicKey      string `json:"public_key"`
		AgentTokenHash string `json:"agent_token_hash"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	bundle, err := s.service.Enroll(r.Context(), input.Token, input.PublicKey, input.AgentTokenHash)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) agentRecover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input control.RecoverAgentInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	bundle, err := s.service.RecoverAgent(input.RecoveryToken, input.PublicKey, input.NewAgentTokenHash)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) agentConfig(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	config, err := s.service.AgentConfig(token)
	if err != nil {
		writeError(w, err)
		return
	}
	// The signature authenticates the complete per-node desired artifact,
	// including certificate generation and metadata. Network revision plus the
	// config digest alone would not change for a node-local certificate renewal.
	etag := fmt.Sprintf("\"%s\"", config.Signature)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, config)
}

func (s *Server) agentBootstrap(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	bundle, err := s.service.AgentBootstrap(token)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	var input control.HeartbeatInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.service.Heartbeat(token, input); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentConfigApplyFailure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: config activation failure does not accept query parameters", control.ErrInvalid))
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	var input control.ConfigApplyFailureInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.service.ReportConfigApplyFailure(token, input); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentRuntimeTelemetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	var input runtimetelemetry.ReportInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	if err := runtimetelemetry.ValidateObservation(input.Observation); err != nil {
		writeRuntimeTelemetryError(w, err)
		return
	}
	activeProbe := runtimetelemetry.UnsupportedActiveProbe()
	if input.ActiveProbe != nil {
		if err := runtimetelemetry.ValidateActiveProbe(*input.ActiveProbe); err != nil {
			writeRuntimeTelemetryError(w, err)
			return
		}
		activeProbe = runtimetelemetry.CloneActiveProbe(*input.ActiveProbe)
	}
	routeOverlap := runtimetelemetry.UnsupportedRouteOverlap()
	if input.RouteOverlap != nil {
		if err := runtimetelemetry.ValidateRouteOverlap(*input.RouteOverlap); err != nil {
			writeRuntimeTelemetryError(w, err)
			return
		}
		routeOverlap = runtimetelemetry.CloneRouteOverlap(*input.RouteOverlap)
	}
	endpointDNS := runtimetelemetry.UnsupportedEndpointDNS()
	if input.EndpointDNS != nil {
		if err := runtimetelemetry.ValidateEndpointDNS(*input.EndpointDNS); err != nil {
			writeRuntimeTelemetryError(w, err)
			return
		}
		endpointDNS = runtimetelemetry.CloneEndpointDNS(*input.EndpointDNS)
	}
	node, err := s.service.AuthorizeRuntimeTelemetry(token, input.HeartbeatSequence)
	if err != nil {
		writeError(w, err)
		return
	}
	receivedAt := s.now().UTC()
	if receivedAt.IsZero() {
		writeError(w, errors.New("runtime telemetry requires a valid receive timestamp"))
		return
	}
	if _, _, err := s.runtimeTelemetry.PutWithConfig(node.ID, input.HeartbeatSequence, receivedAt, input.Observation, activeProbe, routeOverlap, endpointDNS, node.AppliedConfigSHA256); err != nil {
		writeRuntimeTelemetryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentRenew(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	var input struct {
		PublicKey string `json:"public_key"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	bundle, err := s.service.Renew(r.Context(), token, input.PublicKey)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) agentRotateCredential(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, control.ErrUnauthorized)
		return
	}
	var input struct {
		NewTokenHash string `json:"new_token_hash"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	rotation, err := s.service.RotateAgentCredential(token, input.NewTokenHash)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotation)
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	return token, control.ValidBearerToken(token)
}

func (s *Server) revokeNode(w http.ResponseWriter, r *http.Request) {
	node, err := s.service.RevokeNodeAs(mustRequestActor(r), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) revokeNodeWithReceipt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: node revocation does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.RevokeNodeInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	receipt, err := s.service.RevokeNodeWithReceiptAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) rotateNodeCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: certificate rotation does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.RotateNodeCertificateInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	receipt, err := s.service.RotateNodeCertificateAs(r.Context(), mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) updateNodeGroups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: node group update does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.UpdateNodeGroupsInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	receipt, err := s.service.UpdateNodeGroupsAs(r.Context(), mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

type archivedNodeResponse struct {
	control.ArchivedNode
	RuntimeTelemetryRecordRemoved   bool `json:"runtime_telemetry_record_removed"`
	RuntimeTelemetryCleanupComplete bool `json:"runtime_telemetry_cleanup_complete"`
}

func (s *Server) archiveNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: node archival does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.ArchiveNodeInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	archived, err := s.service.ArchiveNodeAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	response := archivedNodeResponse{ArchivedNode: archived, RuntimeTelemetryCleanupComplete: true}
	if !nilInterface(s.runtimeTelemetry) {
		removed, deleteErr := s.runtimeTelemetry.Delete(archived.NodeID)
		if deleteErr != nil {
			response.RuntimeTelemetryCleanupComplete = false
			s.logger.Error("archived node runtime telemetry cleanup failed", "network_id", archived.NetworkID, "node_id", archived.NodeID, "error", deleteErr)
		} else {
			response.RuntimeTelemetryRecordRemoved = removed
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) replaceNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: identity replacement does not accept query parameters", control.ErrInvalid))
		return
	}
	var input control.ReplaceNodeInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	replacement, err := s.service.ReplaceNodeAs(mustRequestActor(r), r.PathValue("nodeID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, replacement)
}

const maxAuditResponseEvents = 100

type auditActorResponse struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	SessionID string `json:"session_id,omitempty"`
}

type auditResponseEvent struct {
	ID                string              `json:"id"`
	Action            string              `json:"action"`
	Resource          string              `json:"resource"`
	ResourceID        string              `json:"resource_id"`
	At                time.Time           `json:"at"`
	Actor             *auditActorResponse `json:"actor,omitempty"`
	TargetPrincipalID string              `json:"target_principal_id,omitempty"`
	TargetSessionID   string              `json:"target_session_id,omitempty"`
	Details           map[string]any      `json:"details,omitempty"`
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	controlEvents, err := s.service.Audit(maxAuditResponseEvents)
	if err != nil {
		writeError(w, err)
		return
	}
	identityEvents, err := s.identityAudit.ListIdentityAudit(r.Context(), identity.IdentityAuditListFilter{Limit: maxAuditResponseEvents})
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	events := make([]auditResponseEvent, 0, len(controlEvents)+len(identityEvents))
	for _, event := range controlEvents {
		events = append(events, controlAuditResponse(event))
	}
	for _, event := range identityEvents {
		events = append(events, identityAuditResponse(event))
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			return events[i].ID < events[j].ID
		}
		return events[i].At.After(events[j].At)
	})
	if len(events) > maxAuditResponseEvents {
		events = events[:maxAuditResponseEvents]
	}
	writeJSON(w, http.StatusOK, events)
}

func controlAuditResponse(event control.AuditEvent) auditResponseEvent {
	details := make(map[string]any, len(event.Details))
	for key, value := range event.Details {
		details[key] = value
	}
	actorID, idOK := details["actor_id"].(string)
	actorKind, kindOK := details["actor_kind"].(string)
	actorSessionID, sessionOK := details["actor_session_id"].(string)
	var actor *auditActorResponse
	if idOK && kindOK && sessionOK {
		actor = &auditActorResponse{ID: actorID, Kind: actorKind, SessionID: actorSessionID}
		delete(details, "actor_id")
		delete(details, "actor_kind")
		delete(details, "actor_session_id")
	}
	if len(details) == 0 {
		details = nil
	}
	return auditResponseEvent{
		ID: event.ID, Action: event.Action, Resource: event.Resource, ResourceID: event.ResourceID,
		At: event.At, Actor: actor, Details: details,
	}
}

func identityAuditResponse(event identity.IdentityAuditSummary) auditResponseEvent {
	details := make(map[string]any, len(event.Details))
	for key, value := range event.Details {
		details[key] = value
	}
	actor := &auditActorResponse{ID: event.Actor.ID, Kind: string(event.Actor.Kind), SessionID: event.Actor.SessionID}
	resource, resourceID := "principal", event.TargetPrincipalID
	if event.TargetSessionID != "" {
		resource, resourceID = "session", event.TargetSessionID
	}
	return auditResponseEvent{
		ID: event.ID, Action: string(event.Type), Resource: resource, ResourceID: resourceID, At: event.At,
		Actor: actor, TargetPrincipalID: event.TargetPrincipalID, TargetSessionID: event.TargetSessionID, Details: details,
	}
}

func (s *Server) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		auth, err := s.authenticateRequest(r)
		if err != nil {
			writeIdentityError(w, err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !auth.bearer && !s.validCookieCSRF(r, auth) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf check failed"})
			return
		}
		if auth.session != nil {
			updated, err := s.touchSessionIfDue(r.Context(), auth.sessionToken, *auth.session, s.currentTime())
			if err != nil {
				writeIdentityError(w, err)
				return
			}
			auth.session = &updated
			auth.principal = updated.Principal
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestAuthenticationKey{}, auth)))
	})
}

func (s *Server) authorized(permission identity.Permission, next http.Handler) http.Handler {
	return s.admin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := requestAuthentication(r.Context())
		if !ok {
			panic("authorization reached handler without request authentication")
		}
		if !identity.RoleAllows(auth.role, permission) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "permission denied"})
			return
		}
		next.ServeHTTP(w, r)
	}))
}

type requestAuthenticationKey struct{}

type authenticatedRequest struct {
	actor        control.Actor
	principal    identity.Principal
	role         identity.Role
	permissions  []identity.Permission
	session      *identity.Session
	sessionToken string
	bearer       bool
}

func requestAuthentication(ctx context.Context) (authenticatedRequest, bool) {
	auth, ok := ctx.Value(requestAuthenticationKey{}).(authenticatedRequest)
	return auth, ok
}

func mustRequestActor(r *http.Request) control.Actor {
	auth, ok := requestAuthentication(r.Context())
	if !ok {
		panic("administrator mutation reached handler without authenticated actor")
	}
	return auth.actor
}

func (s *Server) authenticateRequest(r *http.Request) (authenticatedRequest, error) {
	if values := r.Header.Values("Authorization"); len(values) != 0 {
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.TrimPrefix(values[0], "Bearer ") == "" || strings.TrimSpace(strings.TrimPrefix(values[0], "Bearer ")) != strings.TrimPrefix(values[0], "Bearer ") || !s.identityConfig.LegacyBearer || !s.validToken(strings.TrimPrefix(values[0], "Bearer ")) {
			return authenticatedRequest{}, identity.ErrUnauthorized
		}
		principal, err := identity.NewLegacyPrincipal(s.currentTime())
		if err != nil {
			return authenticatedRequest{}, err
		}
		role, permissions, err := s.accessForPrincipal(principal)
		if err != nil {
			return authenticatedRequest{}, err
		}
		return authenticatedRequest{actor: control.LegacyAdminActor(), principal: principal, role: role, permissions: permissions, bearer: true}, nil
	}
	cookie, ok := singleCookie(r, s.sessionCookie)
	if !ok {
		return authenticatedRequest{}, identity.ErrUnauthorized
	}
	now := s.currentTime()
	session, err := s.sessions.AuthenticateSession(r.Context(), cookie.Value, s.policyFingerprint, now)
	if err != nil {
		return authenticatedRequest{}, err
	}
	identityActor, err := session.Actor()
	if err != nil {
		return authenticatedRequest{}, err
	}
	actor, err := convertActor(identityActor)
	if err != nil {
		return authenticatedRequest{}, err
	}
	copy := session
	role, permissions, err := s.accessForPrincipal(session.Principal)
	if err != nil {
		return authenticatedRequest{}, err
	}
	return authenticatedRequest{actor: actor, principal: session.Principal, role: role, permissions: permissions, session: &copy, sessionToken: cookie.Value}, nil
}

func (s *Server) accessForPrincipal(principal identity.Principal) (identity.Role, []identity.Permission, error) {
	role, err := identity.RoleForPrincipal(principal, s.identityConfig)
	if err != nil {
		return "", nil, err
	}
	permissions, err := identity.PermissionsForRole(role)
	if err != nil {
		return "", nil, err
	}
	return role, permissions, nil
}

func (s *Server) touchSessionIfDue(ctx context.Context, token string, session identity.Session, now time.Time) (identity.Session, error) {
	for attempts := 0; attempts < 3; attempts++ {
		if now.Before(session.LastSeenAt.Add(s.identityConfig.Sessions.TouchInterval)) {
			return session, nil
		}
		idleTTL, _ := s.sessionTTLs(session.Principal.Kind)
		idleExpiresAt := now.Add(idleTTL)
		if idleExpiresAt.After(session.AbsoluteExpiresAt) {
			idleExpiresAt = session.AbsoluteExpiresAt
		}
		updated, err := s.sessions.TouchSession(ctx, session.ID, session.Version, now, idleExpiresAt)
		if err == nil {
			return updated, nil
		}
		if !errors.Is(err, identity.ErrConflict) {
			return identity.Session{}, err
		}
		// Another request may have extended the same session between our read
		// and CAS. Re-authentication proves the credential and reloads the
		// current version, revocation, expiry, and policy fingerprint.
		session, err = s.sessions.AuthenticateSession(ctx, token, s.policyFingerprint, now)
		if err != nil {
			return identity.Session{}, err
		}
	}
	return identity.Session{}, fmt.Errorf("session touch remained conflicted after re-authentication: %w", identity.ErrConflict)
}

func (s *Server) validToken(token string) bool {
	if !validAdminCredential(token) {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash[:], s.adminHash[:]) == 1
}

func validAdminCredential(token string) bool {
	if len(token) < 32 || len(token) > 4096 {
		return false
	}
	for index := 0; index < len(token); index++ {
		if token[index] < 0x21 || token[index] > 0x7e {
			return false
		}
	}
	return true
}

func validRecordID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func (s *Server) validCookieCSRF(r *http.Request, auth authenticatedRequest) bool {
	if auth.session == nil {
		return false
	}
	cookie, ok := singleCookie(r, s.csrfCookie)
	if !ok {
		return false
	}
	headerToken, ok := singleHeader(r, "X-Mesh-CSRF")
	if !ok {
		return false
	}
	if !identity.ValidOpaqueToken(headerToken) || !constantTimeStringEqual(cookie.Value, headerToken) || !auth.session.ValidCSRF(headerToken) {
		return false
	}
	origin, ok := singleHeader(r, "Origin")
	if !ok || !constantTimeStringEqual(origin, s.identityConfig.PublicURL) {
		return false
	}
	if values := r.Header.Values("Sec-Fetch-Site"); len(values) != 0 {
		if len(values) != 1 || values[0] != "same-origin" {
			return false
		}
	}
	return true
}

func singleHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1
}

func singleCookie(r *http.Request, name string) (*http.Cookie, bool) {
	var match *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != name {
			continue
		}
		if match != nil {
			return nil, false
		}
		copy := *cookie
		match = &copy
	}
	return match, match != nil
}

func constantTimeStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func convertActor(actor identity.Actor) (control.Actor, error) {
	if err := actor.Validate(); err != nil {
		return control.Actor{}, err
	}
	kind := ""
	switch actor.Kind {
	case identity.PrincipalOIDCAdmin:
		kind = control.ActorKindOIDCAdmin
	case identity.PrincipalLegacyAdmin:
		kind = control.ActorKindLegacyAdmin
	case identity.PrincipalService:
		kind = control.ActorKindServiceAccount
	case identity.PrincipalBreakGlass:
		kind = control.ActorKindBreakGlass
	default:
		return control.Actor{}, errors.New("identity actor has unsupported kind")
	}
	return control.Actor{ID: actor.ID, Kind: kind, SessionID: actor.SessionID}, nil
}

func (s *Server) currentTime() time.Time { return s.now().UTC() }

func (s *Server) createSession(ctx context.Context, principal identity.Principal, now time.Time) (identity.Session, string, string, error) {
	if err := principal.Validate(); err != nil {
		return identity.Session{}, "", "", err
	}
	authMethod := ""
	switch principal.Kind {
	case identity.PrincipalLegacyAdmin:
		authMethod = "legacy_token"
	case identity.PrincipalOIDCAdmin:
		authMethod = "oidc"
	case identity.PrincipalBreakGlass:
		authMethod = "break_glass"
	default:
		return identity.Session{}, "", "", errors.New("browser session principal kind is unsupported")
	}
	for attempt := 0; attempt < 5; attempt++ {
		idToken, err := identity.NewOpaqueToken()
		if err != nil {
			return identity.Session{}, "", "", err
		}
		sessionToken, err := identity.NewOpaqueToken()
		if err != nil {
			return identity.Session{}, "", "", err
		}
		csrfToken, err := identity.NewOpaqueToken()
		if err != nil {
			return identity.Session{}, "", "", err
		}
		if sessionToken == csrfToken {
			continue
		}
		idleTTL, absoluteTTL := s.sessionTTLs(principal.Kind)
		absoluteExpiresAt := now.Add(absoluteTTL)
		idleExpiresAt := now.Add(idleTTL)
		if idleExpiresAt.After(absoluteExpiresAt) {
			idleExpiresAt = absoluteExpiresAt
		}
		created, err := s.sessions.CreateSession(ctx, identity.CreateSessionInput{
			ID: "session_" + idToken, Token: sessionToken, CSRFToken: csrfToken, Principal: principal,
			PolicyFingerprint: s.policyFingerprint, AuthMethod: authMethod,
			CreatedAt: now, LastSeenAt: now, IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		})
		if err == nil {
			return created, sessionToken, csrfToken, nil
		}
		if !errors.Is(err, identity.ErrConflict) {
			return identity.Session{}, "", "", err
		}
	}
	return identity.Session{}, "", "", fmt.Errorf("could not allocate a unique session: %w", identity.ErrConflict)
}

func (s *Server) sessionTTLs(kind identity.PrincipalKind) (time.Duration, time.Duration) {
	idleTTL := s.identityConfig.Sessions.IdleTTL
	absoluteTTL := s.identityConfig.Sessions.AbsoluteTTL
	if kind == identity.PrincipalBreakGlass {
		idleTTL = min(idleTTL, breakGlassIdleTTL)
		absoluteTTL = min(absoluteTTL, breakGlassAbsoluteTTL)
	}
	return idleTTL, absoluteTTL
}

func (s *Server) throttledLoginFailure(w http.ResponseWriter) {
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		writeError(w, control.ErrRateLimited)
		return
	}
	time.Sleep(300 * time.Millisecond)
	writeError(w, control.ErrUnauthorized)
}

func (s *Server) setSessionCookies(w http.ResponseWriter, sessionToken, csrfToken string, expiresAt, now time.Time) {
	remaining := expiresAt.Sub(now)
	maxAge := int((remaining + time.Second - 1) / time.Second)
	base := http.Cookie{Path: "/", Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: expiresAt.UTC()}
	sessionCookie := base
	sessionCookie.Name, sessionCookie.Value, sessionCookie.HttpOnly = s.sessionCookie, sessionToken, true
	csrfCookie := base
	csrfCookie.Name, csrfCookie.Value = s.csrfCookie, csrfToken
	http.SetCookie(w, &sessionCookie)
	http.SetCookie(w, &csrfCookie)
}

func (s *Server) clearSessionCookies(w http.ResponseWriter) {
	for _, cookie := range []http.Cookie{
		{Name: s.sessionCookie, HttpOnly: true},
		{Name: s.csrfCookie},
	} {
		cookie.Path = "/"
		cookie.Secure = s.secure
		cookie.SameSite = http.SameSiteStrictMode
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0).UTC()
		http.SetCookie(w, &cookie)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if s.secure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("request panic", "error", recovered)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds())
	})
}

func decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("%w: malformed JSON: %v", control.ErrInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: request must contain one JSON value", control.ErrInvalid)
	}
	return nil
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, control.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, control.ErrUnauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, control.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, control.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, control.ErrRateLimited):
		status = http.StatusTooManyRequests
	}
	message := err.Error()
	if status == http.StatusInternalServerError {
		message = "internal server error"
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeIdentityError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, identity.ErrUnauthorized):
		writeError(w, control.ErrUnauthorized)
	case errors.Is(err, identity.ErrNotFound):
		writeError(w, control.ErrNotFound)
	case errors.Is(err, identity.ErrConflict):
		writeError(w, control.ErrConflict)
	case errors.Is(err, identity.ErrLimit):
		writeError(w, control.ErrRateLimited)
	default:
		writeError(w, err)
	}
}

func writeRuntimeTelemetryError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, runtimetelemetry.ErrInvalid):
		writeError(w, control.ErrInvalid)
	case errors.Is(err, runtimetelemetry.ErrReplay), errors.Is(err, runtimetelemetry.ErrConflict):
		writeError(w, control.ErrConflict)
	default:
		writeError(w, err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func DecodeMasterKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("MESH_MASTER_KEY must be unpadded base64url: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("MESH_MASTER_KEY must decode to exactly 32 bytes")
	}
	return key, nil
}
