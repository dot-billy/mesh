package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/runtimetelemetry"
)

const (
	openAPIVersion         = "3.1.0"
	openAPIContractVersion = "1.0.0"
)

type openAPIStatusResponse struct {
	Status string `json:"status"`
}

type openAPIAuthMethodsResponse struct {
	OIDC               bool `json:"oidc"`
	LegacyBrowserLogin bool `json:"legacy_browser_login"`
	BreakGlass         bool `json:"break_glass"`
}

type openAPIOIDCStartRequest struct {
	ReturnPath string `json:"return_path"`
}

type openAPIOIDCStartResponse struct {
	AuthorizationURL string `json:"authorization_url"`
}

type openAPILegacyLoginRequest struct {
	Token string `json:"token"`
}

type openAPIBreakGlassLoginRequest struct {
	Code string `json:"code"`
}

type openAPIBreakGlassCodeRegistrationRequest struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type openAPISessionResponse struct {
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

type openAPIBreakGlassInventoryResponse struct {
	MinimumUsableCodes int                              `json:"minimum_usable_codes"`
	UsableCodes        int                              `json:"usable_codes"`
	Codes              []identity.BreakGlassCodeSummary `json:"codes"`
}

type openAPIEnrollmentPreflightRequest struct {
	Token string `json:"token"`
}

type openAPIEnrollRequest struct {
	Token          string `json:"token"`
	PublicKey      string `json:"public_key"`
	AgentTokenHash string `json:"agent_token_hash"`
}

type openAPICreateNetworkRequest struct {
	Name                  string `json:"name"`
	CIDR                  string `json:"cidr"`
	ListenPort            int    `json:"listen_port,omitempty"`
	CertificateTTLInHours int    `json:"certificate_ttl_hours,omitempty"`
}

type openAPIAgentRenewRequest struct {
	PublicKey string `json:"public_key"`
}

type openAPIAgentCredentialRotationRequest struct {
	NewTokenHash string `json:"new_token_hash"`
}

type openAPIRetiredNetworkResponse struct {
	control.RetiredNetwork
	RuntimeTelemetryRecordsRemoved  int  `json:"runtime_telemetry_records_removed"`
	RuntimeTelemetryCleanupComplete bool `json:"runtime_telemetry_cleanup_complete"`
}

type openAPIArchivedNodeResponse struct {
	control.ArchivedNode
	RuntimeTelemetryRecordRemoved   bool `json:"runtime_telemetry_record_removed"`
	RuntimeTelemetryCleanupComplete bool `json:"runtime_telemetry_cleanup_complete"`
}

type openAPIAuditActorResponse struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	SessionID string `json:"session_id,omitempty"`
}

type openAPIAuditResponseEvent struct {
	ID                string                     `json:"id"`
	Action            string                     `json:"action"`
	Resource          string                     `json:"resource"`
	ResourceID        string                     `json:"resource_id"`
	At                time.Time                  `json:"at"`
	Actor             *openAPIAuditActorResponse `json:"actor,omitempty"`
	TargetPrincipalID string                     `json:"target_principal_id,omitempty"`
	TargetSessionID   string                     `json:"target_session_id,omitempty"`
	Details           map[string]any             `json:"details,omitempty"`
}

type openAPIQueryParameter struct {
	Name        string
	Description string
	Schema      map[string]any
	Required    bool
}

type openAPIOperation struct {
	Method          string
	Path            string
	OperationID     string
	Tag             string
	Summary         string
	Description     string
	Security        string
	Permission      identity.Permission
	Request         reflect.Type
	Response        reflect.Type
	ResponseStatus  int
	ResponseSummary string
	Query           []openAPIQueryParameter
	Optional        string
	Interactive     bool
	Deprecated      bool
}

func openAPIType[T any]() reflect.Type {
	return reflect.TypeOf((*T)(nil)).Elem()
}

func openAPIOperations() []openAPIOperation {
	public := "public"
	admin := "admin"
	agent := "agent"
	oidc := "oidc"
	recovery := "recovery"
	read := identity.PermissionNetworksRead
	write := identity.PermissionNetworksWrite
	security := identity.PermissionNetworksSecurity
	identityManage := identity.PermissionIdentityManage
	auditRead := identity.PermissionAuditRead
	return []openAPIOperation{
		{Method: http.MethodGet, Path: "/healthz", OperationID: "getHealth", Tag: "System", Summary: "Check process health", Description: "Returns success when the HTTP process is running. This endpoint does not prove durable-store readiness.", Security: public, Response: openAPIType[openAPIStatusResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "The process is healthy.", Interactive: true},
		{Method: http.MethodGet, Path: "/readyz", OperationID: "getReadiness", Tag: "System", Summary: "Check service readiness", Description: "Checks the configured durable-store dependency and returns either ready or unavailable.", Security: public, Response: openAPIType[openAPIStatusResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "The service is ready.", Interactive: true},
		{Method: http.MethodHead, Path: "/readyz", OperationID: "headReadiness", Tag: "System", Summary: "Check readiness without a body", Description: "Returns the same status code as GET /readyz without a response body.", Security: public, ResponseStatus: http.StatusOK, ResponseSummary: "The service is ready.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/auth/methods", OperationID: "getAuthenticationMethods", Tag: "Authentication", Summary: "List enabled browser authentication methods", Description: "Returns deployment-specific availability for OIDC, legacy browser login, and break-glass login.", Security: public, Response: openAPIType[openAPIAuthMethodsResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Enabled browser authentication methods.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/auth/oidc/start", OperationID: "startOIDCLogin", Tag: "Authentication", Summary: "Start an OIDC login", Description: "Creates a bounded OIDC transaction after same-origin and JSON-content checks. The browser must follow the returned provider URL.", Security: oidc, Request: openAPIType[openAPIOIDCStartRequest](), Response: openAPIType[openAPIOIDCStartResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "OIDC authorization URL.", Optional: "OIDC", Interactive: false},
		{Method: http.MethodGet, Path: "/api/v1/auth/oidc/callback", OperationID: "completeOIDCLogin", Tag: "Authentication", Summary: "Complete an OIDC callback", Description: "Consumes the provider callback and transaction cookie, creates the Mesh browser session, and redirects to the bound return path.", Security: oidc, ResponseStatus: http.StatusSeeOther, ResponseSummary: "Browser redirect after successful authentication.", Optional: "OIDC", Interactive: false, Query: []openAPIQueryParameter{
			{Name: "state", Description: "Opaque OIDC state bound to the transaction cookie.", Required: true, Schema: map[string]any{"type": "string"}},
			{Name: "code", Description: "Provider authorization code. Mutually exclusive with error.", Schema: map[string]any{"type": "string"}},
			{Name: "error", Description: "Provider error code. Mutually exclusive with code.", Schema: map[string]any{"type": "string"}},
		}},
		{Method: http.MethodPost, Path: "/api/v1/auth/break-glass", OperationID: "loginWithBreakGlassCode", Tag: "Authentication", Summary: "Consume a break-glass code", Description: "Consumes one recovery code after same-origin and JSON-content checks and creates a short-lived browser session.", Security: recovery, Request: openAPIType[openAPIBreakGlassLoginRequest](), Response: openAPIType[openAPISessionResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Authenticated recovery session.", Optional: "Break-glass recovery", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/session", OperationID: "loginWithLegacyToken", Tag: "Authentication", Summary: "Create a legacy browser session", Description: "Exchanges the deployment administrator token for hardened session and CSRF cookies. OIDC is preferred where configured.", Security: public, Request: openAPIType[openAPILegacyLoginRequest](), Response: openAPIType[openAPISessionResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Authenticated browser session.", Interactive: false},
		{Method: http.MethodGet, Path: "/api/v1/session", OperationID: "getCurrentSession", Tag: "Sessions", Summary: "Read the current access context", Description: "Returns the authenticated principal, role, permissions, and browser-session lifetime when applicable.", Security: admin, Response: openAPIType[openAPISessionResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Current authenticated access context.", Interactive: true},
		{Method: http.MethodDelete, Path: "/api/v1/session", OperationID: "logoutCurrentSession", Tag: "Sessions", Summary: "Log out the current browser session", Description: "Revokes the active browser session and clears both session cookies. Legacy bearer requests cannot use this endpoint.", Security: admin, ResponseStatus: http.StatusNoContent, ResponseSummary: "The browser session was revoked.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/sessions", OperationID: "listSessions", Tag: "Sessions", Summary: "List browser sessions", Description: "Lists active sessions, optionally including revoked sessions.", Security: admin, Permission: identityManage, Response: openAPIType[[]identity.SessionSummary](), ResponseStatus: http.StatusOK, ResponseSummary: "Session inventory.", Interactive: true, Query: []openAPIQueryParameter{
			{Name: "limit", Description: "Maximum number of sessions, from 1 through 256.", Schema: map[string]any{"type": "integer", "minimum": 1, "maximum": 256, "default": 100}},
			{Name: "include_revoked", Description: "Include revoked and expired session records.", Schema: map[string]any{"type": "boolean", "default": false}},
		}},
		{Method: http.MethodDelete, Path: "/api/v1/sessions/{sessionID}", OperationID: "revokeSession", Tag: "Sessions", Summary: "Revoke a browser session", Description: "Revokes the selected session idempotently and clears cookies when the caller revokes its own session.", Security: admin, Permission: identityManage, ResponseStatus: http.StatusNoContent, ResponseSummary: "The session is revoked.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/break-glass-codes", OperationID: "listBreakGlassCodes", Tag: "Recovery access", Summary: "List break-glass code metadata", Description: "Returns non-secret code identifiers, expiry, state, and the configured usable-code floor.", Security: admin, Permission: identityManage, Response: openAPIType[openAPIBreakGlassInventoryResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Break-glass code inventory.", Optional: "Break-glass recovery", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/break-glass-codes", OperationID: "registerBreakGlassCode", Tag: "Recovery access", Summary: "Register a break-glass code", Description: "Stores only the verifier for a newly generated one-use recovery code. A recovery-authenticated principal cannot register replacements.", Security: admin, Permission: identityManage, Request: openAPIType[openAPIBreakGlassCodeRegistrationRequest](), Response: openAPIType[identity.BreakGlassCodeSummary](), ResponseStatus: http.StatusCreated, ResponseSummary: "Registered break-glass code metadata.", Optional: "Break-glass recovery", Interactive: false},
		{Method: http.MethodDelete, Path: "/api/v1/break-glass-codes/{codeID}", OperationID: "revokeBreakGlassCode", Tag: "Recovery access", Summary: "Revoke a break-glass code", Description: "Permanently revokes the selected unused recovery code.", Security: admin, Permission: identityManage, ResponseStatus: http.StatusNoContent, ResponseSummary: "The recovery code is revoked.", Optional: "Break-glass recovery", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/install-guide", OperationID: "getInstallGuide", Tag: "Installation", Summary: "Read deployment installation endpoints", Description: "Returns the configured public release-bundle and bootstrap-handoff locations without exposing credentials.", Security: admin, Permission: read, Response: openAPIType[installGuideResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Installation guide.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/enroll/preflight", OperationID: "preflightEnrollment", Tag: "Enrollment", Summary: "Inspect an enrollment before key generation", Description: "Validates a one-time enrollment token and returns the public network and node plan needed by the installer.", Security: public, Request: openAPIType[openAPIEnrollmentPreflightRequest](), Response: openAPIType[control.EnrollmentPreflight](), ResponseStatus: http.StatusOK, ResponseSummary: "Enrollment plan.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/enroll", OperationID: "enrollNode", Tag: "Enrollment", Summary: "Enroll a node", Description: "Consumes a one-time enrollment token, signs the node-generated Nebula public key, and binds the agent credential hash.", Security: public, Request: openAPIType[openAPIEnrollRequest](), Response: openAPIType[control.EnrollmentBundle](), ResponseStatus: http.StatusOK, ResponseSummary: "Initial certificate and signed configuration bundle.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/agent/recover", OperationID: "recoverAgent", Tag: "Agent lifecycle", Summary: "Recover an agent credential", Description: "Consumes a one-use recovery token and returns a replacement agent credential binding and current signed bundle.", Security: recovery, Request: openAPIType[control.RecoverAgentInput](), Response: openAPIType[control.AgentRecoveryBundle](), ResponseStatus: http.StatusOK, ResponseSummary: "Recovered agent bundle.", Interactive: false},
		{Method: http.MethodGet, Path: "/api/v1/agent/config", OperationID: "getAgentConfig", Tag: "Agent lifecycle", Summary: "Fetch desired signed configuration", Description: "Returns the node-specific signed desired artifact. If-None-Match may use the prior signature and receive 304.", Security: agent, Response: openAPIType[control.AgentConfig](), ResponseStatus: http.StatusOK, ResponseSummary: "Current desired agent configuration.", Interactive: false},
		{Method: http.MethodGet, Path: "/api/v1/agent/bootstrap", OperationID: "getAgentBootstrap", Tag: "Agent lifecycle", Summary: "Fetch the current bootstrap bundle", Description: "Returns the node certificate and complete signed configuration bundle for an authenticated agent.", Security: agent, Response: openAPIType[control.EnrollmentBundle](), ResponseStatus: http.StatusOK, ResponseSummary: "Current certificate and signed configuration bundle.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/agent/heartbeat", OperationID: "reportAgentHeartbeat", Tag: "Agent lifecycle", Summary: "Report lifecycle convergence", Description: "Reports the exact configuration, certificate, credential, process, resolver, and probe evidence observed by the managed agent.", Security: agent, Request: openAPIType[control.HeartbeatInput](), ResponseStatus: http.StatusNoContent, ResponseSummary: "Heartbeat accepted.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/agent/config-apply-failure", OperationID: "reportConfigApplyFailure", Tag: "Agent lifecycle", Summary: "Report signed-config activation failure", Description: "Records a bounded failure reason for the exact desired configuration revision.", Security: agent, Request: openAPIType[control.ConfigApplyFailureInput](), ResponseStatus: http.StatusNoContent, ResponseSummary: "Failure evidence accepted.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/agent/runtime-telemetry", OperationID: "reportRuntimeTelemetry", Tag: "Runtime telemetry", Summary: "Publish aggregate Nebula runtime observations", Description: "Publishes allowlisted aggregate observations bound to the latest accepted heartbeat sequence.", Security: agent, Request: openAPIType[runtimetelemetry.ReportInput](), ResponseStatus: http.StatusNoContent, ResponseSummary: "Runtime observation accepted.", Optional: "Runtime telemetry", Interactive: false},
		{Method: http.MethodGet, Path: "/api/v1/fleet/runtime-telemetry", OperationID: "getFleetRuntimeTelemetry", Tag: "Runtime telemetry", Summary: "Read aggregate runtime telemetry", Description: "Returns a secret-free fleet projection separate from lifecycle health.", Security: admin, Permission: read, Response: openAPIType[runtimetelemetry.FleetProjection](), ResponseStatus: http.StatusOK, ResponseSummary: "Fleet runtime projection.", Optional: "Runtime telemetry", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/agent/certificate/renew", OperationID: "renewAgentCertificate", Tag: "Agent lifecycle", Summary: "Renew a node certificate", Description: "Signs the supplied node public key when renewal policy and certificate-generation gates permit it.", Security: agent, Request: openAPIType[openAPIAgentRenewRequest](), Response: openAPIType[control.RenewalBundle](), ResponseStatus: http.StatusOK, ResponseSummary: "Renewed certificate bundle.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/agent/credentials/rotate", OperationID: "rotateAgentCredential", Tag: "Agent lifecycle", Summary: "Rotate an agent credential", Description: "Replaces the active agent credential hash while preserving one bounded overlap for recovery from response loss.", Security: agent, Request: openAPIType[openAPIAgentCredentialRotationRequest](), Response: openAPIType[control.CredentialRotation](), ResponseStatus: http.StatusOK, ResponseSummary: "Credential-rotation receipt.", Interactive: false},
		{Method: http.MethodGet, Path: "/api/v1/fleet/health", OperationID: "getFleetHealth", Tag: "Health and readiness", Summary: "Read fleet health", Description: "Returns one authoritative fleet snapshot across every network.", Security: admin, Permission: read, Response: openAPIType[control.FleetHealthCollection](), ResponseStatus: http.StatusOK, ResponseSummary: "Fleet health collection.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/health", OperationID: "getNetworkHealth", Tag: "Health and readiness", Summary: "Read network health", Description: "Returns lifecycle, redundancy, rollout, and revocation health for one network.", Security: admin, Permission: read, Response: openAPIType[control.FleetHealthReport](), ResponseStatus: http.StatusOK, ResponseSummary: "Network health report.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/readiness", OperationID: "getNetworkReadiness", Tag: "Health and readiness", Summary: "Read deployment readiness", Description: "Returns exact control and optional runtime evidence for the network deployment checklist.", Security: admin, Permission: read, Response: openAPIType[control.NetworkReadinessReport](), ResponseStatus: http.StatusOK, ResponseSummary: "Network readiness report.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks", OperationID: "listNetworks", Tag: "Networks", Summary: "List networks", Description: "Returns the non-secret network inventory.", Security: admin, Permission: read, Response: openAPIType[[]control.NetworkSummary](), ResponseStatus: http.StatusOK, ResponseSummary: "Network inventory.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks", OperationID: "createNetwork", Tag: "Networks", Summary: "Create a network", Description: "Creates an encrypted Nebula certificate authority and configuration-signing identity for one non-overlapping overlay CIDR. listen_port defaults to 4242 and certificate_ttl_hours defaults to 8760 when omitted.", Security: admin, Permission: write, Request: openAPIType[openAPICreateNetworkRequest](), Response: openAPIType[control.Network](), ResponseStatus: http.StatusCreated, ResponseSummary: "Created network.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/retire", OperationID: "retireNetwork", Tag: "Networks", Summary: "Retire a network", Description: "Irreversibly removes the network authority and credentials while permanently reserving its name and CIDR.", Security: admin, Permission: security, Request: openAPIType[control.RetireNetworkInput](), Response: openAPIType[openAPIRetiredNetworkResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Network retirement receipt.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/dns", OperationID: "getNetworkDNS", Tag: "DNS", Summary: "Read managed DNS policy", Description: "Returns the desired DNS and optional native resolver state plus active resolver projection.", Security: admin, Permission: read, Response: openAPIType[control.NetworkDNSDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Managed DNS document.", Interactive: true},
		{Method: http.MethodPut, Path: "/api/v1/networks/{networkID}/dns", OperationID: "updateNetworkDNS", Tag: "DNS", Summary: "Update managed DNS policy", Description: "Updates DNS and optional native resolver settings under an optimistic network revision.", Security: admin, Permission: write, Request: openAPIType[control.UpdateNetworkDNSInput](), Response: openAPIType[control.NetworkDNSDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated managed DNS document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/relays", OperationID: "getNetworkRelays", Tag: "Relays", Summary: "Read managed relay policy", Description: "Returns selected relay nodes and the active relay projection.", Security: admin, Permission: read, Response: openAPIType[control.NetworkRelaysDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Managed relay document.", Interactive: true},
		{Method: http.MethodPut, Path: "/api/v1/networks/{networkID}/relays", OperationID: "updateNetworkRelays", Tag: "Relays", Summary: "Update managed relay policy", Description: "Selects up to eight pending or active relay nodes under an optimistic network revision.", Security: admin, Permission: write, Request: openAPIType[control.UpdateNetworkRelaysInput](), Response: openAPIType[control.NetworkRelaysDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated managed relay document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/ca-rotation", OperationID: "getNetworkCARotation", Tag: "Certificate authority", Summary: "Read CA rotation state", Description: "Returns the staged CA transition, node convergence, and currently available actions.", Security: admin, Permission: read, Response: openAPIType[control.NetworkCARotationDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "CA rotation document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/ca-rotation", OperationID: "updateNetworkCARotation", Tag: "Certificate authority", Summary: "Advance CA rotation", Description: "Performs one revision-bound prepare, activate, finalize, complete, or abort transition.", Security: admin, Permission: security, Request: openAPIType[control.UpdateNetworkCARotationInput](), Response: openAPIType[control.NetworkCARotationDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated CA rotation document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/firewall-rollout", OperationID: "getFirewallRollout", Tag: "Firewall", Summary: "Read firewall rollout state", Description: "Returns the active policy, staged target, canaries, convergence, and available rollout actions.", Security: admin, Permission: read, Response: openAPIType[control.NetworkFirewallRolloutDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Firewall rollout document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/firewall-rollout", OperationID: "updateFirewallRollout", Tag: "Firewall", Summary: "Advance a firewall rollout", Description: "Starts, pauses, resumes, promotes, or rolls back a revision-bound canary rollout.", Security: admin, Permission: write, Request: openAPIType[control.UpdateNetworkFirewallRolloutInput](), Response: openAPIType[control.NetworkFirewallRolloutDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated firewall rollout document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/firewall", OperationID: "getFirewallPolicy", Tag: "Firewall", Summary: "Read firewall policy", Description: "Returns the desired managed Nebula firewall policy and its revision metadata.", Security: admin, Permission: read, Response: openAPIType[control.FirewallPolicyDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Firewall policy document.", Interactive: true},
		{Method: http.MethodPut, Path: "/api/v1/networks/{networkID}/firewall/preview", OperationID: "previewFirewallPolicy", Tag: "Firewall", Summary: "Preview effective firewall policy", Description: "Compiles candidate rules for every active node without changing signed state.", Security: admin, Permission: write, Request: openAPIType[control.FirewallPolicyInput](), Response: openAPIType[control.FirewallPolicyPreview](), ResponseStatus: http.StatusOK, ResponseSummary: "Per-node effective firewall preview.", Interactive: true},
		{Method: http.MethodPut, Path: "/api/v1/networks/{networkID}/firewall", OperationID: "updateFirewallPolicy", Tag: "Firewall", Summary: "Replace firewall policy", Description: "Atomically replaces the managed policy under an optimistic network revision.", Security: admin, Permission: write, Request: openAPIType[control.UpdateFirewallPolicyInput](), Response: openAPIType[control.FirewallPolicyDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated firewall policy document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/route-transfer", OperationID: "getRouteTransfer", Tag: "Routing", Summary: "Read routed-subnet transfer state", Description: "Returns the current certificate-first route ownership transfer and convergence evidence.", Security: admin, Permission: read, Response: openAPIType[control.NetworkRouteTransferDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Route transfer document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/route-transfer", OperationID: "startRouteTransfer", Tag: "Routing", Summary: "Start a routed-subnet transfer", Description: "Stages exact prefixes from one active owner to another while preserving the current route.", Security: admin, Permission: write, Request: openAPIType[control.StartRouteTransferInput](), Response: openAPIType[control.NetworkRouteTransferDocument](), ResponseStatus: http.StatusCreated, ResponseSummary: "Created route transfer document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/route-transfer/advance", OperationID: "advanceRouteTransfer", Tag: "Routing", Summary: "Advance a routed-subnet transfer", Description: "Promotes or completes the active transfer only after its certificate convergence gate.", Security: admin, Permission: write, Request: openAPIType[control.UpdateRouteTransferInput](), Response: openAPIType[control.NetworkRouteTransferDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Advanced route transfer document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/route-transfer/cancel", OperationID: "cancelRouteTransfer", Tag: "Routing", Summary: "Cancel a routed-subnet transfer", Description: "Cancels the active transfer, waiting for certificate cleanup when issuance has already occurred.", Security: admin, Permission: write, Request: openAPIType[control.UpdateRouteTransferInput](), Response: openAPIType[control.NetworkRouteTransferDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Cancelled route transfer document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/route-policies", OperationID: "getRoutePolicies", Tag: "Routing", Summary: "Read weighted route policies", Description: "Returns per-prefix gateway weights, MTU, metric, and convergence.", Security: admin, Permission: read, Response: openAPIType[control.NetworkRoutePoliciesDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Route-policy collection.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/route-policies", OperationID: "updateRoutePolicy", Tag: "Routing", Summary: "Update one weighted route policy", Description: "Updates owner weights and route attributes for one exact managed prefix.", Security: admin, Permission: write, Request: openAPIType[control.UpdateNetworkRoutePolicyInput](), Response: openAPIType[control.NetworkRoutePoliciesDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated route-policy collection.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/networks/{networkID}/nodes", OperationID: "listNodes", Tag: "Nodes", Summary: "List network nodes", Description: "Returns pending, active, and revoked node inventory for one network.", Security: admin, Permission: read, Response: openAPIType[[]control.Node](), ResponseStatus: http.StatusOK, ResponseSummary: "Node inventory.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/networks/{networkID}/nodes", OperationID: "createNode", Tag: "Nodes", Summary: "Create a pending node", Description: "Reserves one overlay identity and creates a one-time enrollment credential.", Security: admin, Permission: write, Request: openAPIType[control.CreateNodeInput](), Response: openAPIType[control.CreatedNode](), ResponseStatus: http.StatusCreated, ResponseSummary: "Created pending node and one-time enrollment material.", Interactive: false},
		{Method: http.MethodPut, Path: "/api/v1/nodes/{nodeID}/topology", OperationID: "updateNodeTopology", Tag: "Nodes", Summary: "Update node placement metadata", Description: "Updates site, failure-domain, and public endpoint metadata without changing certificate identity.", Security: admin, Permission: write, Request: openAPIType[control.UpdateNodeTopologyInput](), Response: openAPIType[control.Node](), ResponseStatus: http.StatusOK, ResponseSummary: "Updated node.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/enrollment/reissue", OperationID: "reissueNodeEnrollment", Tag: "Nodes", Summary: "Reissue pending enrollment", Description: "Invalidates prior enrollment tokens and returns one replacement for a still-pending node.", Security: admin, Permission: write, Response: openAPIType[control.ReissuedEnrollment](), ResponseStatus: http.StatusOK, ResponseSummary: "Replacement one-time enrollment.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/enrollment/cancel", OperationID: "cancelNodeEnrollment", Tag: "Nodes", Summary: "Cancel pending enrollment", Description: "Atomically removes a never-enrolled node and releases its reservations.", Security: admin, Permission: write, Request: openAPIType[control.CancelPendingNodeInput](), Response: openAPIType[control.CancelledPendingNode](), ResponseStatus: http.StatusOK, ResponseSummary: "Pending-node cancellation receipt.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/agent-recovery", OperationID: "issueAgentRecovery", Tag: "Nodes", Summary: "Issue one agent-recovery credential", Description: "Creates a bounded one-time recovery credential for an active identity whose private key remains trusted.", Security: admin, Permission: security, Response: openAPIType[control.IssuedAgentRecovery](), ResponseStatus: http.StatusCreated, ResponseSummary: "One-time agent-recovery material.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/replace", OperationID: "replaceNodeIdentity", Tag: "Node security", Summary: "Replace a lost node identity", Description: "Revokes the old identity and creates one pending replacement carrying its lifecycle metadata.", Security: admin, Permission: security, Request: openAPIType[control.ReplaceNodeInput](), Response: openAPIType[control.ReplacedNode](), ResponseStatus: http.StatusCreated, ResponseSummary: "Revoked source and pending replacement.", Interactive: false},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/revoke", OperationID: "revokeNodeLegacy", Tag: "Node security", Summary: "Revoke a node using the legacy endpoint", Description: "Immediately revokes the node but lacks the explicit confirmation and idempotent receipt contract. New clients should use /revocation.", Security: admin, Permission: security, Response: openAPIType[control.Node](), ResponseStatus: http.StatusOK, ResponseSummary: "Revoked node.", Interactive: false, Deprecated: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/revocation", OperationID: "revokeNode", Tag: "Node security", Summary: "Permanently revoke a node", Description: "Performs an exact-name-, revision-, and idempotency-bound trust cutoff, invalidates credentials, and blocklists every applicable certificate.", Security: admin, Permission: security, Request: openAPIType[control.RevokeNodeInput](), Response: openAPIType[control.RevokedNodeReceipt](), ResponseStatus: http.StatusOK, ResponseSummary: "Durable revocation receipt.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/certificate/rotate", OperationID: "rotateNodeCertificate", Tag: "Node security", Summary: "Rotate a node certificate", Description: "Issues a same-key replacement, blocklists the old certificate through expiry, and returns an idempotent receipt.", Security: admin, Permission: security, Request: openAPIType[control.RotateNodeCertificateInput](), Response: openAPIType[control.RotatedNodeCertificate](), ResponseStatus: http.StatusOK, ResponseSummary: "Certificate-rotation receipt.", Interactive: true},
		{Method: http.MethodPut, Path: "/api/v1/nodes/{nodeID}/groups", OperationID: "updateNodeGroups", Tag: "Node security", Summary: "Replace certificate-bound groups", Description: "Issues a same-key certificate with the new groups and blocklists the previous certificate.", Security: admin, Permission: security, Request: openAPIType[control.UpdateNodeGroupsInput](), Response: openAPIType[control.UpdatedNodeGroups](), ResponseStatus: http.StatusOK, ResponseSummary: "Group-update and certificate-rotation receipt.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/archive", OperationID: "archiveRevokedNode", Tag: "Node security", Summary: "Archive a revoked node", Description: "Removes expired issuance and blocklist history only after the complete certificate authority plus safety margin has ended.", Security: admin, Permission: security, Request: openAPIType[control.ArchiveNodeInput](), Response: openAPIType[openAPIArchivedNodeResponse](), ResponseStatus: http.StatusOK, ResponseSummary: "Revoked-node archival receipt.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/nodes/{nodeID}/route-profile", OperationID: "getNodeRouteProfile", Tag: "Routing", Summary: "Read a node route-profile edit", Description: "Returns the certificate-first routed-subnet membership edit for one node.", Security: admin, Permission: read, Response: openAPIType[control.NodeRouteProfileEditDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Node route-profile document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/route-profile", OperationID: "startNodeRouteProfile", Tag: "Routing", Summary: "Start a node route-profile edit", Description: "Stages an exact desired routed-subnet set and waits for certificate convergence.", Security: admin, Permission: write, Request: openAPIType[control.StartRouteProfileEditInput](), Response: openAPIType[control.NodeRouteProfileEditDocument](), ResponseStatus: http.StatusCreated, ResponseSummary: "Created node route-profile document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/route-profile/advance", OperationID: "advanceNodeRouteProfile", Tag: "Routing", Summary: "Advance a node route-profile edit", Description: "Commits or completes the edit after its exact certificate convergence gate.", Security: admin, Permission: write, Request: openAPIType[control.UpdateRouteProfileEditInput](), Response: openAPIType[control.NodeRouteProfileEditDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Advanced node route-profile document.", Interactive: true},
		{Method: http.MethodPost, Path: "/api/v1/nodes/{nodeID}/route-profile/cancel", OperationID: "cancelNodeRouteProfile", Tag: "Routing", Summary: "Cancel a node route-profile edit", Description: "Cancels the edit, waiting for certificate cleanup when needed.", Security: admin, Permission: write, Request: openAPIType[control.UpdateRouteProfileEditInput](), Response: openAPIType[control.NodeRouteProfileEditDocument](), ResponseStatus: http.StatusOK, ResponseSummary: "Cancelled node route-profile document.", Interactive: true},
		{Method: http.MethodGet, Path: "/api/v1/audit", OperationID: "listAuditEvents", Tag: "Audit", Summary: "Read merged audit activity", Description: "Returns the newest control and identity events with actor attribution and no secret material.", Security: admin, Permission: auditRead, Response: openAPIType[[]openAPIAuditResponseEvent](), ResponseStatus: http.StatusOK, ResponseSummary: "Newest audit events.", Interactive: true},
	}
}

type openAPISchemaBuilder struct {
	schemas   map[string]any
	names     map[reflect.Type]string
	nameTypes map[string]reflect.Type
}

func newOpenAPISchemaBuilder() *openAPISchemaBuilder {
	return &openAPISchemaBuilder{
		schemas:   make(map[string]any),
		names:     make(map[reflect.Type]string),
		nameTypes: make(map[string]reflect.Type),
	}
}

func (b *openAPISchemaBuilder) schemaFor(value reflect.Type) map[string]any {
	if value == nil {
		return nil
	}
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch value.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
		return map[string]any{"type": "integer", "format": "int32"}
	case reflect.Int64:
		return map[string]any{"type": "integer", "format": "int64"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return map[string]any{"type": "integer", "format": "int32", "minimum": 0}
	case reflect.Uint64:
		return map[string]any{"type": "integer", "format": "int64", "minimum": 0}
	case reflect.Float32:
		return map[string]any{"type": "number", "format": "float"}
	case reflect.Float64:
		return map[string]any{"type": "number", "format": "double"}
	case reflect.Array, reflect.Slice:
		return map[string]any{"type": "array", "items": b.schemaFor(value.Elem())}
	case reflect.Map:
		additional := map[string]any{}
		if value.Elem().Kind() != reflect.Interface {
			additional = b.schemaFor(value.Elem())
		}
		return map[string]any{"type": "object", "additionalProperties": additional}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Struct:
		name := b.nameFor(value)
		if _, exists := b.schemas[name]; !exists {
			// Install a placeholder before traversing fields so recursive types
			// resolve to a stable reference instead of recursing indefinitely.
			b.schemas[name] = map[string]any{"type": "object"}
			b.schemas[name] = b.objectSchema(value)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}
	default:
		return map[string]any{}
	}
}

func (b *openAPISchemaBuilder) nameFor(value reflect.Type) string {
	if name, exists := b.names[value]; exists {
		return name
	}
	name := value.Name()
	if strings.HasPrefix(name, "openAPI") {
		name = strings.TrimPrefix(name, "openAPI")
	}
	if name == "" {
		name = "AnonymousObject"
	}
	candidate := name
	if prior, exists := b.nameTypes[candidate]; exists && prior != value {
		pkg := value.PkgPath()
		if slash := strings.LastIndexByte(pkg, '/'); slash >= 0 {
			pkg = pkg[slash+1:]
		}
		candidate = strings.ToUpper(pkg[:1]) + pkg[1:] + name
	}
	for suffix := 2; ; suffix++ {
		prior, exists := b.nameTypes[candidate]
		if !exists || prior == value {
			break
		}
		candidate = name + strconv.Itoa(suffix)
	}
	b.names[value] = candidate
	b.nameTypes[candidate] = value
	return candidate
}

func (b *openAPISchemaBuilder) objectSchema(value reflect.Type) map[string]any {
	properties := make(map[string]any)
	required := make([]string, 0)
	b.collectFields(value, properties, &required)
	sort.Strings(required)
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func (b *openAPISchemaBuilder) collectFields(value reflect.Type, properties map[string]any, required *[]string) {
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct && embedded != reflect.TypeOf(time.Time{}) {
				b.collectFields(embedded, properties, required)
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		omitempty := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				omitempty = true
			}
		}
		properties[name] = b.schemaFor(field.Type)
		if !omitempty {
			*required = append(*required, name)
		}
	}
}

func openAPIExample(value reflect.Type) any {
	return openAPIExampleValue(value, "", 0, make(map[reflect.Type]bool))
}

func openAPIExampleValue(value reflect.Type, fieldName string, depth int, visiting map[reflect.Type]bool) any {
	if value == nil {
		return map[string]any{}
	}
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value == reflect.TypeOf(time.Time{}) {
		return "2026-07-23T12:00:00Z"
	}
	switch value.Kind() {
	case reflect.Bool:
		return false
	case reflect.String:
		return openAPIStringExample(fieldName)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if strings.Contains(strings.ToLower(fieldName), "revision") || strings.Contains(strings.ToLower(fieldName), "sequence") {
			return 1
		}
		return 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return 0
	case reflect.Float32, reflect.Float64:
		return 0
	case reflect.Array, reflect.Slice:
		return []any{openAPIExampleValue(value.Elem(), fieldName, depth+1, visiting)}
	case reflect.Map:
		return map[string]any{"example": openAPIExampleValue(value.Elem(), "value", depth+1, visiting)}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Struct:
		if visiting[value] {
			return map[string]any{}
		}
		visiting[value] = true
		defer delete(visiting, value)
		result := make(map[string]any)
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tag := field.Tag.Get("json")
			parts := strings.Split(tag, ",")
			name := parts[0]
			if name == "-" {
				continue
			}
			if field.Anonymous && name == "" {
				embedded := field.Type
				for embedded.Kind() == reflect.Pointer {
					embedded = embedded.Elem()
				}
				if embedded.Kind() == reflect.Struct && embedded != reflect.TypeOf(time.Time{}) {
					if example, ok := openAPIExampleValue(embedded, fieldName, depth+1, visiting).(map[string]any); ok {
						for key, item := range example {
							result[key] = item
						}
					}
					continue
				}
			}
			if name == "" {
				name = field.Name
			}
			result[name] = openAPIExampleValue(field.Type, name, depth+1, visiting)
		}
		return result
	default:
		return nil
	}
}

func openAPIStringExample(fieldName string) string {
	name := strings.ToLower(fieldName)
	switch {
	case name == "network_id":
		return "net_example"
	case name == "node_id":
		return "node_example"
	case name == "session_id":
		return "session_example"
	case name == "code_id":
		return "code_example"
	case name == "id":
		return "example_id"
	case strings.Contains(name, "cidr") || strings.Contains(name, "subnet") || strings.Contains(name, "prefix"):
		return "10.80.0.0/24"
	case name == "ip" || strings.HasSuffix(name, "_ip"):
		return "10.80.0.10"
	case strings.Contains(name, "url"):
		return "https://mesh.example.com/example"
	case strings.Contains(name, "public_key"):
		return "<node-public-key>"
	case strings.Contains(name, "private_key"):
		return "<redacted-private-key>"
	case strings.Contains(name, "token") || strings.Contains(name, "secret") || strings.Contains(name, "password") || strings.Contains(name, "code") || strings.Contains(name, "hash"):
		return "<redacted>"
	case strings.Contains(name, "fingerprint") || strings.Contains(name, "digest") || strings.Contains(name, "signature"):
		return "<example-digest>"
	case strings.Contains(name, "email"):
		return "operator@example.com"
	case name == "name" || strings.HasSuffix(name, "_name"):
		return "example"
	case name == "status" || strings.HasSuffix(name, "_status"):
		return "active"
	case name == "role":
		return "admin"
	case name == "permission":
		return "networks.read"
	case name == "action":
		return "start"
	case name == "method":
		return "GET"
	case name == "protocol":
		return "tcp"
	case name == "proto":
		return "tcp"
	case name == "port" || strings.HasSuffix(name, "_port"):
		return "443"
	case strings.Contains(name, "duration") || strings.Contains(name, "ttl"):
		return "24h"
	case strings.Contains(name, "error") || strings.Contains(name, "reason"):
		return "example reason"
	default:
		return "example"
	}
}

func openAPIRequestExample(operation openAPIOperation) any {
	overrides := map[string]any{
		"startOIDCLogin":          map[string]any{"return_path": "/"},
		"loginWithLegacyToken":    map[string]any{"token": "<administrator-token>"},
		"loginWithBreakGlassCode": map[string]any{"code": "<one-time-break-glass-code>"},
		"registerBreakGlassCode": map[string]any{
			"code":       "<new-one-time-break-glass-code>",
			"expires_at": "2026-07-24T12:00:00Z",
		},
		"preflightEnrollment": map[string]any{"token": "<one-time-enrollment-token>"},
		"enrollNode": map[string]any{
			"token":            "<one-time-enrollment-token>",
			"public_key":       "<node-public-key>",
			"agent_token_hash": "<agent-token-hash>",
		},
		"createNetwork": map[string]any{
			"name":                  "example-network",
			"cidr":                  "10.80.0.0/24",
			"certificate_ttl_hours": 24,
		},
	}
	if example, exists := overrides[operation.OperationID]; exists {
		return example
	}
	return openAPIExample(operation.Request)
}

func openAPISecurity(operation openAPIOperation) []any {
	switch operation.Security {
	case "admin":
		return []any{
			map[string]any{"cookieSession": []any{}},
			map[string]any{"legacyAdminBearer": []any{}},
		}
	case "agent":
		return []any{map[string]any{"agentBearer": []any{}}}
	default:
		return []any{}
	}
}

func openAPIErrorResponse(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema":  map[string]any{"$ref": "#/components/schemas/Error"},
				"example": map[string]any{"error": strings.ToLower(strings.TrimSuffix(description, "."))},
			},
		},
	}
}

func openAPIPathParameters(path string) []any {
	var parameters []any
	for offset := 0; ; {
		start := strings.IndexByte(path[offset:], '{')
		if start < 0 {
			break
		}
		start += offset
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			break
		}
		end += start
		name := path[start+1 : end]
		description := "Resource identifier."
		switch name {
		case "networkID":
			description = "Network identifier."
		case "nodeID":
			description = "Node identifier."
		case "sessionID":
			description = "Browser-session identifier."
		case "codeID":
			description = "Break-glass code identifier."
		}
		parameters = append(parameters, map[string]any{
			"name": name, "in": "path", "required": true,
			"description": description,
			"schema":      map[string]any{"type": "string", "minLength": 1},
			"example":     openAPIStringExample(strings.ReplaceAll(name, "ID", "_id")),
		})
		offset = end + 1
	}
	return parameters
}

func openAPICurlSample(operation openAPIOperation, requestExample any) string {
	path := operation.Path
	replacements := map[string]string{
		"{networkID}": "net_example",
		"{nodeID}":    "node_example",
		"{sessionID}": "session_example",
		"{codeID}":    "code_example",
	}
	for source, target := range replacements {
		path = strings.ReplaceAll(path, source, target)
	}
	if len(operation.Query) > 0 {
		values := make([]string, 0, len(operation.Query))
		for _, parameter := range operation.Query {
			if parameter.Required {
				values = append(values, parameter.Name+"=<"+parameter.Name+">")
			}
		}
		if len(values) > 0 {
			path += "?" + strings.Join(values, "&")
		}
	}
	parts := []string{"curl --fail-with-body", "-X " + operation.Method}
	switch operation.Security {
	case "admin":
		parts = append(parts, "--cookie '__Host-mesh_session=<browser-session-value>'")
		if operation.Method != http.MethodGet && operation.Method != http.MethodHead {
			parts = append(parts,
				"-H 'Origin: https://mesh.example.com'",
				"-H 'X-Mesh-CSRF: <csrf-cookie-value>'",
			)
		}
	case "agent":
		parts = append(parts, "-H 'Authorization: Bearer <agent-token>'")
	case "oidc", "recovery":
		if operation.Method != http.MethodGet && operation.Method != http.MethodHead {
			parts = append(parts, "-H 'Origin: https://mesh.example.com'")
		}
	}
	if operation.Request != nil {
		raw, _ := json.Marshal(requestExample)
		parts = append(parts, "-H 'Content-Type: application/json'", "-d '"+string(raw)+"'")
	}
	parts = append(parts, "'https://mesh.example.com"+path+"'")
	return strings.Join(parts, " \\\n  ")
}

func buildOpenAPIDocument() (map[string]any, error) {
	builder := newOpenAPISchemaBuilder()
	operations := openAPIOperations()
	paths := make(map[string]any)
	tagSet := make(map[string]bool)
	operationIDs := make(map[string]bool)

	for _, operation := range operations {
		method := strings.ToLower(operation.Method)
		if operationIDs[operation.OperationID] {
			return nil, fmt.Errorf("duplicate OpenAPI operation id %q", operation.OperationID)
		}
		operationIDs[operation.OperationID] = true
		tagSet[operation.Tag] = true
		requestExample := openAPIRequestExample(operation)
		success := map[string]any{"description": operation.ResponseSummary}
		if operation.Response != nil && operation.ResponseStatus != http.StatusNoContent && operation.Method != http.MethodHead {
			success["content"] = map[string]any{
				"application/json": map[string]any{
					"schema":  builder.schemaFor(operation.Response),
					"example": openAPIExample(operation.Response),
				},
			}
		}
		responses := map[string]any{
			strconv.Itoa(operation.ResponseStatus): success,
			"400":                                  map[string]any{"$ref": "#/components/responses/BadRequest"},
			"401":                                  map[string]any{"$ref": "#/components/responses/Unauthorized"},
			"403":                                  map[string]any{"$ref": "#/components/responses/Forbidden"},
			"404":                                  map[string]any{"$ref": "#/components/responses/NotFound"},
			"409":                                  map[string]any{"$ref": "#/components/responses/Conflict"},
			"429":                                  map[string]any{"$ref": "#/components/responses/RateLimited"},
			"500":                                  map[string]any{"$ref": "#/components/responses/InternalError"},
			"503":                                  map[string]any{"$ref": "#/components/responses/Unavailable"},
		}
		if operation.OperationID == "getAgentConfig" {
			responses["304"] = map[string]any{"description": "The supplied configuration signature is current."}
		}
		if operation.ResponseStatus == http.StatusSeeOther {
			success["headers"] = map[string]any{
				"Location": map[string]any{
					"description": "Bound same-origin return path.",
					"schema":      map[string]any{"type": "string"},
				},
			}
		}
		parameters := openAPIPathParameters(operation.Path)
		for _, query := range operation.Query {
			parameters = append(parameters, map[string]any{
				"name": query.Name, "in": "query", "required": query.Required,
				"description": query.Description, "schema": query.Schema,
			})
		}
		item := map[string]any{
			"operationId": operation.OperationID,
			"tags":        []string{operation.Tag},
			"summary":     operation.Summary,
			"description": operation.Description,
			"security":    openAPISecurity(operation),
			"responses":   responses,
			"deprecated":  operation.Deprecated,
			"x-availability": func() string {
				if operation.Optional == "" {
					return "always"
				}
				return "when " + operation.Optional + " is enabled"
			}(),
			"x-interactive": operation.Interactive,
			"x-codeSamples": []any{
				map[string]any{
					"lang": "Shell", "label": "curl",
					"source": openAPICurlSample(operation, requestExample),
				},
			},
		}
		if operation.Permission != "" {
			item["x-required-permission"] = string(operation.Permission)
		}
		if len(parameters) > 0 {
			item["parameters"] = parameters
		}
		if operation.Request != nil {
			item["requestBody"] = map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema":  builder.schemaFor(operation.Request),
						"example": requestExample,
					},
				},
			}
		}
		pathItem, _ := paths[operation.Path].(map[string]any)
		if pathItem == nil {
			pathItem = make(map[string]any)
			paths[operation.Path] = pathItem
		}
		pathItem[method] = item
	}

	// Error is intentionally defined independently of Go reflection: every
	// HTTP error boundary exposes exactly one generic, non-secret message.
	builder.schemas["Error"] = map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"error"},
		"properties": map[string]any{
			"error": map[string]any{
				"type":        "string",
				"description": "Generic, non-secret error message suitable for an operator.",
			},
		},
		"example": map[string]any{"error": "request is invalid"},
	}
	tagNames := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tagNames = append(tagNames, tag)
	}
	sort.Strings(tagNames)
	tags := make([]any, 0, len(tagNames))
	for _, tag := range tagNames {
		tags = append(tags, map[string]any{
			"name":        tag,
			"description": "Mesh " + strings.ToLower(tag) + " operations.",
		})
	}

	return map[string]any{
		"openapi":           openAPIVersion,
		"jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
		"info": map[string]any{
			"title":   "Mesh control-plane API",
			"version": openAPIContractVersion,
			"description": "The canonical contract for Mesh browser, administrator, installer, and managed-agent endpoints. " +
				"Browser sessions use the mesh_session cookie (or __Host-mesh_session over HTTPS). Unsafe cookie-authenticated requests must send the readable mesh_csrf or __Host-mesh_csrf cookie value in X-Mesh-CSRF and must originate from the configured exact public origin. " +
				"Configured legacy administrator bearer authentication is CSRF-exempt. Managed-agent bearer credentials are device-scoped. Examples contain placeholders only; never paste production credentials into documentation tools.",
		},
		"servers": []any{
			map[string]any{"url": "/", "description": "The same Mesh control-plane origin that served this contract."},
		},
		"tags":  tags,
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"cookieSession": map[string]any{
					"type": "apiKey", "in": "cookie", "name": "mesh_session",
					"description": "Hardened browser session. HTTPS deployments use __Host-mesh_session. Unsafe methods also require the matching CSRF cookie value in X-Mesh-CSRF plus the exact configured Origin.",
				},
				"legacyAdminBearer": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "Optional deployment administrator credential. Disabled unless explicitly configured; do not place it in a browser or persist it in documentation tooling.",
				},
				"agentBearer": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "Device-scoped managed-agent credential. Never paste it into the interactive browser reference.",
				},
			},
			"schemas": builder.schemas,
			"responses": map[string]any{
				"BadRequest":   openAPIErrorResponse("The request is invalid."),
				"Unauthorized": openAPIErrorResponse("Authentication is required or invalid."),
				"Forbidden":    openAPIErrorResponse("The principal, origin, content type, or CSRF proof is not authorized."),
				"NotFound":     openAPIErrorResponse("The resource does not exist."),
				"Conflict":     openAPIErrorResponse("The requested transition conflicts with current state or revision."),
				"RateLimited":  openAPIErrorResponse("The bounded endpoint is temporarily rate limited."),
				"InternalError": openAPIErrorResponse(
					"The request failed without exposing internal details.",
				),
				"Unavailable": openAPIErrorResponse("A required dependency or bounded worker is temporarily unavailable."),
			},
		},
	}, nil
}

var (
	openAPIOnce  sync.Once
	openAPIBytes []byte
	openAPIErr   error
)

// CanonicalOpenAPI returns the deterministic OpenAPI 3.1 contract served by
// the application and checked into docs/openapi.json by the documentation
// generator. Callers receive a copy so the cached contract cannot be mutated.
func CanonicalOpenAPI() ([]byte, error) {
	openAPIOnce.Do(func() {
		document, err := buildOpenAPIDocument()
		if err != nil {
			openAPIErr = err
			return
		}
		openAPIBytes, openAPIErr = json.MarshalIndent(document, "", "  ")
		if openAPIErr == nil {
			openAPIBytes = append(openAPIBytes, '\n')
		}
	})
	if openAPIErr != nil {
		return nil, openAPIErr
	}
	return append([]byte(nil), openAPIBytes...), nil
}

func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	document, err := CanonicalOpenAPI()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "API contract is unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/vnd.oai.openapi+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}
