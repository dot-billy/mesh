package control

import "time"

// MaxManagedConfigBytes is the shared control-plane/node-agent ceiling for one
// signed Nebula configuration. It is exported so generation and bundle intake
// cannot drift onto different acceptance envelopes.
const MaxManagedConfigBytes = 4 << 20

type State struct {
	Version                 int                     `json:"version"`
	MasterKeyVerifier       string                  `json:"-"`
	AdminCredentialVerifier string                  `json:"-"`
	Networks                []Network               `json:"networks"`
	Nodes                   []Node                  `json:"nodes"`
	Enrollments             []EnrollmentToken       `json:"enrollments"`
	AgentRecoveries         []AgentRecoveryToken    `json:"agent_recoveries"`
	Issuances               []CertificateIssuance   `json:"issuances"`
	Revocations             []CertificateRevocation `json:"revocations"`
	Audit                   []AuditEvent            `json:"audit"`
}

type Network struct {
	ID                        string                  `json:"id"`
	Name                      string                  `json:"name"`
	CIDR                      string                  `json:"cidr"`
	DNSSettings               NetworkDNSSettings      `json:"dns_settings"`
	RelaySettings             NetworkRelaySettings    `json:"relay_settings"`
	CARotation                NetworkCARotation       `json:"ca_rotation"`
	FirewallRollout           NetworkFirewallRollout  `json:"firewall_rollout"`
	RouteTransfer             NetworkRouteTransfer    `json:"route_transfer"`
	RouteProfileEdit          NetworkRouteProfileEdit `json:"route_profile_edit"`
	RoutePolicies             []NetworkRoutePolicy    `json:"route_policies,omitempty"`
	FirewallPolicy            FirewallPolicy          `json:"firewall_policy"`
	ListenPort                int                     `json:"listen_port"`
	CertificateTTL            int                     `json:"certificate_ttl_hours"`
	CACertificate             string                  `json:"ca_certificate"`
	EncryptedCAKey            string                  `json:"-"`
	ConfigSigningPublicKey    string                  `json:"config_signing_public_key"`
	EncryptedConfigSigningKey string                  `json:"-"`
	ConfigRevision            int64                   `json:"config_revision"`
	ConfigUpdatedAt           time.Time               `json:"config_updated_at"`
	CreatedAt                 time.Time               `json:"created_at"`
}

// NetworkRoutePolicy binds one live routed prefix to its complete active
// gateway set and Nebula's route-specific controls. Gateway membership remains
// certificate-authorized through Node.RoutedSubnets; this record cannot invent
// or omit an owner.
type NetworkRoutePolicy struct {
	Prefix         string                      `json:"prefix"`
	Gateways       []NetworkRoutePolicyGateway `json:"gateways"`
	MTU            int                         `json:"mtu"`
	Metric         int                         `json:"metric"`
	RequestID      string                      `json:"request_id"`
	ConfigRevision int64                       `json:"config_revision"`
	UpdatedAt      time.Time                   `json:"updated_at"`
}

type NetworkRoutePolicyGateway struct {
	NodeID string `json:"node_id"`
	Weight int    `json:"weight"`
}

const (
	RouteTransferPhasePreparingTarget = "preparing_target"
	RouteTransferPhaseCleaningSource  = "cleaning_source"
	RouteTransferPhaseCleaningTarget  = "cleaning_target"
	RouteTransferPhaseCompleted       = "completed"
	RouteTransferPhaseCancelled       = "cancelled"
)

// NetworkRouteTransfer is the durable, non-secret receipt and state machine for
// moving certificate-authorized unsafe routes between two active gateways.
// Original route sets make both promotion and cancellation deterministic even
// after response loss or a process restart.
type NetworkRouteTransfer struct {
	RequestID                   string    `json:"request_id,omitempty"`
	Phase                       string    `json:"phase,omitempty"`
	SourceNodeID                string    `json:"source_node_id,omitempty"`
	TargetNodeID                string    `json:"target_node_id,omitempty"`
	RoutedSubnets               []string  `json:"routed_subnets,omitempty"`
	SourceOriginalSubnets       []string  `json:"source_original_subnets,omitempty"`
	TargetOriginalSubnets       []string  `json:"target_original_subnets,omitempty"`
	TargetCertificateGeneration int64     `json:"target_certificate_generation,omitempty"`
	SourceCertificateGeneration int64     `json:"source_certificate_generation,omitempty"`
	StartedAt                   time.Time `json:"started_at,omitempty"`
	PromotedAt                  time.Time `json:"promoted_at,omitempty"`
	FinishedAt                  time.Time `json:"finished_at,omitempty"`
}

const (
	RouteProfileEditPhasePreparingOwner         = "preparing_owner"
	RouteProfileEditPhaseCleaningOwner          = "cleaning_owner"
	RouteProfileEditPhaseCleaningCancelledOwner = "cleaning_cancelled_owner"
	RouteProfileEditPhaseCompleted              = "completed"
	RouteProfileEditPhaseCancelled              = "cancelled"
)

// NetworkRouteProfileEdit is the durable, non-secret receipt and state machine
// for replacing one active node's complete certificate-authorized routed-prefix
// set. Original and desired snapshots make promotion, cleanup, cancellation,
// and response-loss replay deterministic.
type NetworkRouteProfileEdit struct {
	RequestID                     string    `json:"request_id,omitempty"`
	Phase                         string    `json:"phase,omitempty"`
	NodeID                        string    `json:"node_id,omitempty"`
	OriginalSubnets               []string  `json:"original_subnets,omitempty"`
	DesiredSubnets                []string  `json:"desired_subnets,omitempty"`
	PreparedCertificateGeneration int64     `json:"prepared_certificate_generation,omitempty"`
	CleanupCertificateGeneration  int64     `json:"cleanup_certificate_generation,omitempty"`
	StartedAt                     time.Time `json:"started_at,omitempty"`
	PromotedAt                    time.Time `json:"promoted_at,omitempty"`
	FinishedAt                    time.Time `json:"finished_at,omitempty"`
}

type Node struct {
	ID        string `json:"id"`
	NetworkID string `json:"network_id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	// RoutedSubnets are non-overlay IPv4 prefixes this node is authorized to
	// forward for. They are fixed during ordinary node edits because the exact
	// prefixes are embedded in the Nebula certificate. An exact prefix may have
	// multiple same-network active owners for weighted ECMP; all other overlaps
	// remain invalid. The route-transfer and route-profile-edit state machines are
	// the only active-node paths that stage and prove replacement certificates
	// before changing durable ownership.
	RoutedSubnets []string `json:"routed_subnets,omitempty"`
	// Site and FailureDomain are operator-defined placement metadata. They are
	// deliberately separate from Groups: Nebula embeds Groups in host
	// certificates and uses them for firewall authorization, while placement
	// labels only drive inventory and readiness policy.
	Site                           string     `json:"site,omitempty"`
	FailureDomain                  string     `json:"failure_domain,omitempty"`
	Groups                         []string   `json:"groups"`
	Role                           string     `json:"role"`
	PublicEndpoint                 string     `json:"public_endpoint,omitempty"`
	Status                         string     `json:"status"`
	Certificate                    string     `json:"certificate,omitempty"`
	CertificateFingerprint         string     `json:"certificate_fingerprint,omitempty"`
	CertificateAuthoritySHA256     string     `json:"certificate_authority_sha256,omitempty"`
	CertificateExpiresAt           *time.Time `json:"certificate_expires_at,omitempty"`
	CertificateRenewAfter          *time.Time `json:"certificate_renew_after,omitempty"`
	CertificateGeneration          int64      `json:"certificate_generation"`
	AppliedConfigRevision          int64      `json:"applied_config_revision"`
	AppliedCertificateGeneration   int64      `json:"applied_certificate_generation"`
	AppliedConfigSHA256            string     `json:"applied_config_sha256,omitempty"`
	ReportedCertificateFingerprint string     `json:"reported_certificate_fingerprint,omitempty"`
	NebulaRunning                  bool       `json:"nebula_running"`
	NativeDNSActive                bool       `json:"native_dns_active,omitempty"`
	AgentVersion                   string     `json:"agent_version,omitempty"`
	NebulaVersion                  string     `json:"nebula_version,omitempty"`
	AgentStatus                    string     `json:"agent_status,omitempty"`
	AgentBootID                    string     `json:"agent_boot_id,omitempty"`
	HeartbeatSequence              int64      `json:"heartbeat_sequence"`
	LastError                      string     `json:"last_error,omitempty"`
	LastSeenAt                     *time.Time `json:"last_seen_at,omitempty"`
	AgentTokenHash                 string     `json:"-"`
	PreviousAgentTokenHash         string     `json:"-"`
	PreviousAgentTokenExpiresAt    *time.Time `json:"-"`
	AgentCredentialExpiresAt       *time.Time `json:"agent_credential_expires_at,omitempty"`
	AgentCredentialLastUsedAt      *time.Time `json:"agent_credential_last_used_at,omitempty"`
	AgentCredentialGeneration      int64      `json:"agent_credential_generation"`
	PublicKeyHash                  string     `json:"-"`
	RenewalClaimID                 string     `json:"-"`
	RenewalClaimedAt               *time.Time `json:"-"`
	LastRenewedAt                  *time.Time `json:"last_renewed_at,omitempty"`
	CreatedAt                      time.Time  `json:"created_at"`
	EnrolledAt                     *time.Time `json:"enrolled_at,omitempty"`
	RevokedAt                      *time.Time `json:"revoked_at,omitempty"`
}

type EnrollmentToken struct {
	ID           string     `json:"id"`
	NodeID       string     `json:"node_id"`
	TokenHash    string     `json:"token_hash"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	ClaimID      string     `json:"claim_id,omitempty"`
	ClaimedAt    *time.Time `json:"claimed_at,omitempty"`
	ClaimKeyHash string     `json:"claim_key_hash,omitempty"`
}

// AgentRecoveryToken is a separately scoped, one-time credential for restoring
// an enrolled node's agent bearer without replacing its Nebula identity. Only
// the token hash is persisted. ClaimKeyHash binds both the existing public key
// and the proposed new agent-token hash so an ambiguous response can be retried
// idempotently without permitting either value to change.
type AgentRecoveryToken struct {
	ID                          string               `json:"id"`
	NodeID                      string               `json:"node_id"`
	TokenHash                   string               `json:"token_hash"`
	CreatedAt                   time.Time            `json:"created_at"`
	ExpiresAt                   time.Time            `json:"expires_at"`
	UsedAt                      *time.Time           `json:"used_at,omitempty"`
	ClaimID                     string               `json:"claim_id,omitempty"`
	ClaimedAt                   *time.Time           `json:"claimed_at,omitempty"`
	ClaimKeyHash                string               `json:"claim_key_hash,omitempty"`
	ClaimedCredentialGeneration int64                `json:"claimed_credential_generation,omitempty"`
	CredentialGeneration        int64                `json:"credential_generation,omitempty"`
	CredentialExpiresAt         *time.Time           `json:"credential_expires_at,omitempty"`
	Result                      *AgentRecoveryBundle `json:"result,omitempty"`
}

type CertificateRevocation struct {
	Fingerprint string     `json:"fingerprint"`
	NodeID      string     `json:"node_id"`
	NetworkID   string     `json:"network_id"`
	Reason      string     `json:"reason"`
	At          time.Time  `json:"at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type CertificateIssuance struct {
	Fingerprint string    `json:"fingerprint"`
	NodeID      string    `json:"node_id"`
	NetworkID   string    `json:"network_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type AuditEvent struct {
	ID         string         `json:"id"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id"`
	At         time.Time      `json:"at"`
	Details    map[string]any `json:"details,omitempty"`
}

type NetworkSummary struct {
	Network
	NodeCount   int `json:"node_count"`
	ActiveNodes int `json:"active_nodes"`
}

type EnrollmentBundle struct {
	NodeID                            string    `json:"node_id"`
	NetworkID                         string    `json:"network_id"`
	Node                              Node      `json:"node"`
	Certificate                       string    `json:"certificate"`
	CA                                string    `json:"ca"`
	Config                            string    `json:"config"`
	ConfigRevision                    int64     `json:"config_revision"`
	CertificateExpiresAt              time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter             time.Time `json:"certificate_renew_after"`
	AgentCredentialExpiresAt          time.Time `json:"agent_credential_expires_at"`
	AgentCredentialGeneration         int64     `json:"agent_credential_generation"`
	ConfigIssuedAt                    time.Time `json:"config_issued_at"`
	ConfigSHA256                      string    `json:"config_sha256"`
	CACertificateSHA256               string    `json:"ca_sha256"`
	PreviousCACertificateSHA256       string    `json:"previous_ca_sha256,omitempty"`
	CARotationRequired                bool      `json:"ca_rotation_required,omitempty"`
	CertificateProfileRenewalRequired bool      `json:"certificate_profile_renewal_required,omitempty"`
	CertificateFingerprint            string    `json:"certificate_fingerprint"`
	CertificateGeneration             int64     `json:"certificate_generation"`
	PublicKeyHash                     string    `json:"public_key_hash"`
	ConfigSignature                   string    `json:"config_signature"`
	ConfigSigningPublicKey            string    `json:"config_signing_public_key"`
}

type AgentConfig struct {
	NodeID                            string    `json:"node_id"`
	NetworkID                         string    `json:"network_id"`
	Revision                          int64     `json:"revision"`
	Config                            string    `json:"config"`
	IssuedAt                          time.Time `json:"issued_at"`
	SHA256                            string    `json:"sha256"`
	CACertificateSHA256               string    `json:"ca_sha256"`
	PreviousCACertificateSHA256       string    `json:"previous_ca_sha256,omitempty"`
	CARotationRequired                bool      `json:"ca_rotation_required,omitempty"`
	CertificateProfileRenewalRequired bool      `json:"certificate_profile_renewal_required,omitempty"`
	CertificateFingerprint            string    `json:"certificate_fingerprint"`
	CertificateGeneration             int64     `json:"certificate_generation"`
	PublicKeyHash                     string    `json:"public_key_hash"`
	Signature                         string    `json:"signature"`
	CertificateExpiresAt              time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter             time.Time `json:"certificate_renew_after"`
}

// ConfigSignatureMetadata is the complete identity and certificate context
// authenticated by a desired-config signature. The config digest is passed
// separately to SignConfig and VerifyConfig because it is derived from the
// exact config bytes.
type ConfigSignatureMetadata struct {
	NodeID                            string
	NetworkID                         string
	Revision                          int64
	IssuedAt                          time.Time
	CACertificateSHA256               string
	PreviousCACertificateSHA256       string
	CARotationRequired                bool
	CertificateProfileRenewalRequired bool
	CertificateFingerprint            string
	CertificateExpiresAt              time.Time
	CertificateRenewAfter             time.Time
	CertificateGeneration             int64
	PublicKeyHash                     string
}

func (a AgentConfig) SignatureMetadata() ConfigSignatureMetadata {
	return ConfigSignatureMetadata{
		NodeID:                            a.NodeID,
		NetworkID:                         a.NetworkID,
		Revision:                          a.Revision,
		IssuedAt:                          a.IssuedAt,
		CACertificateSHA256:               a.CACertificateSHA256,
		PreviousCACertificateSHA256:       a.PreviousCACertificateSHA256,
		CARotationRequired:                a.CARotationRequired,
		CertificateProfileRenewalRequired: a.CertificateProfileRenewalRequired,
		CertificateFingerprint:            a.CertificateFingerprint,
		CertificateExpiresAt:              a.CertificateExpiresAt,
		CertificateRenewAfter:             a.CertificateRenewAfter,
		CertificateGeneration:             a.CertificateGeneration,
		PublicKeyHash:                     a.PublicKeyHash,
	}
}

type HeartbeatInput struct {
	AgentVersion           string `json:"agent_version"`
	NebulaVersion          string `json:"nebula_version"`
	AppliedConfigRevision  int64  `json:"applied_config_revision"`
	CertificateGeneration  int64  `json:"certificate_generation,omitempty"`
	AppliedConfigSHA256    string `json:"applied_config_sha256"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	NebulaRunning          bool   `json:"nebula_running"`
	NativeDNSActive        bool   `json:"native_dns_active,omitempty"`
	Status                 string `json:"status"`
	LastError              string `json:"last_error,omitempty"`
	BootID                 string `json:"boot_id"`
	Sequence               int64  `json:"sequence"`
}

// ConfigApplyFailureInput is the bounded evidence a managed node may submit
// after it has authenticated the current signed desired artifact but could not
// activate it locally. The server re-derives the desired digest before this
// evidence can change rollout state.
type ConfigApplyFailureInput struct {
	AttemptedConfigRevision int64  `json:"attempted_config_revision"`
	AttemptedConfigSHA256   string `json:"attempted_config_sha256"`
	FailureCode             string `json:"failure_code"`
}

type RenewalBundle struct {
	NodeID                            string    `json:"node_id"`
	NetworkID                         string    `json:"network_id"`
	CA                                string    `json:"ca"`
	Certificate                       string    `json:"certificate"`
	CertificateExpiresAt              time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter             time.Time `json:"certificate_renew_after"`
	Config                            string    `json:"config"`
	ConfigRevision                    int64     `json:"config_revision"`
	ConfigIssuedAt                    time.Time `json:"config_issued_at"`
	ConfigSHA256                      string    `json:"config_sha256"`
	CACertificateSHA256               string    `json:"ca_sha256"`
	PreviousCACertificateSHA256       string    `json:"previous_ca_sha256,omitempty"`
	CARotationRequired                bool      `json:"ca_rotation_required,omitempty"`
	CertificateProfileRenewalRequired bool      `json:"certificate_profile_renewal_required,omitempty"`
	CertificateFingerprint            string    `json:"certificate_fingerprint"`
	CertificateGeneration             int64     `json:"certificate_generation"`
	PublicKeyHash                     string    `json:"public_key_hash"`
	ConfigSignature                   string    `json:"config_signature"`
}

func (b EnrollmentBundle) SignatureMetadata() ConfigSignatureMetadata {
	return ConfigSignatureMetadata{
		NodeID:                            b.NodeID,
		NetworkID:                         b.NetworkID,
		Revision:                          b.ConfigRevision,
		IssuedAt:                          b.ConfigIssuedAt,
		CACertificateSHA256:               b.CACertificateSHA256,
		PreviousCACertificateSHA256:       b.PreviousCACertificateSHA256,
		CARotationRequired:                b.CARotationRequired,
		CertificateProfileRenewalRequired: b.CertificateProfileRenewalRequired,
		CertificateFingerprint:            b.CertificateFingerprint,
		CertificateExpiresAt:              b.CertificateExpiresAt,
		CertificateRenewAfter:             b.CertificateRenewAfter,
		CertificateGeneration:             b.CertificateGeneration,
		PublicKeyHash:                     b.PublicKeyHash,
	}
}

func (b RenewalBundle) SignatureMetadata() ConfigSignatureMetadata {
	return ConfigSignatureMetadata{
		NodeID:                            b.NodeID,
		NetworkID:                         b.NetworkID,
		Revision:                          b.ConfigRevision,
		IssuedAt:                          b.ConfigIssuedAt,
		CACertificateSHA256:               b.CACertificateSHA256,
		PreviousCACertificateSHA256:       b.PreviousCACertificateSHA256,
		CARotationRequired:                b.CARotationRequired,
		CertificateProfileRenewalRequired: b.CertificateProfileRenewalRequired,
		CertificateFingerprint:            b.CertificateFingerprint,
		CertificateExpiresAt:              b.CertificateExpiresAt,
		CertificateRenewAfter:             b.CertificateRenewAfter,
		CertificateGeneration:             b.CertificateGeneration,
		PublicKeyHash:                     b.PublicKeyHash,
	}
}

type CredentialRotation struct {
	Generation int64     `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RecoverAgentInput is the unauthenticated agent-recovery request body. The
// high-entropy recovery token is the authorization; PublicKey binds the reset
// to the enrolled identity but is not proof of private-key possession.
type RecoverAgentInput struct {
	RecoveryToken     string `json:"recovery_token"`
	PublicKey         string `json:"public_key"`
	NewAgentTokenHash string `json:"new_agent_token_hash"`
}

// AgentRecoveryBundle contains the complete signed current bootstrap plus a
// separately signed receipt authorizing exactly one agent-credential reset.
// The receipt is required because bootstrap v3 intentionally does not include
// agent bearer metadata in its signed payload.
type AgentRecoveryBundle struct {
	EnrollmentBundle
	RecoveryReceipt RecoveryReceipt `json:"recovery_receipt"`
}

// RecoveryReceipt is signed with the network's pinned config-signing key. Its
// signature binds the new bearer hash and credential lifetime to the exact
// signed bootstrap artifact returned by RecoverAgent.
type RecoveryReceipt struct {
	NodeID                    string    `json:"node_id"`
	NetworkID                 string    `json:"network_id"`
	NewAgentTokenHash         string    `json:"new_agent_token_hash"`
	AgentCredentialGeneration int64     `json:"agent_credential_generation"`
	AgentCredentialExpiresAt  time.Time `json:"agent_credential_expires_at"`
	ConfigSHA256              string    `json:"config_sha256"`
	ConfigSignature           string    `json:"config_signature"`
	Signature                 string    `json:"signature"`
}
