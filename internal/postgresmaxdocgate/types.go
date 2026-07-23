//go:build linux && postgresmaxdocgate

// Package postgresmaxdocgate implements the test-only, bounded PostgreSQL
// maximum-valid-document mechanism. It is compiled only for the explicit
// smoke gate and is not linked into release binaries.
package postgresmaxdocgate

import "time"

const (
	ReportSchema                = "mesh-postgres-maximum-document-v1"
	MaximumControlBytes         = 64 << 20
	MaximumIdentityBytes        = 8 << 20
	MaximumApplicationRSSBytes  = 1536 << 20
	MaximumPostgresMemoryBytes  = 1 << 30
	MaximumPostgresDiskBytes    = 512 << 20
	MaximumDatabaseBytes        = 256 << 20
	MaximumWALDeltaBytes        = 256 << 20
	MaximumWorkspaceBytes       = 2 << 30
	MaximumGateDuration         = 15 * time.Minute
	MaximumApplicationOperation = 15 * time.Second
)

type FixtureMetadata struct {
	Schema    string                  `json:"schema"`
	CreatedAt time.Time               `json:"created_at"`
	Control   ControlFixtureMetadata  `json:"control"`
	Identity  IdentityFixtureMetadata `json:"identity"`
	Paths     FixturePaths            `json:"paths"`
}

type FixturePaths struct {
	ControlState  string `json:"control_state"`
	IdentityState string `json:"identity_state"`
	MasterKey     string `json:"master_key"`
	AdminToken    string `json:"admin_token"`
}

type ControlFixtureMetadata struct {
	CanonicalBytes         int    `json:"canonical_bytes"`
	ExactBytes             int    `json:"exact_bytes"`
	PaddingBytes           int    `json:"padding_bytes"`
	SHA256                 string `json:"sha256"`
	NetworkID              string `json:"network_id"`
	NetworkCount           int    `json:"network_count"`
	NetworkCIDR            string `json:"network_cidr"`
	NodeCount              int    `json:"node_count"`
	EnrollmentCount        int    `json:"enrollment_count"`
	AuditCount             int    `json:"audit_count"`
	GroupCount             int    `json:"group_count"`
	InboundRuleCount       int    `json:"inbound_rule_count"`
	OutboundRuleCount      int    `json:"outbound_rule_count"`
	FirewallConfigRevision int64  `json:"firewall_config_revision"`
}

type IdentityFixtureMetadata struct {
	CanonicalBytes        int       `json:"canonical_bytes"`
	ExactBytes            int       `json:"exact_bytes"`
	PaddingBytes          int       `json:"padding_bytes"`
	SHA256                string    `json:"sha256"`
	OIDCClaimsBytes       int       `json:"oidc_claims_bytes"`
	OIDCGroupCount        int       `json:"oidc_group_count"`
	LoginAttemptCount     int       `json:"login_attempt_count"`
	ExpiredLoginAttemptID string    `json:"expired_login_attempt_id"`
	SessionCount          int       `json:"session_count"`
	AuditCount            int       `json:"audit_count"`
	CleanupAt             time.Time `json:"cleanup_at"`
	ExpiredSessionID      string    `json:"expired_session_id"`
	RevokeSessionID       string    `json:"revoke_session_id"`
}

type GenerateOptions struct {
	OutputDirectory string
}

type VerifyOptions struct {
	DSNFile             string
	MetadataFile        string
	BackupID            string
	AllowLocalPlaintext bool
	Phase               string
}

type MutateOptions struct {
	DSNFile             string
	MetadataFile        string
	BackupID            string
	ServerURL           string
	AllowLocalPlaintext bool
}

type DocumentReport struct {
	Revision    int64  `json:"revision"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	LastWriteID string `json:"last_write_id"`
	Resources   int    `json:"resources"`
	Audit       int    `json:"audit"`
	Canonical   bool   `json:"canonical"`
}

type ControlShapeReport struct {
	Networks             int    `json:"networks"`
	NetworkID            string `json:"network_id"`
	NetworkCIDR          string `json:"network_cidr"`
	Nodes                int    `json:"nodes"`
	Enrollments          int    `json:"enrollments"`
	NodeCreatedAudits    int    `json:"node_created_audits"`
	GroupsPerNode        int    `json:"groups_per_node"`
	PendingNodes         int    `json:"pending_nodes"`
	InboundRules         int    `json:"inbound_rules"`
	OutboundRules        int    `json:"outbound_rules"`
	FirewallRevision     int64  `json:"firewall_revision"`
	FirewallUpdateAudits int    `json:"firewall_update_audits"`
}

type IdentityShapeReport struct {
	LoginAttempts           int  `json:"login_attempts"`
	ExpiredAttemptPresent   bool `json:"expired_attempt_present"`
	Sessions                int  `json:"sessions"`
	Audit                   int  `json:"audit"`
	SessionCreatedAudits    int  `json:"session_created_audits"`
	SessionRevocationAudits int  `json:"session_revocation_audits"`
	ExpiredTargetPresent    bool `json:"expired_target_present"`
	RevokeTargetPresent     bool `json:"revoke_target_present"`
	RevokeTargetRevoked     bool `json:"revoke_target_revoked"`
	RevokedSessions         int  `json:"revoked_sessions"`
}

type OperationCount struct {
	Operation string `json:"operation"`
	Count     int64  `json:"count"`
}

type DatabaseReport struct {
	Schema                  string              `json:"schema"`
	Phase                   string              `json:"phase"`
	VerifiedAt              time.Time           `json:"verified_at"`
	Control                 DocumentReport      `json:"control"`
	Identity                DocumentReport      `json:"identity"`
	ControlShape            ControlShapeReport  `json:"control_shape"`
	IdentityShape           IdentityShapeReport `json:"identity_shape"`
	ReceiptHeaders          int64               `json:"receipt_headers"`
	ReceiptDocuments        int64               `json:"receipt_documents"`
	Operations              []OperationCount    `json:"operations"`
	DatabaseBytes           int64               `json:"database_bytes"`
	WALBytes                int64               `json:"wal_bytes"`
	WALBuffersFull          int64               `json:"wal_buffers_full"`
	Deadlocks               int64               `json:"deadlocks"`
	TempBytes               int64               `json:"temp_bytes"`
	ControlReadinessMicros  int64               `json:"control_readiness_micros"`
	IdentityReadinessMicros int64               `json:"identity_readiness_micros"`
}

type MutationReport struct {
	Schema                          string         `json:"schema"`
	MutatedAt                       time.Time      `json:"mutated_at"`
	CleanupLoginAttempts            int            `json:"cleanup_login_attempts"`
	CleanupSessions                 int            `json:"cleanup_sessions"`
	CleanupRevision                 int64          `json:"cleanup_revision"`
	CleanupSHA256                   string         `json:"cleanup_sha256"`
	CleanupWriteID                  string         `json:"cleanup_write_id"`
	CleanupReceiptOperation         string         `json:"cleanup_receipt_operation"`
	CleanupReceiptBaseRevision      int64          `json:"cleanup_receipt_base_revision"`
	CleanupReceiptCommittedRevision int64          `json:"cleanup_receipt_committed_revision"`
	CleanupMicros                   int64          `json:"cleanup_micros"`
	FirewallMicros                  int64          `json:"firewall_micros"`
	RevocationMicros                int64          `json:"revocation_micros"`
	Database                        DatabaseReport `json:"database"`
}
