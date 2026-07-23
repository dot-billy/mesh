//go:build linux && postgresmaxdocgate

package postgresmaxdocgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/postgresstore"
)

func TestMaximumDocumentLimitsCannotDrift(t *testing.T) {
	if MaximumControlBytes != postgresstore.MaxControlDocumentBytes || MaximumIdentityBytes != postgresstore.MaxIdentityDocumentBytes {
		t.Fatal("maximum-document gate limits drifted from PostgreSQL storage limits")
	}
	if MaximumControlBytes != control.MaximumDocumentControlBytes || MaximumIdentityBytes != identity.MaximumDocumentIdentityBytes {
		t.Fatal("maximum-document gate limits drifted from storage and model limits")
	}
	if identity.MaximumDocumentOIDCClaimsBytes != 64<<10 || identity.MaximumDocumentOIDCGroups != 64 {
		t.Fatal("maximum-document identity fixture drifted from its hardened OIDC intake bounds")
	}
}

func TestValidateFixtureMetadata(t *testing.T) {
	controlDigest := sha256.Sum256([]byte("control"))
	identityDigest := sha256.Sum256([]byte("identity"))
	metadata := FixtureMetadata{
		Schema: ReportSchema, CreatedAt: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		Control: ControlFixtureMetadata{
			CanonicalBytes: control.DefaultControlCanonicalMinimum, ExactBytes: MaximumControlBytes,
			PaddingBytes: MaximumControlBytes - control.DefaultControlCanonicalMinimum,
			SHA256:       hex.EncodeToString(controlDigest[:]), NetworkID: "network_1",
			NetworkCount: 1, NetworkCIDR: "10.240.0.0/16",
			NodeCount: 10, EnrollmentCount: 10, AuditCount: 21, FirewallConfigRevision: 2,
			GroupCount: 64, InboundRuleCount: 128, OutboundRuleCount: 128,
		},
		Identity: IdentityFixtureMetadata{
			CanonicalBytes: identity.DefaultIdentityCanonicalMinimum, ExactBytes: MaximumIdentityBytes,
			PaddingBytes:    MaximumIdentityBytes - identity.DefaultIdentityCanonicalMinimum,
			SHA256:          hex.EncodeToString(identityDigest[:]),
			OIDCClaimsBytes: 24 << 10, OIDCGroupCount: identity.MaximumDocumentOIDCGroups,
			LoginAttemptCount: 1, ExpiredLoginAttemptID: "login_expired",
			SessionCount: 4, AuditCount: 4,
			CleanupAt:        time.Date(2026, 7, 20, 12, 30, 0, 0, time.UTC),
			ExpiredSessionID: "session_expired", RevokeSessionID: "session_revoke",
		},
	}
	if err := validateFixtureMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Control.ExactBytes--
	if err := validateFixtureMetadata(metadata); err == nil {
		t.Fatal("non-boundary control size was accepted")
	}
}

func TestValidateLoopbackServerURL(t *testing.T) {
	if value, err := validateLoopbackServerURL("http://127.0.0.1:8443"); err != nil || value != "http://127.0.0.1:8443" {
		t.Fatalf("valid loopback URL=%q err=%v", value, err)
	}
	for _, raw := range []string{"https://127.0.0.1:8443", "http://example.test:8443", "http://127.0.0.1:8443/path", "http://127.0.0.1"} {
		if _, err := validateLoopbackServerURL(raw); err == nil {
			t.Fatalf("unsafe server URL accepted: %s", raw)
		}
	}
}

func TestSummarizeMaximumDocumentInitialShape(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x31}, 32)
	fixtureTime := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	controlFixture, err := control.BuildMaximumDocumentFixture(context.Background(), control.MaximumDocumentFixtureOptions{
		Directory: t.TempDir(), MasterKey: masterKey, AdminToken: bytes.Repeat([]byte{'A'}, 43), At: fixtureTime,
		CanonicalMinimumBytes: 1 << 20, CanonicalMaximumBytes: 1536 << 10, ExactBytes: 2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	identityFixture, err := identity.BuildMaximumDocumentFixture(context.Background(), identity.MaximumDocumentFixtureOptions{
		Sealer: box, At: fixtureTime,
		CanonicalMinimumBytes: 256 << 10, CanonicalMaximumBytes: 512 << 10, ExactBytes: 768 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongBox, err := control.NewSecretBox(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ValidateRecoverySnapshot(identityFixture.ExactBytes, wrongBox); err == nil {
		t.Fatal("maximum-document exact identity fixture accepted a wrong SecretBox")
	}
	var controlDocument decodedControlDocument
	var identityDocument decodedIdentityDocument
	if err := decodeStrictDocument(controlFixture.ExactBytes, &controlDocument); err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictDocument(identityFixture.ExactBytes, &identityDocument); err != nil {
		t.Fatal(err)
	}
	metadata := FixtureMetadata{
		Control: ControlFixtureMetadata{
			NetworkID: controlFixture.NetworkID, NetworkCIDR: controlFixture.NetworkCIDR,
			NodeCount: controlFixture.NodeCount, EnrollmentCount: controlFixture.EnrollmentCount,
			GroupCount: controlFixture.GroupCount, InboundRuleCount: controlFixture.InboundRuleCount,
			OutboundRuleCount: controlFixture.OutboundRuleCount, FirewallConfigRevision: controlFixture.FirewallConfigRevision,
		},
		Identity: IdentityFixtureMetadata{
			LoginAttemptCount: identityFixture.LoginAttemptCount, ExpiredLoginAttemptID: identityFixture.ExpiredLoginAttemptID,
			SessionCount: identityFixture.SessionCount, ExpiredSessionID: identityFixture.ExpiredSessionID,
			RevokeSessionID: identityFixture.RevokeSessionID,
		},
	}
	controlShape, err := summarizeControlShape(controlDocument, metadata, "initial")
	if err != nil {
		t.Fatal(err)
	}
	identityShape, err := summarizeIdentityShape(identityDocument, metadata, "initial")
	if err != nil {
		t.Fatal(err)
	}
	if controlShape.Nodes != controlFixture.NodeCount || controlShape.GroupsPerNode != 64 || controlShape.FirewallRevision != 2 ||
		identityShape.LoginAttempts != 1 || !identityShape.ExpiredAttemptPresent || identityShape.Sessions != identityFixture.SessionCount || !identityShape.ExpiredTargetPresent || !identityShape.RevokeTargetPresent {
		t.Fatalf("unexpected maximum-document shapes: control=%+v identity=%+v", controlShape, identityShape)
	}
}

func TestSummarizeMaximumDocumentTerminalTargets(t *testing.T) {
	groups := []string{"all"}
	for index := 0; index < 63; index++ {
		groups = append(groups, "group_"+hex.EncodeToString([]byte{byte(index)}))
	}
	raw := func(value any) json.RawMessage {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	network := decodedControlNetwork{
		ID: "network_1", CIDR: "10.240.0.0/16", ConfigRevision: 3,
		FirewallPolicy: control.FirewallPolicy{
			Mode: control.FirewallPolicyModeManaged, RendererVersion: control.FirewallRendererVersionV2,
			Inbound:  []control.FirewallRule{{Proto: "any", Port: "any", Group: "all"}},
			Outbound: []control.FirewallRule{{Proto: "any", Port: "any", Host: "any"}},
		},
	}
	controlDocument := decodedControlDocument{
		Version:  control.ControlStateVersionNativeDNS,
		Networks: []json.RawMessage{raw(network)},
		Nodes: []json.RawMessage{raw(decodedControlNode{
			ID: "node_1", NetworkID: network.ID, Groups: groups, Status: "pending",
			Site: control.UnassignedTopologyLabel, FailureDomain: control.UnassignedTopologyLabel,
		})},
		Enrollments: []json.RawMessage{raw(decodedControlEnrollment{NodeID: "node_1"})},
		Audit: []json.RawMessage{
			raw(decodedControlAudit{Action: "control.topology_schema_migrated", ResourceID: "control"}),
			raw(decodedControlAudit{Action: "node.created", ResourceID: "node_1"}),
			raw(decodedControlAudit{Action: "network.firewall_policy_updated", ResourceID: network.ID}),
			raw(decodedControlAudit{Action: "network.firewall_policy_updated", ResourceID: network.ID}),
		},
	}
	revokedAt := time.Date(2026, 7, 20, 12, 1, 0, 0, time.UTC)
	identityDocument := decodedIdentityDocument{
		Sessions: []identity.Session{{ID: "session_revoke", RevokedAt: &revokedAt, RevocationReason: "administrator revocation", Version: 2}},
		Audit: []identity.IdentityAuditEvent{
			{Type: identity.IdentityAuditSessionCreated}, {Type: identity.IdentityAuditSessionCreated},
			{Type: identity.IdentityAuditSessionRevoked, TargetSessionID: "session_revoke"},
		},
	}
	metadata := FixtureMetadata{
		Control: ControlFixtureMetadata{
			NetworkID: network.ID, NetworkCIDR: network.CIDR, NodeCount: 1, EnrollmentCount: 1,
			GroupCount: 64, FirewallConfigRevision: 2,
		},
		Identity: IdentityFixtureMetadata{
			LoginAttemptCount: 1, ExpiredLoginAttemptID: "login_expired",
			SessionCount: 2, ExpiredSessionID: "session_expired", RevokeSessionID: "session_revoke",
		},
	}
	controlShape, err := summarizeControlShape(controlDocument, metadata, "terminal")
	if err != nil {
		t.Fatal(err)
	}
	identityShape, err := summarizeIdentityShape(identityDocument, metadata, "terminal")
	if err != nil {
		t.Fatal(err)
	}
	if controlShape.FirewallRevision != 3 || controlShape.FirewallUpdateAudits != 2 || !identityShape.RevokeTargetRevoked || identityShape.ExpiredTargetPresent {
		t.Fatalf("unexpected terminal shapes: control=%+v identity=%+v", controlShape, identityShape)
	}
}

func TestValidateReceiptLedgerRequiresExactRevisionSequence(t *testing.T) {
	sourceControlHash := sha256.Sum256([]byte("source-control"))
	sourceIdentityHash := sha256.Sum256([]byte("source-identity"))
	terminalControlHash := sha256.Sum256([]byte("terminal-control"))
	cleanupIdentityHash := sha256.Sum256([]byte("cleanup-identity"))
	terminalIdentityHash := sha256.Sum256([]byte("terminal-identity"))
	runtimeTelemetryHash := sha256.Sum256([]byte("runtime-telemetry"))
	controlDocument := postgresstore.Document{Domain: postgresstore.DomainControl, Revision: 2, SHA256: terminalControlHash}
	identityDocument := postgresstore.Document{Domain: postgresstore.DomainIdentity, Revision: 3, SHA256: terminalIdentityHash}
	runtimeTelemetryDocument := postgresstore.Document{Domain: postgresstore.DomainRuntimeTelemetry, Revision: 1, SHA256: runtimeTelemetryHash}
	expected, err := buildReceiptLedgerExpectation("terminal", sourceControlHash, sourceIdentityHash, cleanupIdentityHash, controlDocument, identityDocument, runtimeTelemetryDocument)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]receiptRow, len(expected))
	for index := range expected {
		rows[index] = expected[index]
		rows[index].SHA256 = bytes.Clone(expected[index].SHA256)
	}
	if err := validateReceiptLedger(rows, expected); err != nil {
		t.Fatal(err)
	}
	rows[0].Operation = "wrong.operation"
	if err := validateReceiptLedger(rows, expected); err == nil || !strings.Contains(err.Error(), "operation") {
		t.Fatalf("invalid mutation operation was accepted: %v", err)
	}
	rows[0].Operation = expected[0].Operation
	for index := range rows {
		if rows[index].Domain == string(postgresstore.DomainIdentity) && rows[index].CommittedRevision == 2 {
			rows[index].SHA256[0] ^= 0xff
			break
		}
	}
	if err := validateReceiptLedger(rows, expected); err == nil || !strings.Contains(err.Error(), "identity revision-2 receipt hash mismatch") {
		t.Fatalf("tampered identity cleanup receipt hash was accepted: %v", err)
	}
}

func TestValidateCleanupRevisionProofBindsRevisionTwoReceipt(t *testing.T) {
	box, err := control.NewSecretBox(bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := identity.BuildMaximumDocumentFixture(context.Background(), identity.MaximumDocumentFixtureOptions{
		Sealer: box, At: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		CanonicalMinimumBytes: 256 << 10, CanonicalMaximumBytes: 512 << 10, ExactBytes: 768 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := identity.BuildMaximumDocumentCleanupExpectation(
		fixture.ExactBytes, box, fixture.ExpiredLoginAttemptID, fixture.ExpiredSessionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	document := postgresstore.Document{
		Domain: postgresstore.DomainIdentity, Revision: 2, Bytes: bytes.Clone(expectation.CanonicalBytes),
		SHA256: expectation.SHA256, LastWriteID: "cleanup-receipt",
	}
	receipt := cleanupReceiptProof{
		receiptRow: receiptRow{
			Operation: "identity.state.update", Domain: string(postgresstore.DomainIdentity),
			BaseRevision: 1, CommittedRevision: 2, SHA256: bytes.Clone(expectation.SHA256[:]),
		},
		ID: "cleanup-receipt", DocumentCount: 1,
	}
	if err := validateCleanupRevisionProof(document, receipt, box, expectation); err != nil {
		t.Fatal(err)
	}
	receipt.SHA256[0] ^= 0xff
	if err := validateCleanupRevisionProof(document, receipt, box, expectation); err == nil || !strings.Contains(err.Error(), "cleanup receipt") {
		t.Fatalf("tampered cleanup receipt hash was accepted: %v", err)
	}
}
