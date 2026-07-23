//go:build linux && postgresmaxdocgate

package postgresmaxdocgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/postgresruntime"
	"mesh/internal/postgresstore"
	"mesh/internal/runtimetelemetry"
)

var backupIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type decodedControlDocument struct {
	Version                 int               `json:"version"`
	MasterKeyVerifier       string            `json:"master_key_verifier"`
	AdminCredentialVerifier string            `json:"admin_credential_verifier"`
	Networks                []json.RawMessage `json:"networks"`
	Nodes                   []json.RawMessage `json:"nodes"`
	Enrollments             []json.RawMessage `json:"enrollments"`
	AgentRecoveries         []json.RawMessage `json:"agent_recoveries"`
	Issuances               []json.RawMessage `json:"issuances"`
	Revocations             []json.RawMessage `json:"revocations"`
	Audit                   []json.RawMessage `json:"audit"`
}

type decodedIdentityDocument struct {
	Schema          string                        `json:"schema"`
	LoginAttempts   []json.RawMessage             `json:"login_attempts"`
	Sessions        []identity.Session            `json:"sessions"`
	BreakGlassCodes []json.RawMessage             `json:"break_glass_codes"`
	Audit           []identity.IdentityAuditEvent `json:"audit"`
}

type decodedIdentityLoginAttempt struct {
	ID string `json:"id"`
}

type decodedControlNetwork struct {
	ID             string                 `json:"id"`
	CIDR           string                 `json:"cidr"`
	FirewallPolicy control.FirewallPolicy `json:"firewall_policy"`
	ConfigRevision int64                  `json:"config_revision"`
}

type decodedControlNode struct {
	ID            string   `json:"id"`
	NetworkID     string   `json:"network_id"`
	Groups        []string `json:"groups"`
	Status        string   `json:"status"`
	Site          string   `json:"site"`
	FailureDomain string   `json:"failure_domain"`
}

type decodedControlEnrollment struct {
	NodeID string `json:"node_id"`
}

type decodedControlAudit struct {
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
}

type receiptRow struct {
	Operation         string
	Domain            string
	BaseRevision      int64
	CommittedRevision int64
	SHA256            []byte
}

func VerifyDatabase(ctx context.Context, options VerifyOptions) (report DatabaseReport, resultErr error) {
	if ctx == nil {
		return DatabaseReport{}, errors.New("maximum-document verification context is required")
	}
	if options.Phase != "initial" && options.Phase != "terminal" {
		return DatabaseReport{}, errors.New("maximum-document verification phase must be initial or terminal")
	}
	if !backupIDPattern.MatchString(options.BackupID) {
		return DatabaseReport{}, errors.New("maximum-document backup ID is invalid")
	}
	metadata, err := LoadFixtureMetadata(options.MetadataFile)
	if err != nil {
		return DatabaseReport{}, err
	}
	sourceControl, err := readAuthenticatedFixtureDocument(metadata.Paths.ControlState, metadata.Control.ExactBytes, metadata.Control.SHA256)
	if err != nil {
		return DatabaseReport{}, fmt.Errorf("read authenticated maximum-document control source: %w", err)
	}
	defer clear(sourceControl)
	sourceIdentity, err := readAuthenticatedFixtureDocument(metadata.Paths.IdentityState, metadata.Identity.ExactBytes, metadata.Identity.SHA256)
	if err != nil {
		return DatabaseReport{}, fmt.Errorf("read authenticated maximum-document identity source: %w", err)
	}
	defer clear(sourceIdentity)
	masterKey, adminToken, err := loadFixtureCredentials(metadata)
	if err != nil {
		return DatabaseReport{}, err
	}
	defer clear(masterKey)
	defer func() { adminToken = "" }()
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		return DatabaseReport{}, err
	}
	if err := control.ValidateRecoverySnapshot(sourceControl, box); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate authenticated maximum-document control source: %w", err)
	}
	if err := control.ValidateRecoverySnapshotCredentials(sourceControl, masterKey, []byte(adminToken)); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate authenticated maximum-document control credentials: %w", err)
	}
	if err := identity.ValidateRecoverySnapshot(sourceIdentity, box); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate authenticated maximum-document identity source: %w", err)
	}
	runtime, err := postgresruntime.Open(ctx, postgresruntime.Options{
		DSNFile: options.DSNFile, AllowLocalPlaintext: options.AllowLocalPlaintext,
		StoreOptions: postgresstore.Options{MigrationBuild: "mesh-postgres-maximum-document-gate"},
	})
	if err != nil {
		return DatabaseReport{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, runtime.Close()) }()
	store := runtime.Store()
	readinessCtx, readinessCancel := context.WithTimeout(ctx, MaximumApplicationOperation)
	err = store.CheckImportReadiness(readinessCtx)
	readinessCancel()
	if err != nil {
		return DatabaseReport{}, err
	}
	controlDocument, identityDocument, err := store.ReadPair(ctx)
	if err != nil {
		return DatabaseReport{}, err
	}
	controlAgain, identityAgain, err := store.ReadPair(ctx)
	if err != nil {
		return DatabaseReport{}, err
	}
	if !samePostgresDocument(controlDocument, controlAgain) || !samePostgresDocument(identityDocument, identityAgain) {
		return DatabaseReport{}, errors.New("maximum-document read pair changed between authoritative reads")
	}
	runtimeTelemetryDocument, err := store.Read(ctx, postgresstore.DomainRuntimeTelemetry)
	if err != nil {
		return DatabaseReport{}, fmt.Errorf("read maximum-document runtime telemetry state: %w", err)
	}
	if runtimeTelemetryDocument.Revision != 1 {
		return DatabaseReport{}, errors.New("maximum-document runtime telemetry document revision changed")
	}
	if _, err := runtimetelemetry.DecodeState(runtimeTelemetryDocument.Bytes); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate maximum-document runtime telemetry state: %w", err)
	}
	if err := control.ValidateRecoverySnapshot(controlDocument.Bytes, box); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate PostgreSQL control recovery state: %w", err)
	}
	if err := control.ValidateRecoverySnapshotCredentials(controlDocument.Bytes, masterKey, []byte(adminToken)); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate PostgreSQL control credential binding: %w", err)
	}
	if err := identity.ValidateRecoverySnapshot(identityDocument.Bytes, box); err != nil {
		return DatabaseReport{}, fmt.Errorf("validate PostgreSQL identity recovery state: %w", err)
	}
	var cleanupExpectation identity.MaximumDocumentCleanupExpectation
	defer func() { clear(cleanupExpectation.CanonicalBytes) }()
	switch options.Phase {
	case "initial":
		if !bytes.Equal(controlDocument.Bytes, sourceControl) || !bytes.Equal(identityDocument.Bytes, sourceIdentity) {
			return DatabaseReport{}, errors.New("maximum-document initial PostgreSQL documents differ from the authenticated source bytes")
		}
	case "terminal":
		if err := control.ValidateMaximumDocumentFirewallTransition(sourceControl, controlDocument.Bytes, box, metadata.Control.NetworkID); err != nil {
			return DatabaseReport{}, fmt.Errorf("validate maximum-document control transition: %w", err)
		}
		cleanupExpectation, err = identity.ValidateMaximumDocumentTerminalTransition(
			sourceIdentity, identityDocument.Bytes, box,
			metadata.Identity.ExpiredLoginAttemptID, metadata.Identity.ExpiredSessionID, metadata.Identity.RevokeSessionID,
		)
		if err != nil {
			return DatabaseReport{}, fmt.Errorf("validate maximum-document identity transition: %w", err)
		}
	}
	canonicalControl, err := control.CanonicalizeMaximumDocumentRecoverySnapshot(controlDocument.Bytes, box)
	if err != nil {
		return DatabaseReport{}, fmt.Errorf("canonicalize PostgreSQL control recovery state: %w", err)
	}
	defer clear(canonicalControl)
	canonicalIdentity, err := identity.CanonicalizeMaximumDocumentRecoverySnapshot(identityDocument.Bytes, box)
	if err != nil {
		return DatabaseReport{}, fmt.Errorf("canonicalize PostgreSQL identity recovery state: %w", err)
	}
	defer clear(canonicalIdentity)

	controlStateStore, err := control.NewPostgresStateStore(store, control.PostgresStateStoreOptions{})
	if err != nil {
		return DatabaseReport{}, err
	}
	identityStore, err := identity.NewPostgresStore(store, box, identity.PostgresStoreOptions{})
	if err != nil {
		return DatabaseReport{}, err
	}
	defer identityStore.Close()
	started := time.Now()
	controlReadinessCtx, controlReadinessCancel := context.WithTimeout(ctx, MaximumApplicationOperation)
	err = controlStateStore.CheckReadiness(controlReadinessCtx)
	controlReadinessCancel()
	if err != nil {
		return DatabaseReport{}, err
	}
	controlReadiness := time.Since(started)
	started = time.Now()
	identityReadinessCtx, identityReadinessCancel := context.WithTimeout(ctx, MaximumApplicationOperation)
	err = identityStore.CheckReadiness(identityReadinessCtx)
	identityReadinessCancel()
	if err != nil {
		return DatabaseReport{}, err
	}
	identityReadiness := time.Since(started)
	if controlReadiness > MaximumApplicationOperation || identityReadiness > MaximumApplicationOperation {
		return DatabaseReport{}, fmt.Errorf("maximum-document readiness exceeded %s: control=%s identity=%s", MaximumApplicationOperation, controlReadiness, identityReadiness)
	}

	controlDecoded := decodedControlDocument{}
	identityDecoded := decodedIdentityDocument{}
	if err := decodeStrictDocument(controlDocument.Bytes, &controlDecoded); err != nil {
		return DatabaseReport{}, fmt.Errorf("decode maximum control document: %w", err)
	}
	if err := decodeStrictDocument(identityDocument.Bytes, &identityDecoded); err != nil {
		return DatabaseReport{}, fmt.Errorf("decode maximum identity document: %w", err)
	}
	controlShape, err := summarizeControlShape(controlDecoded, metadata, options.Phase)
	if err != nil {
		return DatabaseReport{}, err
	}
	identityShape, err := summarizeIdentityShape(identityDecoded, metadata, options.Phase)
	if err != nil {
		return DatabaseReport{}, err
	}
	report = DatabaseReport{
		Schema: ReportSchema, Phase: options.Phase, VerifiedAt: time.Now().UTC(),
		Control:                documentReport(controlDocument, len(controlDecoded.Nodes), len(controlDecoded.Audit), bytes.Equal(controlDocument.Bytes, canonicalControl)),
		Identity:               documentReport(identityDocument, len(identityDecoded.Sessions), len(identityDecoded.Audit), bytes.Equal(identityDocument.Bytes, canonicalIdentity)),
		ControlShape:           controlShape,
		IdentityShape:          identityShape,
		ControlReadinessMicros: controlReadiness.Microseconds(), IdentityReadinessMicros: identityReadiness.Microseconds(),
	}
	receiptExpectation, err := buildReceiptLedgerExpectation(
		options.Phase, sha256.Sum256(sourceControl), sha256.Sum256(sourceIdentity), cleanupExpectation.SHA256,
		controlDocument, identityDocument, runtimeTelemetryDocument,
	)
	if err != nil {
		return DatabaseReport{}, err
	}
	if err := populateDatabaseMetrics(ctx, runtime, metadata, options.BackupID, receiptExpectation, &report); err != nil {
		return DatabaseReport{}, err
	}
	if err := validateDatabasePhase(report, metadata); err != nil {
		return DatabaseReport{}, err
	}
	return report, nil
}

func samePostgresDocument(left, right postgresstore.Document) bool {
	return left.Domain == right.Domain && left.Revision == right.Revision && left.SHA256 == right.SHA256 &&
		left.LastWriteID == right.LastWriteID && left.UpdatedAt.Equal(right.UpdatedAt) && bytes.Equal(left.Bytes, right.Bytes)
}

func decodeStrictDocument(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func documentReport(document postgresstore.Document, resources, audit int, canonical bool) DocumentReport {
	return DocumentReport{
		Revision: document.Revision, Bytes: len(document.Bytes), SHA256: hex.EncodeToString(document.SHA256[:]),
		LastWriteID: document.LastWriteID, Resources: resources, Audit: audit, Canonical: canonical,
	}
}

func summarizeControlShape(document decodedControlDocument, metadata FixtureMetadata, phase string) (ControlShapeReport, error) {
	if document.Version != control.ControlStateVersionFirewallScopes {
		return ControlShapeReport{}, errors.New("maximum-document control graph is not current native-DNS schema v12")
	}
	if len(document.Networks) != 1 {
		return ControlShapeReport{}, errors.New("maximum-document control graph does not contain one network")
	}
	var network decodedControlNetwork
	if err := json.Unmarshal(document.Networks[0], &network); err != nil {
		return ControlShapeReport{}, errors.New("decode maximum-document network shape failed")
	}
	if network.ID != metadata.Control.NetworkID || network.CIDR != metadata.Control.NetworkCIDR {
		return ControlShapeReport{}, errors.New("maximum-document network identity or CIDR changed")
	}
	nodeIDs := make(map[string]int, len(document.Nodes))
	nodeAuditCounts := make(map[string]int, len(document.Nodes))
	pendingNodes := 0
	groupsPerNode := -1
	for _, raw := range document.Nodes {
		var node decodedControlNode
		if err := json.Unmarshal(raw, &node); err != nil {
			return ControlShapeReport{}, errors.New("decode maximum-document node shape failed")
		}
		if node.NetworkID != network.ID || node.Status != "pending" || node.Site != control.UnassignedTopologyLabel || node.FailureDomain != control.UnassignedTopologyLabel || len(node.Groups) != metadata.Control.GroupCount || !sort.StringsAreSorted(node.Groups) {
			return ControlShapeReport{}, errors.New("maximum-document node shape changed")
		}
		allIndex := sort.SearchStrings(node.Groups, "all")
		if allIndex >= len(node.Groups) || node.Groups[allIndex] != "all" {
			return ControlShapeReport{}, errors.New("maximum-document node lost its all group")
		}
		if _, duplicate := nodeIDs[node.ID]; duplicate {
			return ControlShapeReport{}, errors.New("maximum-document node shape contains a duplicate")
		}
		nodeIDs[node.ID] = 0
		nodeAuditCounts[node.ID] = 0
		pendingNodes++
		if groupsPerNode < 0 {
			groupsPerNode = len(node.Groups)
		}
	}
	for _, raw := range document.Enrollments {
		var enrollment decodedControlEnrollment
		if err := json.Unmarshal(raw, &enrollment); err != nil {
			return ControlShapeReport{}, errors.New("decode maximum-document enrollment shape failed")
		}
		count, found := nodeIDs[enrollment.NodeID]
		if !found {
			return ControlShapeReport{}, errors.New("maximum-document enrollment lost its node")
		}
		nodeIDs[enrollment.NodeID] = count + 1
	}
	for _, count := range nodeIDs {
		if count != 1 {
			return ControlShapeReport{}, errors.New("maximum-document node does not have exactly one enrollment")
		}
	}
	nodeCreatedAudits := 0
	firewallUpdateAudits := 0
	topologyMigrationAudits := 0
	for _, raw := range document.Audit {
		var event decodedControlAudit
		if err := json.Unmarshal(raw, &event); err != nil {
			return ControlShapeReport{}, errors.New("decode maximum-document control audit shape failed")
		}
		switch event.Action {
		case "node.created":
			if _, found := nodeIDs[event.ResourceID]; !found {
				return ControlShapeReport{}, errors.New("maximum-document node-created audit lost its node")
			}
			nodeAuditCounts[event.ResourceID]++
			nodeCreatedAudits++
		case "network.firewall_policy_updated":
			if event.ResourceID != network.ID {
				return ControlShapeReport{}, errors.New("maximum-document firewall audit lost its network")
			}
			firewallUpdateAudits++
		case "control.topology_schema_migrated":
			if event.ResourceID != "control" {
				return ControlShapeReport{}, errors.New("maximum-document topology migration audit lost its control resource")
			}
			topologyMigrationAudits++
		}
	}
	if topologyMigrationAudits != 1 {
		return ControlShapeReport{}, errors.New("maximum-document control graph does not have exactly one topology migration audit")
	}
	for _, count := range nodeAuditCounts {
		if count != 1 {
			return ControlShapeReport{}, errors.New("maximum-document node does not have exactly one node-created audit")
		}
	}
	shape := ControlShapeReport{
		Networks: len(document.Networks), NetworkID: network.ID, NetworkCIDR: network.CIDR,
		Nodes: len(document.Nodes), Enrollments: len(document.Enrollments), NodeCreatedAudits: nodeCreatedAudits,
		GroupsPerNode: groupsPerNode, PendingNodes: pendingNodes,
		InboundRules: len(network.FirewallPolicy.Inbound), OutboundRules: len(network.FirewallPolicy.Outbound),
		FirewallRevision: network.ConfigRevision, FirewallUpdateAudits: firewallUpdateAudits,
	}
	if shape.Nodes != metadata.Control.NodeCount || shape.Enrollments != metadata.Control.EnrollmentCount ||
		shape.NodeCreatedAudits != metadata.Control.NodeCount || shape.PendingNodes != metadata.Control.NodeCount || shape.GroupsPerNode != metadata.Control.GroupCount {
		return ControlShapeReport{}, errors.New("maximum-document control resource cardinality changed")
	}
	switch phase {
	case "initial":
		if shape.InboundRules != metadata.Control.InboundRuleCount || shape.OutboundRules != metadata.Control.OutboundRuleCount || shape.FirewallRevision != metadata.Control.FirewallConfigRevision || shape.FirewallUpdateAudits != 1 {
			return ControlShapeReport{}, errors.New("maximum-document initial firewall shape changed")
		}
	case "terminal":
		if shape.InboundRules != 1 || shape.OutboundRules != 1 || shape.FirewallRevision != metadata.Control.FirewallConfigRevision+1 || shape.FirewallUpdateAudits != 2 ||
			network.FirewallPolicy.Inbound[0] != (control.FirewallRule{Proto: "any", Port: "any", Group: "all"}) ||
			network.FirewallPolicy.Outbound[0] != (control.FirewallRule{Proto: "any", Port: "any", Host: "any"}) {
			return ControlShapeReport{}, errors.New("maximum-document terminal firewall shape is not the expected minimal policy")
		}
	}
	return shape, nil
}

func summarizeIdentityShape(document decodedIdentityDocument, metadata FixtureMetadata, phase string) (IdentityShapeReport, error) {
	shape := IdentityShapeReport{LoginAttempts: len(document.LoginAttempts), Sessions: len(document.Sessions), Audit: len(document.Audit)}
	for _, raw := range document.LoginAttempts {
		var attempt decodedIdentityLoginAttempt
		if err := json.Unmarshal(raw, &attempt); err != nil {
			return IdentityShapeReport{}, errors.New("decode maximum-document login-attempt shape failed")
		}
		if attempt.ID == metadata.Identity.ExpiredLoginAttemptID {
			shape.ExpiredAttemptPresent = true
		}
	}
	var revokeTarget identity.Session
	for _, session := range document.Sessions {
		if session.ID == metadata.Identity.ExpiredSessionID {
			shape.ExpiredTargetPresent = true
		}
		if session.ID == metadata.Identity.RevokeSessionID {
			shape.RevokeTargetPresent = true
			revokeTarget = session
		}
		if session.RevokedAt != nil {
			shape.RevokedSessions++
		}
	}
	for _, event := range document.Audit {
		switch event.Type {
		case identity.IdentityAuditSessionCreated:
			shape.SessionCreatedAudits++
		case identity.IdentityAuditSessionRevoked:
			if event.TargetSessionID == metadata.Identity.RevokeSessionID {
				shape.SessionRevocationAudits++
			}
		}
	}
	if shape.SessionCreatedAudits != metadata.Identity.SessionCount {
		return IdentityShapeReport{}, errors.New("maximum-document session creation audit cardinality changed")
	}
	switch phase {
	case "initial":
		if shape.LoginAttempts != metadata.Identity.LoginAttemptCount || !shape.ExpiredAttemptPresent ||
			!shape.ExpiredTargetPresent || !shape.RevokeTargetPresent || shape.RevokedSessions != 0 || shape.SessionRevocationAudits != 0 {
			return IdentityShapeReport{}, errors.New("maximum-document initial identity targets changed")
		}
	case "terminal":
		shape.RevokeTargetRevoked = revokeTarget.RevokedAt != nil && revokeTarget.RevocationReason == "administrator revocation" && revokeTarget.Version == 2
		if shape.LoginAttempts != 0 || shape.ExpiredAttemptPresent || shape.ExpiredTargetPresent ||
			!shape.RevokeTargetPresent || !shape.RevokeTargetRevoked || shape.RevokedSessions != 1 || shape.SessionRevocationAudits != 1 {
			return IdentityShapeReport{}, errors.New("maximum-document terminal identity targets changed")
		}
	}
	return shape, nil
}

func populateDatabaseMetrics(ctx context.Context, runtime *postgresruntime.Runtime, metadata FixtureMetadata, backupID string, receiptExpectation []receiptRow, report *DatabaseReport) error {
	pool := runtime.Pool()
	if err := pool.QueryRow(ctx, `
SELECT
    (SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipts),
    (SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipt_documents),
    pg_catalog.pg_database_size(pg_catalog.current_database()),
    w.wal_bytes::bigint, w.wal_buffers_full,
    d.deadlocks, d.temp_bytes
FROM pg_catalog.pg_stat_wal AS w
CROSS JOIN pg_catalog.pg_stat_database AS d
WHERE d.datname = pg_catalog.current_database()`).Scan(
		&report.ReceiptHeaders, &report.ReceiptDocuments, &report.DatabaseBytes,
		&report.WALBytes, &report.WALBuffersFull, &report.Deadlocks, &report.TempBytes,
	); err != nil {
		return errors.New("read maximum-document PostgreSQL metrics failed")
	}
	rows, err := pool.Query(ctx, `
SELECT operation_class, pg_catalog.count(*)
FROM mesh.mesh_write_receipts
GROUP BY operation_class
ORDER BY operation_class`)
	if err != nil {
		return errors.New("read maximum-document operation counts failed")
	}
	defer rows.Close()
	for rows.Next() {
		var item OperationCount
		if err := rows.Scan(&item.Operation, &item.Count); err != nil {
			return errors.New("scan maximum-document operation count failed")
		}
		report.Operations = append(report.Operations, item)
	}
	if err := rows.Err(); err != nil {
		return errors.New("iterate maximum-document operation counts failed")
	}

	var sourceControlHash, sourceIdentityHash []byte
	var sourceControlBytes, sourceIdentityBytes int64
	var sourceFormat, sourceIdentitySchema, sourceBackupID string
	var sourceControlVersion int
	if err := pool.QueryRow(ctx, `
SELECT source_format, source_control_sha256, source_identity_sha256,
       source_control_bytes, source_identity_bytes, source_control_version,
       source_identity_schema, source_backup_id
FROM mesh.mesh_import_metadata
WHERE singleton = 1`).Scan(
		&sourceFormat, &sourceControlHash, &sourceIdentityHash,
		&sourceControlBytes, &sourceIdentityBytes, &sourceControlVersion,
		&sourceIdentitySchema, &sourceBackupID,
	); err != nil {
		return errors.New("read maximum-document import provenance failed")
	}
	if sourceFormat != postgresstore.ImportSourceFormat || sourceControlVersion != postgresstore.ImportControlVersion ||
		sourceIdentitySchema != postgresstore.ImportIdentitySchema || sourceBackupID != backupID ||
		sourceControlBytes != int64(metadata.Control.ExactBytes) || sourceIdentityBytes != int64(metadata.Identity.ExactBytes) ||
		hex.EncodeToString(sourceControlHash) != metadata.Control.SHA256 || hex.EncodeToString(sourceIdentityHash) != metadata.Identity.SHA256 {
		return errors.New("maximum-document import provenance does not match the authenticated fixture")
	}

	receiptRows, err := pool.Query(ctx, `
SELECT r.operation_class, d.document_key, d.base_revision, d.committed_revision, d.document_sha256
FROM mesh.mesh_write_receipts AS r
JOIN mesh.mesh_write_receipt_documents AS d USING (receipt_id)
ORDER BY d.document_key, d.committed_revision`)
	if err != nil {
		return errors.New("read maximum-document receipt ledger failed")
	}
	defer receiptRows.Close()
	var receipts []receiptRow
	for receiptRows.Next() {
		var row receiptRow
		if err := receiptRows.Scan(&row.Operation, &row.Domain, &row.BaseRevision, &row.CommittedRevision, &row.SHA256); err != nil {
			return errors.New("scan maximum-document receipt ledger failed")
		}
		receipts = append(receipts, row)
	}
	if err := receiptRows.Err(); err != nil {
		return errors.New("iterate maximum-document receipt ledger failed")
	}
	if err := validateReceiptLedger(receipts, receiptExpectation); err != nil {
		return err
	}
	return nil
}

func buildReceiptLedgerExpectation(phase string, sourceControlHash, sourceIdentityHash, cleanupIdentityHash [sha256.Size]byte, controlDocument, identityDocument, runtimeTelemetryDocument postgresstore.Document) ([]receiptRow, error) {
	expected := []receiptRow{
		{Operation: postgresstore.OperationImport, Domain: string(postgresstore.DomainControl), BaseRevision: 0, CommittedRevision: 1, SHA256: bytes.Clone(sourceControlHash[:])},
		{Operation: postgresstore.OperationImport, Domain: string(postgresstore.DomainIdentity), BaseRevision: 0, CommittedRevision: 1, SHA256: bytes.Clone(sourceIdentityHash[:])},
		{Operation: postgresstore.OperationInitialize, Domain: string(postgresstore.DomainRuntimeTelemetry), BaseRevision: 0, CommittedRevision: 1, SHA256: bytes.Clone(runtimeTelemetryDocument.SHA256[:])},
	}
	switch phase {
	case "initial":
		return expected, nil
	case "terminal":
		if cleanupIdentityHash == ([sha256.Size]byte{}) {
			return nil, errors.New("maximum-document terminal receipt expectation is missing the cleanup digest")
		}
		expected = append(expected,
			receiptRow{Operation: "control.state.update", Domain: string(postgresstore.DomainControl), BaseRevision: 1, CommittedRevision: 2, SHA256: bytes.Clone(controlDocument.SHA256[:])},
			receiptRow{Operation: "identity.state.update", Domain: string(postgresstore.DomainIdentity), BaseRevision: 1, CommittedRevision: 2, SHA256: bytes.Clone(cleanupIdentityHash[:])},
			receiptRow{Operation: "identity.state.update", Domain: string(postgresstore.DomainIdentity), BaseRevision: 2, CommittedRevision: 3, SHA256: bytes.Clone(identityDocument.SHA256[:])},
		)
		return expected, nil
	default:
		return nil, errors.New("maximum-document receipt expectation phase is invalid")
	}
}

func validateReceiptLedger(receipts, expected []receiptRow) error {
	if len(receipts) != len(expected) || len(expected) < 2 {
		return fmt.Errorf("maximum-document receipt ledger row count=%d, want %d", len(receipts), len(expected))
	}
	actual := append([]receiptRow(nil), receipts...)
	want := append([]receiptRow(nil), expected...)
	sortReceiptRows := func(rows []receiptRow) {
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Domain != rows[j].Domain {
				return rows[i].Domain < rows[j].Domain
			}
			return rows[i].CommittedRevision < rows[j].CommittedRevision
		})
	}
	sortReceiptRows(actual)
	sortReceiptRows(want)
	for index := range want {
		if actual[index].Operation != want[index].Operation {
			return fmt.Errorf("maximum-document receipt operation=%q, want %q for %s revision %d", actual[index].Operation, want[index].Operation, want[index].Domain, want[index].CommittedRevision)
		}
		if actual[index].Domain != want[index].Domain || actual[index].BaseRevision != want[index].BaseRevision || actual[index].CommittedRevision != want[index].CommittedRevision {
			return errors.New("maximum-document receipt domain or revision sequence is invalid")
		}
		if len(actual[index].SHA256) != sha256.Size || len(want[index].SHA256) != sha256.Size || !bytes.Equal(actual[index].SHA256, want[index].SHA256) {
			return fmt.Errorf("maximum-document %s revision-%d receipt hash mismatch", want[index].Domain, want[index].CommittedRevision)
		}
	}
	return nil
}

func validateDatabasePhase(report DatabaseReport, metadata FixtureMetadata) error {
	if report.DatabaseBytes > MaximumDatabaseBytes || report.Deadlocks != 0 {
		return fmt.Errorf("maximum-document database budget failed: bytes=%d deadlocks=%d", report.DatabaseBytes, report.Deadlocks)
	}
	wantOperations := func(expected map[string]int64) bool {
		actual := make(map[string]int64, len(report.Operations))
		for _, item := range report.Operations {
			actual[item.Operation] = item.Count
		}
		if len(actual) != len(expected) {
			return false
		}
		for key, value := range expected {
			if actual[key] != value {
				return false
			}
		}
		return true
	}
	switch report.Phase {
	case "initial":
		if report.Control.Revision != 1 || report.Identity.Revision != 1 ||
			report.Control.Bytes != MaximumControlBytes || report.Identity.Bytes != MaximumIdentityBytes ||
			report.Control.SHA256 != metadata.Control.SHA256 || report.Identity.SHA256 != metadata.Identity.SHA256 ||
			report.Control.Canonical || report.Identity.Canonical ||
			report.Control.Resources != metadata.Control.NodeCount || report.Control.Audit != metadata.Control.AuditCount ||
			report.Identity.Resources != metadata.Identity.SessionCount || report.Identity.Audit != metadata.Identity.AuditCount ||
			report.ReceiptHeaders != 2 || report.ReceiptDocuments != 3 || report.Control.LastWriteID != report.Identity.LastWriteID ||
			!wantOperations(map[string]int64{postgresstore.OperationImport: 1, postgresstore.OperationInitialize: 1}) {
			return errors.New("maximum-document initial PostgreSQL state does not match the exact authenticated import")
		}
	case "terminal":
		if report.Control.Revision != 2 || report.Identity.Revision != 3 ||
			report.Control.Bytes >= metadata.Control.CanonicalBytes || report.Identity.Bytes >= metadata.Identity.CanonicalBytes ||
			!report.Control.Canonical || !report.Identity.Canonical ||
			report.Control.SHA256 == metadata.Control.SHA256 || report.Identity.SHA256 == metadata.Identity.SHA256 ||
			report.Control.Resources != metadata.Control.NodeCount || report.Control.Audit != metadata.Control.AuditCount+1 ||
			report.Identity.Resources != metadata.Identity.SessionCount-1 || report.Identity.Audit != metadata.Identity.AuditCount+1 ||
			report.ReceiptHeaders != 5 || report.ReceiptDocuments != 6 ||
			!wantOperations(map[string]int64{postgresstore.OperationImport: 1, postgresstore.OperationInitialize: 1, "control.state.update": 1, "identity.state.update": 2}) {
			return errors.New("maximum-document terminal PostgreSQL state does not match the bounded mutation sequence")
		}
	}
	return nil
}
