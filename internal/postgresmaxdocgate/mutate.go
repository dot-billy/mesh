//go:build linux && postgresmaxdocgate

package postgresmaxdocgate

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/postgresruntime"
	"mesh/internal/postgresstore"
)

const maximumHTTPResponseBytes = 64 << 10

func Mutate(ctx context.Context, options MutateOptions) (result MutationReport, resultErr error) {
	if ctx == nil {
		return MutationReport{}, errors.New("maximum-document mutation context is required")
	}
	if !backupIDPattern.MatchString(options.BackupID) {
		return MutationReport{}, errors.New("maximum-document backup ID is invalid")
	}
	serverURL, err := validateLoopbackServerURL(options.ServerURL)
	if err != nil {
		return MutationReport{}, err
	}
	metadata, err := LoadFixtureMetadata(options.MetadataFile)
	if err != nil {
		return MutationReport{}, err
	}
	masterKey, adminToken, err := loadFixtureCredentials(metadata)
	if err != nil {
		return MutationReport{}, err
	}
	defer clear(masterKey)
	defer func() { adminToken = "" }()
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		return MutationReport{}, err
	}
	sourceIdentity, err := readAuthenticatedFixtureDocument(metadata.Paths.IdentityState, metadata.Identity.ExactBytes, metadata.Identity.SHA256)
	if err != nil {
		return MutationReport{}, fmt.Errorf("read authenticated maximum-document identity source: %w", err)
	}
	defer clear(sourceIdentity)
	cleanupExpectation, err := identity.BuildMaximumDocumentCleanupExpectation(
		sourceIdentity, box, metadata.Identity.ExpiredLoginAttemptID, metadata.Identity.ExpiredSessionID,
	)
	if err != nil {
		return MutationReport{}, fmt.Errorf("derive maximum-document identity cleanup expectation: %w", err)
	}
	defer clear(cleanupExpectation.CanonicalBytes)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   MaximumApplicationOperation,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("maximum-document HTTP redirects are disabled")
		},
	}
	minimal := control.UpdateFirewallPolicyInput{
		ExpectedConfigRevision: metadata.Control.FirewallConfigRevision,
		Inbound:                []control.FirewallRule{{Proto: "any", Port: "any", Group: "all"}},
		Outbound:               []control.FirewallRule{{Proto: "any", Port: "any", Host: "any"}},
	}
	started := time.Now()
	var updated control.FirewallPolicyDocument
	if err := bearerJSON(ctx, client, adminToken, http.MethodPut, serverURL+"/api/v1/networks/"+url.PathEscape(metadata.Control.NetworkID)+"/firewall", minimal, http.StatusOK, &updated); err != nil {
		return MutationReport{}, fmt.Errorf("shrink maximum-document firewall: %w", err)
	}
	firewallDuration := time.Since(started)
	if firewallDuration > MaximumApplicationOperation || updated.ConfigRevision != metadata.Control.FirewallConfigRevision+1 || len(updated.Inbound) != 1 || len(updated.Outbound) != 1 {
		return MutationReport{}, fmt.Errorf("maximum-document firewall mutation result is invalid: duration=%s revision=%d", firewallDuration, updated.ConfigRevision)
	}

	var (
		cleanup         identity.CleanupResult
		cleanupDuration time.Duration
		cleanupDocument postgresstore.Document
		cleanupReceipt  cleanupReceiptProof
	)
	err = func() (operationErr error) {
		runtime, openErr := postgresruntime.Open(ctx, postgresruntime.Options{
			DSNFile: options.DSNFile, AllowLocalPlaintext: options.AllowLocalPlaintext,
			StoreOptions: postgresstore.Options{MigrationBuild: "mesh-postgres-maximum-document-gate"},
		})
		if openErr != nil {
			return openErr
		}
		defer func() { operationErr = errors.Join(operationErr, runtime.Close()) }()
		identityStore, storeErr := identity.NewPostgresStore(runtime.Store(), box, identity.PostgresStoreOptions{})
		if storeErr != nil {
			return storeErr
		}
		defer func() { operationErr = errors.Join(operationErr, identityStore.Close()) }()

		started = time.Now()
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, MaximumApplicationOperation)
		cleanup, operationErr = identityStore.CleanupExpired(cleanupCtx, metadata.Identity.CleanupAt)
		cleanupCancel()
		cleanupDuration = time.Since(started)
		if operationErr != nil {
			return operationErr
		}

		readCtx, readCancel := context.WithTimeout(ctx, MaximumApplicationOperation)
		cleanupDocument, operationErr = runtime.Store().Read(readCtx, postgresstore.DomainIdentity)
		readCancel()
		if operationErr != nil {
			return operationErr
		}
		receiptCtx, receiptCancel := context.WithTimeout(ctx, MaximumApplicationOperation)
		cleanupReceipt, operationErr = readCleanupReceiptProof(receiptCtx, runtime, cleanupDocument.LastWriteID)
		receiptCancel()
		if operationErr != nil {
			return operationErr
		}
		return validateCleanupRevisionProof(cleanupDocument, cleanupReceipt, box, cleanupExpectation)
	}()
	if err != nil {
		return MutationReport{}, fmt.Errorf("cleanup maximum-document identity state: %w", err)
	}
	if cleanupDuration > MaximumApplicationOperation || cleanup.Sessions != 1 || cleanup.LoginAttempts != metadata.Identity.LoginAttemptCount || cleanup.BreakGlassCodes != 0 {
		return MutationReport{}, fmt.Errorf("maximum-document identity cleanup result is invalid: duration=%s result=%+v", cleanupDuration, cleanup)
	}

	started = time.Now()
	if err := bearerJSON(ctx, client, adminToken, http.MethodDelete, serverURL+"/api/v1/sessions/"+url.PathEscape(metadata.Identity.RevokeSessionID), nil, http.StatusNoContent, nil); err != nil {
		return MutationReport{}, fmt.Errorf("revoke maximum-document identity session: %w", err)
	}
	revocationDuration := time.Since(started)
	if revocationDuration > MaximumApplicationOperation {
		return MutationReport{}, fmt.Errorf("maximum-document session revocation exceeded %s: %s", MaximumApplicationOperation, revocationDuration)
	}

	database, err := VerifyDatabase(ctx, VerifyOptions{
		DSNFile: options.DSNFile, MetadataFile: options.MetadataFile, BackupID: options.BackupID,
		AllowLocalPlaintext: options.AllowLocalPlaintext, Phase: "terminal",
	})
	if err != nil {
		return MutationReport{}, err
	}
	return MutationReport{
		Schema: ReportSchema, MutatedAt: time.Now().UTC(), CleanupLoginAttempts: cleanup.LoginAttempts, CleanupSessions: cleanup.Sessions,
		CleanupRevision: cleanupDocument.Revision, CleanupSHA256: hex.EncodeToString(cleanupDocument.SHA256[:]), CleanupWriteID: cleanupDocument.LastWriteID,
		CleanupReceiptOperation: cleanupReceipt.Operation, CleanupReceiptBaseRevision: cleanupReceipt.BaseRevision,
		CleanupReceiptCommittedRevision: cleanupReceipt.CommittedRevision,
		CleanupMicros:                   cleanupDuration.Microseconds(), FirewallMicros: firewallDuration.Microseconds(),
		RevocationMicros: revocationDuration.Microseconds(), Database: database,
	}, nil
}

func validateLoopbackServerURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("maximum-document server URL must be an origin-only loopback HTTP URL")
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() || parsed.Port() == "" {
		return "", errors.New("maximum-document server URL must use a numeric loopback address and explicit port")
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func bearerJSON(ctx context.Context, client *http.Client, token, method, endpoint string, input any, expectedStatus int, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("create maximum-document HTTP request failed")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("maximum-document HTTP request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumHTTPResponseBytes+1))
	if err != nil || len(raw) > maximumHTTPResponseBytes {
		return errors.New("maximum-document HTTP response is invalid or oversized")
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("maximum-document HTTP status=%d, want %d", response.StatusCode, expectedStatus)
	}
	if output == nil {
		if len(bytes.TrimSpace(raw)) != 0 {
			return errors.New("maximum-document empty HTTP response contained a body")
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("decode maximum-document HTTP response failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("maximum-document HTTP response contains trailing data")
	}
	return nil
}

type cleanupReceiptProof struct {
	receiptRow
	ID            string
	DocumentCount int64
}

func readCleanupReceiptProof(ctx context.Context, runtime *postgresruntime.Runtime, receiptID string) (cleanupReceiptProof, error) {
	var proof cleanupReceiptProof
	proof.ID = receiptID
	err := runtime.Pool().QueryRow(ctx, `
SELECT r.operation_class,
       d.document_key,
       d.base_revision,
       d.committed_revision,
       d.document_sha256,
       (SELECT pg_catalog.count(*)
          FROM mesh.mesh_write_receipt_documents AS all_documents
         WHERE all_documents.receipt_id = r.receipt_id)
FROM mesh.mesh_write_receipts AS r
JOIN mesh.mesh_write_receipt_documents AS d ON d.receipt_id = r.receipt_id
WHERE r.receipt_id = $1::pg_catalog.uuid
  AND d.document_key = 'identity'`, receiptID).Scan(
		&proof.Operation, &proof.Domain, &proof.BaseRevision, &proof.CommittedRevision, &proof.SHA256, &proof.DocumentCount,
	)
	if err != nil {
		return cleanupReceiptProof{}, errors.New("read maximum-document cleanup receipt failed")
	}
	return proof, nil
}

func validateCleanupRevisionProof(document postgresstore.Document, receipt cleanupReceiptProof, sealer identity.Sealer, expectation identity.MaximumDocumentCleanupExpectation) error {
	if document.Domain != postgresstore.DomainIdentity || document.Revision != 2 {
		return fmt.Errorf("maximum-document cleanup document domain=%q revision=%d, want identity revision 2", document.Domain, document.Revision)
	}
	if document.SHA256 != expectation.SHA256 || !bytes.Equal(document.Bytes, expectation.CanonicalBytes) {
		return errors.New("maximum-document cleanup document does not match its source-derived revision-2 digest and bytes")
	}
	if err := identity.ValidateMaximumDocumentCleanupExpectation(document.Bytes, sealer, expectation); err != nil {
		return err
	}
	if receipt.ID != document.LastWriteID || receipt.DocumentCount != 1 ||
		receipt.Operation != "identity.state.update" || receipt.Domain != string(postgresstore.DomainIdentity) ||
		receipt.BaseRevision != 1 || receipt.CommittedRevision != 2 || len(receipt.SHA256) != len(expectation.SHA256) ||
		!bytes.Equal(receipt.SHA256, expectation.SHA256[:]) {
		return errors.New("maximum-document cleanup receipt does not bind the exact identity revision-2 transition")
	}
	return nil
}
