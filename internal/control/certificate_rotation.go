package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
)

const nodeCertificateRotatedAuditAction = "node.certificate_rotated"

// RotateNodeCertificateInput binds an immediate same-key host-certificate
// rotation to the exact visible node and network revision. RequestID makes a
// lost successful response safely replayable without issuing another
// certificate or advancing configuration twice.
type RotateNodeCertificateInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	ConfirmationName       string `json:"confirmation_name"`
	RequestID              string `json:"request_id"`
}

// RotatedNodeCertificate is the non-secret durable receipt for an immediate
// host-certificate rotation. The previous fingerprint remains deliberately
// absent from the API receipt; its blocklist fact and expiry are sufficient
// for an administrator to verify the lifecycle transition.
type RotatedNodeCertificate struct {
	RequestID                       string    `json:"request_id"`
	NodeID                          string    `json:"node_id"`
	NetworkID                       string    `json:"network_id"`
	Name                            string    `json:"name"`
	IP                              string    `json:"ip"`
	Role                            string    `json:"role"`
	RotatedAt                       time.Time `json:"rotated_at"`
	PreviousCertificateExpiresAt    time.Time `json:"previous_certificate_expires_at"`
	CertificateExpiresAt            time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter           time.Time `json:"certificate_renew_after"`
	PreviousCertificateGeneration   int64     `json:"previous_certificate_generation"`
	CertificateGeneration           int64     `json:"certificate_generation"`
	AgentRecoveryRecordsInvalidated int       `json:"agent_recovery_records_invalidated"`
	CertificateIssuancesAdded       int       `json:"certificate_issuances_added"`
	BlocklistEntriesAdded           int       `json:"blocklist_entries_added"`
	PreviousCertificateBlocklisted  bool      `json:"previous_certificate_blocklisted"`
	ConfigRevision                  int64     `json:"config_revision"`
}

func (s *Service) RotateNodeCertificate(ctx context.Context, nodeID string, input RotateNodeCertificateInput) (RotatedNodeCertificate, error) {
	return s.rotateNodeCertificate(ctx, nil, nodeID, input)
}

func (s *Service) RotateNodeCertificateAs(ctx context.Context, actor Actor, nodeID string, input RotateNodeCertificateInput) (RotatedNodeCertificate, error) {
	if err := validateActor(actor); err != nil {
		return RotatedNodeCertificate{}, err
	}
	return s.rotateNodeCertificate(ctx, &actor, nodeID, input)
}

func (s *Service) rotateNodeCertificate(ctx context.Context, actor *Actor, nodeID string, input RotateNodeCertificateInput) (RotatedNodeCertificate, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 || !namePattern.MatchString(input.ConfirmationName) || !validCertificateRotationRequestID(input.RequestID) {
		return RotatedNodeCertificate{}, fmt.Errorf("%w: node ID, expected_config_revision, exact confirmation_name, and a 16-128 character request_id are required", ErrInvalid)
	}
	operationAt := s.now().UTC()
	if operationAt.IsZero() {
		return RotatedNodeCertificate{}, fmt.Errorf("%w: certificate rotation requires a valid timestamp", ErrInvalid)
	}

	var snapshotNode Node
	var snapshotNetwork Network
	var replay RotatedNodeCertificate
	var replayed bool
	err := s.viewState(func(state State) error {
		var replayErr error
		replay, replayed, replayErr = findCertificateRotationReplay(state, nodeID, input)
		if replayErr != nil || replayed {
			return replayErr
		}
		var ok bool
		snapshotNode, ok = findNode(state, nodeID)
		if !ok {
			return ErrNotFound
		}
		if snapshotNode.Status != "active" || snapshotNode.EnrolledAt == nil || snapshotNode.RevokedAt != nil {
			return fmt.Errorf("%w: immediate certificate rotation requires an active enrolled node", ErrConflict)
		}
		if snapshotNode.Name != input.ConfirmationName {
			return fmt.Errorf("%w: confirmation name does not exactly match the active node", ErrConflict)
		}
		snapshotNetwork, ok = findNetwork(state, snapshotNode.NetworkID)
		if !ok {
			return ErrNotFound
		}
		if snapshotNetwork.ConfigRevision != input.ExpectedConfigRevision {
			return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, snapshotNetwork.ConfigRevision)
		}
		if snapshotNetwork.CARotation.Phase != "" || snapshotNetwork.FirewallRollout.Phase != "" || routeTransferIncludesNode(snapshotNetwork.RouteTransfer, snapshotNode.ID) || routeProfileEditIncludesNode(snapshotNetwork.RouteProfileEdit, snapshotNode.ID) {
			return fmt.Errorf("%w: certificate rotation is unavailable during a CA, firewall, or participating route-transfer lifecycle", ErrConflict)
		}
		if err := validateActiveCertificateRotationSource(snapshotNode, operationAt); err != nil {
			return err
		}
		return nil
	})
	if err != nil || replayed {
		return replay, err
	}

	publicKey, err := publicKeyFromNodeCertificate(snapshotNode)
	if err != nil {
		return RotatedNodeCertificate{}, err
	}
	signingCACertificate, signingCAKey := networkSigningAuthority(snapshotNetwork)
	caKey, err := s.box.Open(signingCAKey)
	if err != nil {
		return RotatedNodeCertificate{}, err
	}
	certificate, fingerprint, expiresAt, signErr := s.signDistinctNodeCertificate(
		ctx, snapshotNetwork, snapshotNode, signingCACertificate, string(caKey), publicKey,
	)
	clear(caKey)
	if signErr != nil {
		return RotatedNodeCertificate{}, signErr
	}
	expiresAt = expiresAt.UTC()
	if strings.TrimSpace(certificate) == "" || !fingerprintPattern.MatchString(fingerprint) || !expiresAt.After(operationAt) {
		return RotatedNodeCertificate{}, errors.New("certificate issuer returned invalid rotation metadata")
	}
	renewAfter := expiresAt.Add(-renewalWindow(time.Duration(snapshotNetwork.CertificateTTL) * time.Hour)).UTC()
	if renewAfter.IsZero() || !renewAfter.After(operationAt) || !renewAfter.Before(expiresAt) {
		return RotatedNodeCertificate{}, errors.New("certificate issuer returned invalid renewal metadata")
	}

	var result RotatedNodeCertificate
	err = s.updateState(func(state *State) error {
		committed, found, replayErr := findCertificateRotationReplay(*state, nodeID, input)
		if replayErr != nil {
			return replayErr
		}
		if found {
			result = committed
			return nil
		}
		nodeIndex := -1
		for index := range state.Nodes {
			if state.Nodes[index].ID == nodeID {
				nodeIndex = index
				break
			}
		}
		if nodeIndex < 0 {
			return ErrNotFound
		}
		node := &state.Nodes[nodeIndex]
		if node.Status != "active" || node.EnrolledAt == nil || node.RevokedAt != nil || node.Name != input.ConfirmationName {
			return fmt.Errorf("%w: active node lifecycle changed during certificate rotation", ErrConflict)
		}
		networkIndex := -1
		for index := range state.Networks {
			if state.Networks[index].ID == node.NetworkID {
				networkIndex = index
				break
			}
		}
		if networkIndex < 0 {
			return ErrNotFound
		}
		network := &state.Networks[networkIndex]
		latestSigningCertificate, latestSigningKey := networkSigningAuthority(*network)
		if network.ConfigRevision != input.ExpectedConfigRevision || network.CARotation.Phase != "" || network.FirewallRollout.Phase != "" || routeTransferIncludesNode(network.RouteTransfer, node.ID) || routeProfileEditIncludesNode(network.RouteProfileEdit, node.ID) || latestSigningCertificate != signingCACertificate || latestSigningKey != signingCAKey || network.ConfigSigningPublicKey != snapshotNetwork.ConfigSigningPublicKey || network.EncryptedConfigSigningKey != snapshotNetwork.EncryptedConfigSigningKey {
			return fmt.Errorf("%w: network lifecycle changed during certificate rotation", ErrConflict)
		}
		if node.Certificate != snapshotNode.Certificate || node.CertificateFingerprint != snapshotNode.CertificateFingerprint || node.CertificateGeneration != snapshotNode.CertificateGeneration || node.PublicKeyHash != snapshotNode.PublicKeyHash || !optionalTimesEqual(node.CertificateExpiresAt, snapshotNode.CertificateExpiresAt) || !optionalTimesEqual(node.CertificateRenewAfter, snapshotNode.CertificateRenewAfter) || node.RenewalClaimID != snapshotNode.RenewalClaimID || !optionalTimesEqual(node.RenewalClaimedAt, snapshotNode.RenewalClaimedAt) {
			return fmt.Errorf("%w: node certificate lifecycle changed during certificate rotation", ErrConflict)
		}
		for _, revocation := range state.Revocations {
			if revocation.Fingerprint == snapshotNode.CertificateFingerprint {
				return fmt.Errorf("%w: active certificate is already blocklisted", ErrConflict)
			}
		}

		nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
		if err != nil {
			return err
		}
		previousExpiry := snapshotNode.CertificateExpiresAt.UTC()
		previousGeneration := node.CertificateGeneration
		recoveriesInvalidated := 0
		keptRecoveries := state.AgentRecoveries[:0]
		for _, recovery := range state.AgentRecoveries {
			if recovery.NodeID == node.ID {
				recoveriesInvalidated++
				continue
			}
			keptRecoveries = append(keptRecoveries, recovery)
		}
		if len(keptRecoveries) == 0 {
			keptRecoveries = nil
		}
		state.AgentRecoveries = keptRecoveries

		oldFingerprint := node.CertificateFingerprint
		appendRevocation(state, node.ID, oldFingerprint, "certificate rotated by administrator", operationAt, node.CertificateExpiresAt)
		node.Certificate = certificate
		node.CertificateFingerprint = fingerprint
		if state.Version >= ControlStateVersionCARotation {
			node.CertificateAuthoritySHA256 = ConfigDigest(signingCACertificate)
		}
		node.CertificateExpiresAt = &expiresAt
		node.CertificateRenewAfter = &renewAfter
		node.CertificateGeneration++
		if node.CertificateGeneration != previousGeneration+1 {
			return fmt.Errorf("%w: certificate generation cannot advance", ErrConflict)
		}
		node.LastRenewedAt = &operationAt
		node.RenewalClaimID = ""
		node.RenewalClaimedAt = nil
		network.ConfigRevision = nextRevision
		network.ConfigUpdatedAt = operationAt
		state.Issuances = append(state.Issuances, CertificateIssuance{Fingerprint: fingerprint, NodeID: node.ID, NetworkID: node.NetworkID, IssuedAt: operationAt, ExpiresAt: expiresAt})

		result = RotatedNodeCertificate{
			RequestID: input.RequestID, NodeID: node.ID, NetworkID: node.NetworkID, Name: node.Name, IP: node.IP, Role: node.Role,
			RotatedAt: operationAt, PreviousCertificateExpiresAt: previousExpiry, CertificateExpiresAt: expiresAt, CertificateRenewAfter: renewAfter,
			PreviousCertificateGeneration: previousGeneration, CertificateGeneration: node.CertificateGeneration,
			AgentRecoveryRecordsInvalidated: recoveriesInvalidated, CertificateIssuancesAdded: 1,
			BlocklistEntriesAdded: 1, PreviousCertificateBlocklisted: true, ConfigRevision: nextRevision,
		}
		event, err := newOptionalAttributedAudit(operationAt, nodeCertificateRotatedAuditAction, "node", node.ID, certificateRotationAuditDetails(result, input.ExpectedConfigRevision), actor)
		if err != nil {
			return err
		}
		state.Audit = append(state.Audit, event)
		return nil
	})
	return result, err
}

func (s *Service) signDistinctNodeCertificate(ctx context.Context, network Network, node Node, caCertificate, caKey, publicKey string) (string, string, time.Time, error) {
	for attempt := 0; attempt < 2; attempt++ {
		certificate, fingerprint, expiresAt, err := s.issuer.SignPublicKey(
			ctx, caCertificate, caKey, publicKey,
			node.Name, node.IP+"/"+prefixLength(network.CIDR),
			strings.Join(node.Groups, ","), strings.Join(node.RoutedSubnets, ","),
			time.Duration(network.CertificateTTL)*time.Hour,
		)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if fingerprint != node.CertificateFingerprint {
			return certificate, fingerprint, expiresAt, nil
		}
		if attempt == 0 {
			// Nebula v2 host certificates are deterministic at their timestamp
			// granularity. An administrator rotating immediately after issuance
			// should not have to discover that edge or invent a new request ID.
			delay := time.Until(time.Now().UTC().Truncate(time.Second).Add(time.Second)) + 10*time.Millisecond
			if delay < 10*time.Millisecond {
				delay = 10 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return "", "", time.Time{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return "", "", time.Time{}, fmt.Errorf("%w: replacement certificate was not distinct; retry the same request_id", ErrConflict)
}

func validateActiveCertificateRotationSource(node Node, now time.Time) error {
	if node.Certificate == "" || !fingerprintPattern.MatchString(node.CertificateFingerprint) || node.CertificateExpiresAt == nil || node.CertificateRenewAfter == nil || node.CertificateGeneration < 1 || !ValidTokenHash(node.PublicKeyHash) {
		return fmt.Errorf("%w: active node is missing complete certificate metadata", ErrConflict)
	}
	if node.RenewalClaimID != "" {
		if node.RenewalClaimedAt == nil || node.RenewalClaimedAt.After(now) || now.Sub(*node.RenewalClaimedAt) < 5*time.Minute {
			return fmt.Errorf("%w: node certificate renewal is already in progress", ErrConflict)
		}
	}
	return nil
}

func publicKeyFromNodeCertificate(node Node) (string, error) {
	certificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM([]byte(node.Certificate))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		return "", fmt.Errorf("%w: active node certificate cannot be parsed", ErrConflict)
	}
	publicKey, err := canonicalNebulaPublicKeyPEM(string(certificate.MarshalPublicKeyPEM()))
	if err != nil || !TokenHashEqual(node.PublicKeyHash, HashToken(publicKey)) {
		return "", fmt.Errorf("%w: active node certificate public key does not match its pinned identity", ErrConflict)
	}
	return publicKey, nil
}

func optionalTimesEqual(first, second *time.Time) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return first.Equal(*second)
}

func validCertificateRotationRequestID(value string) bool {
	return len(value) >= 16 && validPersistedID(value)
}

func certificateRotationAuditDetails(result RotatedNodeCertificate, expectedRevision int64) map[string]any {
	return map[string]any{
		"request_id": result.RequestID, "network_id": result.NetworkID, "name": result.Name, "ip": result.IP, "role": result.Role,
		"rotated_at": result.RotatedAt.Format(time.RFC3339Nano), "previous_certificate_expires_at": result.PreviousCertificateExpiresAt.Format(time.RFC3339Nano),
		"certificate_expires_at": result.CertificateExpiresAt.Format(time.RFC3339Nano), "certificate_renew_after": result.CertificateRenewAfter.Format(time.RFC3339Nano),
		"previous_certificate_generation": result.PreviousCertificateGeneration, "certificate_generation": result.CertificateGeneration,
		"expected_config_revision": expectedRevision, "config_revision": result.ConfigRevision,
		"agent_recovery_records_invalidated": result.AgentRecoveryRecordsInvalidated, "certificate_issuances_added": result.CertificateIssuancesAdded,
		"blocklist_entries_added": result.BlocklistEntriesAdded, "previous_certificate_blocklisted": result.PreviousCertificateBlocklisted,
	}
}

func findCertificateRotationReplay(state State, nodeID string, input RotateNodeCertificateInput) (RotatedNodeCertificate, bool, error) {
	for _, event := range state.Audit {
		if event.Action != nodeCertificateRotatedAuditAction {
			continue
		}
		requestID, ok := event.Details["request_id"].(string)
		if !ok || requestID != input.RequestID {
			continue
		}
		receipt, expectedRevision, err := parseNodeCertificateRotationEvent(event)
		if err != nil {
			return RotatedNodeCertificate{}, false, fmt.Errorf("persisted certificate rotation receipt is invalid: %w", err)
		}
		if event.ResourceID != nodeID || receipt.Name != input.ConfirmationName || expectedRevision != input.ExpectedConfigRevision {
			return RotatedNodeCertificate{}, false, fmt.Errorf("%w: request_id is already bound to a different certificate rotation", ErrConflict)
		}
		return receipt, true, nil
	}
	return RotatedNodeCertificate{}, false, nil
}

func validateNodeCertificateRotationAudits(state State) error {
	requestIDs := make(map[string]struct{})
	for _, event := range state.Audit {
		if event.Action != nodeCertificateRotatedAuditAction {
			continue
		}
		receipt, _, err := parseNodeCertificateRotationEvent(event)
		if err != nil {
			return fmt.Errorf("certificate rotation audit %q: %w", event.ID, err)
		}
		if _, duplicate := requestIDs[receipt.RequestID]; duplicate {
			return fmt.Errorf("duplicate certificate rotation request_id %q", receipt.RequestID)
		}
		requestIDs[receipt.RequestID] = struct{}{}
	}
	return nil
}

func parseNodeCertificateRotationEvent(event AuditEvent) (RotatedNodeCertificate, int64, error) {
	required := map[string]struct{}{
		"request_id": {}, "network_id": {}, "name": {}, "ip": {}, "role": {}, "rotated_at": {},
		"previous_certificate_expires_at": {}, "certificate_expires_at": {}, "certificate_renew_after": {},
		"previous_certificate_generation": {}, "certificate_generation": {}, "expected_config_revision": {}, "config_revision": {},
		"agent_recovery_records_invalidated": {}, "certificate_issuances_added": {}, "blocklist_entries_added": {}, "previous_certificate_blocklisted": {},
	}
	allowed := make(map[string]struct{}, len(required)+3)
	for key := range required {
		allowed[key] = struct{}{}
	}
	allowed[auditActorIDKey] = struct{}{}
	allowed[auditActorKindKey] = struct{}{}
	allowed[auditActorSessionIDKey] = struct{}{}
	for key := range event.Details {
		if _, ok := allowed[key]; !ok {
			return RotatedNodeCertificate{}, 0, fmt.Errorf("unexpected detail %q", key)
		}
	}
	for key := range required {
		if _, ok := event.Details[key]; !ok {
			return RotatedNodeCertificate{}, 0, fmt.Errorf("missing detail %q", key)
		}
	}
	if event.Resource != "node" || !validPersistedID(event.ResourceID) {
		return RotatedNodeCertificate{}, 0, errors.New("invalid resource metadata")
	}
	requestID, requestOK := event.Details["request_id"].(string)
	networkID, networkOK := event.Details["network_id"].(string)
	name, nameOK := event.Details["name"].(string)
	ip, ipOK := event.Details["ip"].(string)
	role, roleOK := event.Details["role"].(string)
	rotatedAt, rotatedOK := auditRFC3339Time(event.Details["rotated_at"])
	previousExpiry, previousExpiryOK := auditRFC3339Time(event.Details["previous_certificate_expires_at"])
	expiresAt, expiresOK := auditRFC3339Time(event.Details["certificate_expires_at"])
	renewAfter, renewOK := auditRFC3339Time(event.Details["certificate_renew_after"])
	previousGeneration, previousGenerationOK := auditNonNegativeInteger(event.Details["previous_certificate_generation"])
	generation, generationOK := auditNonNegativeInteger(event.Details["certificate_generation"])
	expectedRevision, expectedRevisionOK := auditNonNegativeInteger(event.Details["expected_config_revision"])
	configRevision, configRevisionOK := auditNonNegativeInteger(event.Details["config_revision"])
	recoveries, recoveriesOK := auditNonNegativeInteger(event.Details["agent_recovery_records_invalidated"])
	issuances, issuancesOK := auditNonNegativeInteger(event.Details["certificate_issuances_added"])
	blocklist, blocklistOK := auditNonNegativeInteger(event.Details["blocklist_entries_added"])
	blocklisted, blocklistedOK := event.Details["previous_certificate_blocklisted"].(bool)
	parsedIP := net.ParseIP(ip)
	if !requestOK || !validCertificateRotationRequestID(requestID) || !networkOK || !validPersistedID(networkID) || !nameOK || !namePattern.MatchString(name) || !ipOK || parsedIP == nil || parsedIP.To4() == nil || parsedIP.To4().String() != ip || !roleOK || role != "member" && role != "lighthouse" || !rotatedOK || !event.At.Equal(rotatedAt) || !previousExpiryOK || !expiresOK || !renewOK || !expiresAt.After(rotatedAt) || !renewAfter.After(rotatedAt) || !renewAfter.Before(expiresAt) || !previousGenerationOK || previousGeneration < 1 || !generationOK || generation != previousGeneration+1 || !expectedRevisionOK || expectedRevision < 1 || !configRevisionOK || configRevision != expectedRevision+1 || !recoveriesOK || !issuancesOK || issuances != 1 || !blocklistOK || blocklist != 1 || !blocklistedOK || !blocklisted {
		return RotatedNodeCertificate{}, 0, errors.New("identity, lifecycle, or transition details are invalid")
	}
	return RotatedNodeCertificate{
		RequestID: requestID, NodeID: event.ResourceID, NetworkID: networkID, Name: name, IP: ip, Role: role,
		RotatedAt: rotatedAt, PreviousCertificateExpiresAt: previousExpiry, CertificateExpiresAt: expiresAt, CertificateRenewAfter: renewAfter,
		PreviousCertificateGeneration: previousGeneration, CertificateGeneration: generation,
		AgentRecoveryRecordsInvalidated: int(recoveries), CertificateIssuancesAdded: int(issuances), BlocklistEntriesAdded: int(blocklist),
		PreviousCertificateBlocklisted: blocklisted, ConfigRevision: configRevision,
	}, expectedRevision, nil
}
