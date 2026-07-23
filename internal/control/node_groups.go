package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"
)

const nodeGroupsUpdatedAuditAction = "node.groups_updated"

// UpdateNodeGroupsInput safely changes certificate-bound group membership.
// The operation keeps the node key, issues a replacement host certificate,
// blocklists the old certificate, and advances the signed config revision in
// one durable commit.
type UpdateNodeGroupsInput struct {
	ExpectedConfigRevision int64    `json:"expected_config_revision"`
	ConfirmationName       string   `json:"confirmation_name"`
	RequestID              string   `json:"request_id"`
	Groups                 []string `json:"groups"`
}

type UpdatedNodeGroups struct {
	RequestID                       string    `json:"request_id"`
	NodeID                          string    `json:"node_id"`
	NetworkID                       string    `json:"network_id"`
	Name                            string    `json:"name"`
	IP                              string    `json:"ip"`
	PreviousGroups                  []string  `json:"previous_groups"`
	Groups                          []string  `json:"groups"`
	UpdatedAt                       time.Time `json:"updated_at"`
	PreviousCertificateExpiresAt    time.Time `json:"previous_certificate_expires_at"`
	CertificateExpiresAt            time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter           time.Time `json:"certificate_renew_after"`
	PreviousCertificateGeneration   int64     `json:"previous_certificate_generation"`
	CertificateGeneration           int64     `json:"certificate_generation"`
	AgentRecoveryRecordsInvalidated int       `json:"agent_recovery_records_invalidated"`
	PreviousCertificateBlocklisted  bool      `json:"previous_certificate_blocklisted"`
	ConfigRevision                  int64     `json:"config_revision"`
}

func canonicalNodeMembershipGroups(groups []string) ([]string, error) {
	canonical, err := normalizeGroups(groups)
	if err != nil {
		return nil, err
	}
	canonical = appendUnique(canonical, "all")
	sort.Strings(canonical)
	if len(canonical) > maxNodeGroups {
		return nil, fmt.Errorf("%w: a node may have at most %d groups including all", ErrInvalid, maxNodeGroups)
	}
	return canonical, nil
}

func (s *Service) UpdateNodeGroups(ctx context.Context, nodeID string, input UpdateNodeGroupsInput) (UpdatedNodeGroups, error) {
	return s.updateNodeGroups(ctx, nil, nodeID, input)
}

func (s *Service) UpdateNodeGroupsAs(ctx context.Context, actor Actor, nodeID string, input UpdateNodeGroupsInput) (UpdatedNodeGroups, error) {
	if err := validateActor(actor); err != nil {
		return UpdatedNodeGroups{}, err
	}
	return s.updateNodeGroups(ctx, &actor, nodeID, input)
}

func (s *Service) updateNodeGroups(ctx context.Context, actor *Actor, nodeID string, input UpdateNodeGroupsInput) (UpdatedNodeGroups, error) {
	nodeID = strings.TrimSpace(nodeID)
	groups, err := canonicalNodeMembershipGroups(input.Groups)
	if err != nil {
		return UpdatedNodeGroups{}, err
	}
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 || !namePattern.MatchString(input.ConfirmationName) || !validCertificateRotationRequestID(input.RequestID) {
		return UpdatedNodeGroups{}, fmt.Errorf("%w: node ID, expected_config_revision, exact confirmation_name, and a 16-128 character request_id are required", ErrInvalid)
	}
	operationAt := s.now().UTC()
	if operationAt.IsZero() {
		return UpdatedNodeGroups{}, fmt.Errorf("%w: group update requires a valid timestamp", ErrInvalid)
	}

	var snapshotNode Node
	var snapshotNetwork Network
	var replay UpdatedNodeGroups
	var replayed bool
	err = s.viewState(func(state State) error {
		var replayErr error
		replay, replayed, replayErr = findNodeGroupsReplay(state, nodeID, input, groups)
		if replayErr != nil || replayed {
			return replayErr
		}
		var ok bool
		snapshotNode, ok = findNode(state, nodeID)
		if !ok {
			return ErrNotFound
		}
		if snapshotNode.Status != "active" || snapshotNode.EnrolledAt == nil || snapshotNode.RevokedAt != nil {
			return fmt.Errorf("%w: group membership can only be changed for an active enrolled node", ErrConflict)
		}
		if snapshotNode.Name != input.ConfirmationName {
			return fmt.Errorf("%w: confirmation name does not exactly match the active node", ErrConflict)
		}
		if slices.Equal(snapshotNode.Groups, groups) {
			return fmt.Errorf("%w: requested groups already match the node certificate", ErrConflict)
		}
		snapshotNetwork, ok = findNetwork(state, snapshotNode.NetworkID)
		if !ok {
			return ErrNotFound
		}
		if snapshotNetwork.ConfigRevision != input.ExpectedConfigRevision {
			return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, snapshotNetwork.ConfigRevision)
		}
		if snapshotNetwork.CARotation.Phase != "" || snapshotNetwork.FirewallRollout.Phase != "" || routeTransferIncludesNode(snapshotNetwork.RouteTransfer, snapshotNode.ID) || routeProfileEditIncludesNode(snapshotNetwork.RouteProfileEdit, snapshotNode.ID) {
			return fmt.Errorf("%w: group membership is unavailable during a CA, firewall, or participating route lifecycle", ErrConflict)
		}
		return validateActiveCertificateRotationSource(snapshotNode, operationAt)
	})
	if err != nil || replayed {
		return replay, err
	}

	publicKey, err := publicKeyFromNodeCertificate(snapshotNode)
	if err != nil {
		return UpdatedNodeGroups{}, err
	}
	signingCACertificate, signingCAKey := networkSigningAuthority(snapshotNetwork)
	caKey, err := s.box.Open(signingCAKey)
	if err != nil {
		return UpdatedNodeGroups{}, err
	}
	desiredNode := snapshotNode
	desiredNode.Groups = slices.Clone(groups)
	certificate, fingerprint, expiresAt, signErr := s.signDistinctNodeCertificate(ctx, snapshotNetwork, desiredNode, signingCACertificate, string(caKey), publicKey)
	clear(caKey)
	if signErr != nil {
		return UpdatedNodeGroups{}, signErr
	}
	expiresAt = expiresAt.UTC()
	if strings.TrimSpace(certificate) == "" || !fingerprintPattern.MatchString(fingerprint) || !expiresAt.After(operationAt) {
		return UpdatedNodeGroups{}, errors.New("certificate issuer returned invalid group replacement metadata")
	}
	renewAfter := expiresAt.Add(-renewalWindow(time.Duration(snapshotNetwork.CertificateTTL) * time.Hour)).UTC()
	if renewAfter.IsZero() || !renewAfter.After(operationAt) || !renewAfter.Before(expiresAt) {
		return UpdatedNodeGroups{}, errors.New("certificate issuer returned invalid renewal metadata")
	}

	var result UpdatedNodeGroups
	err = s.updateState(func(state *State) error {
		committed, found, replayErr := findNodeGroupsReplay(*state, nodeID, input, groups)
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
			return fmt.Errorf("%w: active node lifecycle changed during group update", ErrConflict)
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
			return fmt.Errorf("%w: network lifecycle changed during group update", ErrConflict)
		}
		if !slices.Equal(node.Groups, snapshotNode.Groups) || node.Certificate != snapshotNode.Certificate || node.CertificateFingerprint != snapshotNode.CertificateFingerprint || node.CertificateGeneration != snapshotNode.CertificateGeneration || node.PublicKeyHash != snapshotNode.PublicKeyHash || !optionalTimesEqual(node.CertificateExpiresAt, snapshotNode.CertificateExpiresAt) || !optionalTimesEqual(node.CertificateRenewAfter, snapshotNode.CertificateRenewAfter) || node.RenewalClaimID != snapshotNode.RenewalClaimID || !optionalTimesEqual(node.RenewalClaimedAt, snapshotNode.RenewalClaimedAt) {
			return fmt.Errorf("%w: node certificate lifecycle changed during group update", ErrConflict)
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

		appendRevocation(state, node.ID, node.CertificateFingerprint, "certificate groups changed by administrator", operationAt, node.CertificateExpiresAt)
		node.Groups = slices.Clone(groups)
		node.Certificate = certificate
		node.CertificateFingerprint = fingerprint
		if state.Version >= ControlStateVersionCARotation {
			node.CertificateAuthoritySHA256 = ConfigDigest(signingCACertificate)
		}
		node.CertificateExpiresAt = &expiresAt
		node.CertificateRenewAfter = &renewAfter
		node.CertificateGeneration++
		node.LastRenewedAt = &operationAt
		node.RenewalClaimID = ""
		node.RenewalClaimedAt = nil
		network.ConfigRevision = nextRevision
		network.ConfigUpdatedAt = operationAt
		state.Issuances = append(state.Issuances, CertificateIssuance{Fingerprint: fingerprint, NodeID: node.ID, NetworkID: node.NetworkID, IssuedAt: operationAt, ExpiresAt: expiresAt})

		result = UpdatedNodeGroups{
			RequestID: input.RequestID, NodeID: node.ID, NetworkID: node.NetworkID, Name: node.Name, IP: node.IP,
			PreviousGroups: slices.Clone(snapshotNode.Groups), Groups: slices.Clone(node.Groups), UpdatedAt: operationAt,
			PreviousCertificateExpiresAt: previousExpiry, CertificateExpiresAt: expiresAt, CertificateRenewAfter: renewAfter,
			PreviousCertificateGeneration: previousGeneration, CertificateGeneration: node.CertificateGeneration,
			AgentRecoveryRecordsInvalidated: recoveriesInvalidated, PreviousCertificateBlocklisted: true, ConfigRevision: nextRevision,
		}
		event, err := newOptionalAttributedAudit(operationAt, nodeGroupsUpdatedAuditAction, "node", node.ID, nodeGroupsAuditDetails(result, input.ExpectedConfigRevision), actor)
		if err != nil {
			return err
		}
		state.Audit = append(state.Audit, event)
		return nil
	})
	return result, err
}

func groupsAuditArray(groups []string) []any {
	values := make([]any, len(groups))
	for index, group := range groups {
		values[index] = group
	}
	return values
}

func nodeGroupsAuditDetails(result UpdatedNodeGroups, expectedRevision int64) map[string]any {
	return map[string]any{
		"request_id": result.RequestID, "network_id": result.NetworkID, "name": result.Name, "ip": result.IP,
		"previous_groups": groupsAuditArray(result.PreviousGroups), "groups": groupsAuditArray(result.Groups),
		"updated_at": result.UpdatedAt.Format(time.RFC3339Nano), "previous_certificate_expires_at": result.PreviousCertificateExpiresAt.Format(time.RFC3339Nano),
		"certificate_expires_at": result.CertificateExpiresAt.Format(time.RFC3339Nano), "certificate_renew_after": result.CertificateRenewAfter.Format(time.RFC3339Nano),
		"previous_certificate_generation": result.PreviousCertificateGeneration, "certificate_generation": result.CertificateGeneration,
		"expected_config_revision": expectedRevision, "config_revision": result.ConfigRevision,
		"agent_recovery_records_invalidated": result.AgentRecoveryRecordsInvalidated, "previous_certificate_blocklisted": result.PreviousCertificateBlocklisted,
	}
}

func findNodeGroupsReplay(state State, nodeID string, input UpdateNodeGroupsInput, groups []string) (UpdatedNodeGroups, bool, error) {
	for _, event := range state.Audit {
		if event.Action != nodeGroupsUpdatedAuditAction {
			continue
		}
		requestID, ok := event.Details["request_id"].(string)
		if !ok || requestID != input.RequestID {
			continue
		}
		receipt, expectedRevision, err := parseNodeGroupsEvent(event)
		if err != nil {
			return UpdatedNodeGroups{}, false, fmt.Errorf("persisted group update receipt is invalid: %w", err)
		}
		if event.ResourceID != nodeID || receipt.Name != input.ConfirmationName || expectedRevision != input.ExpectedConfigRevision || !slices.Equal(receipt.Groups, groups) {
			return UpdatedNodeGroups{}, false, fmt.Errorf("%w: request_id is already bound to a different group update", ErrConflict)
		}
		return receipt, true, nil
	}
	return UpdatedNodeGroups{}, false, nil
}

func parseAuditGroups(value any) ([]string, bool) {
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	groups := make([]string, len(raw))
	for index, item := range raw {
		group, ok := item.(string)
		if !ok {
			return nil, false
		}
		groups[index] = group
	}
	return groups, validCanonicalNodeGroups(groups)
}

func parseNodeGroupsEvent(event AuditEvent) (UpdatedNodeGroups, int64, error) {
	if event.Resource != "node" || !validPersistedID(event.ResourceID) {
		return UpdatedNodeGroups{}, 0, errors.New("invalid resource metadata")
	}
	requestID, requestOK := event.Details["request_id"].(string)
	networkID, networkOK := event.Details["network_id"].(string)
	name, nameOK := event.Details["name"].(string)
	ip, ipOK := event.Details["ip"].(string)
	previousGroups, previousGroupsOK := parseAuditGroups(event.Details["previous_groups"])
	groups, groupsOK := parseAuditGroups(event.Details["groups"])
	updatedAt, updatedOK := auditRFC3339Time(event.Details["updated_at"])
	previousExpiry, previousExpiryOK := auditRFC3339Time(event.Details["previous_certificate_expires_at"])
	expiresAt, expiresOK := auditRFC3339Time(event.Details["certificate_expires_at"])
	renewAfter, renewOK := auditRFC3339Time(event.Details["certificate_renew_after"])
	previousGeneration, previousGenerationOK := auditNonNegativeInteger(event.Details["previous_certificate_generation"])
	generation, generationOK := auditNonNegativeInteger(event.Details["certificate_generation"])
	expectedRevision, expectedRevisionOK := auditNonNegativeInteger(event.Details["expected_config_revision"])
	configRevision, configRevisionOK := auditNonNegativeInteger(event.Details["config_revision"])
	recoveries, recoveriesOK := auditNonNegativeInteger(event.Details["agent_recovery_records_invalidated"])
	blocklisted, blocklistedOK := event.Details["previous_certificate_blocklisted"].(bool)
	parsedIP := net.ParseIP(ip)
	if !requestOK || !validCertificateRotationRequestID(requestID) || !networkOK || !validPersistedID(networkID) || !nameOK || !namePattern.MatchString(name) || !ipOK || parsedIP == nil || parsedIP.To4() == nil || parsedIP.To4().String() != ip || !previousGroupsOK || !groupsOK || slices.Equal(previousGroups, groups) || !updatedOK || !event.At.Equal(updatedAt) || !previousExpiryOK || !expiresOK || !renewOK || !expiresAt.After(updatedAt) || !renewAfter.After(updatedAt) || !renewAfter.Before(expiresAt) || !previousGenerationOK || previousGeneration < 1 || !generationOK || generation != previousGeneration+1 || !expectedRevisionOK || expectedRevision < 1 || !configRevisionOK || configRevision != expectedRevision+1 || !recoveriesOK || !blocklistedOK || !blocklisted {
		return UpdatedNodeGroups{}, 0, errors.New("identity, groups, lifecycle, or transition details are invalid")
	}
	return UpdatedNodeGroups{
		RequestID: requestID, NodeID: event.ResourceID, NetworkID: networkID, Name: name, IP: ip,
		PreviousGroups: previousGroups, Groups: groups, UpdatedAt: updatedAt,
		PreviousCertificateExpiresAt: previousExpiry, CertificateExpiresAt: expiresAt, CertificateRenewAfter: renewAfter,
		PreviousCertificateGeneration: previousGeneration, CertificateGeneration: generation,
		AgentRecoveryRecordsInvalidated: int(recoveries), PreviousCertificateBlocklisted: blocklisted, ConfigRevision: configRevision,
	}, expectedRevision, nil
}

func validateNodeGroupAudits(state State) error {
	requestIDs := make(map[string]struct{})
	for _, event := range state.Audit {
		if event.Action != nodeGroupsUpdatedAuditAction {
			continue
		}
		receipt, _, err := parseNodeGroupsEvent(event)
		if err != nil {
			return fmt.Errorf("node group audit %q: %w", event.ID, err)
		}
		if _, duplicate := requestIDs[receipt.RequestID]; duplicate {
			return fmt.Errorf("duplicate node group request_id %q", receipt.RequestID)
		}
		requestIDs[receipt.RequestID] = struct{}{}
	}
	return nil
}
