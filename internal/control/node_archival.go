package control

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	nodeArchivedAuditAction            = "node.archived"
	nodeArchiveCertificateSafetyMargin = 5 * time.Minute
)

// ArchiveNodeInput binds irreversible history cleanup to the exact visible
// network revision and node name.
type ArchiveNodeInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	ConfirmationName       string `json:"confirmation_name"`
}

// ArchivedNode is the durable control-plane receipt for removing a revoked
// node after all of its certificate authority has expired.
type ArchivedNode struct {
	NodeID                           string     `json:"node_id"`
	NetworkID                        string     `json:"network_id"`
	Name                             string     `json:"name"`
	IP                               string     `json:"ip"`
	Role                             string     `json:"role"`
	RevokedAt                        time.Time  `json:"revoked_at"`
	ArchivedAt                       time.Time  `json:"archived_at"`
	LastCertificateExpiredAt         *time.Time `json:"last_certificate_expired_at,omitempty"`
	EnrollmentRecordsRemoved         int        `json:"enrollment_records_removed"`
	AgentRecoveryRecordsRemoved      int        `json:"agent_recovery_records_removed"`
	CertificateIssuancesRemoved      int        `json:"certificate_issuances_removed"`
	RevocationsRemoved               int        `json:"revocations_removed"`
	BlocklistEntriesRemoved          int        `json:"blocklist_entries_removed"`
	RoutedSubnetReservationsReleased int        `json:"routed_subnet_reservations_released"`
	ConfigRevision                   int64      `json:"config_revision"`
}

func (s *Service) ArchiveNode(nodeID string, input ArchiveNodeInput) (ArchivedNode, error) {
	return s.archiveNode(nil, nodeID, input)
}

func (s *Service) ArchiveNodeAs(actor Actor, nodeID string, input ArchiveNodeInput) (ArchivedNode, error) {
	if err := validateActor(actor); err != nil {
		return ArchivedNode{}, err
	}
	return s.archiveNode(&actor, nodeID, input)
}

func (s *Service) archiveNode(actor *Actor, nodeID string, input ArchiveNodeInput) (ArchivedNode, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 || !namePattern.MatchString(input.ConfirmationName) {
		return ArchivedNode{}, fmt.Errorf("%w: node ID, expected_config_revision, and exact confirmation_name are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return ArchivedNode{}, fmt.Errorf("%w: node archival requires a valid timestamp", ErrInvalid)
	}
	var result ArchivedNode
	err := s.updateState(func(state *State) error {
		nodeIndex := -1
		var node Node
		for index, candidate := range state.Nodes {
			if candidate.ID == nodeID {
				nodeIndex = index
				node = candidate
				break
			}
		}
		if nodeIndex < 0 {
			return ErrNotFound
		}
		if node.Status != "revoked" || node.RevokedAt == nil {
			return fmt.Errorf("%w: only a revoked node can be archived", ErrConflict)
		}
		if node.Name != input.ConfirmationName {
			return fmt.Errorf("%w: confirmation name does not exactly match the revoked node", ErrConflict)
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
		if network.ConfigRevision != input.ExpectedConfigRevision {
			return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
		}
		if firewallPolicyReferencesNode(network.FirewallPolicy, node.ID) || network.FirewallRollout.Phase != "" && firewallPolicyReferencesNode(network.FirewallRollout.TargetPolicy, node.ID) {
			return fmt.Errorf("%w: remove firewall rules that reference this node before archiving its identity", ErrConflict)
		}

		lastExpiry := time.Time{}
		if node.CertificateExpiresAt != nil {
			lastExpiry = node.CertificateExpiresAt.UTC()
		}
		issuanceRecords := 0
		for _, issuance := range state.Issuances {
			if issuance.NodeID != node.ID {
				continue
			}
			issuanceRecords++
			if issuance.ExpiresAt.After(lastExpiry) {
				lastExpiry = issuance.ExpiresAt.UTC()
			}
		}
		revocationRecords := 0
		for _, revocation := range state.Revocations {
			if revocation.NodeID != node.ID {
				continue
			}
			revocationRecords++
			if revocation.ExpiresAt == nil {
				return fmt.Errorf("%w: revoked node has a permanent or legacy blocklist entry without an expiry", ErrConflict)
			}
			if revocation.ExpiresAt.After(lastExpiry) {
				lastExpiry = revocation.ExpiresAt.UTC()
			}
		}
		enrolled := node.EnrolledAt != nil
		if enrolled {
			if issuanceRecords == 0 || revocationRecords == 0 || lastExpiry.IsZero() {
				return fmt.Errorf("%w: enrolled revoked node is missing complete certificate history", ErrConflict)
			}
			eligibleAt := lastExpiry.Add(nodeArchiveCertificateSafetyMargin)
			if now.Before(eligibleAt) {
				return fmt.Errorf("%w: certificate blocklist authority remains required until %s", ErrConflict, eligibleAt.Format(time.RFC3339Nano))
			}
		} else if issuanceRecords != 0 || revocationRecords != 0 || !lastExpiry.IsZero() {
			return fmt.Errorf("%w: never-enrolled revoked node has unexpected certificate history", ErrConflict)
		}

		enrollmentRecords := 0
		for _, enrollment := range state.Enrollments {
			if enrollment.NodeID == node.ID {
				enrollmentRecords++
			}
		}
		recoveryRecords := 0
		for _, recovery := range state.AgentRecoveries {
			if recovery.NodeID == node.ID {
				recoveryRecords++
			}
		}

		if revocationRecords > 0 {
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
		}
		lastExpiryDetail := ""
		if !lastExpiry.IsZero() {
			lastExpiryDetail = lastExpiry.Format(time.RFC3339Nano)
		}
		details := map[string]any{
			"network_id": node.NetworkID, "name": node.Name, "ip": node.IP, "role": node.Role,
			"revoked_at": node.RevokedAt.UTC().Format(time.RFC3339Nano), "enrolled": enrolled,
			"last_certificate_expired_at": lastExpiryDetail,
			"enrollment_records_removed":  enrollmentRecords, "agent_recovery_records_removed": recoveryRecords,
			"certificate_issuances_removed": issuanceRecords, "revocations_removed": revocationRecords,
			"blocklist_entries_removed": revocationRecords, "routed_subnet_reservations_released": len(node.RoutedSubnets),
			"certificate_material_removed": true, "agent_credentials_invalidated": true, "all_certificate_records_expired": true,
			"config_revision": network.ConfigRevision,
		}
		event, err := newOptionalAttributedAudit(now, nodeArchivedAuditAction, "node", node.ID, details, actor)
		if err != nil {
			return err
		}

		nodeIDs := map[string]struct{}{node.ID: {}}
		state.Enrollments = deleteEnrollmentsForNodes(state.Enrollments, nodeIDs)
		state.AgentRecoveries = deleteRecoveriesForNodes(state.AgentRecoveries, nodeIDs)
		state.Issuances = deleteIssuancesForNode(state.Issuances, node.ID)
		state.Revocations = deleteRevocationsForNode(state.Revocations, node.ID)
		state.Nodes = append(state.Nodes[:nodeIndex], state.Nodes[nodeIndex+1:]...)
		state.Audit = append(state.Audit, event)

		var lastExpiryPointer *time.Time
		if !lastExpiry.IsZero() {
			expiry := lastExpiry.UTC()
			lastExpiryPointer = &expiry
		}
		result = ArchivedNode{
			NodeID: node.ID, NetworkID: node.NetworkID, Name: node.Name, IP: node.IP, Role: node.Role,
			RevokedAt: node.RevokedAt.UTC(), ArchivedAt: now, LastCertificateExpiredAt: lastExpiryPointer,
			EnrollmentRecordsRemoved: enrollmentRecords, AgentRecoveryRecordsRemoved: recoveryRecords,
			CertificateIssuancesRemoved: issuanceRecords, RevocationsRemoved: revocationRecords, BlocklistEntriesRemoved: revocationRecords,
			RoutedSubnetReservationsReleased: len(node.RoutedSubnets), ConfigRevision: network.ConfigRevision,
		}
		return nil
	})
	return result, err
}

func deleteIssuancesForNode(values []CertificateIssuance, nodeID string) []CertificateIssuance {
	kept := values[:0]
	for _, value := range values {
		if value.NodeID != nodeID {
			kept = append(kept, value)
		}
	}
	return kept
}

func deleteRevocationsForNode(values []CertificateRevocation, nodeID string) []CertificateRevocation {
	kept := values[:0]
	for _, value := range values {
		if value.NodeID != nodeID {
			kept = append(kept, value)
		}
	}
	return kept
}

func validateArchivedNodeTombstones(state State) error {
	archived := make(map[string]struct{})
	for _, event := range state.Audit {
		if event.Action != nodeArchivedAuditAction {
			continue
		}
		if event.Resource != "node" || !validPersistedID(event.ResourceID) {
			return fmt.Errorf("archived node tombstone has invalid resource metadata")
		}
		if _, duplicate := archived[event.ResourceID]; duplicate {
			return fmt.Errorf("duplicate archived node tombstone for %q", event.ResourceID)
		}
		archived[event.ResourceID] = struct{}{}
		if _, exists := findNode(state, event.ResourceID); exists {
			return fmt.Errorf("archived node tombstone %q conflicts with live node", event.ResourceID)
		}
		if err := validateArchivedNodeTombstone(event); err != nil {
			return fmt.Errorf("archived node tombstone %q: %w", event.ResourceID, err)
		}
	}
	return nil
}

func validateArchivedNodeTombstone(event AuditEvent) error {
	required := map[string]struct{}{
		"network_id": {}, "name": {}, "ip": {}, "role": {}, "revoked_at": {}, "enrolled": {}, "last_certificate_expired_at": {},
		"enrollment_records_removed": {}, "agent_recovery_records_removed": {}, "certificate_issuances_removed": {},
		"revocations_removed": {}, "blocklist_entries_removed": {}, "routed_subnet_reservations_released": {},
		"certificate_material_removed": {}, "agent_credentials_invalidated": {}, "all_certificate_records_expired": {}, "config_revision": {},
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
			return fmt.Errorf("unexpected detail %q", key)
		}
	}
	for key := range required {
		if _, ok := event.Details[key]; !ok {
			return fmt.Errorf("missing detail %q", key)
		}
	}

	networkID, networkOK := event.Details["network_id"].(string)
	name, nameOK := event.Details["name"].(string)
	ip, ipOK := event.Details["ip"].(string)
	role, roleOK := event.Details["role"].(string)
	revokedAt, revokedOK := auditRFC3339Time(event.Details["revoked_at"])
	lastExpiryText, expiryOK := event.Details["last_certificate_expired_at"].(string)
	enrolled, enrolledOK := event.Details["enrolled"].(bool)
	configRevision, revisionOK := auditNonNegativeInteger(event.Details["config_revision"])
	if !networkOK || !validPersistedID(networkID) || !nameOK || !namePattern.MatchString(name) || !ipOK || net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil || net.ParseIP(ip).To4().String() != ip || !roleOK || role != "member" && role != "lighthouse" || !revokedOK || revokedAt.After(event.At) || !expiryOK || !enrolledOK || !revisionOK || configRevision < 1 {
		return fmt.Errorf("identity or lifecycle details are invalid")
	}
	counts := make(map[string]int64)
	for _, key := range []string{"enrollment_records_removed", "agent_recovery_records_removed", "certificate_issuances_removed", "revocations_removed", "blocklist_entries_removed", "routed_subnet_reservations_released"} {
		value, ok := auditNonNegativeInteger(event.Details[key])
		if !ok {
			return fmt.Errorf("detail %q is not a non-negative integer", key)
		}
		counts[key] = value
	}
	if counts["blocklist_entries_removed"] != counts["revocations_removed"] || counts["routed_subnet_reservations_released"] > maxRoutedSubnetsPerNode {
		return fmt.Errorf("removal counts are inconsistent")
	}
	for _, key := range []string{"certificate_material_removed", "agent_credentials_invalidated", "all_certificate_records_expired"} {
		if value, ok := event.Details[key].(bool); !ok || !value {
			return fmt.Errorf("detail %q is not true", key)
		}
	}
	if !enrolled {
		if lastExpiryText != "" || counts["certificate_issuances_removed"] != 0 || counts["revocations_removed"] != 0 {
			return fmt.Errorf("never-enrolled tombstone carries certificate history")
		}
		return nil
	}
	lastExpiry, err := time.Parse(time.RFC3339Nano, lastExpiryText)
	if err != nil || counts["certificate_issuances_removed"] < 1 || counts["revocations_removed"] < 1 || event.At.Before(lastExpiry.UTC().Add(nodeArchiveCertificateSafetyMargin)) {
		return fmt.Errorf("enrolled tombstone was archived before certificate authority expired")
	}
	return nil
}

func auditRFC3339Time(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed.UTC(), err == nil && !parsed.IsZero()
	case time.Time:
		return typed.UTC(), !typed.IsZero()
	default:
		return time.Time{}, false
	}
}
