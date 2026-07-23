package control

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const nodeRevocationCommittedAuditAction = "node.revocation_committed"

// RevokeNodeInput binds the trust cutoff to the exact node and visible signed
// network state. RequestID makes a committed response safe to recover without
// repeating revocation side effects.
type RevokeNodeInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	ConfirmationName       string `json:"confirmation_name"`
	RequestID              string `json:"request_id"`
}

// RevokedNodeReceipt is durable, non-secret evidence for one administrator
// revocation. Certificate material and fingerprints deliberately remain out of
// the response; the bounded blocklist count and signed revision prove the
// relevant transition without expanding the API's secret surface.
type RevokedNodeReceipt struct {
	RequestID                        string    `json:"request_id"`
	NodeID                           string    `json:"node_id"`
	NetworkID                        string    `json:"network_id"`
	Name                             string    `json:"name"`
	IP                               string    `json:"ip"`
	Role                             string    `json:"role"`
	RevokedAt                        time.Time `json:"revoked_at"`
	WasEnrolled                      bool      `json:"was_enrolled"`
	EnrollmentRecordsInvalidated     int       `json:"enrollment_records_invalidated"`
	AgentRecoveryRecordsInvalidated  int       `json:"agent_recovery_records_invalidated"`
	BlocklistEntriesAdded            int       `json:"blocklist_entries_added"`
	RelayAssignmentRemoved           bool      `json:"relay_assignment_removed"`
	FirewallCanaryRemoved            bool      `json:"firewall_canary_removed"`
	FirewallRolloutAutoRolledBack    bool      `json:"firewall_rollout_auto_rolled_back"`
	CredentialsInvalidated           bool      `json:"credentials_invalidated"`
	RoutedSubnetReservationsReleased int       `json:"routed_subnet_reservations_released"`
	ConfigRevision                   int64     `json:"config_revision"`
}

func (s *Service) RevokeNodeWithReceipt(nodeID string, input RevokeNodeInput) (RevokedNodeReceipt, error) {
	return s.revokeNodeWithReceipt(nil, nodeID, input)
}

func (s *Service) RevokeNodeWithReceiptAs(actor Actor, nodeID string, input RevokeNodeInput) (RevokedNodeReceipt, error) {
	if err := validateActor(actor); err != nil {
		return RevokedNodeReceipt{}, err
	}
	return s.revokeNodeWithReceipt(&actor, nodeID, input)
}

func (s *Service) revokeNodeWithReceipt(actor *Actor, nodeID string, input RevokeNodeInput) (RevokedNodeReceipt, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 || !namePattern.MatchString(input.ConfirmationName) || !validNodeRevocationRequestID(input.RequestID) {
		return RevokedNodeReceipt{}, fmt.Errorf("%w: node ID, expected_config_revision, exact confirmation_name, and a 16-128 character request_id are required", ErrInvalid)
	}
	_, _, receipt, err := s.revokeOrReplaceNode(actor, nodeID, false, input.ExpectedConfigRevision, &input)
	if err != nil {
		return RevokedNodeReceipt{}, err
	}
	if receipt == nil {
		return RevokedNodeReceipt{}, errors.New("node revocation committed without a receipt")
	}
	return *receipt, nil
}

func validNodeRevocationRequestID(value string) bool {
	return len(value) >= 16 && validPersistedID(value)
}

func nodeRevocationAuditDetails(receipt RevokedNodeReceipt, expectedRevision int64) map[string]any {
	return map[string]any{
		"request_id": receipt.RequestID, "network_id": receipt.NetworkID, "name": receipt.Name, "ip": receipt.IP, "role": receipt.Role,
		"revoked_at": receipt.RevokedAt.Format(time.RFC3339Nano), "was_enrolled": receipt.WasEnrolled,
		"expected_config_revision": expectedRevision, "config_revision": receipt.ConfigRevision,
		"enrollment_records_invalidated":     receipt.EnrollmentRecordsInvalidated,
		"agent_recovery_records_invalidated": receipt.AgentRecoveryRecordsInvalidated,
		"blocklist_entries_added":            receipt.BlocklistEntriesAdded, "relay_assignment_removed": receipt.RelayAssignmentRemoved,
		"firewall_canary_removed":             receipt.FirewallCanaryRemoved,
		"firewall_rollout_auto_rolled_back":   receipt.FirewallRolloutAutoRolledBack,
		"credentials_invalidated":             receipt.CredentialsInvalidated,
		"routed_subnet_reservations_released": receipt.RoutedSubnetReservationsReleased,
	}
}

func findNodeRevocationReplay(state State, nodeID string, input RevokeNodeInput) (RevokedNodeReceipt, bool, error) {
	for _, event := range state.Audit {
		if event.Action != nodeRevocationCommittedAuditAction {
			continue
		}
		requestID, ok := event.Details["request_id"].(string)
		if !ok || requestID != input.RequestID {
			continue
		}
		receipt, expectedRevision, err := parseNodeRevocationEvent(event)
		if err != nil {
			return RevokedNodeReceipt{}, false, fmt.Errorf("persisted node revocation receipt is invalid: %w", err)
		}
		if event.ResourceID != nodeID || receipt.Name != input.ConfirmationName || expectedRevision != input.ExpectedConfigRevision {
			return RevokedNodeReceipt{}, false, fmt.Errorf("%w: request_id is already bound to a different node revocation", ErrConflict)
		}
		return receipt, true, nil
	}
	return RevokedNodeReceipt{}, false, nil
}

func validateNodeRevocationAudits(state State) error {
	requestIDs := make(map[string]struct{})
	for _, event := range state.Audit {
		if event.Action != nodeRevocationCommittedAuditAction {
			continue
		}
		receipt, _, err := parseNodeRevocationEvent(event)
		if err != nil {
			return fmt.Errorf("node revocation audit %q: %w", event.ID, err)
		}
		if _, duplicate := requestIDs[receipt.RequestID]; duplicate {
			return fmt.Errorf("duplicate node revocation request_id %q", receipt.RequestID)
		}
		requestIDs[receipt.RequestID] = struct{}{}
	}
	return nil
}

func parseNodeRevocationEvent(event AuditEvent) (RevokedNodeReceipt, int64, error) {
	required := map[string]struct{}{
		"request_id": {}, "network_id": {}, "name": {}, "ip": {}, "role": {}, "revoked_at": {}, "was_enrolled": {},
		"expected_config_revision": {}, "config_revision": {}, "enrollment_records_invalidated": {},
		"agent_recovery_records_invalidated": {}, "blocklist_entries_added": {}, "relay_assignment_removed": {},
		"firewall_canary_removed": {}, "firewall_rollout_auto_rolled_back": {}, "credentials_invalidated": {},
		"routed_subnet_reservations_released": {},
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
			return RevokedNodeReceipt{}, 0, fmt.Errorf("unexpected detail %q", key)
		}
	}
	for key := range required {
		if _, ok := event.Details[key]; !ok {
			return RevokedNodeReceipt{}, 0, fmt.Errorf("missing detail %q", key)
		}
	}
	if event.Resource != "node" || !validPersistedID(event.ResourceID) {
		return RevokedNodeReceipt{}, 0, errors.New("invalid resource metadata")
	}
	requestID, requestOK := event.Details["request_id"].(string)
	networkID, networkOK := event.Details["network_id"].(string)
	name, nameOK := event.Details["name"].(string)
	ip, ipOK := event.Details["ip"].(string)
	role, roleOK := event.Details["role"].(string)
	revokedAt, revokedOK := auditRFC3339Time(event.Details["revoked_at"])
	wasEnrolled, enrolledOK := event.Details["was_enrolled"].(bool)
	expectedRevision, expectedOK := auditNonNegativeInteger(event.Details["expected_config_revision"])
	configRevision, revisionOK := auditNonNegativeInteger(event.Details["config_revision"])
	enrollments, enrollmentsOK := auditNonNegativeInteger(event.Details["enrollment_records_invalidated"])
	recoveries, recoveriesOK := auditNonNegativeInteger(event.Details["agent_recovery_records_invalidated"])
	blocklist, blocklistOK := auditNonNegativeInteger(event.Details["blocklist_entries_added"])
	relayRemoved, relayOK := event.Details["relay_assignment_removed"].(bool)
	canaryRemoved, canaryOK := event.Details["firewall_canary_removed"].(bool)
	autoRolledBack, rollbackOK := event.Details["firewall_rollout_auto_rolled_back"].(bool)
	credentialsInvalidated, credentialsOK := event.Details["credentials_invalidated"].(bool)
	routesReleased, routesOK := auditNonNegativeInteger(event.Details["routed_subnet_reservations_released"])
	parsedIP := net.ParseIP(ip)
	if !requestOK || !validNodeRevocationRequestID(requestID) || !networkOK || !validPersistedID(networkID) || !nameOK || !namePattern.MatchString(name) || !ipOK || parsedIP == nil || parsedIP.To4() == nil || parsedIP.To4().String() != ip || !roleOK || role != "member" && role != "lighthouse" || !revokedOK || !event.At.Equal(revokedAt) || !enrolledOK || !expectedOK || expectedRevision < 1 || !revisionOK || configRevision != expectedRevision+1 || !enrollmentsOK || !recoveriesOK || !blocklistOK || wasEnrolled && blocklist < 1 || !wasEnrolled && blocklist != 0 || !relayOK || !canaryOK || !rollbackOK || autoRolledBack && !canaryRemoved || !credentialsOK || !credentialsInvalidated || !routesOK {
		return RevokedNodeReceipt{}, 0, errors.New("identity, lifecycle, or transition details are invalid")
	}
	return RevokedNodeReceipt{
		RequestID: requestID, NodeID: event.ResourceID, NetworkID: networkID, Name: name, IP: ip, Role: role,
		RevokedAt: revokedAt, WasEnrolled: wasEnrolled, EnrollmentRecordsInvalidated: int(enrollments),
		AgentRecoveryRecordsInvalidated: int(recoveries), BlocklistEntriesAdded: int(blocklist),
		RelayAssignmentRemoved: relayRemoved, FirewallCanaryRemoved: canaryRemoved,
		FirewallRolloutAutoRolledBack: autoRolledBack, CredentialsInvalidated: credentialsInvalidated,
		RoutedSubnetReservationsReleased: int(routesReleased), ConfigRevision: configRevision,
	}, expectedRevision, nil
}
