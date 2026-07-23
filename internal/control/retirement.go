package control

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

const networkRetiredAuditAction = "network.retired"

// RetireNetworkInput binds an irreversible network retirement to the exact
// authoritative revision and a human-entered network name.
type RetireNetworkInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	ConfirmationName       string `json:"confirmation_name"`
}

// RetiredNetwork is the durable control-plane retirement receipt. NodeIDs are
// intentionally private to the HTTP adapter so it can remove reconstructible
// runtime observations after the control transaction commits.
type RetiredNetwork struct {
	NetworkID                   string    `json:"network_id"`
	Name                        string    `json:"name"`
	CIDR                        string    `json:"cidr"`
	ConfigRevision              int64     `json:"config_revision"`
	RetiredAt                   time.Time `json:"retired_at"`
	NodeCount                   int       `json:"node_count"`
	PendingNodes                int       `json:"pending_nodes"`
	ActiveNodes                 int       `json:"active_nodes"`
	RevokedNodes                int       `json:"revoked_nodes"`
	CredentialsInvalidated      bool      `json:"credentials_invalidated"`
	EncryptedKeyMaterialRemoved bool      `json:"encrypted_key_material_removed"`
	NameCIDRPermanentlyReserved bool      `json:"name_cidr_permanently_reserved"`
	NodeIDs                     []string  `json:"-"`
}

type retiredNetworkReservation struct {
	id             string
	name           string
	cidr           string
	configRevision int64
	nodeCount      int64
	pendingNodes   int64
	activeNodes    int64
	revokedNodes   int64
}

func (s *Service) RetireNetwork(networkID string, input RetireNetworkInput) (RetiredNetwork, error) {
	return s.retireNetwork(nil, networkID, input)
}

func (s *Service) RetireNetworkAs(actor Actor, networkID string, input RetireNetworkInput) (RetiredNetwork, error) {
	if err := validateActor(actor); err != nil {
		return RetiredNetwork{}, err
	}
	return s.retireNetwork(&actor, networkID, input)
}

func (s *Service) retireNetwork(actor *Actor, networkID string, input RetireNetworkInput) (RetiredNetwork, error) {
	if !validPersistedID(networkID) || input.ExpectedConfigRevision < 1 || !namePattern.MatchString(input.ConfirmationName) {
		return RetiredNetwork{}, fmt.Errorf("%w: network ID, expected_config_revision, and exact confirmation_name are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return RetiredNetwork{}, fmt.Errorf("%w: network retirement requires a valid timestamp", ErrInvalid)
	}
	var result RetiredNetwork
	err := s.updateState(func(state *State) error {
		networkIndex := -1
		var network Network
		for index, candidate := range state.Networks {
			if candidate.ID == networkID {
				networkIndex = index
				network = candidate
				break
			}
		}
		if networkIndex < 0 {
			return ErrNotFound
		}
		if network.Name != input.ConfirmationName {
			return fmt.Errorf("%w: confirmation name does not exactly match the network", ErrConflict)
		}
		if network.ConfigRevision != input.ExpectedConfigRevision {
			return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
		}

		nodeIDs := make(map[string]struct{})
		var pendingNodes, activeNodes, revokedNodes int
		for _, node := range state.Nodes {
			if node.NetworkID != networkID {
				continue
			}
			nodeIDs[node.ID] = struct{}{}
			switch node.Status {
			case "pending":
				pendingNodes++
			case "active":
				activeNodes++
			case "revoked":
				revokedNodes++
			}
		}
		enrollmentRecords := 0
		for _, enrollment := range state.Enrollments {
			if _, found := nodeIDs[enrollment.NodeID]; found {
				enrollmentRecords++
			}
		}
		recoveryRecords := 0
		for _, recovery := range state.AgentRecoveries {
			if _, found := nodeIDs[recovery.NodeID]; found {
				recoveryRecords++
			}
		}
		issuanceRecords := 0
		for _, issuance := range state.Issuances {
			if issuance.NetworkID == networkID {
				issuanceRecords++
			}
		}
		revocationRecords := 0
		for _, revocation := range state.Revocations {
			if revocation.NetworkID == networkID {
				revocationRecords++
			}
		}
		details := map[string]any{
			"name": network.Name, "cidr": network.CIDR, "config_revision": network.ConfigRevision,
			"node_count": len(nodeIDs), "pending_nodes": pendingNodes, "active_nodes": activeNodes, "revoked_nodes": revokedNodes,
			"enrollment_records_removed": enrollmentRecords, "agent_recovery_records_removed": recoveryRecords,
			"certificate_issuances_removed": issuanceRecords, "revocations_removed": revocationRecords,
			"credentials_invalidated": true, "encrypted_key_material_removed": true, "name_cidr_permanently_reserved": true,
		}
		event, err := newOptionalAttributedAudit(now, networkRetiredAuditAction, "network", networkID, details, actor)
		if err != nil {
			return err
		}

		state.Networks = append(state.Networks[:networkIndex], state.Networks[networkIndex+1:]...)
		state.Nodes = deleteNodesForNetwork(state.Nodes, networkID)
		state.Enrollments = deleteEnrollmentsForNodes(state.Enrollments, nodeIDs)
		state.AgentRecoveries = deleteRecoveriesForNodes(state.AgentRecoveries, nodeIDs)
		state.Issuances = deleteIssuancesForNetwork(state.Issuances, networkID)
		state.Revocations = deleteRevocationsForNetwork(state.Revocations, networkID)
		state.Audit = append(state.Audit, event)

		retiredNodeIDs := make([]string, 0, len(nodeIDs))
		for nodeID := range nodeIDs {
			retiredNodeIDs = append(retiredNodeIDs, nodeID)
		}
		sort.Strings(retiredNodeIDs)
		result = RetiredNetwork{
			NetworkID: network.ID, Name: network.Name, CIDR: network.CIDR, ConfigRevision: network.ConfigRevision, RetiredAt: now,
			NodeCount: len(nodeIDs), PendingNodes: pendingNodes, ActiveNodes: activeNodes, RevokedNodes: revokedNodes,
			CredentialsInvalidated: true, EncryptedKeyMaterialRemoved: true, NameCIDRPermanentlyReserved: true, NodeIDs: retiredNodeIDs,
		}
		return nil
	})
	return result, err
}

func deleteNodesForNetwork(values []Node, networkID string) []Node {
	kept := values[:0]
	for _, value := range values {
		if value.NetworkID != networkID {
			kept = append(kept, value)
		}
	}
	return kept
}

func deleteEnrollmentsForNodes(values []EnrollmentToken, nodeIDs map[string]struct{}) []EnrollmentToken {
	kept := values[:0]
	for _, value := range values {
		if _, remove := nodeIDs[value.NodeID]; !remove {
			kept = append(kept, value)
		}
	}
	return kept
}

func deleteRecoveriesForNodes(values []AgentRecoveryToken, nodeIDs map[string]struct{}) []AgentRecoveryToken {
	kept := values[:0]
	for _, value := range values {
		if _, remove := nodeIDs[value.NodeID]; !remove {
			kept = append(kept, value)
		}
	}
	return kept
}

func deleteIssuancesForNetwork(values []CertificateIssuance, networkID string) []CertificateIssuance {
	kept := values[:0]
	for _, value := range values {
		if value.NetworkID != networkID {
			kept = append(kept, value)
		}
	}
	return kept
}

func deleteRevocationsForNetwork(values []CertificateRevocation, networkID string) []CertificateRevocation {
	kept := values[:0]
	for _, value := range values {
		if value.NetworkID != networkID {
			kept = append(kept, value)
		}
	}
	return kept
}

func retiredNetworkReservationConflict(state State, name, cidr string) (bool, error) {
	for _, event := range state.Audit {
		reservation, found, err := parseRetiredNetworkReservation(event)
		if err != nil {
			return false, err
		}
		if found && (strings.EqualFold(reservation.name, name) || cidrsOverlap(reservation.cidr, cidr)) {
			return true, nil
		}
	}
	return false, nil
}

func validateRetiredNetworkReservations(state State) error {
	reservations := make([]retiredNetworkReservation, 0)
	for _, event := range state.Audit {
		reservation, found, err := parseRetiredNetworkReservation(event)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		for _, network := range state.Networks {
			if network.ID == reservation.id || strings.EqualFold(network.Name, reservation.name) || cidrsOverlap(network.CIDR, reservation.cidr) {
				return fmt.Errorf("retired network %q conflicts with active network %q", reservation.id, network.ID)
			}
		}
		for _, previous := range reservations {
			if previous.id == reservation.id || strings.EqualFold(previous.name, reservation.name) || cidrsOverlap(previous.cidr, reservation.cidr) {
				return fmt.Errorf("retired network reservation %q is duplicated", reservation.id)
			}
		}
		reservations = append(reservations, reservation)
	}
	return nil
}

func parseRetiredNetworkReservation(event AuditEvent) (retiredNetworkReservation, bool, error) {
	if event.Action != networkRetiredAuditAction {
		return retiredNetworkReservation{}, false, nil
	}
	if event.Resource != "network" {
		return retiredNetworkReservation{}, false, fmt.Errorf("network retirement audit %q has the wrong resource", event.ID)
	}
	name, nameOK := event.Details["name"].(string)
	cidr, cidrOK := event.Details["cidr"].(string)
	if !nameOK || !namePattern.MatchString(name) || !cidrOK || !validRetiredNetworkCIDR(cidr) {
		return retiredNetworkReservation{}, false, fmt.Errorf("network retirement audit %q has an invalid permanent reservation", event.ID)
	}
	configRevision, configOK := auditNonNegativeInteger(event.Details["config_revision"])
	nodeCount, nodeCountOK := auditNonNegativeInteger(event.Details["node_count"])
	pendingNodes, pendingOK := auditNonNegativeInteger(event.Details["pending_nodes"])
	activeNodes, activeOK := auditNonNegativeInteger(event.Details["active_nodes"])
	revokedNodes, revokedOK := auditNonNegativeInteger(event.Details["revoked_nodes"])
	for _, key := range []string{"enrollment_records_removed", "agent_recovery_records_removed", "certificate_issuances_removed", "revocations_removed"} {
		if _, ok := auditNonNegativeInteger(event.Details[key]); !ok {
			return retiredNetworkReservation{}, false, fmt.Errorf("network retirement audit %q has an invalid %s count", event.ID, key)
		}
	}
	if !configOK || configRevision < 1 || !nodeCountOK || !pendingOK || !activeOK || !revokedOK || pendingNodes+activeNodes+revokedNodes != nodeCount {
		return retiredNetworkReservation{}, false, fmt.Errorf("network retirement audit %q has invalid lifecycle counts", event.ID)
	}
	for _, key := range []string{"credentials_invalidated", "encrypted_key_material_removed", "name_cidr_permanently_reserved"} {
		if value, ok := event.Details[key].(bool); !ok || !value {
			return retiredNetworkReservation{}, false, fmt.Errorf("network retirement audit %q is missing %s proof", event.ID, key)
		}
	}
	return retiredNetworkReservation{
		id: event.ResourceID, name: name, cidr: cidr, configRevision: configRevision,
		nodeCount: nodeCount, pendingNodes: pendingNodes, activeNodes: activeNodes, revokedNodes: revokedNodes,
	}, true, nil
}

func validRetiredNetworkCIDR(value string) bool {
	ip, cidr, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil || cidr.String() != value {
		return false
	}
	ones, bits := cidr.Mask.Size()
	return bits == 32 && ones >= 16 && ones <= 28
}

func auditNonNegativeInteger(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), typed >= 0
	case int64:
		return typed, typed >= 0
	case float64:
		if typed < 0 || typed > math.MaxInt64 || math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}
