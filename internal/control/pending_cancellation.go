package control

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// CancelPendingNodeInput requires a human-visible identity match before a
// never-enrolled node and all of its one-time credentials are removed.
type CancelPendingNodeInput struct {
	ConfirmationName string `json:"confirmation_name"`
}

// CancelledPendingNode is the durable receipt for removing an enrollment that
// never became a certificate identity.
type CancelledPendingNode struct {
	NodeID                           string    `json:"node_id"`
	NetworkID                        string    `json:"network_id"`
	Name                             string    `json:"name"`
	IP                               string    `json:"ip"`
	Role                             string    `json:"role"`
	CancelledAt                      time.Time `json:"cancelled_at"`
	EnrollmentRecordsInvalidated     int       `json:"enrollment_records_invalidated"`
	RelayAssignmentRemoved           bool      `json:"relay_assignment_removed"`
	RoutedSubnetReservationsReleased int       `json:"routed_subnet_reservations_released"`
	ConfigRevision                   int64     `json:"config_revision"`
}

func (s *Service) CancelPendingNode(nodeID string, input CancelPendingNodeInput) (CancelledPendingNode, error) {
	return s.cancelPendingNode(nil, nodeID, input)
}

func (s *Service) CancelPendingNodeAs(actor Actor, nodeID string, input CancelPendingNodeInput) (CancelledPendingNode, error) {
	if err := validateActor(actor); err != nil {
		return CancelledPendingNode{}, err
	}
	return s.cancelPendingNode(&actor, nodeID, input)
}

func (s *Service) cancelPendingNode(actor *Actor, nodeID string, input CancelPendingNodeInput) (CancelledPendingNode, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !validPersistedID(nodeID) || !namePattern.MatchString(input.ConfirmationName) {
		return CancelledPendingNode{}, fmt.Errorf("%w: node ID and exact confirmation_name are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return CancelledPendingNode{}, fmt.Errorf("%w: pending enrollment cancellation requires a valid timestamp", ErrInvalid)
	}
	var result CancelledPendingNode
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
		if node.Status != "pending" || node.EnrolledAt != nil || node.Certificate != "" || node.CertificateFingerprint != "" {
			return fmt.Errorf("%w: only a never-enrolled pending node can be cancelled", ErrConflict)
		}
		if node.Name != input.ConfirmationName {
			return fmt.Errorf("%w: confirmation name does not exactly match the pending node", ErrConflict)
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

		keptEnrollments := state.Enrollments[:0]
		invalidated := 0
		for _, enrollment := range state.Enrollments {
			if enrollment.NodeID == node.ID {
				invalidated++
				continue
			}
			keptEnrollments = append(keptEnrollments, enrollment)
		}

		network := &state.Networks[networkIndex]
		relayAssignmentRemoved := false
		if state.Version >= ControlStateVersionNetworkRelays && slices.Contains(network.RelaySettings.RelayNodeIDs, node.ID) {
			network.RelaySettings.RelayNodeIDs = slices.DeleteFunc(network.RelaySettings.RelayNodeIDs, func(candidate string) bool { return candidate == node.ID })
			if len(network.RelaySettings.RelayNodeIDs) == 0 {
				network.RelaySettings.Enabled = false
			}
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
			relayAssignmentRemoved = true
		}

		details := map[string]any{
			"network_id": node.NetworkID, "name": node.Name, "ip": node.IP, "role": node.Role,
			"enrollment_records_invalidated": invalidated, "relay_assignment_removed": relayAssignmentRemoved,
			"routed_subnet_reservations_released": len(node.RoutedSubnets), "config_revision": network.ConfigRevision,
		}
		event, err := newOptionalAttributedAudit(now, "node.pending_cancelled", "node", node.ID, details, actor)
		if err != nil {
			return err
		}
		state.Enrollments = keptEnrollments
		state.Nodes = append(state.Nodes[:nodeIndex], state.Nodes[nodeIndex+1:]...)
		state.Audit = append(state.Audit, event)
		result = CancelledPendingNode{
			NodeID: node.ID, NetworkID: node.NetworkID, Name: node.Name, IP: node.IP, Role: node.Role, CancelledAt: now,
			EnrollmentRecordsInvalidated: invalidated, RelayAssignmentRemoved: relayAssignmentRemoved,
			RoutedSubnetReservationsReleased: len(node.RoutedSubnets), ConfigRevision: network.ConfigRevision,
		}
		return nil
	})
	return result, err
}
