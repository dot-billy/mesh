package control

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const NodeRouteProfileEditDocumentSchema = "mesh-node-route-profile-edit-v1"

type StartRouteProfileEditInput struct {
	RoutedSubnets          []string `json:"routed_subnets"`
	ExpectedConfigRevision int64    `json:"expected_config_revision"`
	RequestID              string   `json:"request_id"`
}

type UpdateRouteProfileEditInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	RequestID              string `json:"request_id"`
}

type RouteProfileEditNodeStatus struct {
	NodeID                       string `json:"node_id"`
	Name                         string `json:"name"`
	CertificateGeneration        int64  `json:"certificate_generation"`
	AppliedCertificateGeneration int64  `json:"applied_certificate_generation"`
	AppliedConfigRevision        int64  `json:"applied_config_revision"`
	DesiredCertificateGeneration int64  `json:"desired_certificate_generation"`
	Ready                        bool   `json:"ready"`
}

type NodeRouteProfileEditDocument struct {
	Schema                string                      `json:"schema"`
	NetworkID             string                      `json:"network_id"`
	NodeID                string                      `json:"node_id"`
	RequestID             string                      `json:"request_id"`
	Phase                 string                      `json:"phase"`
	OriginalRoutedSubnets []string                    `json:"original_routed_subnets"`
	DesiredRoutedSubnets  []string                    `json:"desired_routed_subnets"`
	Additions             []string                    `json:"additions"`
	Removals              []string                    `json:"removals"`
	ConfigRevision        int64                       `json:"config_revision"`
	StartedAt             *time.Time                  `json:"started_at"`
	PromotedAt            *time.Time                  `json:"promoted_at"`
	FinishedAt            *time.Time                  `json:"finished_at"`
	Owner                 *RouteProfileEditNodeStatus `json:"owner"`
	AvailableActions      []string                    `json:"available_actions"`
}

func cloneNetworkRouteProfileEdit(value NetworkRouteProfileEdit) NetworkRouteProfileEdit {
	value.OriginalSubnets = slices.Clone(value.OriginalSubnets)
	value.DesiredSubnets = slices.Clone(value.DesiredSubnets)
	return value
}

func zeroNetworkRouteProfileEdit(value NetworkRouteProfileEdit) bool {
	return value.RequestID == "" && value.Phase == "" && value.NodeID == "" &&
		value.OriginalSubnets == nil && value.DesiredSubnets == nil &&
		value.PreparedCertificateGeneration == 0 && value.CleanupCertificateGeneration == 0 &&
		value.StartedAt.IsZero() && value.PromotedAt.IsZero() && value.FinishedAt.IsZero()
}

func routeProfileEditTerminal(value NetworkRouteProfileEdit) bool {
	return zeroNetworkRouteProfileEdit(value) || value.Phase == RouteProfileEditPhaseCompleted || value.Phase == RouteProfileEditPhaseCancelled
}

func routeProfileEditActive(value NetworkRouteProfileEdit) bool {
	return value.Phase == RouteProfileEditPhasePreparingOwner || value.Phase == RouteProfileEditPhaseCleaningOwner || value.Phase == RouteProfileEditPhaseCleaningCancelledOwner
}

func routeProfileEditIncludesNode(value NetworkRouteProfileEdit, nodeID string) bool {
	return routeProfileEditActive(value) && value.NodeID == nodeID
}

func routeProfileEditAdditions(value NetworkRouteProfileEdit) []string {
	return subnetDifference(value.DesiredSubnets, value.OriginalSubnets)
}

func routeProfileEditRemovals(value NetworkRouteProfileEdit) []string {
	return subnetDifference(value.OriginalSubnets, value.DesiredSubnets)
}

func subnetDifference(left, right []string) []string {
	result := make([]string, 0, len(left))
	for _, route := range left {
		if !slices.Contains(right, route) {
			result = append(result, route)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func validateRouteProfileTransition(original, desired []string) error {
	additions := subnetDifference(desired, original)
	for _, added := range additions {
		addedPrefix, err := netip.ParsePrefix(added)
		if err != nil {
			return fmt.Errorf("%w: desired routed subnet is invalid", ErrInvalid)
		}
		for _, existing := range original {
			existingPrefix, parseErr := netip.ParsePrefix(existing)
			if parseErr != nil {
				return fmt.Errorf("%w: current routed subnet is invalid", ErrConflict)
			}
			if prefixesOverlap(addedPrefix, existingPrefix) {
				return fmt.Errorf("%w: routed subnet %s overlaps current routed subnet %s; remove the old prefix in one completed edit before adding the overlapping replacement", ErrInvalid, addedPrefix, existingPrefix)
			}
		}
	}
	unionCount := len(original) + len(additions)
	if unionCount > maxRoutedSubnetsPerNode {
		return fmt.Errorf("%w: certificate-first staging would require %d routed subnets; complete removals first so the staged profile stays within %d", ErrInvalid, unionCount, maxRoutedSubnetsPerNode)
	}
	return nil
}

func routeProfileEditDesiredGeneration(value NetworkRouteProfileEdit) int64 {
	switch value.Phase {
	case RouteProfileEditPhasePreparingOwner:
		return value.PreparedCertificateGeneration
	case RouteProfileEditPhaseCleaningOwner, RouteProfileEditPhaseCleaningCancelledOwner:
		return value.CleanupCertificateGeneration
	default:
		return 0
	}
}

func validateNetworkRouteProfileEdit(state State, network Network) error {
	edit := network.RouteProfileEdit
	if zeroNetworkRouteProfileEdit(edit) {
		return nil
	}
	if !validRouteTransferRequestID(edit.RequestID) || !validPersistedID(edit.NodeID) || edit.StartedAt.IsZero() {
		return errors.New("identity, request, or start metadata is invalid")
	}
	if edit.Phase != RouteProfileEditPhasePreparingOwner && edit.Phase != RouteProfileEditPhaseCleaningOwner && edit.Phase != RouteProfileEditPhaseCleaningCancelledOwner && edit.Phase != RouteProfileEditPhaseCompleted && edit.Phase != RouteProfileEditPhaseCancelled {
		return errors.New("phase is invalid")
	}
	if err := validateCanonicalRoutedSubnets(edit.OriginalSubnets); err != nil {
		return errors.New("original prefix snapshot is invalid")
	}
	if err := validateCanonicalRoutedSubnets(edit.DesiredSubnets); err != nil {
		return errors.New("desired prefix snapshot is invalid")
	}
	additions, removals := routeProfileEditAdditions(edit), routeProfileEditRemovals(edit)
	if len(additions) == 0 && len(removals) == 0 {
		return errors.New("route profile edit does not change the prefix set")
	}
	if len(additions) == 0 && edit.PreparedCertificateGeneration != 0 || len(additions) > 0 && edit.PreparedCertificateGeneration < 1 {
		return errors.New("prepared certificate generation is inconsistent with additions")
	}
	switch edit.Phase {
	case RouteProfileEditPhasePreparingOwner:
		if len(additions) == 0 || edit.CleanupCertificateGeneration != 0 || !edit.PromotedAt.IsZero() || !edit.FinishedAt.IsZero() {
			return errors.New("prepare phase metadata is invalid")
		}
	case RouteProfileEditPhaseCleaningOwner:
		if len(removals) == 0 || edit.CleanupCertificateGeneration < 1 || edit.PromotedAt.IsZero() || !edit.FinishedAt.IsZero() {
			return errors.New("owner cleanup metadata is invalid")
		}
	case RouteProfileEditPhaseCleaningCancelledOwner:
		if len(additions) == 0 || edit.CleanupCertificateGeneration < 1 || !edit.PromotedAt.IsZero() || !edit.FinishedAt.IsZero() {
			return errors.New("cancelled-owner cleanup metadata is invalid")
		}
	case RouteProfileEditPhaseCompleted:
		if edit.PromotedAt.IsZero() || edit.FinishedAt.IsZero() || len(removals) > 0 && edit.CleanupCertificateGeneration < 1 || len(removals) == 0 && edit.CleanupCertificateGeneration != 0 {
			return errors.New("completion metadata is invalid")
		}
	case RouteProfileEditPhaseCancelled:
		if !edit.PromotedAt.IsZero() || edit.FinishedAt.IsZero() {
			return errors.New("cancellation metadata is invalid")
		}
	}
	if routeProfileEditActive(edit) {
		if routeTransferActive(network.RouteTransfer) {
			return errors.New("route-profile edit overlaps an active route transfer")
		}
		owner, ok := findNode(state, edit.NodeID)
		if !ok || owner.NetworkID != network.ID || owner.Status != "active" || owner.EnrolledAt == nil {
			return errors.New("active route-profile owner is not an active enrolled node in the network")
		}
		desiredGeneration := routeProfileEditDesiredGeneration(edit)
		if desiredGeneration != owner.CertificateGeneration && (owner.CertificateGeneration == int64(^uint64(0)>>1) || desiredGeneration != owner.CertificateGeneration+1) {
			return errors.New("active route-profile desired certificate generation is not current or next")
		}
		expected := edit.OriginalSubnets
		if edit.Phase == RouteProfileEditPhaseCleaningOwner {
			expected = edit.DesiredSubnets
		}
		if !slices.Equal(owner.RoutedSubnets, expected) {
			return errors.New("active route-profile ownership differs from its durable phase snapshot")
		}
	}
	return nil
}

func routeProfileCertificateRoutedSubnets(network Network, node Node) ([]string, bool) {
	edit := network.RouteProfileEdit
	if node.ID != edit.NodeID {
		return nil, false
	}
	switch edit.Phase {
	case RouteProfileEditPhasePreparingOwner:
		return mergeSubnets(edit.OriginalSubnets, edit.DesiredSubnets), true
	case RouteProfileEditPhaseCleaningOwner:
		return slices.Clone(edit.DesiredSubnets), true
	case RouteProfileEditPhaseCleaningCancelledOwner:
		return slices.Clone(edit.OriginalSubnets), true
	default:
		return nil, false
	}
}

func routeProfileCertificateRenewalRequired(network Network, node Node) bool {
	if node.ID != network.RouteProfileEdit.NodeID {
		return false
	}
	desired := routeProfileEditDesiredGeneration(network.RouteProfileEdit)
	return desired > 0 && node.CertificateGeneration < desired
}

func routeProfileEditStartAvailable(network Network, node Node) bool {
	return routeProfileEditTerminal(network.RouteProfileEdit) && routeTransferTerminal(network.RouteTransfer) &&
		network.CARotation.Phase == "" && network.FirewallRollout.Phase == "" &&
		node.Status == "active" && node.EnrolledAt != nil && node.CertificateGeneration > 0 && node.CertificateGeneration < int64(^uint64(0)>>1)
}

func terminalRouteTransitionReplayRevision(expected, current int64) bool {
	return expected == current || current > 1 && expected == current-1
}

func routeProfileEditDocument(state State, network Network, node Node) NodeRouteProfileEditDocument {
	doc := NodeRouteProfileEditDocument{
		Schema: NodeRouteProfileEditDocumentSchema, NetworkID: network.ID, NodeID: node.ID,
		OriginalRoutedSubnets: slices.Clone(node.RoutedSubnets), DesiredRoutedSubnets: slices.Clone(node.RoutedSubnets),
		Additions: []string{}, Removals: []string{}, ConfigRevision: network.ConfigRevision, AvailableActions: []string{},
	}
	if doc.OriginalRoutedSubnets == nil {
		doc.OriginalRoutedSubnets = []string{}
		doc.DesiredRoutedSubnets = []string{}
	}
	edit := network.RouteProfileEdit
	if zeroNetworkRouteProfileEdit(edit) || edit.NodeID != node.ID {
		status := routeProfileEditNodeStatus(state, network, node, 0)
		doc.Owner = &status
		if routeProfileEditStartAvailable(network, node) {
			doc.AvailableActions = append(doc.AvailableActions, "start")
		}
		return doc
	}
	doc.RequestID, doc.Phase = edit.RequestID, edit.Phase
	doc.OriginalRoutedSubnets, doc.DesiredRoutedSubnets = slices.Clone(edit.OriginalSubnets), slices.Clone(edit.DesiredSubnets)
	if doc.OriginalRoutedSubnets == nil {
		doc.OriginalRoutedSubnets = []string{}
	}
	if doc.DesiredRoutedSubnets == nil {
		doc.DesiredRoutedSubnets = []string{}
	}
	doc.Additions, doc.Removals = routeProfileEditAdditions(edit), routeProfileEditRemovals(edit)
	if doc.Additions == nil {
		doc.Additions = []string{}
	}
	if doc.Removals == nil {
		doc.Removals = []string{}
	}
	doc.StartedAt, doc.PromotedAt, doc.FinishedAt = optionalRouteTransferTime(edit.StartedAt), optionalRouteTransferTime(edit.PromotedAt), optionalRouteTransferTime(edit.FinishedAt)
	status := routeProfileEditNodeStatus(state, network, node, routeProfileEditDesiredGeneration(edit))
	doc.Owner = &status
	switch edit.Phase {
	case RouteProfileEditPhasePreparingOwner:
		if status.Ready {
			doc.AvailableActions = append(doc.AvailableActions, "advance")
		}
		doc.AvailableActions = append(doc.AvailableActions, "cancel")
	case RouteProfileEditPhaseCleaningOwner:
		if status.Ready {
			doc.AvailableActions = append(doc.AvailableActions, "advance")
		}
	case RouteProfileEditPhaseCleaningCancelledOwner:
		if status.Ready {
			doc.AvailableActions = append(doc.AvailableActions, "cancel")
		}
	case RouteProfileEditPhaseCompleted, RouteProfileEditPhaseCancelled:
		if routeProfileEditStartAvailable(network, node) {
			doc.AvailableActions = append(doc.AvailableActions, "start")
		}
	}
	return doc
}

func routeProfileEditNodeStatus(state State, network Network, node Node, desiredGeneration int64) RouteProfileEditNodeStatus {
	return RouteProfileEditNodeStatus{
		NodeID: node.ID, Name: node.Name, CertificateGeneration: node.CertificateGeneration,
		AppliedCertificateGeneration: node.AppliedCertificateGeneration, AppliedConfigRevision: node.AppliedConfigRevision,
		DesiredCertificateGeneration: desiredGeneration,
		Ready:                        routeTransferNodeConverged(state, network, node, desiredGeneration),
	}
}

func (s *Service) NodeRouteProfileEdit(nodeID string) (NodeRouteProfileEditDocument, error) {
	if !validPersistedID(nodeID) {
		return NodeRouteProfileEditDocument{}, fmt.Errorf("%w: invalid node ID", ErrInvalid)
	}
	var result NodeRouteProfileEditDocument
	err := s.viewState(func(state State) error {
		node, ok := findNode(state, nodeID)
		if !ok {
			return ErrNotFound
		}
		network, ok := findNetwork(state, node.NetworkID)
		if !ok {
			return ErrNotFound
		}
		result = routeProfileEditDocument(state, network, node)
		return nil
	})
	return result, err
}

func (s *Service) StartRouteProfileEditAs(actor Actor, nodeID string, input StartRouteProfileEditInput) (NodeRouteProfileEditDocument, error) {
	if err := validateActor(actor); err != nil {
		return NodeRouteProfileEditDocument{}, err
	}
	return s.startRouteProfileEdit(&actor, nodeID, input)
}

func (s *Service) startRouteProfileEdit(actor *Actor, nodeID string, input StartRouteProfileEditInput) (NodeRouteProfileEditDocument, error) {
	nodeID, input.RequestID = strings.TrimSpace(nodeID), strings.TrimSpace(input.RequestID)
	desired, err := normalizeRoutedSubnets(input.RoutedSubnets)
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 || !validRouteTransferRequestID(input.RequestID) || err != nil {
		return NodeRouteProfileEditDocument{}, fmt.Errorf("%w: node ID, canonical routed_subnets, expected_config_revision, and a 16-128 character request_id are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return NodeRouteProfileEditDocument{}, errors.New("route-profile edit requires a valid timestamp")
	}
	var result NodeRouteProfileEditDocument
	err = s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: route-profile-edit schema is not current", ErrConflict)
		}
		node, ok := findNode(*state, nodeID)
		if !ok {
			return ErrNotFound
		}
		for networkIndex := range state.Networks {
			network := &state.Networks[networkIndex]
			if network.ID != node.NetworkID {
				continue
			}
			existing := network.RouteProfileEdit
			if existing.RequestID == input.RequestID {
				if existing.NodeID != nodeID || !slices.Equal(existing.DesiredSubnets, desired) {
					return fmt.Errorf("%w: request_id is already bound to different route-profile input", ErrConflict)
				}
				result = routeProfileEditDocument(*state, *network, node)
				return nil
			}
			if !routeProfileEditTerminal(existing) || !routeTransferTerminal(network.RouteTransfer) || network.CARotation.Phase != "" || network.FirewallRollout.Phase != "" || network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: network is not at the requested stable revision", ErrConflict)
			}
			if node.Status != "active" || node.EnrolledAt == nil || node.CertificateGeneration < 1 || node.CertificateGeneration == int64(^uint64(0)>>1) {
				return fmt.Errorf("%w: route-profile owner must be an active enrolled node with an advanceable certificate", ErrConflict)
			}
			if slices.Equal(node.RoutedSubnets, desired) {
				return fmt.Errorf("%w: requested routed_subnets do not change the active profile", ErrInvalid)
			}
			if transitionErr := validateRouteProfileTransition(node.RoutedSubnets, desired); transitionErr != nil {
				return transitionErr
			}
			if validateErr := validateRoutedSubnetsForNode(*state, node.ID, desired); validateErr != nil {
				return validateErr
			}
			nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
			if revisionErr != nil {
				return revisionErr
			}
			edit := NetworkRouteProfileEdit{
				RequestID: input.RequestID, NodeID: node.ID,
				OriginalSubnets: slices.Clone(node.RoutedSubnets), DesiredSubnets: slices.Clone(desired), StartedAt: now,
			}
			additions, removals := routeProfileEditAdditions(edit), routeProfileEditRemovals(edit)
			if len(additions) > 0 {
				edit.Phase = RouteProfileEditPhasePreparingOwner
				edit.PreparedCertificateGeneration = node.CertificateGeneration + 1
			} else {
				edit.Phase, edit.PromotedAt = RouteProfileEditPhaseCleaningOwner, now
				edit.CleanupCertificateGeneration = node.CertificateGeneration + 1
				for nodeIndex := range state.Nodes {
					if state.Nodes[nodeIndex].ID == node.ID {
						state.Nodes[nodeIndex].RoutedSubnets = slices.Clone(desired)
						node = state.Nodes[nodeIndex]
						break
					}
				}
				reconcileNetworkRoutePolicies(state, network)
			}
			network.RouteProfileEdit = edit
			network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
			event, auditErr := newOptionalAttributedAudit(now, "node.route_profile_edit_started", "node", node.ID, map[string]any{
				"request_id": edit.RequestID, "phase": edit.Phase,
				"original_routed_subnets": strings.Join(edit.OriginalSubnets, ","), "desired_routed_subnets": strings.Join(edit.DesiredSubnets, ","),
				"additions": strings.Join(additions, ","), "removals": strings.Join(removals, ","),
				"previous_config_revision": input.ExpectedConfigRevision, "config_revision": nextRevision,
			}, actor)
			if auditErr != nil {
				return auditErr
			}
			state.Audit = append(state.Audit, event)
			result = routeProfileEditDocument(*state, *network, node)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func (s *Service) AdvanceRouteProfileEditAs(actor Actor, nodeID string, input UpdateRouteProfileEditInput) (NodeRouteProfileEditDocument, error) {
	if err := validateActor(actor); err != nil {
		return NodeRouteProfileEditDocument{}, err
	}
	return s.updateRouteProfileEdit(&actor, nodeID, input, false)
}

func (s *Service) CancelRouteProfileEditAs(actor Actor, nodeID string, input UpdateRouteProfileEditInput) (NodeRouteProfileEditDocument, error) {
	if err := validateActor(actor); err != nil {
		return NodeRouteProfileEditDocument{}, err
	}
	return s.updateRouteProfileEdit(&actor, nodeID, input, true)
}

func (s *Service) updateRouteProfileEdit(actor *Actor, nodeID string, input UpdateRouteProfileEditInput, cancel bool) (NodeRouteProfileEditDocument, error) {
	nodeID, input.RequestID = strings.TrimSpace(nodeID), strings.TrimSpace(input.RequestID)
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 || !validRouteTransferRequestID(input.RequestID) {
		return NodeRouteProfileEditDocument{}, fmt.Errorf("%w: node ID, expected_config_revision, and request_id are required", ErrInvalid)
	}
	now := s.now().UTC()
	if now.IsZero() {
		return NodeRouteProfileEditDocument{}, errors.New("route-profile update requires a valid timestamp")
	}
	var result NodeRouteProfileEditDocument
	err := s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: route-profile-edit schema is not current", ErrConflict)
		}
		node, ok := findNode(*state, nodeID)
		if !ok {
			return ErrNotFound
		}
		for networkIndex := range state.Networks {
			network := &state.Networks[networkIndex]
			edit := &network.RouteProfileEdit
			if network.ID != node.NetworkID || edit.NodeID != node.ID {
				continue
			}
			if edit.RequestID != input.RequestID {
				return fmt.Errorf("%w: request_id does not match the authoritative route-profile edit", ErrConflict)
			}
			if (cancel && edit.Phase == RouteProfileEditPhaseCancelled || !cancel && edit.Phase == RouteProfileEditPhaseCompleted) && terminalRouteTransitionReplayRevision(input.ExpectedConfigRevision, network.ConfigRevision) {
				result = routeProfileEditDocument(*state, *network, node)
				return nil
			}
			if network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			if cancel {
				switch edit.Phase {
				case RouteProfileEditPhaseCancelled:
					result = routeProfileEditDocument(*state, *network, node)
					return nil
				case RouteProfileEditPhasePreparingOwner:
					nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
					if revisionErr != nil {
						return revisionErr
					}
					if node.CertificateGeneration < edit.PreparedCertificateGeneration {
						edit.Phase, edit.FinishedAt = RouteProfileEditPhaseCancelled, now
					} else {
						if node.CertificateGeneration == int64(^uint64(0)>>1) {
							return fmt.Errorf("%w: owner certificate generation cannot advance", ErrConflict)
						}
						edit.Phase = RouteProfileEditPhaseCleaningCancelledOwner
						edit.CleanupCertificateGeneration = node.CertificateGeneration + 1
					}
					network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
				case RouteProfileEditPhaseCleaningCancelledOwner:
					if !routeTransferNodeConverged(*state, *network, node, edit.CleanupCertificateGeneration) {
						return fmt.Errorf("%w: cancelled owner certificate cleanup has not converged", ErrConflict)
					}
					edit.Phase, edit.FinishedAt = RouteProfileEditPhaseCancelled, now
				default:
					return fmt.Errorf("%w: route-profile edit can no longer be cancelled", ErrConflict)
				}
				action := "node.route_profile_edit_cancelled"
				if edit.Phase == RouteProfileEditPhaseCleaningCancelledOwner {
					action = "node.route_profile_edit_cancellation_started"
				}
				event, auditErr := newOptionalAttributedAudit(now, action, "node", node.ID, map[string]any{
					"request_id": edit.RequestID, "phase": edit.Phase, "config_revision": network.ConfigRevision,
				}, actor)
				if auditErr != nil {
					return auditErr
				}
				state.Audit = append(state.Audit, event)
				result = routeProfileEditDocument(*state, *network, node)
				return nil
			}

			switch edit.Phase {
			case RouteProfileEditPhaseCompleted:
				result = routeProfileEditDocument(*state, *network, node)
				return nil
			case RouteProfileEditPhasePreparingOwner:
				if !routeTransferNodeConverged(*state, *network, node, edit.PreparedCertificateGeneration) {
					return fmt.Errorf("%w: prepared owner certificate has not converged", ErrConflict)
				}
				nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
				if revisionErr != nil {
					return revisionErr
				}
				for nodeIndex := range state.Nodes {
					if state.Nodes[nodeIndex].ID == node.ID {
						state.Nodes[nodeIndex].RoutedSubnets = slices.Clone(edit.DesiredSubnets)
						node = state.Nodes[nodeIndex]
						break
					}
				}
				reconcileNetworkRoutePolicies(state, network)
				edit.PromotedAt = now
				if len(routeProfileEditRemovals(*edit)) > 0 {
					if node.CertificateGeneration == int64(^uint64(0)>>1) {
						return fmt.Errorf("%w: owner certificate generation cannot advance", ErrConflict)
					}
					edit.Phase = RouteProfileEditPhaseCleaningOwner
					edit.CleanupCertificateGeneration = node.CertificateGeneration + 1
				} else {
					edit.Phase, edit.FinishedAt = RouteProfileEditPhaseCompleted, now
				}
				network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
			case RouteProfileEditPhaseCleaningOwner:
				if !routeTransferNodeConverged(*state, *network, node, edit.CleanupCertificateGeneration) {
					return fmt.Errorf("%w: cleaned owner certificate has not converged", ErrConflict)
				}
				edit.Phase, edit.FinishedAt = RouteProfileEditPhaseCompleted, now
			default:
				return fmt.Errorf("%w: route-profile edit is not advanceable", ErrConflict)
			}
			action := "node.route_profile_edit_promoted"
			if edit.Phase == RouteProfileEditPhaseCompleted {
				action = "node.route_profile_edit_completed"
			}
			event, auditErr := newOptionalAttributedAudit(now, action, "node", node.ID, map[string]any{
				"request_id": edit.RequestID, "phase": edit.Phase,
				"desired_routed_subnets": strings.Join(edit.DesiredSubnets, ","), "config_revision": network.ConfigRevision,
			}, actor)
			if auditErr != nil {
				return auditErr
			}
			state.Audit = append(state.Audit, event)
			result = routeProfileEditDocument(*state, *network, node)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}
