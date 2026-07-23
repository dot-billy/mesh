package control

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const NetworkRouteTransferDocumentSchema = "mesh-network-route-transfer-v1"

type StartRouteTransferInput struct {
	SourceNodeID           string   `json:"source_node_id"`
	TargetNodeID           string   `json:"target_node_id"`
	RoutedSubnets          []string `json:"routed_subnets"`
	ExpectedConfigRevision int64    `json:"expected_config_revision"`
	RequestID              string   `json:"request_id"`
}

type UpdateRouteTransferInput struct {
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
	RequestID              string `json:"request_id"`
}

type RouteTransferNodeStatus struct {
	NodeID                       string `json:"node_id"`
	Name                         string `json:"name"`
	CertificateGeneration        int64  `json:"certificate_generation"`
	AppliedCertificateGeneration int64  `json:"applied_certificate_generation"`
	AppliedConfigRevision        int64  `json:"applied_config_revision"`
	DesiredCertificateGeneration int64  `json:"desired_certificate_generation"`
	Ready                        bool   `json:"ready"`
}

type NetworkRouteTransferDocument struct {
	Schema           string                   `json:"schema"`
	NetworkID        string                   `json:"network_id"`
	RequestID        string                   `json:"request_id"`
	Phase            string                   `json:"phase"`
	RoutedSubnets    []string                 `json:"routed_subnets"`
	ConfigRevision   int64                    `json:"config_revision"`
	StartedAt        *time.Time               `json:"started_at"`
	PromotedAt       *time.Time               `json:"promoted_at"`
	FinishedAt       *time.Time               `json:"finished_at"`
	Source           *RouteTransferNodeStatus `json:"source"`
	Target           *RouteTransferNodeStatus `json:"target"`
	AvailableActions []string                 `json:"available_actions"`
}

func cloneNetworkRouteTransfer(value NetworkRouteTransfer) NetworkRouteTransfer {
	value.RoutedSubnets = slices.Clone(value.RoutedSubnets)
	value.SourceOriginalSubnets = slices.Clone(value.SourceOriginalSubnets)
	value.TargetOriginalSubnets = slices.Clone(value.TargetOriginalSubnets)
	return value
}

func zeroNetworkRouteTransfer(value NetworkRouteTransfer) bool {
	return value.RequestID == "" && value.Phase == "" && value.SourceNodeID == "" && value.TargetNodeID == "" &&
		value.RoutedSubnets == nil && value.SourceOriginalSubnets == nil && value.TargetOriginalSubnets == nil &&
		value.TargetCertificateGeneration == 0 && value.SourceCertificateGeneration == 0 &&
		value.StartedAt.IsZero() && value.PromotedAt.IsZero() && value.FinishedAt.IsZero()
}

func routeTransferTerminal(value NetworkRouteTransfer) bool {
	return zeroNetworkRouteTransfer(value) || value.Phase == RouteTransferPhaseCompleted || value.Phase == RouteTransferPhaseCancelled
}

func routeTransferActive(value NetworkRouteTransfer) bool {
	return value.Phase == RouteTransferPhasePreparingTarget || value.Phase == RouteTransferPhaseCleaningSource || value.Phase == RouteTransferPhaseCleaningTarget
}

func routeTransferIncludesNode(value NetworkRouteTransfer, nodeID string) bool {
	return routeTransferActive(value) && (value.SourceNodeID == nodeID || value.TargetNodeID == nodeID)
}

func validRouteTransferRequestID(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 16 && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\t ")
}

func validateNetworkRouteTransfer(state State, network Network) error {
	transfer := network.RouteTransfer
	if zeroNetworkRouteTransfer(transfer) {
		return nil
	}
	if !validRouteTransferRequestID(transfer.RequestID) || !validPersistedID(transfer.SourceNodeID) || !validPersistedID(transfer.TargetNodeID) || transfer.SourceNodeID == transfer.TargetNodeID || transfer.StartedAt.IsZero() {
		return errors.New("identity, request, or start metadata is invalid")
	}
	if transfer.Phase != RouteTransferPhasePreparingTarget && transfer.Phase != RouteTransferPhaseCleaningSource && transfer.Phase != RouteTransferPhaseCleaningTarget && transfer.Phase != RouteTransferPhaseCompleted && transfer.Phase != RouteTransferPhaseCancelled {
		return errors.New("phase is invalid")
	}
	if err := validateCanonicalRoutedSubnets(transfer.RoutedSubnets); err != nil || len(transfer.RoutedSubnets) == 0 {
		return errors.New("transferred prefixes are invalid")
	}
	if err := validateCanonicalRoutedSubnets(transfer.SourceOriginalSubnets); err != nil || len(transfer.SourceOriginalSubnets) == 0 {
		return errors.New("source prefix snapshot is invalid")
	}
	if err := validateCanonicalRoutedSubnets(transfer.TargetOriginalSubnets); err != nil {
		return errors.New("target prefix snapshot is invalid")
	}
	if !subnetSetContainsAll(transfer.SourceOriginalSubnets, transfer.RoutedSubnets) || transfer.TargetCertificateGeneration < 1 {
		return errors.New("transfer generations or source ownership are invalid")
	}
	if transfer.Phase == RouteTransferPhasePreparingTarget && (!transfer.PromotedAt.IsZero() || !transfer.FinishedAt.IsZero() || transfer.SourceCertificateGeneration != 0) {
		return errors.New("prepare phase has invalid transition metadata")
	}
	if transfer.Phase == RouteTransferPhaseCleaningTarget && (!transfer.PromotedAt.IsZero() || !transfer.FinishedAt.IsZero() || transfer.SourceCertificateGeneration != 0) {
		return errors.New("target cleanup has invalid transition metadata")
	}
	if transfer.Phase == RouteTransferPhaseCleaningSource && (transfer.PromotedAt.IsZero() || !transfer.FinishedAt.IsZero() || transfer.SourceCertificateGeneration < 1) {
		return errors.New("source cleanup has invalid transition metadata")
	}
	if transfer.Phase == RouteTransferPhaseCompleted && (transfer.PromotedAt.IsZero() || transfer.FinishedAt.IsZero() || transfer.SourceCertificateGeneration < 1) {
		return errors.New("completion metadata is invalid")
	}
	if transfer.Phase == RouteTransferPhaseCancelled && (!transfer.PromotedAt.IsZero() || transfer.FinishedAt.IsZero() || transfer.SourceCertificateGeneration != 0) {
		return errors.New("cancellation metadata is invalid")
	}
	if routeTransferActive(transfer) {
		source, sourceOK := findNode(state, transfer.SourceNodeID)
		target, targetOK := findNode(state, transfer.TargetNodeID)
		if !sourceOK || !targetOK || source.NetworkID != network.ID || target.NetworkID != network.ID || source.Status != "active" || target.Status != "active" {
			return errors.New("active transfer participants are not active nodes in the network")
		}
		switch transfer.Phase {
		case RouteTransferPhasePreparingTarget, RouteTransferPhaseCleaningTarget:
			if !slices.Equal(source.RoutedSubnets, transfer.SourceOriginalSubnets) || !slices.Equal(target.RoutedSubnets, transfer.TargetOriginalSubnets) {
				return errors.New("unpromoted transfer ownership differs from its snapshots")
			}
		case RouteTransferPhaseCleaningSource:
			if !slices.Equal(source.RoutedSubnets, subtractSubnets(transfer.SourceOriginalSubnets, transfer.RoutedSubnets)) || !slices.Equal(target.RoutedSubnets, mergeSubnets(transfer.TargetOriginalSubnets, transfer.RoutedSubnets)) {
				return errors.New("promoted transfer ownership differs from its snapshots")
			}
		}
	}
	return nil
}

func subnetSetContainsAll(owner, requested []string) bool {
	for _, route := range requested {
		if !slices.Contains(owner, route) {
			return false
		}
	}
	return true
}

func mergeSubnets(left, right []string) []string {
	result := append(slices.Clone(left), right...)
	result, _ = normalizeRoutedSubnets(result)
	return result
}

func subtractSubnets(owner, removed []string) []string {
	result := make([]string, 0, len(owner))
	for _, route := range owner {
		if !slices.Contains(removed, route) {
			result = append(result, route)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func certificateRoutedSubnets(network Network, node Node) []string {
	transfer := network.RouteTransfer
	switch transfer.Phase {
	case RouteTransferPhasePreparingTarget:
		if node.ID == transfer.TargetNodeID {
			return mergeSubnets(transfer.TargetOriginalSubnets, transfer.RoutedSubnets)
		}
	case RouteTransferPhaseCleaningTarget:
		if node.ID == transfer.TargetNodeID {
			return slices.Clone(transfer.TargetOriginalSubnets)
		}
	}
	if subnets, staged := routeProfileCertificateRoutedSubnets(network, node); staged {
		return subnets
	}
	return slices.Clone(node.RoutedSubnets)
}

func networkCertificateProfileRenewalRequired(network Network, node Node) bool {
	transfer := network.RouteTransfer
	switch transfer.Phase {
	case RouteTransferPhasePreparingTarget, RouteTransferPhaseCleaningTarget:
		return node.ID == transfer.TargetNodeID && node.CertificateGeneration < transfer.TargetCertificateGeneration
	case RouteTransferPhaseCleaningSource:
		return node.ID == transfer.SourceNodeID && node.CertificateGeneration < transfer.SourceCertificateGeneration
	}
	return routeProfileCertificateRenewalRequired(network, node)
}

func routeTransferNodeConverged(state State, network Network, node Node, desiredGeneration int64) bool {
	if desiredGeneration < 1 || node.Status != "active" || node.CertificateGeneration < desiredGeneration || node.AppliedCertificateGeneration != node.CertificateGeneration || node.AppliedConfigRevision != network.ConfigRevision || node.ReportedCertificateFingerprint != node.CertificateFingerprint || !node.NebulaRunning || node.AgentStatus != "healthy" || node.LastSeenAt == nil {
		return false
	}
	return node.AppliedConfigSHA256 == ConfigDigest(renderConfig(state, network, node))
}

func routeTransferDocument(state State, network Network) NetworkRouteTransferDocument {
	transfer := network.RouteTransfer
	doc := NetworkRouteTransferDocument{Schema: NetworkRouteTransferDocumentSchema, NetworkID: network.ID, ConfigRevision: network.ConfigRevision, RoutedSubnets: []string{}, AvailableActions: []string{}}
	if zeroNetworkRouteTransfer(transfer) {
		if network.CARotation.Phase == "" && network.FirewallRollout.Phase == "" && routeProfileEditTerminal(network.RouteProfileEdit) {
			doc.AvailableActions = append(doc.AvailableActions, "start")
		}
		return doc
	}
	doc.RequestID, doc.Phase = transfer.RequestID, transfer.Phase
	doc.RoutedSubnets = slices.Clone(transfer.RoutedSubnets)
	doc.StartedAt, doc.PromotedAt, doc.FinishedAt = optionalRouteTransferTime(transfer.StartedAt), optionalRouteTransferTime(transfer.PromotedAt), optionalRouteTransferTime(transfer.FinishedAt)
	source, _ := findNode(state, transfer.SourceNodeID)
	target, _ := findNode(state, transfer.TargetNodeID)
	if source.ID != "" {
		sourceStatus := routeTransferNodeStatus(state, network, source, transfer.SourceCertificateGeneration)
		doc.Source = &sourceStatus
	}
	if target.ID != "" {
		targetStatus := routeTransferNodeStatus(state, network, target, transfer.TargetCertificateGeneration)
		doc.Target = &targetStatus
	}
	switch transfer.Phase {
	case RouteTransferPhasePreparingTarget:
		if doc.Target != nil && doc.Target.Ready {
			doc.AvailableActions = append(doc.AvailableActions, "advance")
		}
		doc.AvailableActions = append(doc.AvailableActions, "cancel")
	case RouteTransferPhaseCleaningSource:
		if doc.Source != nil && doc.Source.Ready {
			doc.AvailableActions = append(doc.AvailableActions, "advance")
		}
	case RouteTransferPhaseCleaningTarget:
		if doc.Target != nil && doc.Target.Ready {
			doc.AvailableActions = append(doc.AvailableActions, "cancel")
		}
	case RouteTransferPhaseCompleted, RouteTransferPhaseCancelled:
		if network.CARotation.Phase == "" && network.FirewallRollout.Phase == "" && routeProfileEditTerminal(network.RouteProfileEdit) {
			doc.AvailableActions = append(doc.AvailableActions, "start")
		}
	}
	return doc
}

func optionalRouteTransferTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func routeTransferNodeStatus(state State, network Network, node Node, desiredGeneration int64) RouteTransferNodeStatus {
	if node.ID == "" {
		return RouteTransferNodeStatus{DesiredCertificateGeneration: desiredGeneration}
	}
	return RouteTransferNodeStatus{
		NodeID: node.ID, Name: node.Name, CertificateGeneration: node.CertificateGeneration,
		AppliedCertificateGeneration: node.AppliedCertificateGeneration, AppliedConfigRevision: node.AppliedConfigRevision,
		DesiredCertificateGeneration: desiredGeneration,
		Ready:                        routeTransferNodeConverged(state, network, node, desiredGeneration),
	}
}

func (s *Service) NetworkRouteTransfer(networkID string) (NetworkRouteTransferDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkRouteTransferDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	var result NetworkRouteTransferDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = routeTransferDocument(state, network)
		return nil
	})
	return result, err
}

func (s *Service) StartRouteTransferAs(actor Actor, networkID string, input StartRouteTransferInput) (NetworkRouteTransferDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkRouteTransferDocument{}, err
	}
	return s.startRouteTransfer(&actor, networkID, input)
}

func (s *Service) startRouteTransfer(actor *Actor, networkID string, input StartRouteTransferInput) (NetworkRouteTransferDocument, error) {
	input.SourceNodeID, input.TargetNodeID, input.RequestID = strings.TrimSpace(input.SourceNodeID), strings.TrimSpace(input.TargetNodeID), strings.TrimSpace(input.RequestID)
	routes, err := normalizeRoutedSubnets(input.RoutedSubnets)
	if !validPersistedID(networkID) || !validPersistedID(input.SourceNodeID) || !validPersistedID(input.TargetNodeID) || input.SourceNodeID == input.TargetNodeID || input.ExpectedConfigRevision < 1 || !validRouteTransferRequestID(input.RequestID) || err != nil || len(routes) == 0 {
		return NetworkRouteTransferDocument{}, fmt.Errorf("%w: distinct source and target nodes, canonical routed_subnets, expected_config_revision, and a 16-128 character request_id are required", ErrInvalid)
	}
	now := s.now().UTC()
	var result NetworkRouteTransferDocument
	err = s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: route-transfer schema is not current", ErrConflict)
		}
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			existing := network.RouteTransfer
			if existing.RequestID == input.RequestID {
				if existing.SourceNodeID != input.SourceNodeID || existing.TargetNodeID != input.TargetNodeID || !slices.Equal(existing.RoutedSubnets, routes) {
					return fmt.Errorf("%w: request_id is already bound to different transfer input", ErrConflict)
				}
				result = routeTransferDocument(*state, *network)
				return nil
			}
			if !routeTransferTerminal(existing) {
				return fmt.Errorf("%w: another route transfer is active", ErrConflict)
			}
			if network.CARotation.Phase != "" || network.FirewallRollout.Phase != "" || !routeProfileEditTerminal(network.RouteProfileEdit) || network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: network is not at the requested stable revision", ErrConflict)
			}
			source, sourceOK := findNode(*state, input.SourceNodeID)
			target, targetOK := findNode(*state, input.TargetNodeID)
			if !sourceOK || !targetOK || source.NetworkID != network.ID || target.NetworkID != network.ID || source.Status != "active" || target.Status != "active" || source.EnrolledAt == nil || target.EnrolledAt == nil {
				return fmt.Errorf("%w: source and target must be active enrolled nodes in this network", ErrConflict)
			}
			if !subnetSetContainsAll(source.RoutedSubnets, routes) {
				return fmt.Errorf("%w: source does not own every requested routed subnet", ErrConflict)
			}
			for _, route := range routes {
				owners := activeRouteOwners(*state, network.ID, route)
				if len(owners) != 1 || owners[0].ID != source.ID {
					return fmt.Errorf("%w: routed subnet %s has multiple gateways; change ECMP membership with the node route-profile workflow", ErrConflict, route)
				}
			}
			finalTarget, normalizeErr := normalizeRoutedSubnets(append(slices.Clone(target.RoutedSubnets), routes...))
			if normalizeErr != nil || len(finalTarget) > maxRoutedSubnetsPerNode {
				return fmt.Errorf("%w: target route profile would be invalid: %v", ErrConflict, normalizeErr)
			}
			if source.CertificateGeneration < 1 || target.CertificateGeneration < 1 || target.CertificateGeneration == int64(^uint64(0)>>1) {
				return fmt.Errorf("%w: participant certificate generation cannot advance", ErrConflict)
			}
			nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
			if revisionErr != nil {
				return revisionErr
			}
			network.RouteTransfer = NetworkRouteTransfer{
				RequestID: input.RequestID, Phase: RouteTransferPhasePreparingTarget,
				SourceNodeID: source.ID, TargetNodeID: target.ID, RoutedSubnets: slices.Clone(routes),
				SourceOriginalSubnets: slices.Clone(source.RoutedSubnets), TargetOriginalSubnets: slices.Clone(target.RoutedSubnets),
				TargetCertificateGeneration: target.CertificateGeneration + 1, StartedAt: now,
			}
			network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
			event, auditErr := newOptionalAttributedAudit(now, "network.route_transfer_started", "network", network.ID, map[string]any{
				"request_id": input.RequestID, "source_node_id": source.ID, "target_node_id": target.ID,
				"routed_subnets": strings.Join(routes, ","), "previous_config_revision": input.ExpectedConfigRevision,
				"config_revision": nextRevision, "target_certificate_generation": target.CertificateGeneration + 1,
			}, actor)
			if auditErr != nil {
				return auditErr
			}
			state.Audit = append(state.Audit, event)
			result = routeTransferDocument(*state, *network)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func (s *Service) AdvanceRouteTransferAs(actor Actor, networkID string, input UpdateRouteTransferInput) (NetworkRouteTransferDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkRouteTransferDocument{}, err
	}
	return s.updateRouteTransfer(&actor, networkID, input, false)
}

func (s *Service) CancelRouteTransferAs(actor Actor, networkID string, input UpdateRouteTransferInput) (NetworkRouteTransferDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkRouteTransferDocument{}, err
	}
	return s.updateRouteTransfer(&actor, networkID, input, true)
}

func (s *Service) updateRouteTransfer(actor *Actor, networkID string, input UpdateRouteTransferInput, cancel bool) (NetworkRouteTransferDocument, error) {
	input.RequestID = strings.TrimSpace(input.RequestID)
	if !validPersistedID(networkID) || input.ExpectedConfigRevision < 1 || !validRouteTransferRequestID(input.RequestID) {
		return NetworkRouteTransferDocument{}, fmt.Errorf("%w: network ID, expected_config_revision, and request_id are required", ErrInvalid)
	}
	now := s.now().UTC()
	var result NetworkRouteTransferDocument
	err := s.updateState(func(state *State) error {
		if state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: route-transfer schema is not current", ErrConflict)
		}
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			transfer := &network.RouteTransfer
			if transfer.RequestID != input.RequestID {
				return fmt.Errorf("%w: request_id does not match the authoritative transfer", ErrConflict)
			}
			if (cancel && transfer.Phase == RouteTransferPhaseCancelled || !cancel && transfer.Phase == RouteTransferPhaseCompleted) && terminalRouteTransitionReplayRevision(input.ExpectedConfigRevision, network.ConfigRevision) {
				result = routeTransferDocument(*state, *network)
				return nil
			}
			if network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			source, _ := findNode(*state, transfer.SourceNodeID)
			target, _ := findNode(*state, transfer.TargetNodeID)
			if cancel {
				switch transfer.Phase {
				case RouteTransferPhaseCancelled:
					result = routeTransferDocument(*state, *network)
					return nil
				case RouteTransferPhasePreparingTarget:
					nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
					if revisionErr != nil {
						return revisionErr
					}
					if target.CertificateGeneration < transfer.TargetCertificateGeneration {
						transfer.Phase, transfer.FinishedAt = RouteTransferPhaseCancelled, now
					} else {
						if target.CertificateGeneration == int64(^uint64(0)>>1) {
							return fmt.Errorf("%w: target certificate generation cannot advance", ErrConflict)
						}
						transfer.Phase = RouteTransferPhaseCleaningTarget
						transfer.TargetCertificateGeneration = target.CertificateGeneration + 1
					}
					network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
				case RouteTransferPhaseCleaningTarget:
					if !routeTransferNodeConverged(*state, *network, target, transfer.TargetCertificateGeneration) {
						return fmt.Errorf("%w: target certificate cleanup has not converged", ErrConflict)
					}
					transfer.Phase, transfer.FinishedAt = RouteTransferPhaseCancelled, now
				default:
					return fmt.Errorf("%w: transfer can no longer be cancelled", ErrConflict)
				}
				action := "network.route_transfer_cancelled"
				if transfer.Phase == RouteTransferPhaseCleaningTarget {
					action = "network.route_transfer_cancellation_started"
				}
				event, auditErr := newOptionalAttributedAudit(now, action, "network", network.ID, map[string]any{
					"request_id": transfer.RequestID, "phase": transfer.Phase, "config_revision": network.ConfigRevision,
				}, actor)
				if auditErr != nil {
					return auditErr
				}
				state.Audit = append(state.Audit, event)
				result = routeTransferDocument(*state, *network)
				return nil
			}

			switch transfer.Phase {
			case RouteTransferPhaseCompleted:
				result = routeTransferDocument(*state, *network)
				return nil
			case RouteTransferPhasePreparingTarget:
				if !routeTransferNodeConverged(*state, *network, target, transfer.TargetCertificateGeneration) {
					return fmt.Errorf("%w: target gateway has not converged", ErrConflict)
				}
				if source.CertificateGeneration == int64(^uint64(0)>>1) {
					return fmt.Errorf("%w: source certificate generation cannot advance", ErrConflict)
				}
				nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
				if revisionErr != nil {
					return revisionErr
				}
				for nodeIndex := range state.Nodes {
					node := &state.Nodes[nodeIndex]
					switch node.ID {
					case source.ID:
						node.RoutedSubnets = subtractSubnets(transfer.SourceOriginalSubnets, transfer.RoutedSubnets)
					case target.ID:
						node.RoutedSubnets = mergeSubnets(transfer.TargetOriginalSubnets, transfer.RoutedSubnets)
					}
				}
				reconcileNetworkRoutePolicies(state, network)
				transfer.Phase, transfer.PromotedAt = RouteTransferPhaseCleaningSource, now
				transfer.SourceCertificateGeneration = source.CertificateGeneration + 1
				network.ConfigRevision, network.ConfigUpdatedAt = nextRevision, now
			case RouteTransferPhaseCleaningSource:
				if !routeTransferNodeConverged(*state, *network, source, transfer.SourceCertificateGeneration) {
					return fmt.Errorf("%w: source certificate cleanup has not converged", ErrConflict)
				}
				transfer.Phase, transfer.FinishedAt = RouteTransferPhaseCompleted, now
			default:
				return fmt.Errorf("%w: transfer is not advanceable", ErrConflict)
			}
			action := "network.route_transfer_promoted"
			if transfer.Phase == RouteTransferPhaseCompleted {
				action = "network.route_transfer_completed"
			}
			event, auditErr := newOptionalAttributedAudit(now, action, "network", network.ID, map[string]any{
				"request_id": transfer.RequestID, "phase": transfer.Phase, "routed_subnets": strings.Join(transfer.RoutedSubnets, ","),
				"source_node_id": transfer.SourceNodeID, "target_node_id": transfer.TargetNodeID, "config_revision": network.ConfigRevision,
			}, actor)
			if auditErr != nil {
				return auditErr
			}
			state.Audit = append(state.Audit, event)
			result = routeTransferDocument(*state, *network)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}
