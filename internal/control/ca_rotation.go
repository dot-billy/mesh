package control

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	NetworkCARotationDocumentSchema = "mesh-network-ca-rotation-v1"
	CARotationPhasePrepared         = "prepared"
	CARotationPhaseRotating         = "rotating"
	CARotationPhaseFinalizing       = "finalizing"
	CARotationPhaseAborting         = "aborting"
)

// NetworkCARotation is the crash-durable state machine for replacing a
// Nebula CA without ever creating a point where two healthy managed peers do
// not share a trust root. The zero value is the stable state.
type NetworkCARotation struct {
	Phase                     string    `json:"phase,omitempty"`
	NextCACertificate         string    `json:"next_ca_certificate,omitempty"`
	EncryptedNextCAKey        string    `json:"-"`
	PreviousTrustBundleSHA256 string    `json:"previous_trust_bundle_sha256,omitempty"`
	TargetCACertificateSHA256 string    `json:"target_ca_certificate_sha256,omitempty"`
	StartedAt                 time.Time `json:"started_at,omitempty"`
	StageStartedAt            time.Time `json:"stage_started_at,omitempty"`
	StageConfigRevision       int64     `json:"stage_config_revision,omitempty"`
}

type UpdateNetworkCARotationInput struct {
	Action                 string `json:"action"`
	ExpectedConfigRevision int64  `json:"expected_config_revision"`
}

type CARotationNodeStatus struct {
	NodeID                       string `json:"node_id"`
	Name                         string `json:"name"`
	Status                       string `json:"status"`
	CertificateAuthoritySHA256   string `json:"certificate_authority_sha256,omitempty"`
	CertificateGeneration        int64  `json:"certificate_generation"`
	AppliedCertificateGeneration int64  `json:"applied_certificate_generation"`
	AppliedConfigRevision        int64  `json:"applied_config_revision"`
	Converged                    bool   `json:"converged"`
}

type NetworkCARotationDocument struct {
	Schema                    string                 `json:"schema"`
	NetworkID                 string                 `json:"network_id"`
	Phase                     string                 `json:"phase"`
	CurrentTrustBundleSHA256  string                 `json:"current_trust_bundle_sha256"`
	PreviousTrustBundleSHA256 string                 `json:"previous_trust_bundle_sha256"`
	ActiveCACertificateSHA256 string                 `json:"active_ca_certificate_sha256"`
	TargetCACertificateSHA256 string                 `json:"target_ca_certificate_sha256"`
	StageConfigRevision       int64                  `json:"stage_config_revision"`
	ConfigRevision            int64                  `json:"config_revision"`
	ConfigUpdatedAt           time.Time              `json:"config_updated_at"`
	StartedAt                 *time.Time             `json:"started_at"`
	StageStartedAt            *time.Time             `json:"stage_started_at"`
	ActiveNodes               int                    `json:"active_nodes"`
	ConvergedNodes            int                    `json:"converged_nodes"`
	PendingRecoveryReplays    int                    `json:"pending_recovery_replays"`
	AvailableActions          []string               `json:"available_actions"`
	Nodes                     []CARotationNodeStatus `json:"nodes"`
}

func stableCARotationPhase(phase string) string {
	if phase == "" {
		return "stable"
	}
	return phase
}

func concatenateCAs(first, second string) string {
	if second == "" {
		return first
	}
	if strings.HasSuffix(first, "\n") {
		return first + second
	}
	return first + "\n" + second
}

func networkTrustBundle(network Network) string {
	if network.CARotation.Phase == CARotationPhasePrepared || network.CARotation.Phase == CARotationPhaseRotating {
		return concatenateCAs(network.CACertificate, network.CARotation.NextCACertificate)
	}
	return network.CACertificate
}

func networkSigningAuthority(network Network) (string, string) {
	if network.CARotation.Phase == CARotationPhaseRotating {
		return network.CARotation.NextCACertificate, network.CARotation.EncryptedNextCAKey
	}
	return network.CACertificate, network.EncryptedCAKey
}

func networkCARotationRequired(network Network, node Node) bool {
	return network.CARotation.Phase == CARotationPhaseRotating &&
		node.CertificateAuthoritySHA256 != network.CARotation.TargetCACertificateSHA256
}

func validateNetworkCARotation(network Network) error {
	r := network.CARotation
	if r.Phase == "" {
		if r != (NetworkCARotation{}) {
			return errors.New("stable CA rotation must have no transition metadata")
		}
		return nil
	}
	if r.Phase != CARotationPhasePrepared && r.Phase != CARotationPhaseRotating && r.Phase != CARotationPhaseFinalizing && r.Phase != CARotationPhaseAborting {
		return errors.New("CA rotation phase is invalid")
	}
	if !fingerprintPattern.MatchString(r.PreviousTrustBundleSHA256) || !fingerprintPattern.MatchString(r.TargetCACertificateSHA256) || r.StartedAt.IsZero() || r.StageStartedAt.IsZero() || r.StageConfigRevision < 1 || r.StageConfigRevision > network.ConfigRevision {
		return errors.New("CA rotation lifecycle metadata is invalid")
	}
	if r.Phase == CARotationPhasePrepared || r.Phase == CARotationPhaseRotating {
		if !validBoundedUTF8(r.NextCACertificate, maxNebulaCACertificateSize, false) {
			return errors.New("next CA certificate is empty, oversized, or invalid UTF-8")
		}
		if err := validateCanonicalRawURLBase64(r.EncryptedNextCAKey, maxEncryptedCAKeyBytes, secretBoxNonceBytes+secretBoxTagBytes+1, maxNebulaCAPrivateKeySize+secretBoxNonceBytes+secretBoxTagBytes); err != nil {
			return fmt.Errorf("encrypted next CA key: %w", err)
		}
		if ConfigDigest(r.NextCACertificate) != r.TargetCACertificateSHA256 || r.NextCACertificate == network.CACertificate {
			return errors.New("next CA identity is inconsistent")
		}
	} else if r.NextCACertificate != "" || r.EncryptedNextCAKey != "" {
		return errors.New("closing CA rotation retains next CA key material")
	}
	if r.PreviousTrustBundleSHA256 == ConfigDigest(networkTrustBundle(network)) {
		return errors.New("CA rotation previous and current trust bundles are identical")
	}
	return nil
}

func caRotationNodeConverged(network Network, node Node) bool {
	if node.Status != "active" {
		return true
	}
	switch network.CARotation.Phase {
	case CARotationPhasePrepared:
		return node.AppliedConfigRevision >= network.CARotation.StageConfigRevision
	case CARotationPhaseRotating:
		return node.CertificateAuthoritySHA256 == network.CARotation.TargetCACertificateSHA256 &&
			node.AppliedCertificateGeneration >= node.CertificateGeneration &&
			node.ReportedCertificateFingerprint == node.CertificateFingerprint &&
			node.AppliedConfigRevision >= network.CARotation.StageConfigRevision
	case CARotationPhaseFinalizing, CARotationPhaseAborting:
		return node.AppliedConfigRevision >= network.CARotation.StageConfigRevision
	default:
		return true
	}
}

func networkRecoveryReplayCount(state State, networkID string, at time.Time) int {
	count := 0
	for _, recovery := range state.AgentRecoveries {
		if recovery.Result != nil && at.Before(recovery.ExpiresAt) && recovery.Result.NetworkID == networkID {
			count++
		}
	}
	return count
}

func pruneExpiredNetworkRecoveryReplays(state *State, networkID string, at time.Time) error {
	remaining := state.AgentRecoveries[:0]
	for _, recovery := range state.AgentRecoveries {
		if recovery.Result != nil && recovery.Result.NetworkID == networkID {
			if at.Before(recovery.ExpiresAt) {
				return fmt.Errorf("%w: wait for %d in-flight agent recovery replay(s) to expire before changing the CA trust bundle", ErrConflict, networkRecoveryReplayCount(*state, networkID, at))
			}
			continue
		}
		remaining = append(remaining, recovery)
	}
	state.AgentRecoveries = slices.Clip(remaining)
	return nil
}

func networkCARotationDocument(state State, network Network, at time.Time) NetworkCARotationDocument {
	doc := NetworkCARotationDocument{
		Schema: NetworkCARotationDocumentSchema, NetworkID: network.ID, Phase: stableCARotationPhase(network.CARotation.Phase),
		CurrentTrustBundleSHA256: ConfigDigest(networkTrustBundle(network)), PreviousTrustBundleSHA256: network.CARotation.PreviousTrustBundleSHA256,
		ActiveCACertificateSHA256: ConfigDigest(network.CACertificate), TargetCACertificateSHA256: network.CARotation.TargetCACertificateSHA256,
		StageConfigRevision: network.CARotation.StageConfigRevision, ConfigRevision: network.ConfigRevision, ConfigUpdatedAt: network.ConfigUpdatedAt,
		StartedAt: optionalTime(network.CARotation.StartedAt), StageStartedAt: optionalTime(network.CARotation.StageStartedAt),
		PendingRecoveryReplays: networkRecoveryReplayCount(state, network.ID, at), Nodes: []CARotationNodeStatus{}, AvailableActions: []string{},
	}
	allConverged := true
	for _, node := range state.Nodes {
		if node.NetworkID != network.ID || node.Status != "active" {
			continue
		}
		converged := caRotationNodeConverged(network, node)
		doc.ActiveNodes++
		if converged {
			doc.ConvergedNodes++
		} else {
			allConverged = false
		}
		doc.Nodes = append(doc.Nodes, CARotationNodeStatus{
			NodeID: node.ID, Name: node.Name, Status: node.Status, CertificateAuthoritySHA256: node.CertificateAuthoritySHA256,
			CertificateGeneration: node.CertificateGeneration, AppliedCertificateGeneration: node.AppliedCertificateGeneration,
			AppliedConfigRevision: node.AppliedConfigRevision, Converged: converged,
		})
	}
	if doc.ActiveNodes == 0 {
		allConverged = true
	}
	switch network.CARotation.Phase {
	case "":
		if network.FirewallRollout.Phase == "" && routeTransferTerminal(network.RouteTransfer) && routeProfileEditTerminal(network.RouteProfileEdit) {
			doc.AvailableActions = append(doc.AvailableActions, "prepare")
		}
	case CARotationPhasePrepared:
		if allConverged {
			doc.AvailableActions = append(doc.AvailableActions, "activate")
		}
		if doc.PendingRecoveryReplays == 0 {
			doc.AvailableActions = append(doc.AvailableActions, "abort")
		}
	case CARotationPhaseRotating:
		if allConverged && doc.PendingRecoveryReplays == 0 {
			doc.AvailableActions = append(doc.AvailableActions, "finalize")
		}
	case CARotationPhaseFinalizing, CARotationPhaseAborting:
		if allConverged {
			doc.AvailableActions = append(doc.AvailableActions, "complete")
		}
	}
	return doc
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func (s *Service) NetworkCARotation(networkID string) (NetworkCARotationDocument, error) {
	if !validPersistedID(networkID) {
		return NetworkCARotationDocument{}, fmt.Errorf("%w: invalid network ID", ErrInvalid)
	}
	var result NetworkCARotationDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = networkCARotationDocument(state, network, s.now().UTC())
		return nil
	})
	return result, err
}

func (s *Service) UpdateNetworkCARotation(ctx context.Context, networkID string, input UpdateNetworkCARotationInput) (NetworkCARotationDocument, error) {
	return s.updateNetworkCARotation(ctx, nil, networkID, input)
}

func (s *Service) UpdateNetworkCARotationAs(ctx context.Context, actor Actor, networkID string, input UpdateNetworkCARotationInput) (NetworkCARotationDocument, error) {
	if err := validateActor(actor); err != nil {
		return NetworkCARotationDocument{}, err
	}
	return s.updateNetworkCARotation(ctx, &actor, networkID, input)
}

func (s *Service) updateNetworkCARotation(ctx context.Context, actor *Actor, networkID string, input UpdateNetworkCARotationInput) (NetworkCARotationDocument, error) {
	if !validPersistedID(networkID) || input.ExpectedConfigRevision < 1 {
		return NetworkCARotationDocument{}, fmt.Errorf("%w: network ID and expected_config_revision are required", ErrInvalid)
	}
	if input.Action != "prepare" && input.Action != "activate" && input.Action != "finalize" && input.Action != "abort" && input.Action != "complete" {
		return NetworkCARotationDocument{}, fmt.Errorf("%w: unsupported CA rotation action", ErrInvalid)
	}

	var generatedCertificate, encryptedGeneratedKey string
	if input.Action == "prepare" {
		var network Network
		if err := s.viewState(func(state State) error {
			var ok bool
			network, ok = findNetwork(state, networkID)
			if !ok {
				return ErrNotFound
			}
			if state.Version < ControlStateVersionCARotation || state.Version > ControlStateVersionFirewallScopes || network.CARotation.Phase != "" || network.FirewallRollout.Phase != "" || !routeTransferTerminal(network.RouteTransfer) || !routeProfileEditTerminal(network.RouteProfileEdit) || network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: network is not at the requested stable revision", ErrConflict)
			}
			return nil
		}); err != nil {
			return NetworkCARotationDocument{}, err
		}
		certificate, privateKey, err := s.issuer.CreateCA(ctx, network.Name, network.CIDR)
		if err != nil {
			return NetworkCARotationDocument{}, err
		}
		defer func() { privateKey = "" }()
		if err := validateGeneratedCA(certificate, privateKey); err != nil {
			return NetworkCARotationDocument{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		candidate := network
		candidate.CACertificate = certificate
		if _, err := validateNebulaCAKeyPair(candidate, []byte(privateKey)); err != nil {
			return NetworkCARotationDocument{}, fmt.Errorf("%w: generated replacement CA is invalid: %v", ErrInvalid, err)
		}
		sealed, err := s.box.Seal([]byte(privateKey))
		if err != nil {
			return NetworkCARotationDocument{}, err
		}
		generatedCertificate, encryptedGeneratedKey = certificate, sealed
	}

	now := s.now().UTC()
	if now.IsZero() {
		return NetworkCARotationDocument{}, errors.New("CA rotation requires a valid timestamp")
	}
	var result NetworkCARotationDocument
	err := s.updateState(func(state *State) error {
		if state.Version < ControlStateVersionCARotation || state.Version > ControlStateVersionFirewallScopes {
			return fmt.Errorf("%w: CA rotation schema is not current", ErrConflict)
		}
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			if network.ConfigRevision != input.ExpectedConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			phase := network.CARotation.Phase
			allConverged := true
			for _, node := range state.Nodes {
				if node.NetworkID == network.ID && node.Status == "active" && !caRotationNodeConverged(*network, node) {
					allConverged = false
				}
			}
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			details := map[string]any{"previous_config_revision": network.ConfigRevision, "config_revision": nextRevision}
			action := ""
			switch input.Action {
			case "prepare":
				if phase != "" || network.FirewallRollout.Phase != "" || generatedCertificate == "" || encryptedGeneratedKey == "" {
					return fmt.Errorf("%w: CA rotation can only be prepared from stable state", ErrConflict)
				}
				if err := pruneExpiredNetworkRecoveryReplays(state, network.ID, now); err != nil {
					return err
				}
				network.CARotation = NetworkCARotation{
					Phase: CARotationPhasePrepared, NextCACertificate: generatedCertificate, EncryptedNextCAKey: encryptedGeneratedKey,
					PreviousTrustBundleSHA256: ConfigDigest(network.CACertificate), TargetCACertificateSHA256: ConfigDigest(generatedCertificate),
					StartedAt: now, StageStartedAt: now, StageConfigRevision: nextRevision,
				}
				action = "network.ca_rotation_prepared"
				details["target_ca_sha256"] = network.CARotation.TargetCACertificateSHA256
			case "activate":
				if phase != CARotationPhasePrepared || !allConverged {
					return fmt.Errorf("%w: every active node must apply the prepared trust bundle before activation", ErrConflict)
				}
				network.CARotation.Phase = CARotationPhaseRotating
				network.CARotation.StageStartedAt = now
				network.CARotation.StageConfigRevision = nextRevision
				action = "network.ca_rotation_activated"
			case "finalize":
				if phase != CARotationPhaseRotating || !allConverged {
					return fmt.Errorf("%w: every active node must install a replacement certificate before finalization", ErrConflict)
				}
				if err := pruneExpiredNetworkRecoveryReplays(state, network.ID, now); err != nil {
					return err
				}
				dualDigest := ConfigDigest(networkTrustBundle(*network))
				network.CACertificate = network.CARotation.NextCACertificate
				network.EncryptedCAKey = network.CARotation.EncryptedNextCAKey
				network.CARotation.Phase = CARotationPhaseFinalizing
				network.CARotation.NextCACertificate = ""
				network.CARotation.EncryptedNextCAKey = ""
				network.CARotation.PreviousTrustBundleSHA256 = dualDigest
				network.CARotation.StageStartedAt = now
				network.CARotation.StageConfigRevision = nextRevision
				action = "network.ca_rotation_finalized"
			case "abort":
				if phase != CARotationPhasePrepared {
					return fmt.Errorf("%w: only a prepared CA rotation can be aborted", ErrConflict)
				}
				if err := pruneExpiredNetworkRecoveryReplays(state, network.ID, now); err != nil {
					return err
				}
				dualDigest := ConfigDigest(networkTrustBundle(*network))
				targetDigest, startedAt := network.CARotation.TargetCACertificateSHA256, network.CARotation.StartedAt
				network.CARotation = NetworkCARotation{
					Phase: CARotationPhaseAborting, PreviousTrustBundleSHA256: dualDigest, TargetCACertificateSHA256: targetDigest,
					StartedAt: startedAt, StageStartedAt: now, StageConfigRevision: nextRevision,
				}
				action = "network.ca_rotation_aborted"
			case "complete":
				if (phase != CARotationPhaseFinalizing && phase != CARotationPhaseAborting) || !allConverged {
					return fmt.Errorf("%w: every active node must apply the closing trust bundle before completion", ErrConflict)
				}
				details["outcome"] = map[bool]string{true: "finalized", false: "aborted"}[phase == CARotationPhaseFinalizing]
				network.CARotation = NetworkCARotation{}
				action = "network.ca_rotation_completed"
			}
			event, err := newOptionalAttributedAudit(now, action, "network", network.ID, details, actor)
			if err != nil {
				return err
			}
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
			state.Audit = append(state.Audit, event)
			result = networkCARotationDocument(*state, *network, now)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}
