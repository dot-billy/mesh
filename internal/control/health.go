package control

import (
	"errors"
	"sort"
	"time"
)

const (
	fleetHeartbeatWarningAfter   = 2 * time.Minute
	fleetHeartbeatOfflineAfter   = 5 * time.Minute
	fleetCredentialWarningBefore = 30 * 24 * time.Hour
	fleetRequiredLighthouses     = 2
	// Exact lighthouse config digests differ per lighthouse because each
	// config omits itself from the remote lighthouse list. Bound that work so
	// a corrupted or externally imported graph cannot trigger quadratic CPU
	// and allocation growth in this read-only projection.
	maxFleetHealthLighthousesPerNetwork = 64
)

const (
	FleetHealthHealthy  = "healthy"
	FleetHealthWarning  = "warning"
	FleetHealthCritical = "critical"
)

// FleetHealthReport is a read-only projection of the authenticated lifecycle
// evidence already held by the control plane. It intentionally contains no
// credential material, certificate fingerprints, config digests, or agent
// error text.
type FleetHealthReport struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Network     FleetHealthNetwork     `json:"network"`
	Policy      FleetHealthPolicy      `json:"policy"`
	Summary     FleetHealthSummary     `json:"summary"`
	Rollout     FleetRolloutProjection `json:"rollout"`
	Nodes       []FleetNodeHealth      `json:"nodes"`
	Alerts      []FleetHealthAlert     `json:"alerts"`
}

// FleetHealthCollection is the dashboard projection for every network. The
// collection carries one clock sample and one policy; nested network reports
// deliberately omit those fields so consumers cannot accidentally compare
// health derived at different times.
type FleetHealthCollection struct {
	GeneratedAt time.Time                    `json:"generated_at"`
	Policy      FleetHealthPolicy            `json:"policy"`
	Summary     FleetHealthCollectionSummary `json:"summary"`
	Rollout     FleetRolloutSummary          `json:"rollout"`
	Networks    []FleetNetworkHealthReport   `json:"networks"`
}

type FleetNetworkHealthReport struct {
	Network FleetHealthNetwork     `json:"network"`
	Summary FleetHealthSummary     `json:"summary"`
	Rollout FleetRolloutProjection `json:"rollout"`
	Nodes   []FleetNodeHealth      `json:"nodes"`
	Alerts  []FleetHealthAlert     `json:"alerts"`
}

type FleetHealthCollectionSummary struct {
	Overall          string `json:"overall"`
	TotalNetworks    int    `json:"total_networks"`
	HealthyNetworks  int    `json:"healthy_networks"`
	WarningNetworks  int    `json:"warning_networks"`
	CriticalNetworks int    `json:"critical_networks"`
	TotalNodes       int    `json:"total_nodes"`
	SetupNodes       int    `json:"setup_nodes"`
	ActiveNodes      int    `json:"active_nodes"`
	RevokedNodes     int    `json:"revoked_nodes"`
	HealthyNodes     int    `json:"healthy_nodes"`
	WarningNodes     int    `json:"warning_nodes"`
	CriticalNodes    int    `json:"critical_nodes"`
}

type FleetRolloutSummary struct {
	EligibleNodes   int `json:"eligible_nodes"`
	ConvergedNodes  int `json:"converged_nodes"`
	DriftedNodes    int `json:"drifted_nodes"`
	UnreportedNodes int `json:"unreported_nodes"`
	Percent         int `json:"percent"`
}

type fleetRevocationEvidence struct {
	At         time.Time
	Active     int
	Conclusive bool
}

type fleetNetworkEvidence struct {
	Revocation              fleetRevocationEvidence
	ControlTimeAt           time.Time
	ControlTimeInvalid      bool
	ProjectionLimitExceeded bool
	ObservedLighthouses     int
}

type fleetHealthIndex struct {
	NodesByNetwork            map[string][]Node
	EvidenceByNetwork         map[string]fleetNetworkEvidence
	DesiredConfigDigestByNode map[string]string
}

type FleetHealthNetwork struct {
	ID                    string               `json:"id"`
	Name                  string               `json:"name"`
	CIDR                  string               `json:"cidr"`
	ListenPort            int                  `json:"listen_port"`
	DNSSettings           NetworkDNSSettings   `json:"dns_settings"`
	RelaySettings         NetworkRelaySettings `json:"relay_settings"`
	DesiredConfigRevision int64                `json:"desired_config_revision"`
	ConfigUpdatedAt       time.Time            `json:"config_updated_at"`
}

type FleetHealthPolicy struct {
	HeartbeatWarningAfterSeconds   int64  `json:"heartbeat_warning_after_seconds"`
	HeartbeatOfflineAfterSeconds   int64  `json:"heartbeat_offline_after_seconds"`
	CredentialWarningBeforeSeconds int64  `json:"credential_warning_before_seconds"`
	RequiredHealthyLighthouses     int    `json:"required_healthy_lighthouses"`
	EvidenceSource                 string `json:"evidence_source"`
	OverlayReachabilityObserved    bool   `json:"overlay_reachability_observed"`
}

type FleetHealthSummary struct {
	Overall            string `json:"overall"`
	TotalNodes         int    `json:"total_nodes"`
	PendingNodes       int    `json:"pending_nodes"`
	ActiveNodes        int    `json:"active_nodes"`
	RevokedNodes       int    `json:"revoked_nodes"`
	SetupNodes         int    `json:"setup_nodes"`
	HealthyNodes       int    `json:"healthy_nodes"`
	WarningNodes       int    `json:"warning_nodes"`
	CriticalNodes      int    `json:"critical_nodes"`
	ActiveLighthouses  int    `json:"active_lighthouses"`
	HealthyLighthouses int    `json:"healthy_lighthouses"`
}

type FleetRolloutProjection struct {
	DesiredConfigRevision int64 `json:"desired_config_revision"`
	EligibleNodes         int   `json:"eligible_nodes"`
	ConvergedNodes        int   `json:"converged_nodes"`
	DriftedNodes          int   `json:"drifted_nodes"`
	UnreportedNodes       int   `json:"unreported_nodes"`
	Percent               int   `json:"percent"`
}

type FleetNodeHealth struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	IP                string   `json:"ip"`
	RoutedSubnets     []string `json:"routed_subnets"`
	Site              string   `json:"site"`
	FailureDomain     string   `json:"failure_domain"`
	Role              string   `json:"role"`
	LifecycleStatus   string   `json:"lifecycle_status"`
	HeartbeatSequence int64    `json:"heartbeat_sequence"`
	Phase             string   `json:"phase"`
	Severity          string   `json:"severity"`
	// Operational means the authenticated lifecycle agent recently proved the
	// local runtime/config state. It is not a Nebula handshake or UDP probe.
	Operational                  bool               `json:"operational"`
	RolloutCurrent               bool               `json:"rollout_current"`
	LastSeenAt                   *time.Time         `json:"last_seen_at,omitempty"`
	AgentStatus                  string             `json:"agent_status,omitempty"`
	NebulaRunning                bool               `json:"nebula_running"`
	DesiredConfigRevision        int64              `json:"desired_config_revision"`
	AppliedConfigRevision        int64              `json:"applied_config_revision"`
	DesiredCertificateGeneration int64              `json:"desired_certificate_generation"`
	AppliedCertificateGeneration int64              `json:"applied_certificate_generation"`
	CertificateExpiresAt         *time.Time         `json:"certificate_expires_at,omitempty"`
	CertificateRenewAfter        *time.Time         `json:"certificate_renew_after,omitempty"`
	AgentCredentialExpiresAt     *time.Time         `json:"agent_credential_expires_at,omitempty"`
	Alerts                       []FleetHealthAlert `json:"alerts"`
}

type FleetHealthAlert struct {
	Severity string              `json:"severity"`
	Code     string              `json:"code"`
	Scope    string              `json:"scope"`
	NodeID   string              `json:"node_id,omitempty"`
	Evidence FleetHealthEvidence `json:"evidence"`
}

// FleetHealthEvidence is deliberately an allowlist rather than an open-ended
// map so new alert logic cannot accidentally serialize secret state.
type FleetHealthEvidence struct {
	SinceAt                      *time.Time `json:"since_at,omitempty"`
	LastSeenAt                   *time.Time `json:"last_seen_at,omitempty"`
	AgeSeconds                   *int64     `json:"age_seconds,omitempty"`
	ThresholdSeconds             *int64     `json:"threshold_seconds,omitempty"`
	DesiredConfigRevision        *int64     `json:"desired_config_revision,omitempty"`
	AppliedConfigRevision        *int64     `json:"applied_config_revision,omitempty"`
	DesiredCertificateGeneration *int64     `json:"desired_certificate_generation,omitempty"`
	AppliedCertificateGeneration *int64     `json:"applied_certificate_generation,omitempty"`
	ExpiresAt                    *time.Time `json:"expires_at,omitempty"`
	RenewAfter                   *time.Time `json:"renew_after,omitempty"`
	ReportedStatus               string     `json:"reported_status,omitempty"`
	NebulaRunning                *bool      `json:"nebula_running,omitempty"`
	ErrorReported                *bool      `json:"error_reported,omitempty"`
	ActiveLighthouses            *int       `json:"active_lighthouses,omitempty"`
	HealthyLighthouses           *int       `json:"healthy_lighthouses,omitempty"`
	RequiredLighthouses          *int       `json:"required_lighthouses,omitempty"`
	ActiveRevocations            *int       `json:"active_revocations,omitempty"`
	RevocationAt                 *time.Time `json:"revocation_at,omitempty"`
	ControlTimeAt                *time.Time `json:"control_time_at,omitempty"`
	ObservedLighthouses          *int       `json:"observed_lighthouses,omitempty"`
	ProjectionLimit              *int       `json:"projection_limit,omitempty"`
}

// FleetHealth derives a deterministic network health and rollout snapshot.
// It performs exactly one stable store read and never appends audit events or
// mutates persisted lifecycle state.
func (s *Service) FleetHealth(networkID string) (FleetHealthReport, error) {
	if s == nil || s.now == nil {
		return FleetHealthReport{}, ErrInvalidStateStore
	}
	var report FleetHealthReport
	err := s.viewState(func(state State) error {
		// Sample time after acquiring the stable snapshot. Otherwise a heartbeat
		// committed between an earlier clock read and this view could appear to
		// come from the future on a busy multi-replica control plane.
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("fleet health requires a valid timestamp")
		}
		var err error
		report, err = deriveFleetHealth(state, networkID, now)
		return err
	})
	return report, err
}

// FleetHealthAll derives all network reports from one control-state snapshot
// and one clock sample. This is the collection path for multi-replica
// deployments where one View corresponds to one authoritative document read.
func (s *Service) FleetHealthAll() (FleetHealthCollection, error) {
	if s == nil || s.now == nil {
		return FleetHealthCollection{}, ErrInvalidStateStore
	}
	var collection FleetHealthCollection
	err := s.viewState(func(state State) error {
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("fleet health requires a valid timestamp")
		}
		collection = FleetHealthCollection{
			GeneratedAt: now,
			Policy:      fleetHealthPolicy(),
			Summary:     FleetHealthCollectionSummary{Overall: FleetHealthHealthy},
			Rollout:     FleetRolloutSummary{Percent: 100},
			Networks:    []FleetNetworkHealthReport{},
		}
		index := buildFleetHealthIndex(state, now)
		for _, network := range state.Networks {
			report := deriveFleetHealthForNetwork(network, index.NodesByNetwork[network.ID], now, index.EvidenceByNetwork[network.ID], index.DesiredConfigDigestByNode)
			collection.Networks = append(collection.Networks, FleetNetworkHealthReport{
				Network: report.Network, Summary: report.Summary, Rollout: report.Rollout,
				Nodes: report.Nodes, Alerts: report.Alerts,
			})
		}
		sort.Slice(collection.Networks, func(i, j int) bool {
			if collection.Networks[i].Network.Name != collection.Networks[j].Network.Name {
				return collection.Networks[i].Network.Name < collection.Networks[j].Network.Name
			}
			return collection.Networks[i].Network.ID < collection.Networks[j].Network.ID
		})
		aggregateFleetHealth(&collection)
		return nil
	})
	return collection, err
}

func deriveFleetHealth(state State, networkID string, now time.Time) (FleetHealthReport, error) {
	network, ok := findNetwork(state, networkID)
	if !ok {
		return FleetHealthReport{}, ErrNotFound
	}
	index := buildFleetHealthIndex(state, now)
	return deriveFleetHealthForNetwork(network, index.NodesByNetwork[network.ID], now, index.EvidenceByNetwork[network.ID], index.DesiredConfigDigestByNode), nil
}

func deriveFleetHealthForNetwork(network Network, nodes []Node, now time.Time, evidence fleetNetworkEvidence, desiredDigests map[string]string) FleetHealthReport {
	report := FleetHealthReport{
		GeneratedAt: now,
		Network: FleetHealthNetwork{
			ID: network.ID, Name: network.Name, CIDR: network.CIDR, ListenPort: network.ListenPort,
			DNSSettings:           effectiveNetworkDNSSettings(network.DNSSettings),
			RelaySettings:         effectiveNetworkRelaySettings(network.RelaySettings),
			DesiredConfigRevision: network.ConfigRevision,
			ConfigUpdatedAt:       network.ConfigUpdatedAt.UTC(),
		},
		Policy:  fleetHealthPolicy(),
		Rollout: FleetRolloutProjection{DesiredConfigRevision: network.ConfigRevision},
		Nodes:   []FleetNodeHealth{},
		Alerts:  []FleetHealthAlert{},
	}

	if evidence.ControlTimeInvalid {
		at := evidence.ControlTimeAt
		report.Alerts = append(report.Alerts, FleetHealthAlert{
			Severity: FleetHealthCritical, Code: "control_time_invalid", Scope: "network",
			Evidence: FleetHealthEvidence{ControlTimeAt: timeEvidence(&at)},
		})
	}
	if evidence.ProjectionLimitExceeded {
		report.Alerts = append(report.Alerts, FleetHealthAlert{
			Severity: FleetHealthCritical, Code: "projection_limit_exceeded", Scope: "network",
			Evidence: FleetHealthEvidence{
				ObservedLighthouses: intEvidence(evidence.ObservedLighthouses),
				ProjectionLimit:     intEvidence(maxFleetHealthLighthousesPerNetwork),
			},
		})
	}
	var latestRevocationAt *time.Time
	if evidence.Revocation.Conclusive {
		at := evidence.Revocation.At
		latestRevocationAt = &at
	}
	for _, node := range nodes {
		projected := projectFleetNode(node, network, now, latestRevocationAt, evidence.Revocation.Active, desiredDigests[node.ID])
		report.Nodes = append(report.Nodes, projected)
		report.Alerts = append(report.Alerts, projected.Alerts...)
		report.Summary.TotalNodes++
		switch node.Status {
		case "pending":
			report.Summary.PendingNodes++
			report.Summary.SetupNodes++
		case "revoked":
			report.Summary.RevokedNodes++
		case "active":
			report.Summary.ActiveNodes++
			report.Rollout.EligibleNodes++
			if projected.Phase == "setup" {
				report.Summary.SetupNodes++
			} else {
				switch projected.Severity {
				case FleetHealthCritical:
					report.Summary.CriticalNodes++
				case FleetHealthWarning:
					report.Summary.WarningNodes++
				default:
					report.Summary.HealthyNodes++
				}
			}
			if node.LastSeenAt == nil {
				report.Rollout.UnreportedNodes++
			} else if projected.RolloutCurrent {
				report.Rollout.ConvergedNodes++
			} else {
				report.Rollout.DriftedNodes++
			}
			if node.Role == "lighthouse" {
				report.Summary.ActiveLighthouses++
				if projected.Operational {
					report.Summary.HealthyLighthouses++
				}
			}
		}
	}

	sort.Slice(report.Nodes, func(i, j int) bool {
		if report.Nodes[i].Name != report.Nodes[j].Name {
			return report.Nodes[i].Name < report.Nodes[j].Name
		}
		return report.Nodes[i].ID < report.Nodes[j].ID
	})
	if report.Summary.HealthyLighthouses < fleetRequiredLighthouses {
		severity, code := FleetHealthWarning, "lighthouse_single"
		if report.Summary.HealthyLighthouses == 0 {
			severity, code = FleetHealthCritical, "lighthouse_unavailable"
		}
		report.Alerts = append(report.Alerts, FleetHealthAlert{
			Severity: severity, Code: code, Scope: "network",
			Evidence: FleetHealthEvidence{
				ActiveLighthouses:   intEvidence(report.Summary.ActiveLighthouses),
				HealthyLighthouses:  intEvidence(report.Summary.HealthyLighthouses),
				RequiredLighthouses: intEvidence(fleetRequiredLighthouses),
			},
		})
	}
	sortFleetAlerts(report.Alerts)
	report.Summary.Overall = severityForAlerts(report.Alerts)
	if report.Rollout.EligibleNodes == 0 {
		report.Rollout.Percent = 100
	} else {
		report.Rollout.Percent = 100 * report.Rollout.ConvergedNodes / report.Rollout.EligibleNodes
	}
	return report
}

func fleetHealthPolicy() FleetHealthPolicy {
	return FleetHealthPolicy{
		HeartbeatWarningAfterSeconds:   int64(fleetHeartbeatWarningAfter / time.Second),
		HeartbeatOfflineAfterSeconds:   int64(fleetHeartbeatOfflineAfter / time.Second),
		CredentialWarningBeforeSeconds: int64(fleetCredentialWarningBefore / time.Second),
		RequiredHealthyLighthouses:     fleetRequiredLighthouses,
		EvidenceSource:                 "authenticated_agent_heartbeat",
		OverlayReachabilityObserved:    false,
	}
}

func aggregateFleetHealth(collection *FleetHealthCollection) {
	collection.Summary = FleetHealthCollectionSummary{Overall: FleetHealthHealthy, TotalNetworks: len(collection.Networks)}
	collection.Rollout = FleetRolloutSummary{Percent: 100}
	for _, report := range collection.Networks {
		switch report.Summary.Overall {
		case FleetHealthCritical:
			collection.Summary.CriticalNetworks++
			collection.Summary.Overall = FleetHealthCritical
		case FleetHealthWarning:
			collection.Summary.WarningNetworks++
			if collection.Summary.Overall != FleetHealthCritical {
				collection.Summary.Overall = FleetHealthWarning
			}
		default:
			collection.Summary.HealthyNetworks++
		}
		collection.Summary.TotalNodes += report.Summary.TotalNodes
		collection.Summary.SetupNodes += report.Summary.SetupNodes
		collection.Summary.ActiveNodes += report.Summary.ActiveNodes
		collection.Summary.RevokedNodes += report.Summary.RevokedNodes
		collection.Summary.HealthyNodes += report.Summary.HealthyNodes
		collection.Summary.WarningNodes += report.Summary.WarningNodes
		collection.Summary.CriticalNodes += report.Summary.CriticalNodes
		collection.Rollout.EligibleNodes += report.Rollout.EligibleNodes
		collection.Rollout.ConvergedNodes += report.Rollout.ConvergedNodes
		collection.Rollout.DriftedNodes += report.Rollout.DriftedNodes
		collection.Rollout.UnreportedNodes += report.Rollout.UnreportedNodes
	}
	if collection.Rollout.EligibleNodes > 0 {
		collection.Rollout.Percent = 100 * collection.Rollout.ConvergedNodes / collection.Rollout.EligibleNodes
	}
}

func projectFleetNode(node Node, network Network, now time.Time, latestRevocationAt *time.Time, activeRevocations int, desiredConfigDigest string) FleetNodeHealth {
	agentStatus, validAgentStatus := fleetAgentStatus(node)
	validAppliedConfigRevision := node.AppliedConfigRevision >= 0 && node.AppliedConfigRevision <= network.ConfigRevision
	appliedConfigRevision := node.AppliedConfigRevision
	if !validAppliedConfigRevision {
		// Keep the collection consumable by strict clients while retaining a
		// fail-closed signal. Impossible counters are not trustworthy evidence
		// and must not be reflected back as normal telemetry.
		appliedConfigRevision = 0
	}
	projected := FleetNodeHealth{
		ID: node.ID, Name: node.Name, IP: node.IP, RoutedSubnets: append([]string{}, node.RoutedSubnets...), Site: readinessTopologyLabel(node.Site), FailureDomain: readinessTopologyLabel(node.FailureDomain), Role: node.Role, LifecycleStatus: node.Status,
		HeartbeatSequence: node.HeartbeatSequence, Phase: node.Status, Severity: FleetHealthHealthy,
		LastSeenAt: timeEvidence(node.LastSeenAt), AgentStatus: agentStatus, NebulaRunning: node.NebulaRunning,
		DesiredConfigRevision: network.ConfigRevision, AppliedConfigRevision: appliedConfigRevision,
		DesiredCertificateGeneration: node.CertificateGeneration, AppliedCertificateGeneration: node.AppliedCertificateGeneration,
		CertificateExpiresAt:     timeEvidence(node.CertificateExpiresAt),
		CertificateRenewAfter:    timeEvidence(node.CertificateRenewAfter),
		AgentCredentialExpiresAt: timeEvidence(node.AgentCredentialExpiresAt),
		Alerts:                   []FleetHealthAlert{},
	}
	if node.Status == "pending" {
		projected.Phase = "setup"
		return projected
	}
	if node.Status == "revoked" {
		return projected
	}
	if node.Status != "active" {
		projected.Phase = "setup"
		return projected
	}

	if node.LastSeenAt == nil && node.EnrolledAt != nil && !node.EnrolledAt.After(now) && now.Sub(*node.EnrolledAt) < fleetHeartbeatWarningAfter {
		projected.Phase = "setup"
	} else {
		projected.Phase = "active"
	}
	appendNodeHeartbeatAlert(&projected, node, now)
	if !validAgentStatus || !validAppliedConfigRevision {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "telemetry_invalid", FleetHealthEvidence{}))
	}

	if node.LastSeenAt != nil {
		if agentStatus == "degraded" {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "agent_degraded", FleetHealthEvidence{ReportedStatus: agentStatus}))
		}
		if !node.NebulaRunning {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "nebula_stopped", FleetHealthEvidence{NebulaRunning: boolEvidence(false)}))
		}
		if node.LastError != "" {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "agent_error", FleetHealthEvidence{ErrorReported: boolEvidence(true)}))
		}
		if validAppliedConfigRevision && node.AppliedConfigRevision != network.ConfigRevision {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "config_drift", FleetHealthEvidence{
				DesiredConfigRevision: int64Evidence(network.ConfigRevision), AppliedConfigRevision: int64Evidence(node.AppliedConfigRevision),
			}))
		} else if validAppliedConfigRevision && (desiredConfigDigest == "" || node.AppliedConfigSHA256 != desiredConfigDigest) {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "config_digest_drift", FleetHealthEvidence{
				DesiredConfigRevision: int64Evidence(network.ConfigRevision), AppliedConfigRevision: int64Evidence(node.AppliedConfigRevision),
			}))
		}
		if node.AppliedCertificateGeneration != node.CertificateGeneration {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "certificate_generation_drift", FleetHealthEvidence{
				DesiredCertificateGeneration: int64Evidence(node.CertificateGeneration), AppliedCertificateGeneration: int64Evidence(node.AppliedCertificateGeneration),
			}))
		}
		if node.ReportedCertificateFingerprint == "" || node.CertificateFingerprint == "" || node.ReportedCertificateFingerprint != node.CertificateFingerprint {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "certificate_fingerprint_drift", FleetHealthEvidence{
				DesiredCertificateGeneration: int64Evidence(node.CertificateGeneration), AppliedCertificateGeneration: int64Evidence(node.AppliedCertificateGeneration),
			}))
		}
	}

	validCertificateLifecycle := node.CertificateExpiresAt != nil && node.CertificateRenewAfter != nil &&
		!node.CertificateRenewAfter.IsZero() && node.CertificateRenewAfter.Before(*node.CertificateExpiresAt)
	if !validCertificateLifecycle {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "certificate_metadata_missing", FleetHealthEvidence{}))
	} else if !now.Before(*node.CertificateExpiresAt) {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "certificate_expired", FleetHealthEvidence{ExpiresAt: timeEvidence(node.CertificateExpiresAt)}))
	} else if !now.Before(*node.CertificateRenewAfter) {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "certificate_renewal_due", FleetHealthEvidence{
			ExpiresAt: timeEvidence(node.CertificateExpiresAt), RenewAfter: timeEvidence(node.CertificateRenewAfter),
		}))
	}
	if node.AgentCredentialExpiresAt == nil {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "credential_metadata_missing", FleetHealthEvidence{}))
	} else if !now.Before(*node.AgentCredentialExpiresAt) {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "credential_expired", FleetHealthEvidence{ExpiresAt: timeEvidence(node.AgentCredentialExpiresAt)}))
	} else if node.AgentCredentialExpiresAt.Sub(now) <= fleetCredentialWarningBefore {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "credential_expiring", FleetHealthEvidence{
			ExpiresAt: timeEvidence(node.AgentCredentialExpiresAt), ThresholdSeconds: int64Evidence(int64(fleetCredentialWarningBefore / time.Second)),
		}))
	}

	if validAppliedConfigRevision && latestRevocationAt != nil && node.LastSeenAt != nil && !node.LastSeenAt.Before(*latestRevocationAt) && node.AppliedConfigRevision < network.ConfigRevision {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "stale_revocation", FleetHealthEvidence{
			LastSeenAt: timeEvidence(node.LastSeenAt), RevocationAt: timeEvidence(latestRevocationAt), ActiveRevocations: intEvidence(activeRevocations),
			DesiredConfigRevision: int64Evidence(network.ConfigRevision), AppliedConfigRevision: int64Evidence(node.AppliedConfigRevision),
		}))
	}

	sortFleetAlerts(projected.Alerts)
	projected.Severity = severityForAlerts(projected.Alerts)
	heartbeatCurrent := node.LastSeenAt != nil && !node.LastSeenAt.After(now) && now.Sub(*node.LastSeenAt) < fleetHeartbeatOfflineAfter
	certificateCurrent := validCertificateLifecycle && now.Before(*node.CertificateExpiresAt)
	credentialCurrent := node.AgentCredentialExpiresAt != nil && now.Before(*node.AgentCredentialExpiresAt)
	projected.RolloutCurrent = heartbeatCurrent && validAgentStatus && agentStatus != "" && node.NebulaRunning &&
		validAppliedConfigRevision && node.AppliedConfigRevision == network.ConfigRevision &&
		desiredConfigDigest != "" && node.AppliedConfigSHA256 == desiredConfigDigest &&
		node.AppliedCertificateGeneration == node.CertificateGeneration &&
		node.ReportedCertificateFingerprint != "" && node.CertificateFingerprint != "" && node.ReportedCertificateFingerprint == node.CertificateFingerprint &&
		certificateCurrent && credentialCurrent
	projected.Operational = projected.RolloutCurrent && agentStatus == "healthy" && projected.Severity != FleetHealthCritical
	return projected
}

func fleetAgentStatus(node Node) (string, bool) {
	switch node.AgentStatus {
	case "healthy", "degraded":
		return node.AgentStatus, true
	case "":
		// A freshly enrolled node has no reported status until its first
		// heartbeat. Once LastSeenAt exists, absence is malformed telemetry.
		return "", node.LastSeenAt == nil
	default:
		return "", false
	}
}

func appendNodeHeartbeatAlert(projected *FleetNodeHealth, node Node, now time.Time) {
	if node.LastSeenAt != nil {
		if node.LastSeenAt.After(now) {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "heartbeat_time_invalid", FleetHealthEvidence{LastSeenAt: timeEvidence(node.LastSeenAt)}))
			return
		}
		age := now.Sub(*node.LastSeenAt)
		if age >= fleetHeartbeatOfflineAfter {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "heartbeat_offline", heartbeatEvidence(node.LastSeenAt, age, fleetHeartbeatOfflineAfter)))
		} else if age >= fleetHeartbeatWarningAfter {
			projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "heartbeat_late", heartbeatEvidence(node.LastSeenAt, age, fleetHeartbeatWarningAfter)))
		}
		return
	}
	if node.EnrolledAt == nil {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "heartbeat_missing", FleetHealthEvidence{
			ThresholdSeconds: int64Evidence(int64(fleetHeartbeatOfflineAfter / time.Second)),
		}))
		return
	}
	if node.EnrolledAt.After(now) {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "heartbeat_time_invalid", FleetHealthEvidence{SinceAt: timeEvidence(node.EnrolledAt)}))
		return
	}
	age := now.Sub(*node.EnrolledAt)
	if age >= fleetHeartbeatOfflineAfter {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthCritical, "heartbeat_missing", heartbeatEvidence(node.EnrolledAt, age, fleetHeartbeatOfflineAfter)))
	} else if age >= fleetHeartbeatWarningAfter {
		projected.Alerts = append(projected.Alerts, nodeAlert(node.ID, FleetHealthWarning, "heartbeat_missing", heartbeatEvidence(node.EnrolledAt, age, fleetHeartbeatWarningAfter)))
	}
}

func heartbeatEvidence(anchor *time.Time, age, threshold time.Duration) FleetHealthEvidence {
	return FleetHealthEvidence{
		SinceAt: timeEvidence(anchor), AgeSeconds: int64Evidence(int64(age / time.Second)),
		ThresholdSeconds: int64Evidence(int64(threshold / time.Second)),
	}
}

// buildFleetHealthIndex scans the control graph once, then renders one shared
// member config and at most maxFleetHealthLighthousesPerNetwork exact
// lighthouse configs per network. It also centralizes the conservative
// revocation proof so collection and single-network responses have identical
// semantics.
func buildFleetHealthIndex(state State, now time.Time) fleetHealthIndex {
	index := fleetHealthIndex{
		NodesByNetwork:            make(map[string][]Node, len(state.Networks)),
		EvidenceByNetwork:         make(map[string]fleetNetworkEvidence, len(state.Networks)),
		DesiredConfigDigestByNode: make(map[string]string, len(state.Nodes)),
	}
	networks := make(map[string]Network, len(state.Networks))
	for _, network := range state.Networks {
		networks[network.ID] = network
		if network.ConfigUpdatedAt.After(now) {
			index.EvidenceByNetwork[network.ID] = fleetNetworkEvidence{
				ControlTimeAt: network.ConfigUpdatedAt.UTC(), ControlTimeInvalid: true,
			}
		}
	}
	nodes := make(map[string]Node, len(state.Nodes))
	for _, node := range state.Nodes {
		nodes[node.ID] = node
		index.NodesByNetwork[node.NetworkID] = append(index.NodesByNetwork[node.NetworkID], node)
	}
	revocationsByNetwork := make(map[string][]CertificateRevocation, len(state.Networks))
	for _, revocation := range state.Revocations {
		networkID := revocation.NetworkID
		if networkID == "" {
			if node, ok := nodes[revocation.NodeID]; ok {
				networkID = node.NetworkID
			}
		}
		if _, ok := networks[networkID]; ok {
			revocationsByNetwork[networkID] = append(revocationsByNetwork[networkID], revocation)
			if revocation.At.After(now) {
				evidence := index.EvidenceByNetwork[networkID]
				if !evidence.ControlTimeInvalid || revocation.At.After(evidence.ControlTimeAt) {
					evidence.ControlTimeAt = revocation.At.UTC()
				}
				evidence.ControlTimeInvalid = true
				index.EvidenceByNetwork[networkID] = evidence
			}
		}
	}
	for networkID, network := range networks {
		activeLighthouses := 0
		for _, node := range index.NodesByNetwork[networkID] {
			if node.Status == "active" && node.Role == "lighthouse" {
				activeLighthouses++
			}
		}
		if activeLighthouses > maxFleetHealthLighthousesPerNetwork {
			evidence := index.EvidenceByNetwork[networkID]
			evidence.ProjectionLimitExceeded = true
			evidence.ObservedLighthouses = activeLighthouses
			index.EvidenceByNetwork[networkID] = evidence
			continue
		}
		localState := State{Nodes: index.NodesByNetwork[networkID], Revocations: revocationsByNetwork[networkID]}
		memberDigest := ""
		for _, node := range index.NodesByNetwork[networkID] {
			if node.Status != "active" {
				continue
			}
			if node.Role == "member" {
				if memberDigest == "" {
					memberDigest = ConfigDigest(renderConfig(localState, network, node))
				}
				index.DesiredConfigDigestByNode[node.ID] = memberDigest
				continue
			}
			index.DesiredConfigDigestByNode[node.ID] = ConfigDigest(renderConfig(localState, network, node))
		}
	}
	latestConfigEvent := make(map[string]AuditEvent, len(state.Networks))
	latestConfigEventsAreRevocations := make(map[string]bool, len(state.Networks))
	for _, event := range state.Audit {
		networkID, ok := configEventNetworkID(event, nodes)
		if !ok {
			continue
		}
		if _, exists := networks[networkID]; !exists {
			continue
		}
		latest, exists := latestConfigEvent[networkID]
		switch {
		case !exists || event.At.After(latest.At):
			latestConfigEvent[networkID] = event
			latestConfigEventsAreRevocations[networkID] = event.Action == "node.revoked"
		case event.At.Equal(latest.At):
			latestConfigEventsAreRevocations[networkID] = latestConfigEventsAreRevocations[networkID] && event.Action == "node.revoked"
		}
		if event.At.After(now) {
			evidence := index.EvidenceByNetwork[networkID]
			if !evidence.ControlTimeInvalid || event.At.After(evidence.ControlTimeAt) {
				evidence.ControlTimeAt = event.At.UTC()
			}
			evidence.ControlTimeInvalid = true
			index.EvidenceByNetwork[networkID] = evidence
		}
	}
	for networkID, event := range latestConfigEvent {
		network := networks[networkID]
		if !latestConfigEventsAreRevocations[networkID] || !event.At.Equal(network.ConfigUpdatedAt) || now.Before(event.At) {
			continue
		}
		evidence := index.EvidenceByNetwork[networkID]
		evidence.Revocation = fleetRevocationEvidence{At: event.At.UTC(), Conclusive: true}
		index.EvidenceByNetwork[networkID] = evidence
	}
	for networkID, revocations := range revocationsByNetwork {
		evidence, ok := index.EvidenceByNetwork[networkID]
		if !ok || !evidence.Revocation.Conclusive {
			continue
		}
		for _, revocation := range revocations {
			if !revocation.At.Equal(evidence.Revocation.At) || (revocation.ExpiresAt != nil && !now.Before(*revocation.ExpiresAt)) {
				continue
			}
			evidence.Revocation.Active++
		}
		index.EvidenceByNetwork[networkID] = evidence
	}
	for networkID, evidence := range index.EvidenceByNetwork {
		if evidence.Revocation.Conclusive && evidence.Revocation.Active == 0 {
			evidence.Revocation = fleetRevocationEvidence{}
			index.EvidenceByNetwork[networkID] = evidence
		}
	}
	return index
}

func configEventNetworkID(event AuditEvent, nodes map[string]Node) (string, bool) {
	switch event.Action {
	case "network.firewall_policy_updated", "network.firewall_renderer_migrated":
		return event.ResourceID, event.Resource == "network"
	case "node.revoked":
		node, ok := nodes[event.ResourceID]
		return node.NetworkID, event.Resource == "node" && ok
	case "node.enrolled":
		node, ok := nodes[event.ResourceID]
		return node.NetworkID, event.Resource == "node" && ok && node.Role == "lighthouse"
	default:
		return "", false
	}
}

func nodeAlert(nodeID, severity, code string, evidence FleetHealthEvidence) FleetHealthAlert {
	return FleetHealthAlert{Severity: severity, Code: code, Scope: "node", NodeID: nodeID, Evidence: evidence}
}

func severityForAlerts(alerts []FleetHealthAlert) string {
	severity := FleetHealthHealthy
	for _, alert := range alerts {
		if alert.Severity == FleetHealthCritical {
			return FleetHealthCritical
		}
		if alert.Severity == FleetHealthWarning {
			severity = FleetHealthWarning
		}
	}
	return severity
}

func sortFleetAlerts(alerts []FleetHealthAlert) {
	sort.SliceStable(alerts, func(i, j int) bool {
		left, right := fleetSeverityRank(alerts[i].Severity), fleetSeverityRank(alerts[j].Severity)
		if left != right {
			return left > right
		}
		if alerts[i].Code != alerts[j].Code {
			return alerts[i].Code < alerts[j].Code
		}
		if alerts[i].Scope != alerts[j].Scope {
			return alerts[i].Scope < alerts[j].Scope
		}
		return alerts[i].NodeID < alerts[j].NodeID
	})
}

func fleetSeverityRank(severity string) int {
	switch severity {
	case FleetHealthCritical:
		return 2
	case FleetHealthWarning:
		return 1
	default:
		return 0
	}
}

func timeEvidence(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func int64Evidence(value int64) *int64 { return &value }
func intEvidence(value int) *int       { return &value }
func boolEvidence(value bool) *bool    { return &value }
