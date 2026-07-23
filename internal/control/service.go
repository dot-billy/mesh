package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrInvalid           = errors.New("invalid input")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrRateLimited       = errors.New("rate limited")
	ErrInvalidStateStore = errors.New("invalid control state store")
	namePattern          = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
	groupPattern         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
	topologyLabelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	fingerprintPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	ControlStateVersionCredentialBinding = 2
	ControlStateVersionTopology          = 3
	ControlStateVersionNetworkDNS        = 4
	ControlStateVersionNetworkRelays     = 5
	ControlStateVersionCARotation        = 6
	ControlStateVersionFirewallRollout   = 7
	ControlStateVersionFirewallPause     = 8
	ControlStateVersionRouteTransfer     = 9
	ControlStateVersionRouteProfileEdit  = 10
	ControlStateVersionRoutePolicies     = 11
	ControlStateVersionNativeDNS         = 12
	ControlStateVersionFirewallScopes    = 13
	UnassignedTopologyLabel              = "unassigned"
)

// StateStore is the transactional persistence boundary used by Service.
//
// View must invoke fn at most once with a stable snapshot. Update must invoke
// fn at most once and commit all callback mutations atomically, or commit none
// of them. An Update implementation must not transparently retry fn: service
// callbacks may generate one-time credentials and other externally returned
// values. ErrUncertainCommit is reserved for a commit whose outcome cannot yet
// be proven.
type StateStore interface {
	View(func(State) error) error
	Update(func(*State) error) error
}

// currentStateStore is an optional trusted-read optimization. It deliberately
// remains private because callbacks receive storage-owned state and therefore
// must neither mutate nor retain it. The file Store uses it on authentication
// preflights to avoid attacker-controlled O(state size) clones; other backends
// safely fall back to View.
type currentStateStore interface {
	readCurrent(func(State) error) error
}

var _ StateStore = (*Store)(nil)

type Service struct {
	// store is retained for same-package compatibility and diagnostics around
	// the file implementation. Service operations use stateStore exclusively.
	store          *Store
	stateStore     StateStore
	box            *SecretBox
	issuer         CertificateIssuer
	now            func() time.Time
	generateBearer func() (string, error)
	// endpointResolver is used only by the administrator-triggered deployment
	// readiness projection. Keeping it injectable makes the DNS evidence
	// deterministic in tests while production uses the host's configured
	// resolver under a bounded request context.
	endpointResolver endpointHostResolver
	// recoveryClaimed is a deterministic concurrency hook used by package tests
	// after the recovery claim commits and before its compare-and-commit. It is
	// nil in production.
	recoveryClaimed func()
	// credentialRotationPreflighted is the equivalent deterministic package-test
	// hook for rotation/recovery ordering. It is nil in production.
	credentialRotationPreflighted func()
}

func NewService(store *Store, box *SecretBox, issuer CertificateIssuer) *Service {
	return newService(store, store, box, issuer)
}

// NewServiceWithStateStore constructs a Service over a non-file transactional
// backend. It rejects both nil interfaces and typed nil implementations before
// any service operation can dereference them.
func NewServiceWithStateStore(store StateStore, box *SecretBox, issuer CertificateIssuer) (*Service, error) {
	if nilStateStore(store) {
		return nil, ErrInvalidStateStore
	}
	return newService(nil, store, box, issuer), nil
}

func newService(fileStore *Store, stateStore StateStore, box *SecretBox, issuer CertificateIssuer) *Service {
	return &Service{
		store: fileStore, stateStore: stateStore, box: box, issuer: issuer,
		now:              func() time.Time { return time.Now().UTC() },
		generateBearer:   func() (string, error) { return RandomToken(32) },
		endpointResolver: net.DefaultResolver,
	}
}

func nilStateStore(store StateStore) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (s *Service) viewState(fn func(State) error) error {
	if s == nil || s.stateStore == nil {
		return ErrInvalidStateStore
	}
	return s.stateStore.View(fn)
}

func (s *Service) readCurrentState(fn func(State) error) error {
	if s == nil || s.stateStore == nil {
		return ErrInvalidStateStore
	}
	if store, ok := s.stateStore.(currentStateStore); ok {
		return store.readCurrent(fn)
	}
	return s.stateStore.View(fn)
}

func (s *Service) updateState(fn func(*State) error) error {
	if s == nil || s.stateStore == nil {
		return ErrInvalidStateStore
	}
	return s.stateStore.Update(fn)
}

// CheckRecoveryCredentialBinding is the read-only startup preflight. The store's
// process lock prevents another server from changing the binding before the
// later atomic Ensure call.
func (s *Service) CheckRecoveryCredentialBinding(masterVerifier, adminVerifier string, allowAdminRotation bool) error {
	if !ValidMasterKeyVerifier(masterVerifier) || !ValidAdminCredentialVerifier(adminVerifier) {
		return fmt.Errorf("%w: invalid recovery credential verifier", ErrInvalid)
	}
	return s.readCurrentState(func(state State) error {
		return validateRecoveryCredentialTransition(state.MasterKeyVerifier, masterVerifier, state.AdminCredentialVerifier, adminVerifier, allowAdminRotation)
	})
}

// CheckCurrentRecoveryCredentialBinding is the read-only runtime counterpart
// to the compatibility-aware startup preflight. Readiness requires the current
// schema and exact persisted bindings; it must never treat an unbound legacy
// state as healthy or authorize an administrator credential rotation.
func (s *Service) CheckCurrentRecoveryCredentialBinding(masterVerifier, adminVerifier string) error {
	if !ValidMasterKeyVerifier(masterVerifier) || !ValidAdminCredentialVerifier(adminVerifier) {
		return fmt.Errorf("%w: invalid recovery credential verifier", ErrInvalid)
	}
	return s.readCurrentState(func(state State) error {
		if state.Version != ControlStateVersionFirewallScopes ||
			!masterKeyVerifierEqual(state.MasterKeyVerifier, masterVerifier) ||
			!adminCredentialVerifierEqual(state.AdminCredentialVerifier, adminVerifier) {
			return fmt.Errorf("%w: recovery credential binding is not current", ErrConflict)
		}
		return nil
	})
}

// EnsureRecoveryCredentialBinding atomically binds the control state to both
// credentials supplied for this startup. Repeating a startup with the same
// verifiers is write-free. The explicit rotation authority applies only to the
// administrator credential; master-key replacement always fails closed.
func (s *Service) EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier string, allowAdminRotation bool) error {
	if !ValidMasterKeyVerifier(masterVerifier) || !ValidAdminCredentialVerifier(adminVerifier) {
		return fmt.Errorf("%w: invalid recovery credential verifier", ErrInvalid)
	}
	return s.updateState(func(state *State) error {
		if err := validateRecoveryCredentialTransition(state.MasterKeyVerifier, masterVerifier, state.AdminCredentialVerifier, adminVerifier, allowAdminRotation); err != nil {
			return err
		}
		if masterKeyVerifierEqual(state.MasterKeyVerifier, masterVerifier) && adminCredentialVerifierEqual(state.AdminCredentialVerifier, adminVerifier) {
			return nil
		}
		action := "admin.credential_bound"
		if state.AdminCredentialVerifier != "" {
			action = "admin.credential_rotated"
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("administrator credential binding requires a valid timestamp")
		}
		if state.Version < ControlStateVersionCredentialBinding {
			state.Version = ControlStateVersionCredentialBinding
		}
		state.MasterKeyVerifier = masterVerifier
		state.AdminCredentialVerifier = adminVerifier
		state.Audit = append(state.Audit, newAudit(now, action, "administrator", "admin", nil))
		return nil
	})
}

// EnsureTopologySchema performs the one-way control-state v2 to v3 migration.
// Existing nodes are explicitly marked unassigned instead of inventing a
// location or claiming independent failure domains. Agent-recovery replay
// results carry a detached Node copy and are migrated in the same transaction.
// Repeating startup after v3 or a later schema is durable is write-free.
func (s *Service) EnsureTopologySchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionTopology, ControlStateVersionNetworkDNS, ControlStateVersionNetworkRelays, ControlStateVersionCARotation, ControlStateVersionFirewallRollout, ControlStateVersionFirewallPause, ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionCredentialBinding:
		default:
			return fmt.Errorf("%w: topology migration requires credential-bound control state v2", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("topology schema migration requires a valid timestamp")
		}
		for index := range state.Nodes {
			state.Nodes[index].Site = UnassignedTopologyLabel
			state.Nodes[index].FailureDomain = UnassignedTopologyLabel
		}
		nodesByID := make(map[string]Node, len(state.Nodes))
		for _, node := range state.Nodes {
			nodesByID[node.ID] = node
		}
		for index := range state.AgentRecoveries {
			if state.AgentRecoveries[index].Result == nil {
				continue
			}
			if node, ok := nodesByID[state.AgentRecoveries[index].Result.Node.ID]; ok {
				state.AgentRecoveries[index].Result.Node.Site = node.Site
				state.AgentRecoveries[index].Result.Node.FailureDomain = node.FailureDomain
			}
		}
		state.Version = ControlStateVersionTopology
		state.Audit = append(state.Audit, newAudit(now, "control.topology_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionCredentialBinding,
			"to_version":   ControlStateVersionTopology,
			"nodes":        len(state.Nodes),
		}))
		return nil
	})
}

// EnsureNetworkDNSSchema performs the one-way control-state v3 to v4
// migration. Disabled settings intentionally render no new Nebula bytes, so
// the migration does not advance any signed configuration revision. Repeating
// startup after v4 is durable is write-free.
func (s *Service) EnsureNetworkDNSSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionNetworkDNS, ControlStateVersionNetworkRelays, ControlStateVersionCARotation, ControlStateVersionFirewallRollout, ControlStateVersionFirewallPause, ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionTopology:
		default:
			return fmt.Errorf("%w: network DNS migration requires topology control state v3", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("network DNS schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].DNSSettings = defaultNetworkDNSSettings()
		}
		state.Version = ControlStateVersionNetworkDNS
		state.Audit = append(state.Audit, newAudit(now, "control.network_dns_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionTopology,
			"to_version":   ControlStateVersionNetworkDNS,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureNetworkRelaySchema performs the one-way control-state v4 to v5
// migration. Disabled relay settings render no new Nebula bytes, so signed
// revisions remain unchanged. Repeating current startup is write-free.
func (s *Service) EnsureNetworkRelaySchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionNetworkRelays, ControlStateVersionCARotation, ControlStateVersionFirewallRollout, ControlStateVersionFirewallPause, ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionNetworkDNS:
		default:
			return fmt.Errorf("%w: network relay migration requires network DNS control state v4", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("network relay schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].RelaySettings = defaultNetworkRelaySettings()
		}
		state.Version = ControlStateVersionNetworkRelays
		state.Audit = append(state.Audit, newAudit(now, "control.network_relay_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionNetworkDNS,
			"to_version":   ControlStateVersionNetworkRelays,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureCARotationSchema performs the ordered v5 to v6 migration. Existing
// certificates were all issued by the one network CA available in v5, so the
// issuer digest can be filled without changing any signed config bytes.
func (s *Service) EnsureCARotationSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionCARotation, ControlStateVersionFirewallRollout, ControlStateVersionFirewallPause, ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionNetworkRelays:
		default:
			return fmt.Errorf("%w: CA rotation migration requires network relay control state v5", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("CA rotation schema migration requires a valid timestamp")
		}
		networks := make(map[string]Network, len(state.Networks))
		for index := range state.Networks {
			state.Networks[index].CARotation = NetworkCARotation{}
			networks[state.Networks[index].ID] = state.Networks[index]
		}
		for index := range state.Nodes {
			if state.Nodes[index].Certificate == "" {
				continue
			}
			network, ok := networks[state.Nodes[index].NetworkID]
			if !ok {
				return fmt.Errorf("node %q references a missing network during CA rotation migration", state.Nodes[index].ID)
			}
			state.Nodes[index].CertificateAuthoritySHA256 = ConfigDigest(network.CACertificate)
		}
		for index := range state.AgentRecoveries {
			if state.AgentRecoveries[index].Result == nil || state.AgentRecoveries[index].Result.Node.Certificate == "" {
				continue
			}
			network, ok := networks[state.AgentRecoveries[index].Result.NetworkID]
			if !ok {
				return fmt.Errorf("agent recovery %q references a missing network during CA rotation migration", state.AgentRecoveries[index].ID)
			}
			state.AgentRecoveries[index].Result.Node.CertificateAuthoritySHA256 = ConfigDigest(network.CACertificate)
		}
		state.Version = ControlStateVersionCARotation
		state.Audit = append(state.Audit, newAudit(now, "control.ca_rotation_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionNetworkRelays,
			"to_version":   ControlStateVersionCARotation,
			"networks":     len(state.Networks),
			"nodes":        len(state.Nodes),
		}))
		return nil
	})
}

// EnsureFirewallRolloutSchema performs the ordered v6 to v7 migration. The
// zero rollout state renders the already-active firewall policy for every node,
// so this migration changes no signed configuration bytes or revisions.
func (s *Service) EnsureFirewallRolloutSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionFirewallRollout, ControlStateVersionFirewallPause, ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionCARotation:
		default:
			return fmt.Errorf("%w: firewall rollout migration requires CA rotation control state v6", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("firewall rollout schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].FirewallRollout = NetworkFirewallRollout{}
		}
		state.Version = ControlStateVersionFirewallRollout
		state.Audit = append(state.Audit, newAudit(now, "control.firewall_rollout_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionCARotation,
			"to_version":   ControlStateVersionFirewallRollout,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureFirewallPauseSchema performs the ordered v7 to v8 migration. A zero
// PausedAt preserves both stable and in-flight canary semantics, so existing
// desired config bytes, revisions, timestamps, identities, and telemetry are
// unchanged. Repeating startup after v8 is durable is write-free.
func (s *Service) EnsureFirewallPauseSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionFirewallPause, ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionFirewallRollout:
		default:
			return fmt.Errorf("%w: firewall pause migration requires firewall rollout control state v7", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("firewall pause schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].FirewallRollout.PausedAt = time.Time{}
		}
		state.Version = ControlStateVersionFirewallPause
		state.Audit = append(state.Audit, newAudit(now, "control.firewall_rollout_pause_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionFirewallRollout,
			"to_version":   ControlStateVersionFirewallPause,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureRouteTransferSchema performs the ordered v8 to v9 migration. Empty
// route-transfer receipts render exactly the existing desired configuration,
// so no network revision or timestamp changes.
func (s *Service) EnsureRouteTransferSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionRouteTransfer, ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionFirewallPause:
		default:
			return fmt.Errorf("%w: route-transfer migration requires firewall-pause control state v8", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("route-transfer schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].RouteTransfer = NetworkRouteTransfer{}
		}
		state.Version = ControlStateVersionRouteTransfer
		state.Audit = append(state.Audit, newAudit(now, "control.route_transfer_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionFirewallPause,
			"to_version":   ControlStateVersionRouteTransfer,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureRouteProfileEditSchema performs the ordered v9 to v10 migration. An
// empty route-profile edit renders the already-active route and certificate
// profile exactly, so no signed bytes, revisions, timestamps, or telemetry
// change. Repeating startup after v10 is durable is write-free.
func (s *Service) EnsureRouteProfileEditSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionRouteProfileEdit, ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionRouteTransfer:
		default:
			return fmt.Errorf("%w: route-profile-edit migration requires route-transfer control state v9", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("route-profile-edit schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].RouteProfileEdit = NetworkRouteProfileEdit{}
		}
		state.Version = ControlStateVersionRouteProfileEdit
		state.Audit = append(state.Audit, newAudit(now, "control.route_profile_edit_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionRouteTransfer,
			"to_version":   ControlStateVersionRouteProfileEdit,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureRoutePolicySchema performs the ordered v10 to v11 migration. Existing
// single-owner routes derive the same scalar unsafe-route entries from an empty
// policy list, so signed bytes, revisions, timestamps, and telemetry are
// unchanged. Repeating startup after v11 is durable is write-free.
func (s *Service) EnsureRoutePolicySchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionRoutePolicies, ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionRouteProfileEdit:
		default:
			return fmt.Errorf("%w: route-policy migration requires route-profile control state v10", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("route-policy schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].RoutePolicies = nil
		}
		state.Version = ControlStateVersionRoutePolicies
		state.Audit = append(state.Audit, newAudit(now, "control.route_policy_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionRouteProfileEdit,
			"to_version":   ControlStateVersionRoutePolicies,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureNativeDNSSchema performs the ordered v11 to v12 migration. Native
// resolver integration defaults disabled with an empty search domain, so the
// already-rendered signed bytes and network revisions remain unchanged.
func (s *Service) EnsureNativeDNSSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionNativeDNS, ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionRoutePolicies:
		default:
			return fmt.Errorf("%w: native DNS migration requires route-policy control state v11", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("native DNS schema migration requires a valid timestamp")
		}
		for index := range state.Networks {
			state.Networks[index].DNSSettings.NativeResolver = false
			state.Networks[index].DNSSettings.SearchDomain = ""
		}
		state.Version = ControlStateVersionNativeDNS
		state.Audit = append(state.Audit, newAudit(now, "control.native_dns_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionRoutePolicies,
			"to_version":   ControlStateVersionNativeDNS,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

// EnsureFirewallScopeSchema performs the ordered v12 to v13 migration. Existing
// policies have no local targets or peer-node selectors, so their rendered
// signed bytes and network revisions remain unchanged. The version boundary
// prevents an older binary from ignoring newly persisted rule fields.
func (s *Service) EnsureFirewallScopeSchema() error {
	return s.updateState(func(state *State) error {
		switch state.Version {
		case ControlStateVersionFirewallScopes:
			return nil
		case ControlStateVersionNativeDNS:
		default:
			return fmt.Errorf("%w: firewall scope migration requires native-DNS control state v12", ErrConflict)
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("firewall scope schema migration requires a valid timestamp")
		}
		state.Version = ControlStateVersionFirewallScopes
		state.Audit = append(state.Audit, newAudit(now, "control.firewall_scope_schema_migrated", "control_state", "control", map[string]any{
			"from_version": ControlStateVersionNativeDNS,
			"to_version":   ControlStateVersionFirewallScopes,
			"networks":     len(state.Networks),
		}))
		return nil
	})
}

func validateRecoveryCredentialTransition(currentMaster, proposedMaster, currentAdmin, proposedAdmin string, allowAdminRotation bool) error {
	if currentMaster == "" && currentAdmin == "" {
		return nil
	}
	if !masterKeyVerifierEqual(currentMaster, proposedMaster) {
		return fmt.Errorf("%w: master key differs from the persisted binding", ErrConflict)
	}
	if adminCredentialVerifierEqual(currentAdmin, proposedAdmin) || allowAdminRotation {
		return nil
	}
	return fmt.Errorf("%w: administrator credential differs from the persisted binding; authorize the intended rotation explicitly", ErrConflict)
}

func (s *Service) EnsureManagedNetworks() error {
	return s.updateState(func(state *State) error {
		for i := range state.Networks {
			network := &state.Networks[i]
			// Authenticate at least one existing CA ciphertext before performing
			// any compatibility migration. Without this preflight, a wrong master
			// key could write a new signing key into an otherwise empty legacy
			// network and make the correct key unable to reopen the store.
			caKey, err := s.box.Open(network.EncryptedCAKey)
			clear(caKey)
			if err != nil {
				return fmt.Errorf("network %s CA key: %w", network.ID, err)
			}
			if network.CARotation.Phase == CARotationPhasePrepared || network.CARotation.Phase == CARotationPhaseRotating {
				nextKey, err := s.box.Open(network.CARotation.EncryptedNextCAKey)
				if err != nil {
					return fmt.Errorf("network %s next CA key: %w", network.ID, err)
				}
				nextNetwork := *network
				nextNetwork.CACertificate = network.CARotation.NextCACertificate
				_, pairErr := validateNebulaCAKeyPair(nextNetwork, nextKey)
				clear(nextKey)
				if pairErr != nil {
					return fmt.Errorf("network %s next CA key: %w", network.ID, pairErr)
				}
			}
			upgradedFirewall, renderedBytesChanged, err := upgradeFirewallRenderer(network.FirewallPolicy)
			if err != nil {
				return fmt.Errorf("network %s firewall renderer: %w", network.ID, err)
			}
			if upgradedFirewall.RendererVersion != network.FirewallPolicy.RendererVersion {
				oldRendered := renderFirewallPolicy(network.FirewallPolicy)
				previousRevision := network.ConfigRevision
				if renderedBytesChanged {
					migratedAt := s.now().UTC()
					if migratedAt.IsZero() {
						return fmt.Errorf("network %s firewall renderer migration has an invalid timestamp", network.ID)
					}
					nextRevision, revisionErr := nextConfigRevision(network.ConfigRevision, true)
					if revisionErr != nil {
						return fmt.Errorf("network %s firewall renderer migration: %w", network.ID, revisionErr)
					}
					network.ConfigRevision = nextRevision
					network.ConfigUpdatedAt = migratedAt
					state.Audit = append(state.Audit, newAudit(migratedAt, "network.firewall_renderer_migrated", "network", network.ID, map[string]any{
						"from_renderer_version":    FirewallRendererVersionV1,
						"to_renderer_version":      upgradedFirewall.RendererVersion,
						"rendered_bytes_changed":   true,
						"old_sha256":               ConfigDigest(oldRendered),
						"new_sha256":               ConfigDigest(renderFirewallPolicy(upgradedFirewall)),
						"previous_config_revision": previousRevision,
						"config_revision":          network.ConfigRevision,
					}))
				}
				network.FirewallPolicy = upgradedFirewall
			}
			hasPublicKey := network.ConfigSigningPublicKey != ""
			hasPrivateKey := network.EncryptedConfigSigningKey != ""
			if hasPublicKey && hasPrivateKey {
				privateKey, err := s.box.OpenFor("config-signing-key-v1", network.EncryptedConfigSigningKey)
				if err != nil {
					return fmt.Errorf("network %s config signing key: %w", network.ID, err)
				}
				err = ValidateConfigSigningKeyPair(network.ConfigSigningPublicKey, privateKey)
				for j := range privateKey {
					privateKey[j] = 0
				}
				if err != nil {
					return fmt.Errorf("network %s config signing key: %w", network.ID, err)
				}
				for j := range state.Nodes {
					node := &state.Nodes[j]
					if node.NetworkID != network.ID || node.Status != "active" {
						continue
					}
					if node.CertificateGeneration < 0 || !fingerprintPattern.MatchString(node.CertificateFingerprint) || node.CertificateExpiresAt == nil || !ValidTokenHash(node.PublicKeyHash) {
						return fmt.Errorf("network %s has an active legacy node without complete certificate metadata", network.ID)
					}
					if node.CertificateRenewAfter == nil {
						renewAfter := node.CertificateExpiresAt.Add(-renewalWindow(time.Duration(network.CertificateTTL) * time.Hour))
						node.CertificateRenewAfter = &renewAfter
					}
					if node.CertificateRenewAfter.IsZero() || !node.CertificateRenewAfter.Before(*node.CertificateExpiresAt) {
						return fmt.Errorf("network %s has an active node with invalid certificate renewal metadata", network.ID)
					}
					if node.CertificateGeneration == 0 {
						node.CertificateGeneration = 1
					}
				}
				continue
			}
			if hasPublicKey != hasPrivateKey {
				return fmt.Errorf("network %s has an incomplete config signing key pair", network.ID)
			}
			for _, node := range state.Nodes {
				if node.NetworkID == network.ID {
					return fmt.Errorf("network %s has nodes but no config signing key pair", network.ID)
				}
			}
			publicKey, privateKey, err := GenerateConfigSigningKey()
			if err != nil {
				return err
			}
			encrypted, err := s.box.SealFor("config-signing-key-v1", privateKey)
			for j := range privateKey {
				privateKey[j] = 0
			}
			if err != nil {
				return err
			}
			network.ConfigSigningPublicKey = publicKey
			network.EncryptedConfigSigningKey = encrypted
		}
		return nil
	})
}

type CreateNetworkInput struct {
	Name           string `json:"name"`
	CIDR           string `json:"cidr"`
	ListenPort     int    `json:"listen_port"`
	CertificateTTL int    `json:"certificate_ttl_hours"`
}

func (s *Service) CreateNetwork(ctx context.Context, in CreateNetworkInput) (Network, error) {
	return s.createNetwork(ctx, nil, in)
}

func (s *Service) CreateNetworkAs(ctx context.Context, actor Actor, in CreateNetworkInput) (Network, error) {
	if err := validateActor(actor); err != nil {
		return Network{}, err
	}
	return s.createNetwork(ctx, &actor, in)
}

func (s *Service) createNetwork(ctx context.Context, actor *Actor, in CreateNetworkInput) (Network, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !namePattern.MatchString(in.Name) {
		return Network{}, fmt.Errorf("%w: name must be 1-63 letters, digits, dots, dashes, or underscores", ErrInvalid)
	}
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(in.CIDR))
	if err != nil || ip.To4() == nil {
		return Network{}, fmt.Errorf("%w: CIDR must be a valid IPv4 network", ErrInvalid)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones < 16 || ones > 28 {
		return Network{}, fmt.Errorf("%w: CIDR prefix must be between /16 and /28", ErrInvalid)
	}
	canonicalCIDR := ipnet.String()
	if in.ListenPort == 0 {
		in.ListenPort = 4242
	}
	if in.ListenPort < 1 || in.ListenPort > 65535 {
		return Network{}, fmt.Errorf("%w: listen port must be 1-65535", ErrInvalid)
	}
	if in.CertificateTTL == 0 {
		in.CertificateTTL = 8760
	}
	if in.CertificateTTL < 24 || in.CertificateTTL > 8760 {
		return Network{}, fmt.Errorf("%w: certificate lifetime must be between 24 and 8760 hours", ErrInvalid)
	}
	var duplicate bool
	if err := s.viewState(func(state State) error {
		for _, network := range state.Networks {
			if strings.EqualFold(network.Name, in.Name) || cidrsOverlap(network.CIDR, canonicalCIDR) {
				duplicate = true
			}
		}
		retiredConflict, err := retiredNetworkReservationConflict(state, in.Name, canonicalCIDR)
		if err != nil {
			return err
		}
		duplicate = duplicate || retiredConflict
		if _, overlap := managedCIDROverlapsRoutedSubnet(state, canonicalCIDR); overlap {
			duplicate = true
		}
		return nil
	}); err != nil {
		return Network{}, err
	}
	if duplicate {
		return Network{}, fmt.Errorf("%w: network name or address range already exists", ErrConflict)
	}
	caCert, caKey, err := s.issuer.CreateCA(ctx, in.Name, canonicalCIDR)
	if err != nil {
		return Network{}, err
	}
	if err := validateGeneratedCA(caCert, caKey); err != nil {
		return Network{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	encryptedKey, err := s.box.Seal([]byte(caKey))
	if err != nil {
		return Network{}, err
	}
	configSigningPublicKey, configSigningPrivateKey, err := GenerateConfigSigningKey()
	if err != nil {
		return Network{}, err
	}
	encryptedConfigSigningKey, err := s.box.SealFor("config-signing-key-v1", configSigningPrivateKey)
	for i := range configSigningPrivateKey {
		configSigningPrivateKey[i] = 0
	}
	if err != nil {
		return Network{}, err
	}
	id, err := RandomToken(12)
	if err != nil {
		return Network{}, err
	}
	now := s.now()
	network := Network{ID: id, Name: in.Name, CIDR: canonicalCIDR, FirewallPolicy: defaultManagedFirewallPolicy(), ListenPort: in.ListenPort, CertificateTTL: in.CertificateTTL, CACertificate: caCert, EncryptedCAKey: encryptedKey, ConfigSigningPublicKey: configSigningPublicKey, EncryptedConfigSigningKey: encryptedConfigSigningKey, ConfigRevision: 1, ConfigUpdatedAt: now, CreatedAt: now}
	err = s.updateState(func(state *State) error {
		for _, existing := range state.Networks {
			if strings.EqualFold(existing.Name, in.Name) || cidrsOverlap(existing.CIDR, canonicalCIDR) {
				return fmt.Errorf("%w: network name or address range already exists", ErrConflict)
			}
		}
		retiredConflict, err := retiredNetworkReservationConflict(*state, in.Name, canonicalCIDR)
		if err != nil {
			return err
		}
		if retiredConflict {
			return fmt.Errorf("%w: retired network names and address ranges are permanently reserved", ErrConflict)
		}
		if routed, overlap := managedCIDROverlapsRoutedSubnet(*state, canonicalCIDR); overlap {
			return fmt.Errorf("%w: network address range overlaps reserved routed subnet %s", ErrConflict, routed)
		}
		if state.Version >= ControlStateVersionNetworkDNS {
			network.DNSSettings = defaultNetworkDNSSettings()
		}
		if state.Version >= ControlStateVersionNetworkRelays {
			network.RelaySettings = defaultNetworkRelaySettings()
		}
		event, err := newOptionalAttributedAudit(now, "network.created", "network", id, map[string]any{"name": in.Name, "cidr": canonicalCIDR}, actor)
		if err != nil {
			return err
		}
		persistedNetwork := network
		persistedNetwork.FirewallPolicy = cloneFirewallPolicy(network.FirewallPolicy)
		state.Networks = append(state.Networks, persistedNetwork)
		state.Audit = append(state.Audit, event)
		return nil
	})
	return network, err
}

type CreateNodeInput struct {
	Name           string   `json:"name"`
	IP             string   `json:"ip,omitempty"`
	RoutedSubnets  []string `json:"routed_subnets,omitempty"`
	Site           string   `json:"site,omitempty"`
	FailureDomain  string   `json:"failure_domain,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Role           string   `json:"role"`
	PublicEndpoint string   `json:"public_endpoint,omitempty"`
}

type CreatedNode struct {
	Node            Node      `json:"node"`
	EnrollmentToken string    `json:"enrollment_token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type ReplaceNodeInput struct {
	ExpectedConfigRevision int64 `json:"expected_config_revision"`
}

// ReplacedNode is the one-time response for an atomic identity replacement.
// Only the enrollment token hash is persisted; interrupted responses recover
// through the ordinary pending-node enrollment reissue flow.
type ReplacedNode struct {
	RevokedNodeID   string    `json:"revoked_node_id"`
	Node            Node      `json:"node"`
	EnrollmentToken string    `json:"enrollment_token"`
	ExpiresAt       time.Time `json:"expires_at"`
	ConfigRevision  int64     `json:"config_revision"`
}

type UpdateNodeTopologyInput struct {
	Site          string `json:"site"`
	FailureDomain string `json:"failure_domain"`
}

// ReissuedEnrollment contains the replacement credential for a pending node.
// EnrollmentToken is intentionally returned only by the mutating operation;
// the store persists its hash and there is no read API for recovering it.
type ReissuedEnrollment struct {
	Node            Node      `json:"node"`
	EnrollmentToken string    `json:"enrollment_token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// IssuedAgentRecovery contains a one-time credential for restoring the agent
// bearer on an already-enrolled node. RecoveryToken is returned once; only its
// hash is persisted by the control plane.
type IssuedAgentRecovery struct {
	Node          Node      `json:"node"`
	RecoveryToken string    `json:"recovery_token"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s *Service) CreateNode(networkID string, in CreateNodeInput) (CreatedNode, error) {
	return s.createNode(nil, networkID, in)
}

func (s *Service) CreateNodeAs(actor Actor, networkID string, in CreateNodeInput) (CreatedNode, error) {
	if err := validateActor(actor); err != nil {
		return CreatedNode{}, err
	}
	return s.createNode(&actor, networkID, in)
}

func (s *Service) createNode(actor *Actor, networkID string, in CreateNodeInput) (CreatedNode, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !namePattern.MatchString(in.Name) {
		return CreatedNode{}, fmt.Errorf("%w: invalid node name", ErrInvalid)
	}
	if in.Role == "" {
		in.Role = "member"
	}
	if in.Role != "member" && in.Role != "lighthouse" {
		return CreatedNode{}, fmt.Errorf("%w: role must be member or lighthouse", ErrInvalid)
	}
	in.PublicEndpoint = strings.TrimSpace(in.PublicEndpoint)
	if in.Role == "lighthouse" && in.PublicEndpoint == "" {
		return CreatedNode{}, fmt.Errorf("%w: a lighthouse requires a public host:port endpoint", ErrInvalid)
	}
	if in.PublicEndpoint != "" {
		if err := validateEndpoint(in.PublicEndpoint); err != nil {
			return CreatedNode{}, err
		}
	}
	site, err := normalizeTopologyLabel(in.Site, "site")
	if err != nil {
		return CreatedNode{}, err
	}
	failureDomain, err := normalizeTopologyLabel(in.FailureDomain, "failure domain")
	if err != nil {
		return CreatedNode{}, err
	}
	groups, err := normalizeGroups(in.Groups)
	if err != nil {
		return CreatedNode{}, err
	}
	groups = appendUnique(groups, "all")
	sort.Strings(groups)
	if len(groups) > maxNodeGroups {
		return CreatedNode{}, fmt.Errorf("%w: a node may have at most %d groups including all", ErrInvalid, maxNodeGroups)
	}
	routedSubnets, err := normalizeRoutedSubnets(in.RoutedSubnets)
	if err != nil {
		return CreatedNode{}, err
	}
	nodeID, err := RandomToken(12)
	if err != nil {
		return CreatedNode{}, err
	}
	enrollmentID, err := RandomToken(12)
	if err != nil {
		return CreatedNode{}, err
	}
	now, expires := s.now(), s.now().Add(30*time.Minute)
	var created Node
	var token string
	err = s.updateState(func(state *State) error {
		if state.Version < ControlStateVersionTopology && (in.Site != "" || in.FailureDomain != "") {
			return fmt.Errorf("%w: topology schema is not current", ErrConflict)
		}
		network, ok := findNetwork(*state, networkID)
		if !ok {
			return ErrNotFound
		}
		if err := validateNewRoutedSubnets(*state, routedSubnets); err != nil {
			return err
		}
		for _, node := range state.Nodes {
			if node.NetworkID == networkID && strings.EqualFold(node.Name, in.Name) && node.Status != "revoked" {
				return fmt.Errorf("%w: node name already exists", ErrConflict)
			}
		}
		address := strings.TrimSpace(in.IP)
		if address == "" {
			address, err = nextAddress(network, state.Nodes)
			if err != nil {
				return err
			}
		} else if err := validateNodeIP(network, state.Nodes, address); err != nil {
			return err
		}
		token, err = s.uniqueBearer(*state, now)
		if err != nil {
			return err
		}
		auditDetails := map[string]any{"name": in.Name, "ip": address, "role": in.Role}
		if len(routedSubnets) > 0 {
			auditRoutes := make([]any, len(routedSubnets))
			for index, routedSubnet := range routedSubnets {
				auditRoutes[index] = routedSubnet
			}
			auditDetails["routed_subnets"] = auditRoutes
		}
		event, err := newOptionalAttributedAudit(now, "node.created", "node", nodeID, auditDetails, actor)
		if err != nil {
			return err
		}
		created = Node{ID: nodeID, NetworkID: networkID, Name: in.Name, IP: address, RoutedSubnets: routedSubnets, Groups: groups, Role: in.Role, PublicEndpoint: in.PublicEndpoint, Status: "pending", CreatedAt: now}
		if state.Version >= ControlStateVersionTopology {
			created.Site = site
			created.FailureDomain = failureDomain
		}
		state.Nodes = append(state.Nodes, created)
		state.Enrollments = append(state.Enrollments, EnrollmentToken{ID: enrollmentID, NodeID: nodeID, TokenHash: HashToken(token), CreatedAt: now, ExpiresAt: expires})
		state.Audit = append(state.Audit, event)
		return nil
	})
	if err != nil {
		return CreatedNode{}, err
	}
	return CreatedNode{Node: created, EnrollmentToken: token, ExpiresAt: expires}, nil
}

func (s *Service) UpdateNodeTopology(nodeID string, in UpdateNodeTopologyInput) (Node, error) {
	return s.updateNodeTopology(nil, nodeID, in)
}

func (s *Service) UpdateNodeTopologyAs(actor Actor, nodeID string, in UpdateNodeTopologyInput) (Node, error) {
	if err := validateActor(actor); err != nil {
		return Node{}, err
	}
	return s.updateNodeTopology(&actor, nodeID, in)
}

func (s *Service) updateNodeTopology(actor *Actor, nodeID string, in UpdateNodeTopologyInput) (Node, error) {
	if !validPersistedID(nodeID) {
		return Node{}, fmt.Errorf("%w: invalid node ID", ErrInvalid)
	}
	site, err := normalizeTopologyLabel(in.Site, "site")
	if err != nil {
		return Node{}, err
	}
	failureDomain, err := normalizeTopologyLabel(in.FailureDomain, "failure domain")
	if err != nil {
		return Node{}, err
	}
	var updated Node
	err = s.updateState(func(state *State) error {
		if state.Version < ControlStateVersionTopology {
			return fmt.Errorf("%w: topology schema is not current", ErrConflict)
		}
		index := -1
		for candidate := range state.Nodes {
			if state.Nodes[candidate].ID == nodeID {
				index = candidate
				break
			}
		}
		if index < 0 {
			return ErrNotFound
		}
		node := &state.Nodes[index]
		if node.Status == "revoked" {
			return fmt.Errorf("%w: revoked node placement cannot be changed", ErrConflict)
		}
		if node.Site == site && node.FailureDomain == failureDomain {
			updated = *node
			return nil
		}
		now := s.now().UTC()
		if now.IsZero() {
			return errors.New("topology update requires a valid timestamp")
		}
		oldSite, oldFailureDomain := node.Site, node.FailureDomain
		node.Site, node.FailureDomain = site, failureDomain
		for recoveryIndex := range state.AgentRecoveries {
			result := state.AgentRecoveries[recoveryIndex].Result
			if result != nil && result.Node.ID == nodeID {
				result.Node.Site = site
				result.Node.FailureDomain = failureDomain
			}
		}
		event, err := newOptionalAttributedAudit(now, "node.topology_updated", "node", nodeID, map[string]any{
			"old_site": oldSite, "site": site,
			"old_failure_domain": oldFailureDomain, "failure_domain": failureDomain,
		}, actor)
		if err != nil {
			return err
		}
		state.Audit = append(state.Audit, event)
		updated = *node
		return nil
	})
	return updated, err
}

func normalizeTopologyLabel(value, field string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return UnassignedTopologyLabel, nil
	}
	if !topologyLabelPattern.MatchString(value) {
		return "", fmt.Errorf("%w: %s must be a 1-63 character lowercase placement label", ErrInvalid, field)
	}
	return value, nil
}

// ReissueEnrollment replaces every enrollment token for a never-enrolled
// pending node in one store transaction. Generating the replacement while the
// store is locked preserves global bearer uniqueness and makes an in-flight
// claim lose its final compare-and-commit after the old record is removed.
func (s *Service) ReissueEnrollment(nodeID string) (ReissuedEnrollment, error) {
	return s.reissueEnrollment(nil, nodeID)
}

func (s *Service) ReissueEnrollmentAs(actor Actor, nodeID string) (ReissuedEnrollment, error) {
	if err := validateActor(actor); err != nil {
		return ReissuedEnrollment{}, err
	}
	return s.reissueEnrollment(&actor, nodeID)
}

func (s *Service) reissueEnrollment(actor *Actor, nodeID string) (ReissuedEnrollment, error) {
	nodeID = strings.TrimSpace(nodeID)
	now := s.now()
	expiresAt := now.Add(30 * time.Minute)
	var result ReissuedEnrollment
	err := s.updateState(func(state *State) error {
		var node Node
		found := false
		for _, candidate := range state.Nodes {
			if candidate.ID != nodeID {
				continue
			}
			found = true
			node = candidate
			break
		}
		if !found {
			return ErrNotFound
		}
		if node.Status != "pending" || node.EnrolledAt != nil {
			return fmt.Errorf("%w: enrollment can only be reissued for a never-enrolled pending node", ErrConflict)
		}

		// Check the candidate against all enrollment records, including expired
		// ones, before removing them. Reissuing an expired raw token would make a
		// credential the operator reasonably considers dead valid again.
		token, err := s.uniqueUnseenEnrollmentBearer(*state)
		if err != nil {
			return err
		}
		enrollmentID, err := uniqueEnrollmentID(*state)
		if err != nil {
			return err
		}

		kept := state.Enrollments[:0]
		invalidated := 0
		for _, enrollment := range state.Enrollments {
			if enrollment.NodeID == nodeID {
				invalidated++
				continue
			}
			kept = append(kept, enrollment)
		}
		event, err := newOptionalAttributedAudit(now, "node.enrollment_reissued", "node", nodeID, map[string]any{
			"expires_at": expiresAt, "invalidated_tokens": invalidated,
		}, actor)
		if err != nil {
			return err
		}
		state.Enrollments = append(kept, EnrollmentToken{
			ID: enrollmentID, NodeID: nodeID, TokenHash: HashToken(token), CreatedAt: now, ExpiresAt: expiresAt,
		})
		state.Audit = append(state.Audit, event)
		result = ReissuedEnrollment{Node: node, EnrollmentToken: token, ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		return ReissuedEnrollment{}, err
	}
	return result, nil
}

// IssueAgentRecovery creates a separately scoped, one-time reset credential
// for an active enrolled node. Reissuing atomically removes every unused or
// in-flight reset record for that node, so those transactions lose their final
// compare-and-commit. A committed used result is retained until a newer reset
// commits, allowing a response-loss client to exact-replay its bound request.
func (s *Service) IssueAgentRecovery(nodeID string) (IssuedAgentRecovery, error) {
	return s.issueAgentRecovery(nil, nodeID)
}

func (s *Service) IssueAgentRecoveryAs(actor Actor, nodeID string) (IssuedAgentRecovery, error) {
	if err := validateActor(actor); err != nil {
		return IssuedAgentRecovery{}, err
	}
	return s.issueAgentRecovery(&actor, nodeID)
}

func (s *Service) issueAgentRecovery(actor *Actor, nodeID string) (IssuedAgentRecovery, error) {
	nodeID = strings.TrimSpace(nodeID)
	now := s.now()
	expiresAt := now.Add(30 * time.Minute)
	var result IssuedAgentRecovery
	err := s.updateState(func(state *State) error {
		var node Node
		found := false
		for _, candidate := range state.Nodes {
			if candidate.ID == nodeID {
				node = candidate
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		if node.Status != "active" || node.EnrolledAt == nil || node.RevokedAt != nil || !ValidTokenHash(node.PublicKeyHash) {
			return fmt.Errorf("%w: agent recovery requires an active, non-revoked enrolled node", ErrConflict)
		}
		token, err := s.uniqueUnseenRecoveryBearer(*state)
		if err != nil {
			return err
		}
		recoveryID, err := uniqueAgentRecoveryID(*state)
		if err != nil {
			return err
		}
		kept := state.AgentRecoveries[:0]
		invalidated := 0
		retainedUsed := 0
		for _, recovery := range state.AgentRecoveries {
			if recovery.NodeID == nodeID && recovery.UsedAt == nil {
				invalidated++
				continue
			}
			if recovery.NodeID == nodeID {
				retainedUsed++
			}
			kept = append(kept, recovery)
		}
		event, err := newOptionalAttributedAudit(now, "node.agent_recovery_issued", "node", nodeID, map[string]any{
			"expires_at": expiresAt, "invalidated_tokens": invalidated, "retained_used_results": retainedUsed,
		}, actor)
		if err != nil {
			return err
		}
		state.AgentRecoveries = append(kept, AgentRecoveryToken{
			ID: recoveryID, NodeID: nodeID, TokenHash: HashToken(token), CreatedAt: now, ExpiresAt: expiresAt,
		})
		state.Audit = append(state.Audit, event)
		result = IssuedAgentRecovery{Node: node, RecoveryToken: token, ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		return IssuedAgentRecovery{}, err
	}
	return result, nil
}

// RecoverAgent uses the admin-issued recovery token as the sole reset
// authorization. The existing X25519 public-key match binds the reset to the
// node identity already on record, but is deliberately not described as proof
// of private-key possession: Nebula public keys are public data.
func (s *Service) RecoverAgent(token, publicKey, newAgentTokenHash string) (AgentRecoveryBundle, error) {
	token = strings.TrimSpace(token)
	newAgentTokenHash = strings.TrimSpace(newAgentTokenHash)
	if !ValidBearerToken(token) || !ValidTokenHash(newAgentTokenHash) {
		return AgentRecoveryBundle{}, ErrUnauthorized
	}
	var err error
	publicKey, err = canonicalNebulaPublicKeyPEM(publicKey)
	if err != nil {
		return AgentRecoveryBundle{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	publicKeyHash := HashToken(publicKey)
	requestHash := HashToken(publicKey + "\x00" + newAgentTokenHash)
	preflightAt := s.now()
	if err := s.preflightAgentRecovery(tokenHash, publicKeyHash, preflightAt); err != nil {
		return AgentRecoveryBundle{}, err
	}

	claimID, err := RandomToken(18)
	if err != nil {
		return AgentRecoveryBundle{}, err
	}
	claimedAt := s.now()
	var recovery AgentRecoveryToken
	var replay AgentRecoveryBundle
	var isReplay bool
	err = s.updateState(func(state *State) error {
		for i := range state.AgentRecoveries {
			candidate := &state.AgentRecoveries[i]
			// A used token may replay its exact bound request after issuance
			// expiry. An unused token expires strictly.
			if !TokenEqual(candidate.TokenHash, token) || (candidate.UsedAt == nil && !claimedAt.Before(candidate.ExpiresAt)) {
				continue
			}
			node, ok := findNode(*state, candidate.NodeID)
			if !ok || node.Status != "active" || node.EnrolledAt == nil || node.RevokedAt != nil || !TokenHashEqual(node.PublicKeyHash, publicKeyHash) {
				return ErrUnauthorized
			}
			if candidate.UsedAt != nil {
				if !TokenHashEqual(candidate.ClaimKeyHash, requestHash) || candidate.Result == nil || candidate.CredentialGeneration != node.AgentCredentialGeneration || candidate.CredentialExpiresAt == nil || node.AgentCredentialExpiresAt == nil || !candidate.CredentialExpiresAt.Equal(*node.AgentCredentialExpiresAt) || !TokenHashEqual(node.AgentTokenHash, newAgentTokenHash) {
					return ErrUnauthorized
				}
				replay = *candidate.Result
				isReplay = true
				return nil
			}
			if strictCredentialHashInUse(*state, newAgentTokenHash) {
				return fmt.Errorf("%w: agent credential hash is already in use", ErrConflict)
			}
			if candidate.ClaimedAt != nil && claimedAt.Sub(*candidate.ClaimedAt) < 5*time.Minute {
				return ErrUnauthorized
			}
			candidate.ClaimID = claimID
			candidate.ClaimedAt = &claimedAt
			candidate.ClaimKeyHash = requestHash
			candidate.ClaimedCredentialGeneration = node.AgentCredentialGeneration
			recovery = *candidate
			return nil
		}
		return ErrUnauthorized
	})
	if err != nil {
		if recovery.ID != "" {
			s.releaseAgentRecoveryClaim(recovery.ID, claimID)
		}
		return AgentRecoveryBundle{}, err
	}
	if isReplay {
		return replay, nil
	}
	if s.recoveryClaimed != nil {
		s.recoveryClaimed()
	}

	now := s.now()
	credentialExpiresAt := now.Add(90 * 24 * time.Hour)
	var result AgentRecoveryBundle
	err = s.updateState(func(state *State) error {
		var record *AgentRecoveryToken
		for i := range state.AgentRecoveries {
			if state.AgentRecoveries[i].ID == recovery.ID {
				record = &state.AgentRecoveries[i]
				break
			}
		}
		if record == nil || record.UsedAt != nil || !now.Before(record.ExpiresAt) || record.ClaimID != claimID || !TokenHashEqual(record.ClaimKeyHash, requestHash) {
			return ErrUnauthorized
		}
		var node *Node
		for i := range state.Nodes {
			if state.Nodes[i].ID == record.NodeID {
				node = &state.Nodes[i]
				break
			}
		}
		if node == nil || node.Status != "active" || node.EnrolledAt == nil || node.RevokedAt != nil || !TokenHashEqual(node.PublicKeyHash, publicKeyHash) || node.AgentCredentialGeneration != record.ClaimedCredentialGeneration {
			return ErrUnauthorized
		}
		if strictCredentialHashInUse(*state, newAgentTokenHash) {
			return fmt.Errorf("%w: agent credential hash is already in use", ErrConflict)
		}
		if node.AgentCredentialGeneration < 1 || node.AgentCredentialGeneration == int64(^uint64(0)>>1) {
			return fmt.Errorf("%w: agent credential generation cannot advance", ErrConflict)
		}
		node.AgentTokenHash = newAgentTokenHash
		// Recovery is an administrative reset, not a grace rotation: every old
		// current/grace bearer is invalid immediately on commit.
		node.PreviousAgentTokenHash = ""
		node.PreviousAgentTokenExpiresAt = nil
		node.AgentCredentialExpiresAt = &credentialExpiresAt
		node.AgentCredentialGeneration++
		node.AgentCredentialLastUsedAt = &now

		network, ok := findNetwork(*state, node.NetworkID)
		if !ok {
			return ErrUnauthorized
		}
		config := renderConfig(*state, network, *node)
		signed, err := s.signConfig(network, *node, config, now)
		if err != nil {
			return err
		}
		bundle := enrollmentBundle(network, *node, config, signed)
		receipt := RecoveryReceipt{
			NodeID: node.ID, NetworkID: node.NetworkID, NewAgentTokenHash: newAgentTokenHash,
			AgentCredentialGeneration: node.AgentCredentialGeneration,
			AgentCredentialExpiresAt:  credentialExpiresAt,
			ConfigSHA256:              bundle.ConfigSHA256, ConfigSignature: bundle.ConfigSignature,
		}
		receipt.Signature, err = s.signRecoveryReceipt(network, receipt)
		if err != nil {
			return err
		}
		result = AgentRecoveryBundle{EnrollmentBundle: bundle, RecoveryReceipt: receipt}
		record.UsedAt = &now
		record.CredentialGeneration = node.AgentCredentialGeneration
		record.CredentialExpiresAt = &credentialExpiresAt
		persistedResult := result
		record.Result = &persistedResult
		committedRecoveryID := record.ID
		// The newly committed result supersedes every older recovery record for
		// this node. Retaining only it bounds response-replay state to one signed
		// result per node while leaving other nodes' records untouched.
		keptRecoveries := make([]AgentRecoveryToken, 0, len(state.AgentRecoveries))
		for _, candidate := range state.AgentRecoveries {
			if candidate.NodeID != node.ID || candidate.ID == committedRecoveryID {
				keptRecoveries = append(keptRecoveries, candidate)
			}
		}
		state.AgentRecoveries = keptRecoveries
		state.Audit = append(state.Audit, newAudit(now, "node.agent_recovered", "node", node.ID, map[string]any{
			"credential_generation": node.AgentCredentialGeneration, "recovery_id": committedRecoveryID,
		}))
		return nil
	})
	if err != nil {
		s.releaseAgentRecoveryClaim(recovery.ID, claimID)
		return AgentRecoveryBundle{}, err
	}
	return result, nil
}

func (s *Service) preflightAgentRecovery(tokenHash, publicKeyHash string, at time.Time) error {
	return s.readCurrentState(func(state State) error {
		for _, recovery := range state.AgentRecoveries {
			if !TokenHashEqual(recovery.TokenHash, tokenHash) || (recovery.UsedAt == nil && !at.Before(recovery.ExpiresAt)) {
				continue
			}
			node, ok := findNode(state, recovery.NodeID)
			if ok && node.Status == "active" && node.EnrolledAt != nil && node.RevokedAt == nil && TokenHashEqual(node.PublicKeyHash, publicKeyHash) {
				return nil
			}
		}
		return ErrUnauthorized
	})
}

func (s *Service) signRecoveryReceipt(network Network, receipt RecoveryReceipt) (string, error) {
	privateKey, err := s.box.OpenFor("config-signing-key-v1", network.EncryptedConfigSigningKey)
	if err != nil {
		return "", err
	}
	signature, signErr := SignRecoveryReceipt(privateKey, receipt)
	for i := range privateKey {
		privateKey[i] = 0
	}
	return signature, signErr
}

func (s *Service) releaseAgentRecoveryClaim(recoveryID, claimID string) {
	_ = s.updateState(func(state *State) error {
		for i := range state.AgentRecoveries {
			recovery := &state.AgentRecoveries[i]
			if recovery.ID == recoveryID && recovery.UsedAt == nil && recovery.ClaimID == claimID {
				recovery.ClaimID = ""
				recovery.ClaimedAt = nil
				recovery.ClaimKeyHash = ""
				recovery.ClaimedCredentialGeneration = 0
			}
		}
		return nil
	})
}

func (s *Service) Enroll(ctx context.Context, token, publicKey, agentTokenHash string) (EnrollmentBundle, error) {
	token = strings.TrimSpace(token)
	agentTokenHash = strings.TrimSpace(agentTokenHash)
	if !ValidBearerToken(token) || !ValidTokenHash(agentTokenHash) {
		return EnrollmentBundle{}, ErrUnauthorized
	}
	var err error
	publicKey, err = canonicalNebulaPublicKeyPEM(publicKey)
	if err != nil {
		return EnrollmentBundle{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	preflightAt := s.now()
	if err := s.readCurrentState(func(state State) error {
		for _, candidate := range state.Enrollments {
			if preflightAt.Before(candidate.ExpiresAt) && TokenHashEqual(candidate.TokenHash, tokenHash) {
				return nil
			}
		}
		return ErrUnauthorized
	}); err != nil {
		return EnrollmentBundle{}, err
	}
	claimID, err := RandomToken(18)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	var node Node
	var network Network
	var enrollment EnrollmentToken
	var replay bool
	var replayConfig string
	var replaySigned AgentConfig
	claimedAt := s.now()
	if err := s.updateState(func(state *State) error {
		for i := range state.Enrollments {
			candidate := &state.Enrollments[i]
			if claimedAt.Before(candidate.ExpiresAt) && TokenEqual(candidate.TokenHash, token) {
				requestHash := HashToken(publicKey + "\x00" + agentTokenHash)
				if candidate.UsedAt != nil {
					if candidate.ClaimKeyHash != requestHash {
						return ErrUnauthorized
					}
					var ok bool
					node, ok = findNode(*state, candidate.NodeID)
					if !ok || node.Status != "active" || node.AgentTokenHash != agentTokenHash {
						return ErrUnauthorized
					}
					network, ok = findNetwork(*state, node.NetworkID)
					if !ok {
						return ErrUnauthorized
					}
					replayConfig = renderConfig(*state, network, node)
					var err error
					replaySigned, err = s.signConfig(network, node, replayConfig, claimedAt)
					if err != nil {
						return err
					}
					replay = true
					return nil
				}
				if strictCredentialHashInUse(*state, agentTokenHash) {
					return ErrUnauthorized
				}
				if candidate.ClaimedAt != nil && claimedAt.Sub(*candidate.ClaimedAt) < 5*time.Minute {
					return ErrUnauthorized
				}
				var ok bool
				node, ok = findNode(*state, candidate.NodeID)
				if !ok || node.Status != "pending" {
					return ErrUnauthorized
				}
				network, ok = findNetwork(*state, node.NetworkID)
				if !ok {
					return ErrUnauthorized
				}
				candidate.ClaimID = claimID
				candidate.ClaimedAt = &claimedAt
				candidate.ClaimKeyHash = HashToken(publicKey + "\x00" + agentTokenHash)
				enrollment = *candidate
				return nil
			}
		}
		return ErrUnauthorized
	}); err != nil {
		return EnrollmentBundle{}, err
	}
	if replay {
		return enrollmentBundle(network, node, replayConfig, replaySigned), nil
	}
	signingCACertificate, signingCAKey := networkSigningAuthority(network)
	caKey, err := s.box.Open(signingCAKey)
	if err != nil {
		s.releaseEnrollmentClaim(enrollment.ID, claimID)
		return EnrollmentBundle{}, err
	}
	certificate, fingerprint, certificateExpiresAt, err := s.issuer.SignPublicKey(ctx, signingCACertificate, string(caKey), publicKey, node.Name, node.IP+"/"+prefixLength(network.CIDR), strings.Join(node.Groups, ","), strings.Join(node.RoutedSubnets, ","), time.Duration(network.CertificateTTL)*time.Hour)
	for i := range caKey {
		caKey[i] = 0
	}
	if err != nil {
		s.releaseEnrollmentClaim(enrollment.ID, claimID)
		return EnrollmentBundle{}, err
	}
	if !fingerprintPattern.MatchString(fingerprint) || certificateExpiresAt.IsZero() {
		s.releaseEnrollmentClaim(enrollment.ID, claimID)
		return EnrollmentBundle{}, errors.New("certificate issuer returned invalid certificate metadata")
	}
	now := s.now()
	certificateExpiresAt = certificateExpiresAt.UTC()
	if !certificateExpiresAt.After(now) {
		s.releaseEnrollmentClaim(enrollment.ID, claimID)
		return EnrollmentBundle{}, errors.New("certificate issuer returned an expired certificate")
	}
	certificateRenewAfter := certificateExpiresAt.Add(-renewalWindow(time.Duration(network.CertificateTTL) * time.Hour))
	if certificateRenewAfter.IsZero() || !certificateRenewAfter.After(now) || !certificateRenewAfter.Before(certificateExpiresAt) {
		s.releaseEnrollmentClaim(enrollment.ID, claimID)
		return EnrollmentBundle{}, errors.New("certificate issuer returned invalid renewal metadata")
	}
	agentCredentialExpiresAt := now.Add(90 * 24 * time.Hour)
	var config string
	var signed AgentConfig
	err = s.updateState(func(state *State) error {
		latestNetwork, ok := findNetwork(*state, network.ID)
		if !ok {
			return ErrUnauthorized
		}
		latestSigningCertificate, _ := networkSigningAuthority(latestNetwork)
		if latestSigningCertificate != signingCACertificate {
			return fmt.Errorf("%w: network CA lifecycle changed during enrollment", ErrConflict)
		}
		network = latestNetwork
		if strictCredentialHashInUse(*state, agentTokenHash) {
			return ErrUnauthorized
		}
		claimStillCurrent := false
		for i := range state.Enrollments {
			if state.Enrollments[i].ID == enrollment.ID {
				if state.Enrollments[i].UsedAt != nil || state.Enrollments[i].ClaimID != claimID || state.Enrollments[i].ClaimKeyHash != HashToken(publicKey+"\x00"+agentTokenHash) {
					return ErrUnauthorized
				}
				state.Enrollments[i].UsedAt = &now
				claimStillCurrent = true
				break
			}
		}
		if !claimStillCurrent {
			return ErrUnauthorized
		}
		nodeStillPending := false
		for i := range state.Nodes {
			if state.Nodes[i].ID == node.ID {
				if state.Nodes[i].Status != "pending" {
					return ErrUnauthorized
				}
				nodeStillPending = true
				state.Nodes[i].Status = "active"
				state.Nodes[i].Certificate = certificate
				state.Nodes[i].CertificateFingerprint = fingerprint
				if state.Version >= ControlStateVersionCARotation {
					state.Nodes[i].CertificateAuthoritySHA256 = ConfigDigest(signingCACertificate)
				}
				state.Nodes[i].CertificateExpiresAt = &certificateExpiresAt
				state.Nodes[i].CertificateRenewAfter = &certificateRenewAfter
				state.Nodes[i].CertificateGeneration = 1
				state.Nodes[i].AgentTokenHash = agentTokenHash
				state.Nodes[i].AgentCredentialExpiresAt = &agentCredentialExpiresAt
				state.Nodes[i].AgentCredentialGeneration = 1
				state.Nodes[i].PublicKeyHash = HashToken(publicKey)
				state.Nodes[i].EnrolledAt = &now
				node = state.Nodes[i]
				break
			}
		}
		if !nodeStillPending {
			return ErrUnauthorized
		}
		state.Issuances = append(state.Issuances, CertificateIssuance{Fingerprint: fingerprint, NodeID: node.ID, NetworkID: node.NetworkID, IssuedAt: now, ExpiresAt: certificateExpiresAt})
		for i := range state.Networks {
			if state.Networks[i].ID == network.ID {
				if node.Role == "lighthouse" || len(node.RoutedSubnets) > 0 {
					state.Networks[i].ConfigRevision++
					state.Networks[i].ConfigUpdatedAt = now
				}
				reconcileNetworkRoutePolicies(state, &state.Networks[i])
				network = state.Networks[i]
			}
		}
		config = renderConfig(*state, network, node)
		var signErr error
		signed, signErr = s.signConfig(network, node, config, now)
		if signErr != nil {
			return signErr
		}
		state.Audit = append(state.Audit, newAudit(now, "node.enrolled", "node", node.ID, nil))
		return nil
	})
	if err != nil {
		s.releaseEnrollmentClaim(enrollment.ID, claimID)
		return EnrollmentBundle{}, err
	}
	return enrollmentBundle(network, node, config, signed), nil
}

func enrollmentBundle(network Network, node Node, config string, signed AgentConfig) EnrollmentBundle {
	return EnrollmentBundle{
		NodeID:                            signed.NodeID,
		NetworkID:                         signed.NetworkID,
		Node:                              node,
		Certificate:                       node.Certificate,
		CA:                                networkTrustBundle(network),
		Config:                            config,
		ConfigRevision:                    signed.Revision,
		CertificateExpiresAt:              signed.CertificateExpiresAt,
		CertificateRenewAfter:             signed.CertificateRenewAfter,
		AgentCredentialExpiresAt:          valueOrZero(node.AgentCredentialExpiresAt),
		AgentCredentialGeneration:         node.AgentCredentialGeneration,
		ConfigIssuedAt:                    signed.IssuedAt,
		ConfigSHA256:                      signed.SHA256,
		CACertificateSHA256:               signed.CACertificateSHA256,
		PreviousCACertificateSHA256:       signed.PreviousCACertificateSHA256,
		CARotationRequired:                signed.CARotationRequired,
		CertificateProfileRenewalRequired: signed.CertificateProfileRenewalRequired,
		CertificateFingerprint:            signed.CertificateFingerprint,
		CertificateGeneration:             signed.CertificateGeneration,
		PublicKeyHash:                     signed.PublicKeyHash,
		ConfigSignature:                   signed.Signature,
		ConfigSigningPublicKey:            network.ConfigSigningPublicKey,
	}
}

func (s *Service) releaseEnrollmentClaim(enrollmentID, claimID string) {
	_ = s.updateState(func(state *State) error {
		for i := range state.Enrollments {
			if state.Enrollments[i].ID == enrollmentID && state.Enrollments[i].UsedAt == nil && state.Enrollments[i].ClaimID == claimID {
				state.Enrollments[i].ClaimID = ""
				state.Enrollments[i].ClaimedAt = nil
				state.Enrollments[i].ClaimKeyHash = ""
			}
		}
		return nil
	})
}

func (s *Service) AgentConfig(token string) (AgentConfig, error) {
	token = strings.TrimSpace(token)
	if !ValidBearerToken(token) {
		return AgentConfig{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	if _, err := s.preflightAgentCredential(tokenHash, s.now()); err != nil {
		return AgentConfig{}, err
	}
	var result AgentConfig
	err := s.viewState(func(state State) error {
		node, ok := findAgent(state, tokenHash, s.now())
		if !ok {
			return ErrUnauthorized
		}
		network, ok := findNetwork(state, node.NetworkID)
		if !ok || node.CertificateExpiresAt == nil {
			return ErrUnauthorized
		}
		var err error
		result, err = s.signConfig(network, node, renderConfig(state, network, node), s.now())
		return err
	})
	return result, err
}

func (s *Service) AgentBootstrap(token string) (EnrollmentBundle, error) {
	token = strings.TrimSpace(token)
	if !ValidBearerToken(token) {
		return EnrollmentBundle{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	if _, err := s.preflightAgentCredential(tokenHash, s.now()); err != nil {
		return EnrollmentBundle{}, err
	}
	var bundle EnrollmentBundle
	err := s.viewState(func(state State) error {
		node, ok := findAgent(state, tokenHash, s.now())
		if !ok || node.CertificateExpiresAt == nil || node.AgentCredentialExpiresAt == nil {
			return ErrUnauthorized
		}
		network, ok := findNetwork(state, node.NetworkID)
		if !ok {
			return ErrUnauthorized
		}
		config := renderConfig(state, network, node)
		signed, err := s.signConfig(network, node, config, s.now())
		if err != nil {
			return err
		}
		bundle = enrollmentBundle(network, node, config, signed)
		return nil
	})
	return bundle, err
}

func (s *Service) signConfig(network Network, node Node, config string, issuedAt time.Time) (AgentConfig, error) {
	if !network.ConfigUpdatedAt.IsZero() {
		issuedAt = network.ConfigUpdatedAt
	}
	privateKey, err := s.box.OpenFor("config-signing-key-v1", network.EncryptedConfigSigningKey)
	if err != nil {
		return AgentConfig{}, err
	}
	expiresAt := time.Time{}
	renewAfter := time.Time{}
	if node.CertificateExpiresAt != nil {
		expiresAt = node.CertificateExpiresAt.UTC()
	}
	if node.CertificateRenewAfter != nil {
		renewAfter = node.CertificateRenewAfter.UTC()
	}
	metadata := ConfigSignatureMetadata{
		NodeID:                            node.ID,
		NetworkID:                         network.ID,
		Revision:                          network.ConfigRevision,
		IssuedAt:                          issuedAt,
		CACertificateSHA256:               ConfigDigest(networkTrustBundle(network)),
		PreviousCACertificateSHA256:       network.CARotation.PreviousTrustBundleSHA256,
		CARotationRequired:                networkCARotationRequired(network, node),
		CertificateProfileRenewalRequired: networkCertificateProfileRenewalRequired(network, node),
		CertificateFingerprint:            node.CertificateFingerprint,
		CertificateExpiresAt:              expiresAt,
		CertificateRenewAfter:             renewAfter,
		CertificateGeneration:             node.CertificateGeneration,
		PublicKeyHash:                     node.PublicKeyHash,
	}
	digest, signature, err := SignConfig(privateKey, metadata, config)
	for i := range privateKey {
		privateKey[i] = 0
	}
	if err != nil {
		return AgentConfig{}, err
	}
	return AgentConfig{
		NodeID:                            metadata.NodeID,
		NetworkID:                         metadata.NetworkID,
		Revision:                          metadata.Revision,
		Config:                            config,
		IssuedAt:                          metadata.IssuedAt,
		SHA256:                            digest,
		CACertificateSHA256:               metadata.CACertificateSHA256,
		PreviousCACertificateSHA256:       metadata.PreviousCACertificateSHA256,
		CARotationRequired:                metadata.CARotationRequired,
		CertificateProfileRenewalRequired: metadata.CertificateProfileRenewalRequired,
		CertificateFingerprint:            metadata.CertificateFingerprint,
		CertificateGeneration:             metadata.CertificateGeneration,
		PublicKeyHash:                     metadata.PublicKeyHash,
		Signature:                         signature,
		CertificateExpiresAt:              metadata.CertificateExpiresAt,
		CertificateRenewAfter:             metadata.CertificateRenewAfter,
	}, nil
}

func (s *Service) preflightAgentCredential(tokenHash string, at time.Time) (Node, error) {
	var node Node
	err := s.readCurrentState(func(state State) error {
		var ok bool
		node, ok = findAgent(state, tokenHash, at)
		if !ok {
			return ErrUnauthorized
		}
		return nil
	})
	return node, err
}

// AuthorizeRuntimeTelemetry binds a separately persisted observation to the
// exact lifecycle heartbeat already accepted for this active node. It is a
// read-only authorization check: telemetry can never advance heartbeat state
// or revive an expired/revoked credential.
func (s *Service) AuthorizeRuntimeTelemetry(token string, heartbeatSequence int64) (Node, error) {
	token = strings.TrimSpace(token)
	if !ValidBearerToken(token) {
		return Node{}, ErrUnauthorized
	}
	if heartbeatSequence < 1 || heartbeatSequence > maxPersistedHeartbeatSequence {
		return Node{}, fmt.Errorf("%w: runtime telemetry heartbeat sequence is invalid", ErrInvalid)
	}
	node, err := s.preflightAgentCredential(HashToken(token), s.now())
	if err != nil {
		return Node{}, err
	}
	if node.HeartbeatSequence != heartbeatSequence || node.LastSeenAt == nil {
		return Node{}, fmt.Errorf("%w: runtime telemetry does not match the current heartbeat", ErrConflict)
	}
	return node, nil
}

func (s *Service) Heartbeat(token string, input HeartbeatInput) (Node, error) {
	token = strings.TrimSpace(token)
	input.AgentVersion = strings.TrimSpace(input.AgentVersion)
	input.NebulaVersion = strings.TrimSpace(input.NebulaVersion)
	input.Status = strings.TrimSpace(input.Status)
	input.LastError = strings.TrimSpace(input.LastError)
	input.BootID = strings.TrimSpace(input.BootID)
	input.AppliedConfigSHA256 = strings.TrimSpace(input.AppliedConfigSHA256)
	input.CertificateFingerprint = strings.TrimSpace(input.CertificateFingerprint)
	if !ValidBearerToken(token) || !validTelemetry(input.AgentVersion, maxPersistedAgentVersionBytes) || !validTelemetry(input.NebulaVersion, maxPersistedNebulaVersionBytes) || !validTelemetry(input.LastError, maxPersistedLastErrorBytes) || !namePattern.MatchString(input.BootID) {
		return Node{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	if _, err := s.preflightAgentCredential(tokenHash, s.now()); err != nil {
		return Node{}, err
	}
	if input.Status == "" {
		input.Status = "healthy"
	}
	if input.Status != "healthy" && input.Status != "degraded" {
		return Node{}, fmt.Errorf("%w: status must be healthy or degraded", ErrInvalid)
	}
	if input.AppliedConfigRevision < 0 || input.CertificateGeneration < 0 || input.Sequence < 1 || input.Sequence > maxPersistedHeartbeatSequence {
		return Node{}, fmt.Errorf("%w: heartbeat counters are invalid", ErrInvalid)
	}
	if input.AppliedConfigRevision == 0 && input.AppliedConfigSHA256 != "" {
		return Node{}, fmt.Errorf("%w: applied config digest requires an applied revision", ErrInvalid)
	}
	now := s.now()
	var updated Node
	err := s.updateState(func(state *State) error {
		for i := range state.Nodes {
			candidate := &state.Nodes[i]
			matched, current := agentCredentialMatch(*candidate, tokenHash, now)
			if candidate.Status != "active" || !matched {
				continue
			}
			var network *Network
			for networkIndex := range state.Networks {
				if state.Networks[networkIndex].ID == candidate.NetworkID {
					network = &state.Networks[networkIndex]
					break
				}
			}
			if network == nil || network.ConfigRevision < 1 || candidate.CertificateGeneration < 1 || candidate.AppliedConfigRevision < 0 || candidate.AppliedCertificateGeneration < 0 || candidate.HeartbeatSequence < 0 {
				return fmt.Errorf("authoritative node state is invalid")
			}
			if input.AppliedConfigRevision > network.ConfigRevision || input.AppliedConfigRevision < candidate.AppliedConfigRevision {
				return fmt.Errorf("%w: applied config revision is not valid", ErrInvalid)
			}
			if input.CertificateGeneration > candidate.CertificateGeneration || (input.CertificateGeneration > 0 && input.CertificateGeneration < candidate.AppliedCertificateGeneration) {
				return fmt.Errorf("%w: certificate generation is not valid", ErrInvalid)
			}
			if input.Sequence <= candidate.HeartbeatSequence {
				return fmt.Errorf("%w: heartbeat sequence must increase", ErrConflict)
			}
			// Persist-before-send can leave benign sequence gaps. Bound those gaps so
			// a stolen bearer cannot submit MaxInt64 and permanently strand the
			// legitimate agent's monotonic counter.
			if input.Sequence-candidate.HeartbeatSequence > 1_000_000 {
				return fmt.Errorf("%w: heartbeat sequence advanced too far", ErrInvalid)
			}
			if candidate.LastSeenAt != nil && now.Sub(*candidate.LastSeenAt) < 5*time.Second {
				return fmt.Errorf("%w: heartbeat interval is at least 5 seconds", ErrRateLimited)
			}
			if input.AppliedConfigRevision > 0 && !fingerprintPattern.MatchString(input.AppliedConfigSHA256) {
				return fmt.Errorf("%w: applied config digest is invalid", ErrInvalid)
			}
			if input.CertificateFingerprint != "" && !fingerprintPattern.MatchString(input.CertificateFingerprint) {
				return fmt.Errorf("%w: certificate fingerprint is invalid", ErrInvalid)
			}
			autoRollbackRuntimeStopped := false
			if input.AppliedConfigRevision == network.ConfigRevision {
				desiredDigest := ConfigDigest(renderConfig(*state, *network, *candidate))
				nativeDNSRequired := effectiveNetworkDNSSettings(network.DNSSettings).NativeResolver
				if input.AppliedConfigSHA256 != desiredDigest || input.CertificateFingerprint != candidate.CertificateFingerprint || (input.CertificateGeneration > 0 && input.CertificateGeneration != candidate.CertificateGeneration) || input.NativeDNSActive != nativeDNSRequired {
					return fmt.Errorf("%w: applied state does not match the desired signed configuration", ErrConflict)
				}
				if !input.NebulaRunning {
					autoRollbackRuntimeStopped = network.FirewallRollout.Phase == FirewallRolloutPhaseCanary &&
						slices.Contains(network.FirewallRollout.CanaryNodeIDs, candidate.ID) &&
						input.CertificateGeneration == candidate.CertificateGeneration && input.Status == "degraded"
					if !autoRollbackRuntimeStopped {
						return fmt.Errorf("%w: applied state does not match the desired signed configuration", ErrConflict)
					}
				}
			}
			candidate.AgentVersion = input.AgentVersion
			candidate.NebulaVersion = input.NebulaVersion
			candidate.AppliedConfigRevision = input.AppliedConfigRevision
			if input.CertificateGeneration > 0 {
				candidate.AppliedCertificateGeneration = input.CertificateGeneration
			} else if input.CertificateFingerprint == candidate.CertificateFingerprint {
				// Compatibility for agents predating the explicit generation field:
				// an exact authoritative fingerprint proves the current generation.
				candidate.AppliedCertificateGeneration = candidate.CertificateGeneration
			}
			candidate.AppliedConfigSHA256 = input.AppliedConfigSHA256
			candidate.ReportedCertificateFingerprint = input.CertificateFingerprint
			candidate.NebulaRunning = input.NebulaRunning
			candidate.NativeDNSActive = input.NativeDNSActive
			candidate.AgentStatus = input.Status
			candidate.AgentBootID = input.BootID
			candidate.HeartbeatSequence = input.Sequence
			candidate.LastError = input.LastError
			candidate.LastSeenAt = &now
			candidate.AgentCredentialLastUsedAt = &now
			if current {
				candidate.PreviousAgentTokenHash = ""
				candidate.PreviousAgentTokenExpiresAt = nil
			}
			updated = *candidate
			if autoRollbackRuntimeStopped {
				_, err := autoRollbackFirewallRollout(state, network, *candidate, now.UTC(), "canary_target_runtime_stopped", map[string]any{
					"failed_config_revision": input.AppliedConfigRevision,
					"failed_config_sha256":   input.AppliedConfigSHA256,
					"heartbeat_sequence":     input.Sequence,
					"nebula_running":         false,
					"agent_status":           "degraded",
				})
				if err != nil {
					return err
				}
			}
			return nil
		}
		return ErrUnauthorized
	})
	return updated, err
}

func (s *Service) RotateAgentCredential(token, newTokenHash string) (CredentialRotation, error) {
	token = strings.TrimSpace(token)
	newTokenHash = strings.TrimSpace(newTokenHash)
	if !ValidBearerToken(token) || !ValidTokenHash(newTokenHash) {
		return CredentialRotation{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	now := s.now()
	if _, err := s.preflightAgentCredential(tokenHash, now); err != nil {
		return CredentialRotation{}, err
	}
	if s.credentialRotationPreflighted != nil {
		s.credentialRotationPreflighted()
	}
	expiresAt := now.Add(90 * 24 * time.Hour)
	var result CredentialRotation
	err := s.updateState(func(state *State) error {
		for i := range state.Nodes {
			candidate := &state.Nodes[i]
			matched, current := agentCredentialMatch(*candidate, tokenHash, now)
			if candidate.Status != "active" || !matched {
				continue
			}
			if !current {
				if candidate.AgentTokenHash == newTokenHash {
					if candidate.AgentCredentialGeneration < 1 || candidate.AgentCredentialExpiresAt == nil || !candidate.AgentCredentialExpiresAt.After(now) {
						return fmt.Errorf("authoritative credential state is invalid")
					}
					result = CredentialRotation{Generation: candidate.AgentCredentialGeneration, ExpiresAt: valueOrZero(candidate.AgentCredentialExpiresAt)}
					return nil
				}
				return ErrUnauthorized
			}
			if candidate.AgentTokenHash == newTokenHash {
				if candidate.AgentCredentialGeneration < 1 || candidate.AgentCredentialExpiresAt == nil || !candidate.AgentCredentialExpiresAt.After(now) {
					return fmt.Errorf("authoritative credential state is invalid")
				}
				result = CredentialRotation{Generation: candidate.AgentCredentialGeneration, ExpiresAt: valueOrZero(candidate.AgentCredentialExpiresAt)}
				return nil
			}
			// The new hash may not revive this node's grace credential or alias any
			// other node. Otherwise authentication would become ambiguous and a
			// rotation could silently roll the authoritative credential backwards.
			if strictCredentialHashInUse(*state, newTokenHash) {
				return fmt.Errorf("%w: agent credential hash is already in use", ErrConflict)
			}
			if candidate.AgentCredentialGeneration < 1 || candidate.AgentCredentialGeneration == int64(^uint64(0)>>1) {
				return fmt.Errorf("%w: agent credential generation cannot advance", ErrConflict)
			}
			graceExpiresAt := now.Add(time.Hour)
			previousGeneration := candidate.AgentCredentialGeneration
			candidate.PreviousAgentTokenHash = candidate.AgentTokenHash
			candidate.PreviousAgentTokenExpiresAt = &graceExpiresAt
			candidate.AgentTokenHash = newTokenHash
			candidate.AgentCredentialExpiresAt = &expiresAt
			candidate.AgentCredentialGeneration++
			if candidate.AgentCredentialGeneration <= previousGeneration {
				return fmt.Errorf("authoritative credential generation did not advance")
			}
			candidate.AgentCredentialLastUsedAt = &now
			result = CredentialRotation{Generation: candidate.AgentCredentialGeneration, ExpiresAt: expiresAt}
			state.Audit = append(state.Audit, newAudit(now, "node.credential_rotated", "node", candidate.ID, map[string]any{"generation": candidate.AgentCredentialGeneration}))
			return nil
		}
		return ErrUnauthorized
	})
	return result, err
}

func (s *Service) Renew(ctx context.Context, token, publicKey string) (RenewalBundle, error) {
	token = strings.TrimSpace(token)
	if !ValidBearerToken(token) {
		return RenewalBundle{}, ErrUnauthorized
	}
	var err error
	publicKey, err = canonicalNebulaPublicKeyPEM(publicKey)
	if err != nil {
		return RenewalBundle{}, ErrUnauthorized
	}
	tokenHash := HashToken(token)
	preflightNode, err := s.preflightAgentCredential(tokenHash, s.now())
	if err != nil || !TokenEqual(preflightNode.PublicKeyHash, publicKey) {
		return RenewalBundle{}, ErrUnauthorized
	}
	claimID, err := RandomToken(18)
	if err != nil {
		return RenewalBundle{}, err
	}
	claimedAt := s.now()
	var node Node
	var network Network
	var replay bool
	var replayConfig string
	var replaySigned AgentConfig
	var caRotationRenewal bool
	var certificateProfileRenewal bool
	err = s.updateState(func(state *State) error {
		for i := range state.Nodes {
			candidate := &state.Nodes[i]
			matched, _ := agentCredentialMatch(*candidate, tokenHash, claimedAt)
			if candidate.Status != "active" || !matched {
				continue
			}
			if !TokenEqual(candidate.PublicKeyHash, publicKey) {
				return ErrUnauthorized
			}
			var ok bool
			network, ok = findNetwork(*state, candidate.NetworkID)
			if !ok {
				return ErrUnauthorized
			}
			caRotationRenewal = networkCARotationRequired(network, *candidate)
			certificateProfileRenewal = networkCertificateProfileRenewalRequired(network, *candidate)
			if candidate.LastRenewedAt != nil && claimedAt.Sub(*candidate.LastRenewedAt) < 10*time.Minute && !caRotationRenewal && !certificateProfileRenewal {
				node = *candidate
				replayConfig = renderConfig(*state, network, node)
				var signErr error
				replaySigned, signErr = s.signConfig(network, node, replayConfig, claimedAt)
				if signErr != nil {
					return signErr
				}
				replay = true
				return nil
			}
			if candidate.CertificateExpiresAt == nil || candidate.CertificateRenewAfter == nil || claimedAt.Before(*candidate.CertificateRenewAfter) && !caRotationRenewal && !certificateProfileRenewal {
				return fmt.Errorf("%w: certificate is not yet eligible for renewal", ErrConflict)
			}
			if candidate.CertificateGeneration < 1 || candidate.CertificateGeneration == int64(^uint64(0)>>1) {
				return fmt.Errorf("%w: certificate generation cannot advance", ErrConflict)
			}
			if candidate.RenewalClaimedAt != nil && claimedAt.Sub(*candidate.RenewalClaimedAt) < 5*time.Minute {
				return ErrUnauthorized
			}
			candidate.RenewalClaimID = claimID
			candidate.RenewalClaimedAt = &claimedAt
			node = *candidate
			return nil
		}
		return ErrUnauthorized
	})
	if err != nil {
		return RenewalBundle{}, err
	}
	if replay {
		return renewalBundle(network, node, replayConfig, replaySigned), nil
	}
	signingCACertificate, signingCAKey := networkSigningAuthority(network)
	caKey, err := s.box.Open(signingCAKey)
	if err != nil {
		s.releaseRenewalClaim(node.ID, claimID)
		return RenewalBundle{}, err
	}
	certificateSubnets := certificateRoutedSubnets(network, node)
	certificate, fingerprint, expiresAt, err := s.issuer.SignPublicKey(ctx, signingCACertificate, string(caKey), publicKey, node.Name, node.IP+"/"+prefixLength(network.CIDR), strings.Join(node.Groups, ","), strings.Join(certificateSubnets, ","), time.Duration(network.CertificateTTL)*time.Hour)
	for i := range caKey {
		caKey[i] = 0
	}
	if err != nil {
		s.releaseRenewalClaim(node.ID, claimID)
		return RenewalBundle{}, err
	}
	if !fingerprintPattern.MatchString(fingerprint) || expiresAt.IsZero() {
		s.releaseRenewalClaim(node.ID, claimID)
		return RenewalBundle{}, errors.New("certificate issuer returned invalid certificate metadata")
	}
	now := s.now()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) {
		s.releaseRenewalClaim(node.ID, claimID)
		return RenewalBundle{}, errors.New("certificate issuer returned an expired certificate")
	}
	var config string
	var signed AgentConfig
	var renewAfter time.Time
	err = s.updateState(func(state *State) error {
		latestNetwork, ok := findNetwork(*state, node.NetworkID)
		if !ok {
			return ErrUnauthorized
		}
		latestSigningCertificate, _ := networkSigningAuthority(latestNetwork)
		if latestSigningCertificate != signingCACertificate {
			return fmt.Errorf("%w: network CA lifecycle changed during certificate renewal", ErrConflict)
		}
		renewAfter = expiresAt.Add(-renewalWindow(time.Duration(latestNetwork.CertificateTTL) * time.Hour))
		if renewAfter.IsZero() || !renewAfter.After(now) || !renewAfter.Before(expiresAt) {
			return errors.New("certificate issuer returned invalid renewal metadata")
		}
		network = latestNetwork
		found := false
		for i := range state.Nodes {
			candidate := &state.Nodes[i]
			if candidate.ID != node.ID {
				continue
			}
			matched, _ := agentCredentialMatch(*candidate, tokenHash, now)
			if candidate.Status != "active" || candidate.RenewalClaimID != claimID || !matched {
				return ErrUnauthorized
			}
			candidate.Certificate = certificate
			candidate.CertificateFingerprint = fingerprint
			if state.Version >= ControlStateVersionCARotation {
				candidate.CertificateAuthoritySHA256 = ConfigDigest(signingCACertificate)
			}
			candidate.CertificateExpiresAt = &expiresAt
			candidate.CertificateRenewAfter = &renewAfter
			previousGeneration := candidate.CertificateGeneration
			candidate.CertificateGeneration++
			if candidate.CertificateGeneration <= previousGeneration {
				return fmt.Errorf("authoritative certificate generation did not advance")
			}
			candidate.LastRenewedAt = &now
			candidate.RenewalClaimID = ""
			candidate.RenewalClaimedAt = nil
			node = *candidate
			found = true
		}
		if !found {
			return ErrUnauthorized
		}
		state.Issuances = append(state.Issuances, CertificateIssuance{Fingerprint: fingerprint, NodeID: node.ID, NetworkID: node.NetworkID, IssuedAt: now, ExpiresAt: expiresAt})
		config = renderConfig(*state, network, node)
		var signErr error
		signed, signErr = s.signConfig(network, node, config, now)
		if signErr != nil {
			return signErr
		}
		state.Audit = append(state.Audit, newAudit(now, "node.certificate_renewed", "node", node.ID, map[string]any{"fingerprint": fingerprint, "config_revision": network.ConfigRevision, "certificate_generation": node.CertificateGeneration}))
		return nil
	})
	if err != nil {
		s.releaseRenewalClaim(node.ID, claimID)
		return RenewalBundle{}, err
	}
	return renewalBundle(network, node, config, signed), nil
}

func renewalBundle(network Network, node Node, config string, signed AgentConfig) RenewalBundle {
	return RenewalBundle{
		NodeID:                            signed.NodeID,
		NetworkID:                         signed.NetworkID,
		CA:                                networkTrustBundle(network),
		Certificate:                       node.Certificate,
		CertificateExpiresAt:              signed.CertificateExpiresAt,
		CertificateRenewAfter:             signed.CertificateRenewAfter,
		Config:                            config,
		ConfigRevision:                    signed.Revision,
		ConfigIssuedAt:                    signed.IssuedAt,
		ConfigSHA256:                      signed.SHA256,
		CACertificateSHA256:               signed.CACertificateSHA256,
		PreviousCACertificateSHA256:       signed.PreviousCACertificateSHA256,
		CARotationRequired:                signed.CARotationRequired,
		CertificateProfileRenewalRequired: signed.CertificateProfileRenewalRequired,
		CertificateFingerprint:            signed.CertificateFingerprint,
		CertificateGeneration:             signed.CertificateGeneration,
		PublicKeyHash:                     signed.PublicKeyHash,
		ConfigSignature:                   signed.Signature,
	}
}

func (s *Service) releaseRenewalClaim(nodeID, claimID string) {
	_ = s.updateState(func(state *State) error {
		for i := range state.Nodes {
			if state.Nodes[i].ID == nodeID && state.Nodes[i].RenewalClaimID == claimID {
				state.Nodes[i].RenewalClaimID = ""
				state.Nodes[i].RenewalClaimedAt = nil
			}
		}
		return nil
	})
}

func (s *Service) RevokeNode(nodeID string) (Node, error) {
	return s.revokeNode(nil, nodeID)
}

func (s *Service) RevokeNodeAs(actor Actor, nodeID string) (Node, error) {
	if err := validateActor(actor); err != nil {
		return Node{}, err
	}
	return s.revokeNode(&actor, nodeID)
}

func (s *Service) revokeNode(actor *Actor, nodeID string) (Node, error) {
	node, _, _, err := s.revokeOrReplaceNode(actor, nodeID, false, 0, nil)
	return node, err
}

func (s *Service) ReplaceNode(nodeID string, input ReplaceNodeInput) (ReplacedNode, error) {
	return s.replaceNode(nil, nodeID, input)
}

func (s *Service) ReplaceNodeAs(actor Actor, nodeID string, input ReplaceNodeInput) (ReplacedNode, error) {
	if err := validateActor(actor); err != nil {
		return ReplacedNode{}, err
	}
	return s.replaceNode(&actor, nodeID, input)
}

func (s *Service) replaceNode(actor *Actor, nodeID string, input ReplaceNodeInput) (ReplacedNode, error) {
	if !validPersistedID(nodeID) || input.ExpectedConfigRevision < 1 {
		return ReplacedNode{}, fmt.Errorf("%w: node ID and expected_config_revision are required", ErrInvalid)
	}
	_, replacement, _, err := s.revokeOrReplaceNode(actor, nodeID, true, input.ExpectedConfigRevision, nil)
	if err != nil {
		return ReplacedNode{}, err
	}
	return *replacement, nil
}

func (s *Service) revokeOrReplaceNode(actor *Actor, nodeID string, replace bool, expectedConfigRevision int64, revocationInput *RevokeNodeInput) (Node, *ReplacedNode, *RevokedNodeReceipt, error) {
	var node Node
	var replacement *ReplacedNode
	var revocationReceipt *RevokedNodeReceipt
	now := s.now()
	err := s.updateState(func(state *State) error {
		source, sourceFound := findNode(*state, nodeID)
		if !sourceFound {
			return ErrNotFound
		}
		if network, ok := findNetwork(*state, source.NetworkID); ok && (routeTransferIncludesNode(network.RouteTransfer, nodeID) || routeProfileEditIncludesNode(network.RouteProfileEdit, nodeID)) {
			return fmt.Errorf("%w: node lifecycle changes are unavailable while it participates in a route transition", ErrConflict)
		}
		if revocationInput != nil {
			replayed, found, err := findNodeRevocationReplay(*state, nodeID, *revocationInput)
			if err != nil {
				return err
			}
			if found {
				revocationReceipt = &replayed
				return nil
			}
			if source.Status == "revoked" || source.RevokedAt != nil {
				return fmt.Errorf("%w: node already revoked", ErrConflict)
			}
			if source.Name != revocationInput.ConfirmationName {
				return fmt.Errorf("%w: confirmation name does not exactly match the node", ErrConflict)
			}
			network, ok := findNetwork(*state, source.NetworkID)
			if !ok || network.ConfigRevision != revocationInput.ExpectedConfigRevision {
				return fmt.Errorf("%w: expected config revision does not match the node network", ErrConflict)
			}
		}
		if replace {
			if source.Status != "active" || source.EnrolledAt == nil || source.RevokedAt != nil {
				return fmt.Errorf("%w: identity replacement requires an active enrolled node", ErrConflict)
			}
			network, ok := findNetwork(*state, source.NetworkID)
			if !ok || network.ConfigRevision != expectedConfigRevision {
				return fmt.Errorf("%w: expected config revision does not match the active node network", ErrConflict)
			}
			if network.FirewallRollout.Phase != "" {
				return fmt.Errorf("%w: identity replacement is unavailable during a firewall rollout", ErrConflict)
			}
		}
		found := false
		for i := range state.Nodes {
			if state.Nodes[i].ID == nodeID {
				if state.Nodes[i].Status == "revoked" {
					return fmt.Errorf("%w: node already revoked", ErrConflict)
				}
				state.Nodes[i].Status = "revoked"
				state.Nodes[i].RevokedAt = &now
				state.Nodes[i].AgentTokenHash = ""
				state.Nodes[i].PreviousAgentTokenHash = ""
				state.Nodes[i].PreviousAgentTokenExpiresAt = nil
				state.Nodes[i].AgentCredentialExpiresAt = nil
				state.Nodes[i].RenewalClaimID = ""
				state.Nodes[i].RenewalClaimedAt = nil
				state.Nodes[i].AgentStatus = "revoked"
				node = state.Nodes[i]
				found = true
			}
		}
		if !found {
			return ErrNotFound
		}
		recoveriesInvalidated := 0
		keptRecoveries := state.AgentRecoveries[:0]
		for _, recovery := range state.AgentRecoveries {
			if recovery.NodeID != node.ID {
				keptRecoveries = append(keptRecoveries, recovery)
			} else {
				recoveriesInvalidated++
			}
		}
		if len(keptRecoveries) == 0 {
			keptRecoveries = nil
		}
		state.AgentRecoveries = keptRecoveries
		enrollmentsInvalidated := 0
		if revocationInput != nil {
			keptEnrollments := state.Enrollments[:0]
			for _, enrollment := range state.Enrollments {
				if enrollment.NodeID != node.ID {
					keptEnrollments = append(keptEnrollments, enrollment)
				} else {
					enrollmentsInvalidated++
				}
			}
			if len(keptEnrollments) == 0 {
				keptEnrollments = nil
			}
			state.Enrollments = keptEnrollments
		}
		previousRevocations := len(state.Revocations)
		for _, issuance := range state.Issuances {
			if issuance.NodeID == node.ID && issuance.ExpiresAt.After(now) {
				expiresAt := issuance.ExpiresAt
				appendRevocation(state, node.ID, issuance.Fingerprint, "node revoked", now, &expiresAt)
			}
		}
		if node.CertificateFingerprint != "" {
			appendRevocation(state, node.ID, node.CertificateFingerprint, "node revoked", now, node.CertificateExpiresAt)
		}
		relayAssignmentRemoved := false
		firewallCanaryRemoved := false
		firewallRolloutAutoRolledBack := false
		firewallRolloutPreviousCanaries := 0
		firewallRolloutDiscardedSHA256 := ""
		if state.Version >= ControlStateVersionNetworkRelays {
			for index := range state.Networks {
				network := &state.Networks[index]
				if network.ID != node.NetworkID {
					continue
				}
				if slices.Contains(network.RelaySettings.RelayNodeIDs, node.ID) {
					network.RelaySettings.RelayNodeIDs = slices.DeleteFunc(network.RelaySettings.RelayNodeIDs, func(candidate string) bool { return candidate == node.ID })
					if len(network.RelaySettings.RelayNodeIDs) == 0 {
						network.RelaySettings.Enabled = false
					}
					relayAssignmentRemoved = true
				}
				if state.Version >= ControlStateVersionFirewallRollout && (network.FirewallRollout.Phase == FirewallRolloutPhaseCanary || network.FirewallRollout.Phase == FirewallRolloutPhasePaused) && slices.Contains(network.FirewallRollout.CanaryNodeIDs, node.ID) {
					firewallCanaryRemoved = true
					firewallRolloutPreviousCanaries = len(network.FirewallRollout.CanaryNodeIDs)
					firewallRolloutDiscardedSHA256 = firewallPolicySHA256(network.FirewallRollout.TargetPolicy)
					network.FirewallRollout.CanaryNodeIDs = slices.DeleteFunc(network.FirewallRollout.CanaryNodeIDs, func(candidate string) bool { return candidate == node.ID })
					if len(network.FirewallRollout.CanaryNodeIDs) == 0 {
						network.FirewallRollout = NetworkFirewallRollout{}
						firewallRolloutAutoRolledBack = true
					}
				}
			}
		}
		configRevision := int64(0)
		for i := range state.Networks {
			if state.Networks[i].ID == node.NetworkID {
				nextRevision, err := nextConfigRevision(state.Networks[i].ConfigRevision, true)
				if err != nil {
					return err
				}
				state.Networks[i].ConfigRevision = nextRevision
				state.Networks[i].ConfigUpdatedAt = now
				reconcileNetworkRoutePolicies(state, &state.Networks[i])
				configRevision = nextRevision
				if firewallCanaryRemoved {
					action := "network.firewall_rollout_canary_removed"
					details := map[string]any{
						"node_id": node.ID, "previous_canary_nodes": firewallRolloutPreviousCanaries,
						"remaining_canary_nodes": firewallRolloutPreviousCanaries - 1, "config_revision": nextRevision,
					}
					if firewallRolloutAutoRolledBack {
						action = "network.firewall_rollout_auto_rolled_back"
						details["discarded_sha256"] = firewallRolloutDiscardedSHA256
						details["retained_sha256"] = firewallPolicySHA256(state.Networks[i].FirewallPolicy)
						details["reason_code"] = "last_canary_revoked"
					}
					rolloutEvent, err := newOptionalAttributedAudit(now, action, "network", state.Networks[i].ID, details, actor)
					if err != nil {
						return err
					}
					state.Audit = append(state.Audit, rolloutEvent)
				}
			}
		}
		if configRevision < 1 {
			return errors.New("revoked node network is missing")
		}
		eventAction := "node.revoked"
		eventDetails := map[string]any{
			"fingerprint": node.CertificateFingerprint, "relay_assignment_removed": relayAssignmentRemoved,
			"firewall_canary_removed": firewallCanaryRemoved, "firewall_rollout_auto_rolled_back": firewallRolloutAutoRolledBack,
		}
		if revocationInput != nil {
			receipt := RevokedNodeReceipt{
				RequestID: revocationInput.RequestID, NodeID: node.ID, NetworkID: node.NetworkID, Name: node.Name, IP: node.IP, Role: node.Role,
				RevokedAt: now.UTC(), WasEnrolled: node.EnrolledAt != nil, EnrollmentRecordsInvalidated: enrollmentsInvalidated,
				AgentRecoveryRecordsInvalidated: recoveriesInvalidated, BlocklistEntriesAdded: len(state.Revocations) - previousRevocations,
				RelayAssignmentRemoved: relayAssignmentRemoved, FirewallCanaryRemoved: firewallCanaryRemoved,
				FirewallRolloutAutoRolledBack: firewallRolloutAutoRolledBack, CredentialsInvalidated: true,
				RoutedSubnetReservationsReleased: len(node.RoutedSubnets), ConfigRevision: configRevision,
			}
			revocationReceipt = &receipt
			eventAction = nodeRevocationCommittedAuditAction
			eventDetails = nodeRevocationAuditDetails(receipt, revocationInput.ExpectedConfigRevision)
		}
		event, err := newOptionalAttributedAudit(now, eventAction, "node", nodeID, eventDetails, actor)
		if err != nil {
			return err
		}
		state.Audit = append(state.Audit, event)
		if replace {
			network, ok := findNetwork(*state, source.NetworkID)
			if !ok {
				return errors.New("replacement source network is missing")
			}
			// Identity replacement is a certificate-first continuation of one
			// already-authorized node, not an ordinary pending-node create. After
			// the source is revoked, allow only exact prefixes still served by
			// active enrolled owners in this network so an ECMP member can be
			// replaced without withdrawing the surviving route. Partial,
			// cross-network, managed-CIDR, and pending-owner overlap still fails.
			if err := validateRoutedSubnetsForNode(*state, source.ID, source.RoutedSubnets); err != nil {
				return err
			}
			address, err := nextAddress(network, state.Nodes)
			if err != nil {
				return err
			}
			replacementID, err := RandomToken(12)
			if err != nil {
				return err
			}
			enrollmentID, err := uniqueEnrollmentID(*state)
			if err != nil {
				return err
			}
			token, err := s.uniqueUnseenEnrollmentBearer(*state)
			if err != nil {
				return err
			}
			expiresAt := now.Add(30 * time.Minute)
			created := Node{
				ID: replacementID, NetworkID: source.NetworkID, Name: source.Name, IP: address,
				RoutedSubnets: slices.Clone(source.RoutedSubnets), Site: source.Site, FailureDomain: source.FailureDomain,
				Groups: slices.Clone(source.Groups), Role: source.Role, PublicEndpoint: source.PublicEndpoint,
				Status: "pending", CreatedAt: now,
			}
			transferredFirewallReferences := replaceFirewallPolicyNodeReferences(&network.FirewallPolicy, source.ID, replacementID)
			replacementEvent, err := newOptionalAttributedAudit(now, "node.identity_replacement_created", "node", replacementID, map[string]any{
				"revoked_node_id": source.ID, "name": created.Name, "ip": created.IP,
				"role": created.Role, "config_revision": network.ConfigRevision, "expires_at": expiresAt,
				"firewall_references_transferred": transferredFirewallReferences,
			}, actor)
			if err != nil {
				return err
			}
			state.Nodes = append(state.Nodes, created)
			state.Enrollments = append(state.Enrollments, EnrollmentToken{ID: enrollmentID, NodeID: replacementID, TokenHash: HashToken(token), CreatedAt: now, ExpiresAt: expiresAt})
			state.Audit = append(state.Audit, replacementEvent)
			replacement = &ReplacedNode{RevokedNodeID: source.ID, Node: created, EnrollmentToken: token, ExpiresAt: expiresAt, ConfigRevision: network.ConfigRevision}
		}
		return nil
	})
	return node, replacement, revocationReceipt, err
}

func (s *Service) Networks() ([]NetworkSummary, error) {
	var result []NetworkSummary
	err := s.viewState(func(state State) error {
		for _, network := range state.Networks {
			summary := NetworkSummary{Network: network}
			for _, node := range state.Nodes {
				if node.NetworkID == network.ID {
					summary.NodeCount++
					if node.Status == "active" {
						summary.ActiveNodes++
					}
				}
			}
			result = append(result, summary)
		}
		sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
		return nil
	})
	return result, err
}

func (s *Service) GetFirewallPolicy(networkID string) (FirewallPolicyDocument, error) {
	var result FirewallPolicyDocument
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		result = firewallPolicyDocument(state, network, network.FirewallPolicy)
		return nil
	})
	return result, err
}

func (s *Service) PreviewFirewallPolicy(networkID string, input FirewallPolicyInput) (FirewallPolicyPreview, error) {
	var result FirewallPolicyPreview
	err := s.viewState(func(state State) error {
		network, ok := findNetwork(state, networkID)
		if !ok {
			return ErrNotFound
		}
		desired, err := normalizeFirewallPolicy(input, network.CIDR)
		if err != nil {
			return err
		}
		if err := validateFirewallPolicyReferences(state, network, desired); err != nil {
			return err
		}
		if network.DNSSettings.Enabled && !firewallAllowsNetworkDNS(desired, network.CIDR, network.DNSSettings.ListenPort) {
			return fmt.Errorf("%w: firewall must keep UDP port %d available from all managed nodes while network DNS is enabled", ErrConflict, network.DNSSettings.ListenPort)
		}
		changed := !sameEffectiveFirewallPolicy(network.FirewallPolicy, desired)
		proposedRevision, err := nextConfigRevision(network.ConfigRevision, changed)
		if err != nil {
			return err
		}
		if !changed {
			desired = network.FirewallPolicy
		}
		result = FirewallPolicyPreview{
			FirewallPolicyDocument: firewallPolicyDocument(state, network, desired),
			WouldChange:            changed, ProposedConfigRevision: proposedRevision,
		}
		return nil
	})
	return result, err
}

func (s *Service) UpdateFirewallPolicy(networkID string, input UpdateFirewallPolicyInput) (FirewallPolicyDocument, error) {
	return s.updateFirewallPolicy(nil, networkID, input)
}

func (s *Service) UpdateFirewallPolicyAs(actor Actor, networkID string, input UpdateFirewallPolicyInput) (FirewallPolicyDocument, error) {
	if err := validateActor(actor); err != nil {
		return FirewallPolicyDocument{}, err
	}
	return s.updateFirewallPolicy(&actor, networkID, input)
}

func (s *Service) updateFirewallPolicy(actor *Actor, networkID string, input UpdateFirewallPolicyInput) (FirewallPolicyDocument, error) {
	if input.ExpectedConfigRevision < 1 {
		return FirewallPolicyDocument{}, fmt.Errorf("%w: expected_config_revision must be positive", ErrInvalid)
	}
	var result FirewallPolicyDocument
	now := s.now()
	err := s.updateState(func(state *State) error {
		for index := range state.Networks {
			network := &state.Networks[index]
			if network.ID != networkID {
				continue
			}
			desired, err := normalizeFirewallPolicy(FirewallPolicyInput{Inbound: input.Inbound, Outbound: input.Outbound}, network.CIDR)
			if err != nil {
				return err
			}
			if err := validateFirewallPolicyReferences(*state, *network, desired); err != nil {
				return err
			}
			if firewallPolicyUsesNodeScopes(desired) && state.Version < ControlStateVersionFirewallScopes {
				return fmt.Errorf("%w: firewall scope schema is not current", ErrConflict)
			}
			if network.DNSSettings.Enabled && !firewallAllowsNetworkDNS(desired, network.CIDR, network.DNSSettings.ListenPort) {
				return fmt.Errorf("%w: firewall must keep UDP port %d available from all managed nodes while network DNS is enabled", ErrConflict, network.DNSSettings.ListenPort)
			}
			if sameEffectiveFirewallPolicy(network.FirewallPolicy, desired) {
				result = firewallPolicyDocument(*state, *network, network.FirewallPolicy)
				return nil
			}
			if network.FirewallRollout.Phase != "" {
				return fmt.Errorf("%w: direct firewall updates are disabled during a canary rollout", ErrConflict)
			}
			if routeTransferActive(network.RouteTransfer) {
				return fmt.Errorf("%w: direct firewall updates are disabled during a route transfer", ErrConflict)
			}
			if routeProfileEditActive(network.RouteProfileEdit) {
				return fmt.Errorf("%w: direct firewall updates are disabled during a route-profile edit", ErrConflict)
			}
			if input.ExpectedConfigRevision != network.ConfigRevision {
				return fmt.Errorf("%w: expected config revision %d does not match current revision %d", ErrConflict, input.ExpectedConfigRevision, network.ConfigRevision)
			}
			nextRevision, err := nextConfigRevision(network.ConfigRevision, true)
			if err != nil {
				return err
			}
			event, err := newOptionalAttributedAudit(now, "network.firewall_policy_updated", "network", network.ID, map[string]any{
				"old_sha256": firewallPolicySHA256(network.FirewallPolicy), "new_sha256": firewallPolicySHA256(desired),
				"inbound_rules": len(desired.Inbound), "outbound_rules": len(desired.Outbound),
				"config_revision": nextRevision,
			}, actor)
			if err != nil {
				return err
			}
			network.FirewallPolicy = desired
			network.ConfigRevision = nextRevision
			network.ConfigUpdatedAt = now
			state.Audit = append(state.Audit, event)
			result = firewallPolicyDocument(*state, *network, network.FirewallPolicy)
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func (s *Service) Nodes(networkID string) ([]Node, error) {
	var result []Node
	err := s.viewState(func(state State) error {
		if _, ok := findNetwork(state, networkID); !ok {
			return ErrNotFound
		}
		for _, node := range state.Nodes {
			if node.NetworkID == networkID {
				result = append(result, node)
			}
		}
		sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
		return nil
	})
	return result, err
}

func (s *Service) Audit(limit int) ([]AuditEvent, error) {
	var result []AuditEvent
	err := s.viewState(func(state State) error {
		start := len(state.Audit) - limit
		if start < 0 {
			start = 0
		}
		for i := len(state.Audit) - 1; i >= start; i-- {
			result = append(result, state.Audit[i])
		}
		return nil
	})
	return result, err
}

func renderConfig(state State, network Network, node Node) string {
	var lighthouses []Node
	type routedConfigGateway struct {
		ip     string
		weight int
	}
	type routedConfigEntry struct {
		route    string
		gateways []routedConfigGateway
		mtu      int
		metric   int
	}
	var routedEntries []routedConfigEntry
	routeOwners := make(map[string][]Node)
	var blocklist []string
	blocked := map[string]bool{}
	for _, candidate := range state.Nodes {
		if candidate.NetworkID != network.ID {
			continue
		}
		if candidate.Role == "lighthouse" && candidate.Status == "active" && candidate.PublicEndpoint != "" {
			lighthouses = append(lighthouses, candidate)
		}
		if candidate.Status == "active" {
			for _, route := range candidate.RoutedSubnets {
				routeOwners[route] = append(routeOwners[route], candidate)
			}
		}
		if candidate.Status == "revoked" && candidate.CertificateFingerprint != "" {
			blocked[candidate.CertificateFingerprint] = true
		}
	}
	sort.Slice(lighthouses, func(i, j int) bool { return lighthouses[i].IP < lighthouses[j].IP })
	localCertificateRoutes := certificateRoutedSubnets(network, node)
	for route := range routeOwners {
		if slices.Contains(localCertificateRoutes, route) {
			continue
		}
		policy := effectiveRoutePolicy(state, network, route)
		entry := routedConfigEntry{route: route, mtu: policy.MTU, metric: policy.Metric}
		for _, gateway := range policy.Gateways {
			candidate, ok := findNode(state, gateway.NodeID)
			if ok {
				entry.gateways = append(entry.gateways, routedConfigGateway{ip: candidate.IP, weight: gateway.Weight})
			}
		}
		if len(entry.gateways) > 0 {
			routedEntries = append(routedEntries, entry)
		}
	}
	sort.Slice(routedEntries, func(i, j int) bool {
		return routedEntries[i].route < routedEntries[j].route
	})
	for _, revocation := range state.Revocations {
		revocationNetworkID := revocation.NetworkID
		if revocationNetworkID == "" {
			if candidate, ok := findNode(state, revocation.NodeID); ok {
				revocationNetworkID = candidate.NetworkID
			}
		}
		if revocationNetworkID == network.ID {
			blocked[revocation.Fingerprint] = true
		}
	}
	for fingerprint := range blocked {
		blocklist = append(blocklist, fingerprint)
	}
	sort.Strings(blocklist)
	var b strings.Builder
	b.WriteString(renderNativeDNSPolicy(state, network, node))
	b.WriteString("pki:\n  ca: /etc/nebula/ca.crt\n  cert: /etc/nebula/host.crt\n  key: /etc/nebula/host.key\n")
	if len(blocklist) > 0 {
		b.WriteString("  blocklist:\n")
		for _, fp := range blocklist {
			fmt.Fprintf(&b, "    - %q\n", fp)
		}
	}
	b.WriteString("  disconnect_invalid: true\n")
	b.WriteString("static_host_map:\n")
	for _, lh := range lighthouses {
		fmt.Fprintf(&b, "  %q: [%q]\n", lh.IP, lh.PublicEndpoint)
	}
	var remoteLighthouses []Node
	for _, lh := range lighthouses {
		if lh.ID != node.ID {
			remoteLighthouses = append(remoteLighthouses, lh)
		}
	}
	fmt.Fprintf(&b, "lighthouse:\n  am_lighthouse: %t\n", node.Role == "lighthouse")
	if node.Role == "lighthouse" && network.DNSSettings.Enabled {
		fmt.Fprintf(&b, "  serve_dns: true\n  dns:\n    host: %q\n    port: %d\n", node.IP, network.DNSSettings.ListenPort)
	}
	b.WriteString("  interval: 60\n")
	if len(remoteLighthouses) == 0 {
		b.WriteString("  hosts: []\n")
	} else {
		b.WriteString("  hosts:\n")
		for _, lh := range remoteLighthouses {
			fmt.Fprintf(&b, "    - %q\n", lh.IP)
		}
	}
	fmt.Fprintf(&b, "listen:\n  host: 0.0.0.0\n  port: %d\npunchy:\n  punch: true\n", network.ListenPort)
	relaySettings := effectiveNetworkRelaySettings(network.RelaySettings)
	if relaySettings.Enabled {
		b.WriteString("relay:\n")
		if slices.Contains(relaySettings.RelayNodeIDs, node.ID) {
			b.WriteString("  am_relay: true\n  use_relays: false\n")
		} else {
			relays := activeNetworkRelays(state, network)
			if len(relays) == 0 {
				b.WriteString("  relays: []\n")
			} else {
				b.WriteString("  relays:\n")
				for _, relay := range relays {
					fmt.Fprintf(&b, "    - %q\n", relay.IP)
				}
			}
			b.WriteString("  am_relay: false\n  use_relays: true\n")
		}
	}
	if len(routedEntries) > 0 {
		b.WriteString("tun:\n  unsafe_routes:\n")
		for _, entry := range routedEntries {
			fmt.Fprintf(&b, "    - route: %q\n", entry.route)
			if len(entry.gateways) == 1 {
				fmt.Fprintf(&b, "      via: %q\n", entry.gateways[0].ip)
			} else {
				b.WriteString("      via:\n")
				for _, gateway := range entry.gateways {
					fmt.Fprintf(&b, "        - gateway: %q\n          weight: %d\n", gateway.ip, gateway.weight)
				}
			}
			if entry.mtu != 0 {
				fmt.Fprintf(&b, "      mtu: %d\n", entry.mtu)
			}
			if entry.metric != 0 {
				fmt.Fprintf(&b, "      metric: %d\n", entry.metric)
			}
		}
	}
	effectiveFirewall := effectiveFirewallPolicyForNode(state, node, firewallPolicyForNode(network, node))
	b.WriteString(renderFirewallPolicyForNode(effectiveFirewall, certificateRoutedSubnets(network, node)))
	b.WriteString("logging:\n  level: info\n  format: json\n")
	return b.String()
}

func findAgent(state State, tokenHash string, now time.Time) (Node, bool) {
	var matched Node
	found := false
	for _, node := range state.Nodes {
		credentialMatched, _ := agentCredentialMatch(node, tokenHash, now)
		if node.Status == "active" && credentialMatched {
			if found {
				// Legacy or externally-corrupted state must fail closed rather than
				// letting slice order choose a node identity.
				return Node{}, false
			}
			matched = node
			found = true
		}
	}
	return matched, found
}

// uniqueBearer creates a server-issued enrollment bearer inside the state
// transaction that commits it. This makes uniqueness race-free. Collisions are
// cryptographically improbable, but bounded retries make the invariant
// deterministic and testable instead of relying on probability alone.
func (s *Service) uniqueBearer(state State, _ time.Time) (string, error) {
	if s.generateBearer == nil {
		return "", errors.New("bearer generator is not configured")
	}
	for range 16 {
		token, err := s.generateBearer()
		if err != nil {
			return "", err
		}
		if !ValidBearerToken(token) {
			return "", errors.New("bearer generator returned an invalid token")
		}
		hash := HashToken(token)
		if strictCredentialHashInUse(state, hash) {
			continue
		}
		return token, nil
	}
	return "", errors.New("could not generate a unique bearer credential")
}

// uniqueUnseenEnrollmentBearer is stricter than uniqueBearer because a
// reissue must not revive an expired raw enrollment token. Agent credentials
// are checked with the same active/grace rules as other issuance paths; every
// enrollment hash still retained by the control plane is treated as used.
func (s *Service) uniqueUnseenEnrollmentBearer(state State) (string, error) {
	if s.generateBearer == nil {
		return "", errors.New("bearer generator is not configured")
	}
	for range 16 {
		token, err := s.generateBearer()
		if err != nil {
			return "", err
		}
		if !ValidBearerToken(token) {
			return "", errors.New("bearer generator returned an invalid token")
		}
		hash := HashToken(token)
		if !strictCredentialHashInUse(state, hash) {
			return token, nil
		}
	}
	return "", errors.New("could not generate a globally unique enrollment bearer")
}

// uniqueUnseenRecoveryBearer never revives any retained credential across the
// enrollment, recovery, current-agent, or grace-agent domains.
func (s *Service) uniqueUnseenRecoveryBearer(state State) (string, error) {
	if s.generateBearer == nil {
		return "", errors.New("bearer generator is not configured")
	}
	for range 16 {
		token, err := s.generateBearer()
		if err != nil {
			return "", err
		}
		if !ValidBearerToken(token) {
			return "", errors.New("bearer generator returned an invalid token")
		}
		if !strictCredentialHashInUse(state, HashToken(token)) {
			return token, nil
		}
	}
	return "", errors.New("could not generate a globally unique agent recovery bearer")
}

func uniqueEnrollmentID(state State) (string, error) {
	for range 16 {
		id, err := RandomToken(12)
		if err != nil {
			return "", err
		}
		unique := true
		for _, enrollment := range state.Enrollments {
			if enrollment.ID == id {
				unique = false
				break
			}
		}
		if unique {
			for _, recovery := range state.AgentRecoveries {
				if recovery.ID == id {
					unique = false
					break
				}
			}
		}
		if unique {
			return id, nil
		}
	}
	return "", errors.New("could not generate a unique enrollment record ID")
}

func uniqueAgentRecoveryID(state State) (string, error) {
	for range 16 {
		id, err := RandomToken(12)
		if err != nil {
			return "", err
		}
		unique := true
		for _, recovery := range state.AgentRecoveries {
			if recovery.ID == id {
				unique = false
				break
			}
		}
		if unique {
			for _, enrollment := range state.Enrollments {
				if enrollment.ID == id {
					unique = false
					break
				}
			}
		}
		if unique {
			return id, nil
		}
	}
	return "", errors.New("could not generate a unique agent recovery record ID")
}

// strictCredentialHashInUse treats every retained secret hash as consumed,
// even when its credential has expired. This prevents administrative recovery
// from reviving an old raw bearer in another authentication domain.
func strictCredentialHashInUse(state State, hash string) bool {
	for _, node := range state.Nodes {
		if TokenHashEqual(node.AgentTokenHash, hash) || TokenHashEqual(node.PreviousAgentTokenHash, hash) {
			return true
		}
	}
	for _, enrollment := range state.Enrollments {
		if TokenHashEqual(enrollment.TokenHash, hash) {
			return true
		}
	}
	for _, recovery := range state.AgentRecoveries {
		if TokenHashEqual(recovery.TokenHash, hash) {
			return true
		}
		if recovery.Result != nil && TokenHashEqual(recovery.Result.RecoveryReceipt.NewAgentTokenHash, hash) {
			return true
		}
	}
	return false
}

// credentialHashInUse checks both current and grace credentials globally. The
// optional allowed node/slot is used only for idempotent rotation to the same
// current credential; a grace credential is never an allowed rotation target.
func credentialHashInUse(state State, hash, allowedNodeID, allowedSlot string, now time.Time) bool {
	for _, node := range state.Nodes {
		if node.Status != "active" {
			continue
		}
		if node.AgentCredentialExpiresAt != nil && now.Before(*node.AgentCredentialExpiresAt) && TokenHashEqual(node.AgentTokenHash, hash) {
			if node.ID != allowedNodeID || allowedSlot != "current" {
				return true
			}
		}
		if node.PreviousAgentTokenExpiresAt != nil && now.Before(*node.PreviousAgentTokenExpiresAt) && TokenHashEqual(node.PreviousAgentTokenHash, hash) {
			return true
		}
	}
	return false
}

func enrollmentHashInUse(state State, hash string, now time.Time) bool {
	for _, enrollment := range state.Enrollments {
		if now.Before(enrollment.ExpiresAt) && TokenHashEqual(enrollment.TokenHash, hash) {
			return true
		}
	}
	return false
}

func bearerHashInUse(state State, hash string, now time.Time) bool {
	if credentialHashInUse(state, hash, "", "", now) || enrollmentHashInUse(state, hash, now) {
		return true
	}
	for _, recovery := range state.AgentRecoveries {
		if now.Before(recovery.ExpiresAt) && TokenHashEqual(recovery.TokenHash, hash) {
			return true
		}
	}
	return false
}

func agentCredentialMatch(node Node, tokenHash string, now time.Time) (matched, current bool) {
	if node.AgentCredentialExpiresAt != nil && now.Before(*node.AgentCredentialExpiresAt) && TokenHashEqual(node.AgentTokenHash, tokenHash) {
		return true, true
	}
	if node.PreviousAgentTokenExpiresAt != nil && now.Before(*node.PreviousAgentTokenExpiresAt) && TokenHashEqual(node.PreviousAgentTokenHash, tokenHash) {
		return true, false
	}
	return false, false
}

func valueOrZero(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func networkTTL(state State, networkID string) time.Duration {
	if network, ok := findNetwork(state, networkID); ok {
		return time.Duration(network.CertificateTTL) * time.Hour
	}
	return 0
}

func renewalWindow(ttl time.Duration) time.Duration {
	window := ttl / 3
	if window < time.Hour {
		window = time.Hour
	}
	if window > 30*24*time.Hour {
		window = 30 * 24 * time.Hour
	}
	return window
}

func appendRevocation(state *State, nodeID, fingerprint, reason string, at time.Time, expiresAt *time.Time) {
	if fingerprint == "" {
		return
	}
	for _, existing := range state.Revocations {
		if existing.Fingerprint == fingerprint {
			return
		}
	}
	node, _ := findNode(*state, nodeID)
	state.Revocations = append(state.Revocations, CertificateRevocation{Fingerprint: fingerprint, NodeID: nodeID, NetworkID: node.NetworkID, Reason: reason, At: at, ExpiresAt: expiresAt})
}

func validTelemetry(value string, max int) bool {
	if len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 && r != '\t' {
			return false
		}
	}
	return true
}

func findNetwork(state State, id string) (Network, bool) {
	for _, v := range state.Networks {
		if v.ID == id {
			return v, true
		}
	}
	return Network{}, false
}
func findNode(state State, id string) (Node, bool) {
	for _, v := range state.Nodes {
		if v.ID == id {
			return v, true
		}
	}
	return Node{}, false
}

func nextAddress(network Network, nodes []Node) (string, error) {
	base, ipnet, _ := net.ParseCIDR(network.CIDR)
	used := map[string]bool{}
	for _, node := range nodes {
		if node.NetworkID == network.ID {
			used[node.IP] = true
		}
	}
	address := base.To4()
	for offset := uint32(10); offset < 1<<16; offset++ {
		candidate := addIPv4(address, offset)
		if !ipnet.Contains(candidate) {
			break
		}
		value := candidate.String()
		if !used[value] && !isBroadcast(candidate, ipnet) {
			return value, nil
		}
	}
	return "", fmt.Errorf("%w: network address space is exhausted", ErrConflict)
}

func validateNodeIP(network Network, nodes []Node, value string) error {
	ip := net.ParseIP(value).To4()
	_, ipnet, _ := net.ParseCIDR(network.CIDR)
	if ip == nil || !ipnet.Contains(ip) || ip.Equal(ipnet.IP) || isBroadcast(ip, ipnet) {
		return fmt.Errorf("%w: IP must be a usable address in %s", ErrInvalid, network.CIDR)
	}
	for _, node := range nodes {
		if node.NetworkID == network.ID && node.IP == value {
			return fmt.Errorf("%w: IP is already assigned", ErrConflict)
		}
	}
	return nil
}

func addIPv4(ip net.IP, n uint32) net.IP {
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += n
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func isBroadcast(ip net.IP, network *net.IPNet) bool {
	base := network.IP.To4()
	mask := network.Mask
	for i := 0; i < 4; i++ {
		if ip[i] != base[i]|^mask[i] {
			return false
		}
	}
	return true
}
func prefixLength(cidr string) string {
	_, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	return strconv.Itoa(ones)
}
func cidrsOverlap(a, b string) bool {
	aip, an, _ := net.ParseCIDR(a)
	bip, bn, _ := net.ParseCIDR(b)
	return an.Contains(bip) || bn.Contains(aip)
}
func validateEndpoint(value string) error {
	if len(value) > maxPublicEndpointBytes || !utf8.ValidString(value) {
		return fmt.Errorf("%w: endpoint is oversized or not valid UTF-8", ErrInvalid)
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return fmt.Errorf("%w: endpoint must be host:port (IPv6 in brackets)", ErrInvalid)
	}
	if err := validateEndpointHost(host); err != nil {
		return err
	}
	for _, character := range port {
		if character < '0' || character > '9' {
			return fmt.Errorf("%w: endpoint port must be numeric", ErrInvalid)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: endpoint port is invalid", ErrInvalid)
	}
	return nil
}

func validateEndpointHost(host string) error {
	if !validBoundedPlainText(host, maxPublicEndpointHostBytes, false) {
		return fmt.Errorf("%w: endpoint host is empty, oversized, not valid UTF-8, or contains control characters", ErrInvalid)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	// DNS wire labels are ASCII. International names remain supported in their
	// standard punycode form, avoiding locale-dependent normalization here.
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed == "" {
		return fmt.Errorf("%w: endpoint host must be a DNS name or IP address", ErrInvalid)
	}
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: endpoint DNS labels must be 1-63 characters and cannot start or end with a dash", ErrInvalid)
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return fmt.Errorf("%w: endpoint DNS name must use letters, digits, dots, or dashes (use punycode for international names)", ErrInvalid)
		}
	}
	return nil
}
func normalizeGroups(groups []string) ([]string, error) {
	if len(groups) > maxNodeGroups {
		return nil, fmt.Errorf("%w: a node may have at most %d groups including all", ErrInvalid, maxNodeGroups)
	}
	var result []string
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		if !groupPattern.MatchString(group) {
			return nil, fmt.Errorf("%w: invalid group %q", ErrInvalid, group)
		}
		result = appendUnique(result, group)
	}
	sort.Strings(result)
	return result, nil
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
func newAudit(at time.Time, action, resource, id string, details map[string]any) AuditEvent {
	eventID, _ := RandomToken(12)
	return AuditEvent{ID: eventID, Action: action, Resource: resource, ResourceID: id, At: at, Details: details}
}
