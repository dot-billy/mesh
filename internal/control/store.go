package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const maxPersistedStateSize = 64 << 20

const (
	maxPersistedAgentVersionBytes  = 64
	maxPersistedNebulaVersionBytes = 64
	maxPersistedLastErrorBytes     = 512
	// Heartbeat sequences cross a JSON boundary and are compared by browser
	// tooling. Keeping the durable value within the exactly representable
	// integer range also leaves an effectively inexhaustible counter at the
	// enforced five-second minimum heartbeat interval.
	maxPersistedHeartbeatSequence int64 = 1<<53 - 1
)

type Store struct {
	path              string
	lock              *os.File
	mu                sync.RWMutex
	state             State
	syncDirectory     func(string) error
	durabilityPending bool
	// cloneCount provides a lightweight regression signal for authentication
	// preflights; it is not part of persisted state or the public API.
	cloneCount atomic.Uint64
}

var (
	ErrUncertainCommit = errors.New("state commit durability is uncertain")
	ErrClosed          = errors.New("control store is closed")
)

func OpenStore(path string) (*Store, error) {
	dataDir := filepath.Dir(path)
	if filepath.Clean(dataDir) == string(filepath.Separator) {
		return nil, errors.New("state data directory must be a dedicated private directory, not the filesystem root")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	dirInfo, err := os.Lstat(dataDir)
	if err != nil || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() || !statePathPrivate(dirInfo) {
		return nil, errors.New("state data directory must be a real directory accessible only by its owner (0700)")
	}
	lockPath := filepath.Join(dataDir, ".mesh.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !statePathPrivate(info) {
			return nil, errors.New("state lock must be a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect state lock: %w", err)
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := lockStateFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("lock state (is another mesh-server running?): %w", err)
	}
	s := &Store{path: path, lock: lock, state: State{Version: 1}, syncDirectory: syncStateDirectory}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !statePathPrivate(info) {
			s.Close()
			return nil, errors.New("state must be a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.Close()
		return nil, fmt.Errorf("inspect state: %w", err)
	}
	b, err := readPersistedState(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.Close()
			return nil, fmt.Errorf("read store: %w", err)
		}
		if err := s.persistLocked(); err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	}
	if err := decodePersistedState(b, &s.state); err != nil {
		s.Close()
		return nil, fmt.Errorf("decode store: %w", err)
	}
	if s.state.Version != 1 && s.state.Version != ControlStateVersionCredentialBinding && s.state.Version != ControlStateVersionTopology && s.state.Version != ControlStateVersionNetworkDNS && s.state.Version != ControlStateVersionNetworkRelays && s.state.Version != ControlStateVersionCARotation && s.state.Version != ControlStateVersionFirewallRollout && s.state.Version != ControlStateVersionFirewallPause && s.state.Version != ControlStateVersionRouteTransfer && s.state.Version != ControlStateVersionRouteProfileEdit && s.state.Version != ControlStateVersionRoutePolicies && s.state.Version != ControlStateVersionNativeDNS && s.state.Version != ControlStateVersionFirewallScopes {
		s.Close()
		return nil, fmt.Errorf("unsupported store version %d", s.state.Version)
	}
	if err := validateStateGraph(s.state); err != nil {
		s.Close()
		return nil, fmt.Errorf("validate store: %w", err)
	}
	return s, nil
}

func readPersistedState(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPersistedStateSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPersistedStateSize {
		return nil, fmt.Errorf("state exceeds the %d-byte safety limit", maxPersistedStateSize)
	}
	return data, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	var durabilityErr error
	if err := s.ensureDurableLocked(); err != nil {
		durabilityErr = err
	}
	_ = unlockStateFile(s.lock)
	err := s.lock.Close()
	s.lock = nil
	return errors.Join(durabilityErr, err)
}

func (s *Store) View(fn func(State) error) error {
	for {
		s.mu.RLock()
		if s.lock == nil {
			s.mu.RUnlock()
			return ErrClosed
		}
		if !s.durabilityPending {
			s.cloneCount.Add(1)
			copy, err := cloneState(s.state)
			s.mu.RUnlock()
			if err != nil {
				return err
			}
			return fn(copy)
		}
		s.mu.RUnlock()
		if err := s.ensureDurable(); err != nil {
			return err
		}
	}
}

// readCurrent is for trusted, read-only service callbacks on hot paths where a
// full state clone would let random credentials amplify authentication into
// O(state size) allocation. The callback must not mutate or retain the state.
func (s *Store) readCurrent(fn func(State) error) error {
	for {
		s.mu.RLock()
		if s.lock == nil {
			s.mu.RUnlock()
			return ErrClosed
		}
		if !s.durabilityPending {
			err := fn(s.state)
			s.mu.RUnlock()
			return err
		}
		s.mu.RUnlock()
		if err := s.ensureDurable(); err != nil {
			return err
		}
	}
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrClosed
	}
	if err := s.ensureDurableLocked(); err != nil {
		return err
	}
	s.cloneCount.Add(1)
	next, err := cloneState(s.state)
	if err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	if err := validateStateGraph(next); err != nil {
		return fmt.Errorf("refuse invalid state mutation: %w", err)
	}
	// Idempotent API retries must not turn into global disk writes. This also
	// preserves the state file's inode and mtime when a transaction observes
	// that the requested value is already committed.
	if reflect.DeepEqual(next, s.state) {
		return nil
	}
	previous := s.state
	s.state = next
	if err := s.persistLocked(); err != nil {
		if !errors.Is(err, ErrUncertainCommit) {
			s.state = previous
		} else {
			s.durabilityPending = true
		}
		return err
	}
	return nil
}

func (s *Store) ensureDurable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrClosed
	}
	return s.ensureDurableLocked()
}

// CheckReadiness proves that the store is still open and that any atomic
// replacement whose parent-directory sync was uncertain has since crossed its
// durability barrier. It performs no state mutation.
func (s *Store) CheckReadiness() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrClosed
	}
	return s.ensureDurableLocked()
}

// ensureDurableLocked retries the parent-directory barrier after an atomic
// rename whose durability was uncertain. No later read or mutation may claim
// success until this barrier succeeds. s.mu must be held.
func (s *Store) ensureDurableLocked() error {
	if !s.durabilityPending {
		return nil
	}
	if s.syncDirectory == nil {
		return fmt.Errorf("%w: state directory sync is unavailable", ErrUncertainCommit)
	}
	if err := s.syncDirectory(filepath.Dir(s.path)); err != nil {
		return fmt.Errorf("%w: retry sync state directory: %v", ErrUncertainCommit, err)
	}
	s.durabilityPending = false
	return nil
}

func cloneState(in State) (State, error) {
	out := in
	out.Networks = append([]Network(nil), in.Networks...)
	for i := range out.Networks {
		out.Networks[i].FirewallPolicy = cloneFirewallPolicy(in.Networks[i].FirewallPolicy)
		out.Networks[i].RelaySettings = cloneNetworkRelaySettings(in.Networks[i].RelaySettings)
		out.Networks[i].RouteTransfer = cloneNetworkRouteTransfer(in.Networks[i].RouteTransfer)
		out.Networks[i].RouteProfileEdit = cloneNetworkRouteProfileEdit(in.Networks[i].RouteProfileEdit)
		out.Networks[i].RoutePolicies = cloneNetworkRoutePolicies(in.Networks[i].RoutePolicies)
	}
	out.Nodes = append([]Node(nil), in.Nodes...)
	for i := range out.Nodes {
		out.Nodes[i].Groups = append([]string(nil), in.Nodes[i].Groups...)
		out.Nodes[i].RoutedSubnets = append([]string(nil), in.Nodes[i].RoutedSubnets...)
	}
	out.Enrollments = append([]EnrollmentToken(nil), in.Enrollments...)
	out.AgentRecoveries = append([]AgentRecoveryToken(nil), in.AgentRecoveries...)
	for i := range out.AgentRecoveries {
		if in.AgentRecoveries[i].Result != nil {
			result := *in.AgentRecoveries[i].Result
			result.Node.Groups = append([]string(nil), in.AgentRecoveries[i].Result.Node.Groups...)
			result.Node.RoutedSubnets = append([]string(nil), in.AgentRecoveries[i].Result.Node.RoutedSubnets...)
			out.AgentRecoveries[i].Result = &result
		}
	}
	out.Issuances = append([]CertificateIssuance(nil), in.Issuances...)
	out.Revocations = append([]CertificateRevocation(nil), in.Revocations...)
	out.Audit = append([]AuditEvent(nil), in.Audit...)
	for i := range out.Audit {
		if in.Audit[i].Details != nil {
			var err error
			out.Audit[i].Details, err = cloneAuditDetails(in.Audit[i].Details)
			if err != nil {
				return State{}, err
			}
		}
	}
	return out, nil
}

func (s *Store) persistLocked() error {
	b, err := encodePersistedState(s.state)
	if err != nil {
		return fmt.Errorf("encode store: %w", err)
	}
	if len(b) > maxPersistedStateSize {
		return fmt.Errorf("state exceeds the %d-byte safety limit", maxPersistedStateSize)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".mesh-state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	if err := s.syncDirectory(filepath.Dir(s.path)); err != nil {
		return fmt.Errorf("%w: sync state directory: %v", ErrUncertainCommit, err)
	}
	return nil
}

type persistedNetwork struct {
	Network
	EncryptedCAKey            string `json:"encrypted_ca_key"`
	EncryptedNextCAKey        string `json:"encrypted_next_ca_key,omitempty"`
	EncryptedConfigSigningKey string `json:"encrypted_config_signing_key"`
}

type persistedNode struct {
	Node
	AgentTokenHash              string     `json:"agent_token_hash,omitempty"`
	PreviousAgentTokenHash      string     `json:"previous_agent_token_hash,omitempty"`
	PreviousAgentTokenExpiresAt *time.Time `json:"previous_agent_token_expires_at,omitempty"`
	PublicKeyHash               string     `json:"public_key_hash,omitempty"`
	RenewalClaimID              string     `json:"renewal_claim_id,omitempty"`
	RenewalClaimedAt            *time.Time `json:"renewal_claimed_at,omitempty"`
}

type persistedState struct {
	Version                 int                     `json:"version"`
	MasterKeyVerifier       string                  `json:"master_key_verifier,omitempty"`
	AdminCredentialVerifier string                  `json:"admin_credential_verifier,omitempty"`
	Networks                []persistedNetwork      `json:"networks"`
	Nodes                   []persistedNode         `json:"nodes"`
	Enrollments             []EnrollmentToken       `json:"enrollments"`
	AgentRecoveries         []AgentRecoveryToken    `json:"agent_recoveries,omitempty"`
	Issuances               []CertificateIssuance   `json:"issuances,omitempty"`
	Revocations             []CertificateRevocation `json:"revocations,omitempty"`
	Audit                   []AuditEvent            `json:"audit"`
}

func encodePersistedState(state State) ([]byte, error) {
	persisted := persistedState{Version: state.Version, MasterKeyVerifier: state.MasterKeyVerifier, AdminCredentialVerifier: state.AdminCredentialVerifier, Enrollments: state.Enrollments, AgentRecoveries: state.AgentRecoveries, Issuances: state.Issuances, Revocations: state.Revocations, Audit: state.Audit}
	for _, network := range state.Networks {
		persisted.Networks = append(persisted.Networks, persistedNetwork{Network: network, EncryptedCAKey: network.EncryptedCAKey, EncryptedNextCAKey: network.CARotation.EncryptedNextCAKey, EncryptedConfigSigningKey: network.EncryptedConfigSigningKey})
	}
	for _, node := range state.Nodes {
		persisted.Nodes = append(persisted.Nodes, persistedNode{Node: node, AgentTokenHash: node.AgentTokenHash, PreviousAgentTokenHash: node.PreviousAgentTokenHash, PreviousAgentTokenExpiresAt: node.PreviousAgentTokenExpiresAt, PublicKeyHash: node.PublicKeyHash, RenewalClaimID: node.RenewalClaimID, RenewalClaimedAt: node.RenewalClaimedAt})
	}
	return json.MarshalIndent(persisted, "", "  ")
}

func decodePersistedState(data []byte, state *State) error {
	if !utf8.Valid(data) {
		return errors.New("state is not valid UTF-8")
	}
	if err := rejectDuplicateRecoveryJSONNames(data); err != nil {
		return err
	}
	var persisted persistedState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("state contains trailing JSON data")
	}
	state.Version, state.MasterKeyVerifier, state.AdminCredentialVerifier, state.Enrollments, state.AgentRecoveries, state.Issuances, state.Revocations, state.Audit = persisted.Version, persisted.MasterKeyVerifier, persisted.AdminCredentialVerifier, persisted.Enrollments, persisted.AgentRecoveries, persisted.Issuances, persisted.Revocations, persisted.Audit
	for _, network := range persisted.Networks {
		value := network.Network
		value.EncryptedCAKey = network.EncryptedCAKey
		value.CARotation.EncryptedNextCAKey = network.EncryptedNextCAKey
		value.EncryptedConfigSigningKey = network.EncryptedConfigSigningKey
		if value.ConfigRevision == 0 {
			value.ConfigRevision = 1
		}
		if value.ConfigUpdatedAt.IsZero() {
			value.ConfigUpdatedAt = value.CreatedAt
		}
		if value.FirewallPolicy.Mode == "" {
			value.FirewallPolicy = legacyDefaultFirewallPolicy()
		} else if value.FirewallPolicy.RendererVersion == 0 {
			// Policies persisted before renderer versioning used the exact v1
			// unquoted-group bytes. Preserve that identity until the service can
			// migrate a managed policy and, if the bytes change, advance its
			// signed config revision in the same durable transaction.
			value.FirewallPolicy.RendererVersion = FirewallRendererVersionV1
		}
		state.Networks = append(state.Networks, value)
	}
	for _, node := range persisted.Nodes {
		value := node.Node
		value.AgentTokenHash, value.PublicKeyHash = node.AgentTokenHash, node.PublicKeyHash
		value.PreviousAgentTokenHash, value.PreviousAgentTokenExpiresAt = node.PreviousAgentTokenHash, node.PreviousAgentTokenExpiresAt
		value.RenewalClaimID, value.RenewalClaimedAt = node.RenewalClaimID, node.RenewalClaimedAt
		state.Nodes = append(state.Nodes, value)
	}
	return nil
}

// validateStateGraph rejects structurally corrupt or internally inconsistent
// state before it can be persisted or used for CA operations. Cryptographic
// key-pair validation remains in Service.EnsureManagedNetworks because it
// requires the separately supplied master key.
func validateStateGraph(state State) error {
	if state.Version != 1 && state.Version != ControlStateVersionCredentialBinding && state.Version != ControlStateVersionTopology && state.Version != ControlStateVersionNetworkDNS && state.Version != ControlStateVersionNetworkRelays && state.Version != ControlStateVersionCARotation && state.Version != ControlStateVersionFirewallRollout && state.Version != ControlStateVersionFirewallPause && state.Version != ControlStateVersionRouteTransfer && state.Version != ControlStateVersionRouteProfileEdit && state.Version != ControlStateVersionRoutePolicies && state.Version != ControlStateVersionNativeDNS && state.Version != ControlStateVersionFirewallScopes {
		return fmt.Errorf("unsupported store version %d", state.Version)
	}
	// Version 1 is the pre-binding compatibility schema. A successful server
	// startup atomically adds the versioned verifier and advances to version 2,
	// making the one-way decoder/recovery boundary explicit to older binaries.
	if state.Version == 1 && (state.MasterKeyVerifier != "" || state.AdminCredentialVerifier != "") {
		return errors.New("version 1 state must not contain recovery credential verifiers")
	}
	if state.Version >= ControlStateVersionCredentialBinding && (!ValidMasterKeyVerifier(state.MasterKeyVerifier) || !ValidAdminCredentialVerifier(state.AdminCredentialVerifier)) {
		return fmt.Errorf("version %d state requires valid master-key and administrator credential verifiers", state.Version)
	}
	networks := make(map[string]Network, len(state.Networks))
	networkNames := make(map[string]struct{}, len(state.Networks))
	for index, network := range state.Networks {
		if !validPersistedID(network.ID) || !namePattern.MatchString(network.Name) {
			return fmt.Errorf("network %d has an invalid identity", index)
		}
		if _, exists := networks[network.ID]; exists {
			return fmt.Errorf("duplicate network ID %q", network.ID)
		}
		foldedName := strings.ToLower(network.Name)
		if _, exists := networkNames[foldedName]; exists {
			return fmt.Errorf("duplicate network name %q", network.Name)
		}
		ip, cidr, err := net.ParseCIDR(network.CIDR)
		ones, bits := 0, 0
		if err == nil {
			ones, bits = cidr.Mask.Size()
		}
		if err != nil || ip.To4() == nil || cidr.String() != network.CIDR || bits != 32 || ones < 16 || ones > 28 {
			return fmt.Errorf("network %q has an invalid canonical IPv4 CIDR", network.ID)
		}
		if network.ListenPort < 1 || network.ListenPort > 65535 || network.CertificateTTL < 24 || network.CertificateTTL > 8760 || network.ConfigRevision < 1 || network.CreatedAt.IsZero() || network.ConfigUpdatedAt.IsZero() {
			return fmt.Errorf("network %q has invalid lifecycle metadata", network.ID)
		}
		if strings.TrimSpace(network.CACertificate) == "" || strings.TrimSpace(network.EncryptedCAKey) == "" {
			return fmt.Errorf("network %q is missing CA material", network.ID)
		}
		if err := validatePersistedNetworkMaterial(network); err != nil {
			return fmt.Errorf("network %q has invalid key material: %w", network.ID, err)
		}
		if err := validateStoredFirewallPolicy(network.FirewallPolicy, network.CIDR); err != nil {
			return fmt.Errorf("network %q has invalid firewall policy: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionFirewallScopes && firewallPolicyUsesNodeScopes(network.FirewallPolicy) {
			return fmt.Errorf("network %q has scoped firewall fields before control state v13", network.ID)
		}
		if state.Version < ControlStateVersionNetworkDNS {
			if network.DNSSettings != (NetworkDNSSettings{}) {
				return fmt.Errorf("network %q has DNS settings before control state v4", network.ID)
			}
		} else if err := validateNetworkDNSInvariant(network); err != nil {
			return fmt.Errorf("network %q has invalid DNS settings: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionNetworkRelays {
			if network.RelaySettings.Enabled || network.RelaySettings.RelayNodeIDs != nil {
				return fmt.Errorf("network %q has relay settings before control state v5", network.ID)
			}
		} else if err := validateNetworkRelaySettings(state, network); err != nil {
			return fmt.Errorf("network %q has invalid relay settings: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionCARotation {
			if network.CARotation != (NetworkCARotation{}) {
				return fmt.Errorf("network %q has CA rotation state before control state v6", network.ID)
			}
		} else if err := validateNetworkCARotation(network); err != nil {
			return fmt.Errorf("network %q has invalid CA rotation: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionFirewallRollout {
			if !zeroNetworkFirewallRollout(network.FirewallRollout) {
				return fmt.Errorf("network %q has firewall rollout state before control state v7", network.ID)
			}
		} else if err := validateNetworkFirewallRollout(state, network); err != nil {
			return fmt.Errorf("network %q has invalid firewall rollout: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionFirewallScopes && network.FirewallRollout.Phase != "" && firewallPolicyUsesNodeScopes(network.FirewallRollout.TargetPolicy) {
			return fmt.Errorf("network %q has scoped firewall rollout fields before control state v13", network.ID)
		}
		if state.Version < ControlStateVersionRouteTransfer {
			if !zeroNetworkRouteTransfer(network.RouteTransfer) {
				return fmt.Errorf("network %q has route-transfer state before control state v9", network.ID)
			}
		} else if err := validateNetworkRouteTransfer(state, network); err != nil {
			return fmt.Errorf("network %q has invalid route transfer: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionRouteProfileEdit {
			if !zeroNetworkRouteProfileEdit(network.RouteProfileEdit) {
				return fmt.Errorf("network %q has route-profile edit state before control state v10", network.ID)
			}
		} else if err := validateNetworkRouteProfileEdit(state, network); err != nil {
			return fmt.Errorf("network %q has invalid route-profile edit: %w", network.ID, err)
		}
		if state.Version < ControlStateVersionRoutePolicies {
			if network.RoutePolicies != nil {
				return fmt.Errorf("network %q has route policies before control state v11", network.ID)
			}
		} else if err := validateNetworkRoutePolicies(state, network); err != nil {
			return fmt.Errorf("network %q has invalid route policies: %w", network.ID, err)
		}
		for _, existing := range networks {
			if cidrsOverlap(existing.CIDR, network.CIDR) {
				return fmt.Errorf("network %q overlaps network %q", network.ID, existing.ID)
			}
		}
		networks[network.ID] = network
		networkNames[foldedName] = struct{}{}
	}

	nodes := make(map[string]Node, len(state.Nodes))
	nodeAddresses := make(map[string]string, len(state.Nodes))
	credentialHashes := make(map[string]string, len(state.Nodes)*2+len(state.Enrollments)+len(state.AgentRecoveries))
	for index, node := range state.Nodes {
		network, networkExists := networks[node.NetworkID]
		if !validPersistedID(node.ID) || !networkExists || !namePattern.MatchString(node.Name) {
			return fmt.Errorf("node %d has an invalid identity or network reference", index)
		}
		if _, exists := nodes[node.ID]; exists {
			return fmt.Errorf("duplicate node ID %q", node.ID)
		}
		if node.Role != "member" && node.Role != "lighthouse" {
			return fmt.Errorf("node %q has invalid role %q", node.ID, node.Role)
		}
		if !validCanonicalNodeGroups(node.Groups) {
			return fmt.Errorf("node %q has non-canonical certificate groups", node.ID)
		}
		if err := validateCanonicalRoutedSubnets(node.RoutedSubnets); err != nil {
			return fmt.Errorf("node %q has invalid routed subnets: %w", node.ID, err)
		}
		if state.Version >= ControlStateVersionTopology {
			if !validTopologyLabel(node.Site) || !validTopologyLabel(node.FailureDomain) {
				return fmt.Errorf("node %q has non-canonical topology metadata", node.ID)
			}
		} else if node.Site != "" || node.FailureDomain != "" {
			return fmt.Errorf("node %q has topology metadata before control state v3", node.ID)
		}
		if node.PublicEndpoint != "" {
			if err := validateEndpoint(node.PublicEndpoint); err != nil {
				return fmt.Errorf("node %q has an invalid public endpoint: %w", node.ID, err)
			}
		}
		if !validBoundedUTF8(node.Certificate, maxNebulaHostCertificateSize, true) {
			return fmt.Errorf("node %q has an oversized or invalid UTF-8 certificate", node.ID)
		}
		if node.Status != "pending" && node.Status != "active" && node.Status != "revoked" {
			return fmt.Errorf("node %q has invalid status %q", node.ID, node.Status)
		}
		if node.CertificateGeneration < 0 || node.AppliedCertificateGeneration < 0 || node.AppliedCertificateGeneration > node.CertificateGeneration || node.AgentCredentialGeneration < 0 {
			return fmt.Errorf("node %q has invalid certificate generation state", node.ID)
		}
		if state.Version < ControlStateVersionCARotation {
			if node.CertificateAuthoritySHA256 != "" {
				return fmt.Errorf("node %q has certificate authority metadata before control state v6", node.ID)
			}
		} else if node.Certificate == "" {
			if node.CertificateAuthoritySHA256 != "" {
				return fmt.Errorf("node %q has a certificate authority without a certificate", node.ID)
			}
		} else if !fingerprintPattern.MatchString(node.CertificateAuthoritySHA256) {
			return fmt.Errorf("node %q has an invalid certificate authority digest", node.ID)
		}
		hasRenewalClaimID := node.RenewalClaimID != ""
		hasRenewalClaimedAt := node.RenewalClaimedAt != nil
		if hasRenewalClaimID != hasRenewalClaimedAt || hasRenewalClaimID && (!validPersistedID(node.RenewalClaimID) || node.RenewalClaimedAt.IsZero()) {
			return fmt.Errorf("node %q has invalid renewal claim metadata", node.ID)
		}
		if state.Version < ControlStateVersionNativeDNS && node.NativeDNSActive {
			return fmt.Errorf("node %q has native DNS telemetry before control state v12", node.ID)
		}
		if err := validatePersistedNodeTelemetry(node, network); err != nil {
			return fmt.Errorf("node %q has invalid lifecycle telemetry: %w", node.ID, err)
		}
		if (node.PreviousAgentTokenHash == "") != (node.PreviousAgentTokenExpiresAt == nil) {
			return fmt.Errorf("node %q has incomplete previous agent credential state", node.ID)
		}
		switch node.Status {
		case "pending":
			if node.EnrolledAt != nil || node.RevokedAt != nil || node.AgentTokenHash != "" || node.AgentCredentialExpiresAt != nil || node.AgentCredentialGeneration != 0 || node.PublicKeyHash != "" {
				return fmt.Errorf("pending node %q has invalid enrolled credential state", node.ID)
			}
		case "active":
			if node.EnrolledAt == nil || node.RevokedAt != nil || !ValidTokenHash(node.AgentTokenHash) || node.AgentCredentialExpiresAt == nil || node.AgentCredentialGeneration < 1 || !ValidTokenHash(node.PublicKeyHash) {
				return fmt.Errorf("active node %q has incomplete enrolled credential state", node.ID)
			}
		case "revoked":
			if node.RevokedAt == nil || node.AgentTokenHash != "" || node.PreviousAgentTokenHash != "" || node.AgentCredentialExpiresAt != nil {
				return fmt.Errorf("revoked node %q retains live credential state", node.ID)
			}
		}
		address := net.ParseIP(node.IP)
		_, networkCIDR, _ := net.ParseCIDR(network.CIDR)
		if address == nil || address.To4() == nil || !networkCIDR.Contains(address) {
			return fmt.Errorf("node %q has an address outside its network", node.ID)
		}
		addressKey := node.NetworkID + "\x00" + address.String()
		if existingID, exists := nodeAddresses[addressKey]; exists {
			return fmt.Errorf("nodes %q and %q have the same address", existingID, node.ID)
		}
		if node.CreatedAt.IsZero() {
			return fmt.Errorf("node %q is missing its creation time", node.ID)
		}
		for slot, hash := range map[string]string{"current": node.AgentTokenHash, "previous": node.PreviousAgentTokenHash} {
			if hash == "" {
				continue
			}
			if !ValidTokenHash(hash) {
				return fmt.Errorf("node %q has an invalid %s agent credential hash", node.ID, slot)
			}
			if owner, exists := credentialHashes[hash]; exists {
				return fmt.Errorf("node %q has an agent credential hash already used by %s", node.ID, owner)
			}
			credentialHashes[hash] = "node " + node.ID + " " + slot
		}
		nodes[node.ID] = node
		nodeAddresses[addressKey] = node.ID
	}
	for _, network := range state.Networks {
		if err := validateFirewallPolicyReferences(state, network, network.FirewallPolicy); err != nil {
			return fmt.Errorf("network %q has invalid firewall references: %w", network.ID, err)
		}
		if network.FirewallRollout.Phase != "" {
			if err := validateFirewallPolicyReferences(state, network, network.FirewallRollout.TargetPolicy); err != nil {
				return fmt.Errorf("network %q has invalid firewall rollout references: %w", network.ID, err)
			}
		}
	}

	enrollments := make(map[string]struct{}, len(state.Enrollments))
	for _, enrollment := range state.Enrollments {
		if !validPersistedID(enrollment.ID) || !ValidTokenHash(enrollment.TokenHash) || enrollment.CreatedAt.IsZero() || !enrollment.ExpiresAt.After(enrollment.CreatedAt) {
			return fmt.Errorf("enrollment %q has invalid metadata", enrollment.ID)
		}
		if err := validatePersistedEnrollmentClaim(enrollment); err != nil {
			return fmt.Errorf("enrollment %q has invalid claim metadata: %w", enrollment.ID, err)
		}
		if _, exists := nodes[enrollment.NodeID]; !exists {
			return fmt.Errorf("enrollment %q references a missing node", enrollment.ID)
		}
		if _, exists := enrollments[enrollment.ID]; exists {
			return fmt.Errorf("duplicate enrollment ID %q", enrollment.ID)
		}
		if owner, exists := credentialHashes[enrollment.TokenHash]; exists {
			return fmt.Errorf("enrollment %q has a token hash already used by %s", enrollment.ID, owner)
		}
		credentialHashes[enrollment.TokenHash] = "enrollment " + enrollment.ID
		enrollments[enrollment.ID] = struct{}{}
	}

	recoveries := make(map[string]struct{}, len(state.AgentRecoveries))
	recoveryHashes := make(map[string]struct{}, len(state.AgentRecoveries))
	recoveredCredentialHashes := make(map[string]string, len(state.AgentRecoveries))
	for _, recovery := range state.AgentRecoveries {
		node, nodeExists := nodes[recovery.NodeID]
		if !validPersistedID(recovery.ID) || !ValidTokenHash(recovery.TokenHash) || recovery.CreatedAt.IsZero() || !recovery.ExpiresAt.After(recovery.CreatedAt) || recovery.ExpiresAt.Sub(recovery.CreatedAt) > 30*time.Minute {
			return fmt.Errorf("agent recovery %q has invalid metadata", recovery.ID)
		}
		if !nodeExists || node.Status != "active" || node.EnrolledAt == nil || node.RevokedAt != nil {
			return fmt.Errorf("agent recovery %q references a node outside the active enrolled lifecycle", recovery.ID)
		}
		if _, exists := recoveries[recovery.ID]; exists {
			return fmt.Errorf("duplicate agent recovery ID %q", recovery.ID)
		}
		if _, exists := enrollments[recovery.ID]; exists {
			return fmt.Errorf("agent recovery ID %q is already used by an enrollment", recovery.ID)
		}
		if _, exists := recoveryHashes[recovery.TokenHash]; exists {
			return fmt.Errorf("duplicate agent recovery token hash for %q", recovery.ID)
		}
		if owner, exists := credentialHashes[recovery.TokenHash]; exists {
			return fmt.Errorf("agent recovery %q has a token hash already used by %s", recovery.ID, owner)
		}
		recoveries[recovery.ID] = struct{}{}
		recoveryHashes[recovery.TokenHash] = struct{}{}
		credentialHashes[recovery.TokenHash] = "agent recovery " + recovery.ID

		hasClaimID := recovery.ClaimID != ""
		hasClaimedAt := recovery.ClaimedAt != nil
		hasClaimKey := recovery.ClaimKeyHash != ""
		if hasClaimID != hasClaimedAt || hasClaimID != hasClaimKey || (hasClaimID && (!validPersistedID(recovery.ClaimID) || !ValidTokenHash(recovery.ClaimKeyHash) || recovery.ClaimedCredentialGeneration < 1)) || (!hasClaimID && recovery.ClaimedCredentialGeneration != 0) {
			return fmt.Errorf("agent recovery %q has invalid claim metadata", recovery.ID)
		}
		if recovery.ClaimedAt != nil && (recovery.ClaimedAt.Before(recovery.CreatedAt) || recovery.ClaimedAt.After(recovery.ExpiresAt)) {
			return fmt.Errorf("agent recovery %q has a claim outside its lifetime", recovery.ID)
		}
		if recovery.UsedAt == nil {
			if recovery.CredentialGeneration != 0 || recovery.CredentialExpiresAt != nil || recovery.Result != nil {
				return fmt.Errorf("unused agent recovery %q has committed result metadata", recovery.ID)
			}
			continue
		}
		if recovery.ClaimedAt == nil || recovery.UsedAt.Before(*recovery.ClaimedAt) || recovery.UsedAt.After(recovery.ExpiresAt) || recovery.CredentialGeneration != recovery.ClaimedCredentialGeneration+1 || recovery.CredentialGeneration > node.AgentCredentialGeneration || recovery.CredentialExpiresAt == nil || !recovery.CredentialExpiresAt.After(*recovery.UsedAt) || recovery.CredentialExpiresAt.After(recovery.UsedAt.Add(90*24*time.Hour)) || recovery.Result == nil {
			return fmt.Errorf("used agent recovery %q has invalid result metadata", recovery.ID)
		}
		result := recovery.Result
		if result.NodeID != recovery.NodeID || result.NetworkID != node.NetworkID || result.Node.ID != recovery.NodeID || result.Node.Site != node.Site || result.Node.FailureDomain != node.FailureDomain || !slices.Equal(result.Node.RoutedSubnets, node.RoutedSubnets) || state.Version >= ControlStateVersionCARotation && result.Node.CertificateAuthoritySHA256 != node.CertificateAuthoritySHA256 || !TokenHashEqual(result.PublicKeyHash, node.PublicKeyHash) || result.AgentCredentialGeneration != recovery.CredentialGeneration || !result.AgentCredentialExpiresAt.Equal(*recovery.CredentialExpiresAt) || result.ConfigSigningPublicKey != networks[node.NetworkID].ConfigSigningPublicKey {
			return fmt.Errorf("used agent recovery %q has a mismatched bootstrap result", recovery.ID)
		}
		if err := validatePersistedRecoveryResultMaterial(result, networks[node.NetworkID]); err != nil {
			return fmt.Errorf("used agent recovery %q has invalid bounded bootstrap material: %w", recovery.ID, err)
		}
		if err := VerifyConfig(result.ConfigSigningPublicKey, result.SignatureMetadata(), result.Config, result.ConfigSHA256, result.ConfigSignature); err != nil {
			return fmt.Errorf("used agent recovery %q has an invalid signed bootstrap: %w", recovery.ID, err)
		}
		receipt := result.RecoveryReceipt
		if receipt.NodeID != result.NodeID || receipt.NetworkID != result.NetworkID || receipt.AgentCredentialGeneration != result.AgentCredentialGeneration || !receipt.AgentCredentialExpiresAt.Equal(result.AgentCredentialExpiresAt) || receipt.ConfigSHA256 != result.ConfigSHA256 || receipt.ConfigSignature != result.ConfigSignature {
			return fmt.Errorf("used agent recovery %q has a mismatched receipt", recovery.ID)
		}
		if err := VerifyRecoveryReceipt(result.ConfigSigningPublicKey, receipt); err != nil {
			return fmt.Errorf("used agent recovery %q has an invalid receipt: %w", recovery.ID, err)
		}
		if owner, exists := recoveredCredentialHashes[receipt.NewAgentTokenHash]; exists {
			return fmt.Errorf("used agent recovery %q reuses the recovered credential hash from %s", recovery.ID, owner)
		}
		if _, exists := credentialHashes[receipt.NewAgentTokenHash]; exists && !TokenHashEqual(node.AgentTokenHash, receipt.NewAgentTokenHash) && !TokenHashEqual(node.PreviousAgentTokenHash, receipt.NewAgentTokenHash) {
			return fmt.Errorf("used agent recovery %q has a recovered credential hash used by another credential domain", recovery.ID)
		}
		recoveredCredentialHashes[receipt.NewAgentTokenHash] = "agent recovery " + recovery.ID
		if recovery.CredentialGeneration == node.AgentCredentialGeneration && (node.AgentCredentialExpiresAt == nil || !node.AgentCredentialExpiresAt.Equal(*recovery.CredentialExpiresAt) || !TokenHashEqual(node.AgentTokenHash, receipt.NewAgentTokenHash)) {
			return fmt.Errorf("used agent recovery %q does not match the current node credential", recovery.ID)
		}
	}

	for _, issuance := range state.Issuances {
		node, exists := nodes[issuance.NodeID]
		if !exists || node.NetworkID != issuance.NetworkID || !fingerprintPattern.MatchString(issuance.Fingerprint) || issuance.IssuedAt.IsZero() || !issuance.ExpiresAt.After(issuance.IssuedAt) {
			return fmt.Errorf("certificate issuance for node %q is invalid", issuance.NodeID)
		}
	}
	for _, revocation := range state.Revocations {
		node, exists := nodes[revocation.NodeID]
		if !exists || node.NetworkID != revocation.NetworkID || !fingerprintPattern.MatchString(revocation.Fingerprint) || revocation.At.IsZero() {
			return fmt.Errorf("certificate revocation for node %q is invalid", revocation.NodeID)
		}
		if revocation.ExpiresAt != nil && revocation.ExpiresAt.IsZero() {
			return fmt.Errorf("certificate revocation for node %q has an empty expiry", revocation.NodeID)
		}
		// Empty reasons remain readable for records written before reasons were
		// required operationally; every non-empty value is still strictly bounded.
		if !validBoundedPlainText(revocation.Reason, maxRevocationReasonBytes, true) {
			return fmt.Errorf("certificate revocation for node %q has an unsafe reason", revocation.NodeID)
		}
	}
	if err := validateReservedIPv4PrefixGraph(state); err != nil {
		return fmt.Errorf("managed and routed address graph is invalid: %w", err)
	}
	auditIDs := make(map[string]struct{}, len(state.Audit))
	for _, event := range state.Audit {
		if !validPersistedID(event.ID) || event.At.IsZero() || !validAuditLabel(event.Action, maxAuditActionBytes) || !validAuditLabel(event.Resource, maxAuditResourceBytes) || !validPersistedID(event.ResourceID) {
			return fmt.Errorf("audit event %q has invalid metadata", event.ID)
		}
		if err := validateAuditDetails(event.Details); err != nil {
			return fmt.Errorf("audit event %q has invalid details: %w", event.ID, err)
		}
		if err := validateAuditActorMetadata(event.Details); err != nil {
			return fmt.Errorf("audit event %q has invalid actor metadata: %w", event.ID, err)
		}
		if _, exists := auditIDs[event.ID]; exists {
			return fmt.Errorf("duplicate audit event ID %q", event.ID)
		}
		auditIDs[event.ID] = struct{}{}
	}
	if err := validateRetiredNetworkReservations(state); err != nil {
		return fmt.Errorf("retired network reservation graph is invalid: %w", err)
	}
	if err := validateArchivedNodeTombstones(state); err != nil {
		return fmt.Errorf("archived node tombstone graph is invalid: %w", err)
	}
	if err := validateNodeCertificateRotationAudits(state); err != nil {
		return fmt.Errorf("node certificate rotation audit graph is invalid: %w", err)
	}
	if err := validateNodeGroupAudits(state); err != nil {
		return fmt.Errorf("node group audit graph is invalid: %w", err)
	}
	if err := validateNodeRevocationAudits(state); err != nil {
		return fmt.Errorf("node revocation audit graph is invalid: %w", err)
	}
	return nil
}

func validatePersistedNodeTelemetry(node Node, network Network) error {
	if !validTelemetry(node.AgentVersion, maxPersistedAgentVersionBytes) {
		return errors.New("agent version is oversized or contains unsafe text")
	}
	if !validTelemetry(node.NebulaVersion, maxPersistedNebulaVersionBytes) {
		return errors.New("Nebula version is oversized or contains unsafe text")
	}
	if !validTelemetry(node.LastError, maxPersistedLastErrorBytes) {
		return errors.New("last error is oversized or contains unsafe text")
	}
	if node.AppliedConfigRevision < 0 || node.AppliedConfigRevision > network.ConfigRevision {
		return errors.New("applied config revision is outside the authoritative network range")
	}
	if node.HeartbeatSequence < 0 || node.HeartbeatSequence > maxPersistedHeartbeatSequence {
		return errors.New("heartbeat sequence is outside its safety bound")
	}
	if node.AppliedConfigSHA256 != "" && !fingerprintPattern.MatchString(node.AppliedConfigSHA256) {
		return errors.New("applied config digest is not a canonical SHA-256 value")
	}
	if node.AppliedConfigRevision == 0 && node.AppliedConfigSHA256 != "" {
		return errors.New("applied config digest is set without an applied revision")
	}
	if node.AppliedConfigRevision > 0 && node.AppliedConfigSHA256 == "" {
		return errors.New("applied config revision is missing its SHA-256 digest")
	}
	if node.ReportedCertificateFingerprint != "" && !fingerprintPattern.MatchString(node.ReportedCertificateFingerprint) {
		return errors.New("reported certificate fingerprint is not a canonical SHA-256 value")
	}
	if node.AgentBootID != "" && !namePattern.MatchString(node.AgentBootID) {
		return errors.New("agent boot ID is invalid")
	}

	hasHeartbeat := node.LastSeenAt != nil
	if !hasHeartbeat {
		if node.HeartbeatSequence != 0 || node.AppliedConfigRevision != 0 || node.AppliedCertificateGeneration != 0 || node.AppliedConfigSHA256 != "" || node.ReportedCertificateFingerprint != "" || node.NebulaRunning || node.AgentVersion != "" || node.NebulaVersion != "" || node.AgentBootID != "" || node.LastError != "" {
			return errors.New("heartbeat evidence is present without a last-seen time")
		}
		switch node.Status {
		case "pending", "active":
			if node.AgentStatus != "" {
				return errors.New("node outside heartbeat lifecycle has an agent status")
			}
		case "revoked":
			// Empty is retained for recovery compatibility with revoked records
			// written before the explicit terminal telemetry status existed.
			if node.AgentStatus != "" && node.AgentStatus != "revoked" {
				return errors.New("revoked node has a non-terminal agent status")
			}
		}
		return nil
	}

	if node.LastSeenAt.IsZero() || node.EnrolledAt == nil || node.LastSeenAt.Before(*node.EnrolledAt) {
		return errors.New("last-seen time is outside the enrolled lifecycle")
	}
	if node.HeartbeatSequence < 1 {
		return errors.New("last-seen time is missing a positive heartbeat sequence")
	}
	if node.AgentBootID == "" {
		return errors.New("last-seen time is missing its agent boot ID")
	}
	switch node.Status {
	case "active":
		if node.AgentStatus != "healthy" && node.AgentStatus != "degraded" {
			return errors.New("active heartbeat has an unsupported agent status")
		}
	case "pending":
		return errors.New("pending node contains heartbeat evidence")
	case "revoked":
		// Current revocation writes "revoked". Empty remains readable for an
		// older revoked record whose heartbeat fields predate that status.
		if node.AgentStatus != "" && node.AgentStatus != "revoked" {
			return errors.New("revoked heartbeat has a non-terminal agent status")
		}
	}
	return nil
}

func validPersistedID(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}
