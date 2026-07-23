//go:build postgresmaxdocgate

package control

// This file is compiled only for the explicit PostgreSQL maximum-document
// gate. It deliberately lives in package control so the fixture cannot skip
// the same private canonicalization and graph validation used by production.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
)

const (
	MaximumDocumentControlBytes       = maxPersistedStateSize
	DefaultControlCanonicalMinimum    = 62 << 20
	DefaultControlCanonicalMaximum    = 63 << 20
	maximumDocumentFixtureNetworkName = "maximum-document"
	maximumDocumentFixtureNetworkCIDR = "10.240.0.0/16"
	maximumDocumentFixtureBlockSize   = 256
	maximumDocumentFixtureMaxNodes    = 65_525
	// Credential binding, ten ordered control-schema migrations, network
	// creation, and firewall publication precede the per-node audit records.
	maximumDocumentFixtureBaselineAuditCount = 13
)

// MaximumDocumentFixtureOptions controls the structured portion of the exact
// boundary fixture. Smaller bands are useful for static tests; the gate uses
// the 62-63 MiB defaults.
type MaximumDocumentFixtureOptions struct {
	Directory             string
	MasterKey             []byte
	AdminToken            []byte
	At                    time.Time
	CanonicalMinimumBytes int
	CanonicalMaximumBytes int
	// ExactBytes defaults to the production 64 MiB ceiling. Tests may inject a
	// smaller boundary without allocating the live gate's document.
	ExactBytes int
}

// MaximumDocumentFixture contains canonical production-shaped state plus an
// exact-limit JSON document made only by appending legal trailing whitespace.
type MaximumDocumentFixture struct {
	CanonicalBytes         []byte
	ExactBytes             []byte
	NetworkID              string
	NetworkCount           int
	NetworkCIDR            string
	NodeCount              int
	EnrollmentCount        int
	AuditCount             int
	GroupCount             int
	InboundRuleCount       int
	OutboundRuleCount      int
	FirewallConfigRevision int64
}

// CanonicalizeMaximumDocumentRecoverySnapshot returns the exact production
// persistence encoding of a fully validated recovery snapshot. It exists only
// under the maximum-document build tag so the live gate can distinguish a
// canonical post-mutation rewrite from merely valid JSON without duplicating
// private persistence structs outside package control.
func CanonicalizeMaximumDocumentRecoverySnapshot(raw []byte, box *SecretBox) ([]byte, error) {
	state, err := validateRecoverySnapshot(raw, box)
	if err != nil {
		return nil, err
	}
	return encodePersistedState(state)
}

// BuildMaximumDocumentFixture constructs one real current-version control state,
// including a valid Nebula CA/key pair and config-signing key pair. Node,
// enrollment, and node.created audit records are generated in bounded blocks,
// then committed through Store.Update so validateStateGraph and the canonical
// persistence encoder remain authoritative.
func BuildMaximumDocumentFixture(ctx context.Context, options MaximumDocumentFixtureOptions) (MaximumDocumentFixture, error) {
	if ctx == nil {
		return MaximumDocumentFixture{}, errors.New("maximum-document control fixture requires a context")
	}
	if err := ctx.Err(); err != nil {
		return MaximumDocumentFixture{}, err
	}
	fixtureTime := options.At
	if fixtureTime.IsZero() {
		fixtureTime = time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	} else {
		fixtureTime = fixtureTime.UTC().Truncate(time.Second)
	}
	if !filepath.IsAbs(options.Directory) || filepath.Clean(options.Directory) != options.Directory {
		return MaximumDocumentFixture{}, errors.New("maximum-document control fixture directory must be clean and absolute")
	}
	minimum, maximum := options.CanonicalMinimumBytes, options.CanonicalMaximumBytes
	if minimum == 0 {
		minimum = DefaultControlCanonicalMinimum
	}
	if maximum == 0 {
		maximum = DefaultControlCanonicalMaximum
	}
	if minimum < 1 || maximum < minimum || maximum >= MaximumDocumentControlBytes {
		return MaximumDocumentFixture{}, errors.New("maximum-document control canonical byte band is invalid")
	}
	exactBytes := options.ExactBytes
	if exactBytes == 0 {
		exactBytes = MaximumDocumentControlBytes
	}
	if exactBytes <= maximum || exactBytes > MaximumDocumentControlBytes {
		return MaximumDocumentFixture{}, errors.New("maximum-document control exact byte target is invalid")
	}
	box, err := NewSecretBox(options.MasterKey)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	masterVerifier, err := DeriveMasterKeyVerifier(options.MasterKey)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(options.MasterKey, options.AdminToken)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}

	statePath := filepath.Join(options.Directory, "control-canonical.json")
	store, err := OpenStore(statePath)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	defer store.Close()
	service := NewService(store, box, maximumDocumentFixtureIssuer{at: fixtureTime})
	service.now = func() time.Time { return fixtureTime }
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("bind fixture recovery credentials: %w", err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture topology schema: %w", err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture network DNS schema: %w", err)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture network relay schema: %w", err)
	}
	if err := service.EnsureCARotationSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture CA rotation schema: %w", err)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture firewall rollout schema: %w", err)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture firewall pause schema: %w", err)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture route transfer schema: %w", err)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture route profile schema: %w", err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture route policy schema: %w", err)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture native DNS schema: %w", err)
	}
	if err := service.EnsureFirewallScopeSchema(); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("migrate fixture firewall scope schema: %w", err)
	}
	network, err := service.CreateNetwork(ctx, CreateNetworkInput{
		Name: maximumDocumentFixtureNetworkName, CIDR: maximumDocumentFixtureNetworkCIDR,
		CertificateTTL: 8760,
	})
	if err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("create fixture network: %w", err)
	}
	maxFirewall := maximumDocumentFirewallInput()
	updatedFirewall, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: network.ConfigRevision,
		Inbound:                maxFirewall.Inbound, Outbound: maxFirewall.Outbound,
	})
	if err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("install fixture firewall: %w", err)
	}

	var state State
	if err := store.View(func(current State) error {
		state = current
		return nil
	}); err != nil {
		return MaximumDocumentFixture{}, err
	}
	groups, err := normalizeGroups(maximumDocumentInputGroups())
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	groups = appendUnique(groups, "all")
	sort.Strings(groups)
	if !validCanonicalNodeGroups(groups) {
		return MaximumDocumentFixture{}, errors.New("maximum-document fixture groups are not canonical")
	}

	baseRaw, err := encodePersistedState(state)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	if len(baseRaw) >= minimum {
		return MaximumDocumentFixture{}, errors.New("maximum-document control baseline unexpectedly reaches the target band")
	}
	// One sample block gives a stable contribution estimate without repeatedly
	// serializing a growing 60+ MiB graph. Fixed-width identifiers keep all
	// record contributions stable except for the bounded IPv4 text length.
	if err := appendMaximumDocumentRecords(&state, groups, fixtureTime, 1, maximumDocumentFixtureBlockSize); err != nil {
		return MaximumDocumentFixture{}, err
	}
	sampleRaw, err := encodePersistedState(state)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	average := (len(sampleRaw) - len(baseRaw)) / maximumDocumentFixtureBlockSize
	if average < 1 {
		return MaximumDocumentFixture{}, errors.New("maximum-document control record contribution is invalid")
	}
	estimatedCount := (minimum - len(baseRaw) + average - 1) / average
	if estimatedCount < maximumDocumentFixtureBlockSize {
		estimatedCount = maximumDocumentFixtureBlockSize
	}
	if estimatedCount > maximumDocumentFixtureMaxNodes {
		return MaximumDocumentFixture{}, errors.New("maximum-document control target exceeds one /16 fixture network")
	}
	if err := appendMaximumDocumentRecords(&state, groups, fixtureTime, maximumDocumentFixtureBlockSize+1, estimatedCount); err != nil {
		return MaximumDocumentFixture{}, err
	}

	var canonical []byte
	for attempts := 0; attempts < 8; attempts++ {
		canonical, err = encodePersistedState(state)
		if err != nil {
			return MaximumDocumentFixture{}, err
		}
		switch {
		case len(canonical) < minimum:
			additional := (minimum - len(canonical) + average - 1) / average
			if additional < 1 {
				additional = 1
			}
			start := len(state.Nodes) + 1
			end := len(state.Nodes) + additional
			if end > maximumDocumentFixtureMaxNodes {
				return MaximumDocumentFixture{}, errors.New("maximum-document control fixture exhausted its /16")
			}
			if err := appendMaximumDocumentRecords(&state, groups, fixtureTime, start, end); err != nil {
				return MaximumDocumentFixture{}, err
			}
		case len(canonical) > maximum:
			remove := (len(canonical) - maximum + average - 1) / average
			if remove < 1 || remove >= len(state.Nodes) {
				return MaximumDocumentFixture{}, errors.New("maximum-document control target could not be bounded")
			}
			state.Nodes = state.Nodes[:len(state.Nodes)-remove]
			state.Enrollments = state.Enrollments[:len(state.Enrollments)-remove]
			state.Audit = state.Audit[:len(state.Audit)-remove]
		default:
			attempts = 8
		}
	}
	canonical, err = encodePersistedState(state)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	if len(canonical) < minimum || len(canonical) > maximum {
		return MaximumDocumentFixture{}, fmt.Errorf("maximum-document control canonical size %d is outside %d..%d", len(canonical), minimum, maximum)
	}
	if err := validateStateGraph(state); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("validate generated control graph: %w", err)
	}
	if err := store.Update(func(current *State) error {
		*current = state
		return nil
	}); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("commit generated control graph: %w", err)
	}
	canonical, err = store.ExportRecoverySnapshot(ctx, box)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	if len(canonical) < minimum || len(canonical) > maximum {
		return MaximumDocumentFixture{}, fmt.Errorf("persisted control canonical size %d is outside %d..%d", len(canonical), minimum, maximum)
	}
	exact, err := padMaximumDocumentJSON(canonical, exactBytes)
	if err != nil {
		return MaximumDocumentFixture{}, err
	}
	if err := ValidateRecoverySnapshot(exact, box); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("validate exact control recovery document: %w", err)
	}
	if err := ValidateRecoverySnapshotCredentials(exact, options.MasterKey, options.AdminToken); err != nil {
		return MaximumDocumentFixture{}, fmt.Errorf("validate exact control credential binding: %w", err)
	}
	return MaximumDocumentFixture{
		CanonicalBytes: canonical, ExactBytes: exact, NetworkID: network.ID,
		NetworkCount: len(state.Networks), NetworkCIDR: state.Networks[0].CIDR,
		NodeCount: len(state.Nodes), EnrollmentCount: len(state.Enrollments), AuditCount: len(state.Audit),
		GroupCount: len(groups), InboundRuleCount: len(maxFirewall.Inbound), OutboundRuleCount: len(maxFirewall.Outbound),
		FirewallConfigRevision: updatedFirewall.ConfigRevision,
	}, nil
}

func appendMaximumDocumentRecords(state *State, groups []string, at time.Time, start, end int) error {
	for index := start; index <= end; index++ {
		if index > maximumDocumentFixtureMaxNodes {
			return errors.New("maximum-document control fixture exceeds /16 node capacity")
		}
		nodeID := maximumDocumentIdentifier("node_", index)
		enrollmentID := maximumDocumentIdentifier("enrollment_", index)
		auditID := maximumDocumentIdentifier("audit_", index)
		name := maximumDocumentName(index)
		address := maximumDocumentAddress(index)
		node := Node{
			ID: nodeID, NetworkID: state.Networks[0].ID, Name: name, IP: address,
			Groups: groups, Role: "member", Status: "pending",
			Site: UnassignedTopologyLabel, FailureDomain: UnassignedTopologyLabel, CreatedAt: at,
		}
		enrollment := EnrollmentToken{
			ID: enrollmentID, NodeID: nodeID,
			TokenHash: HashToken("maximum-document-enrollment-" + strconv.Itoa(index)),
			CreatedAt: at, ExpiresAt: at.Add(30 * time.Minute),
		}
		audit := AuditEvent{
			ID: auditID, Action: "node.created", Resource: "node", ResourceID: nodeID,
			At:      at,
			Details: map[string]any{"name": name, "ip": address, "role": "member"},
		}
		state.Nodes = append(state.Nodes, node)
		state.Enrollments = append(state.Enrollments, enrollment)
		state.Audit = append(state.Audit, audit)
	}
	return nil
}

func maximumDocumentIdentifier(prefix string, index int) string {
	return prefix + fmt.Sprintf("%0*d", 128-len(prefix), index)
}

func maximumDocumentName(index int) string {
	const prefix = "maximum-document-node-"
	return prefix + fmt.Sprintf("%0*d", 63-len(prefix), index)
}

func maximumDocumentAddress(index int) string {
	offset := index + 9
	return fmt.Sprintf("10.240.%d.%d", offset/256, offset%256)
}

func maximumDocumentInputGroups() []string {
	groups := make([]string, 0, maxNodeGroups-1)
	for index := 0; index < maxNodeGroups-1; index++ {
		const prefix = "group_"
		groups = append(groups, prefix+fmt.Sprintf("%0*d", 32-len(prefix), index))
	}
	return groups
}

func maximumDocumentFirewallInput() FirewallPolicyInput {
	inbound := make([]FirewallRule, 0, maxFirewallRulesPerDirection)
	outbound := make([]FirewallRule, 0, maxFirewallRulesPerDirection)
	for port := 1; port <= maxFirewallRulesPerDirection; port++ {
		value := strconv.Itoa(port)
		inbound = append(inbound, FirewallRule{Proto: "tcp", Port: value, Group: "maximum_document_fixture_group"})
		outbound = append(outbound, FirewallRule{Proto: "tcp", Port: value, Host: "any"})
	}
	return FirewallPolicyInput{Inbound: inbound, Outbound: outbound}
}

func padMaximumDocumentJSON(canonical []byte, target int) ([]byte, error) {
	if len(canonical) < 1 || len(canonical) >= target {
		return nil, errors.New("maximum-document canonical JSON cannot be padded to its target")
	}
	exact := make([]byte, target)
	copy(exact, canonical)
	for index := len(canonical); index < len(exact); index++ {
		exact[index] = ' '
	}
	return exact, nil
}

type maximumDocumentFixtureIssuer struct{ at time.Time }

func (issuer maximumDocumentFixtureIssuer) CreateCA(_ context.Context, name, cidr string) (string, string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", "", err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	defer clear(privateKey)
	certificate, err := (&nebulacert.TBSCertificate{
		Version: nebulacert.Version2, Curve: nebulacert.Curve_CURVE25519,
		Name: name, Networks: []netip.Prefix{prefix.Masked()}, IsCA: true,
		NotBefore: issuer.at.Add(-time.Hour),
		NotAfter:  issuer.at.Add(10 * 365 * 24 * time.Hour),
		PublicKey: publicKey,
	}).Sign(nil, nebulacert.Curve_CURVE25519, privateKey)
	if err != nil {
		return "", "", err
	}
	certificatePEM, err := certificate.MarshalPEM()
	if err != nil {
		return "", "", err
	}
	privateKeyPEM := nebulacert.MarshalSigningPrivateKeyToPEM(nebulacert.Curve_CURVE25519, privateKey)
	if len(privateKeyPEM) == 0 {
		return "", "", errors.New("marshal maximum-document CA private key")
	}
	return string(certificatePEM), string(privateKeyPEM), nil
}

func (maximumDocumentFixtureIssuer) SignPublicKey(context.Context, string, string, string, string, string, string, string, time.Duration) (string, string, time.Time, error) {
	return "", "", time.Time{}, errors.New("maximum-document fixture contains pending nodes only")
}
