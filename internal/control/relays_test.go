package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func newNetworkRelayTestService(t *testing.T, migrateRelays bool) (*Service, *Store) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x65}, 32)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &countingIssuer{}
	service := NewService(store, box, issuer)
	now := time.Date(2026, 7, 21, 14, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	issuer.now = service.now
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'R'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if migrateRelays {
		if err := service.EnsureNetworkRelaySchema(); err != nil {
			t.Fatal(err)
		}
	}
	return service, store
}

func TestEnsureNetworkRelaySchemaMigratesDisabledWithoutChangingSignedRevision(t *testing.T) {
	service, store := newNetworkRelayTestService(t, false)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "relay-migration", CIDR: "10.84.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if network.RelaySettings.Enabled || network.RelaySettings.RelayNodeIDs != nil {
		t.Fatalf("network DNS v4 unexpectedly carried relay settings: %#v", network.RelaySettings)
	}
	beforeRevision, beforeUpdatedAt := network.ConfigRevision, network.ConfigUpdatedAt
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	var migrated State
	if err := store.View(func(state State) error { migrated = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if migrated.Version != ControlStateVersionNetworkRelays || len(migrated.Networks) != 1 || migrated.Networks[0].RelaySettings.Enabled || !slices.Equal(migrated.Networks[0].RelaySettings.RelayNodeIDs, []string{}) {
		t.Fatalf("unexpected relay migration: version=%d networks=%#v", migrated.Version, migrated.Networks)
	}
	if migrated.Networks[0].ConfigRevision != beforeRevision || !migrated.Networks[0].ConfigUpdatedAt.Equal(beforeUpdatedAt) {
		t.Fatal("disabled relay migration changed signed configuration lifecycle")
	}
	last := migrated.Audit[len(migrated.Audit)-1]
	if last.Action != "control.network_relay_schema_migrated" || last.Details["from_version"] != ControlStateVersionNetworkDNS || last.Details["to_version"] != ControlStateVersionNetworkRelays || last.Details["networks"] != 1 {
		t.Fatalf("unexpected relay migration audit: %#v", last)
	}
	infoBefore, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) {
		t.Fatal("ordered current-schema startup rewrote relay v5 state")
	}
}

func TestNetworkRelayLifecycleRendersAssignmentsAndRemovesRevokedRelay(t *testing.T) {
	service, _ := newNetworkRelayTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "relay-lifecycle", CIDR: "10.85.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := service.NetworkRelays(network.ID)
	if err != nil || initial.Schema != NetworkRelaysDocumentSchema || initial.Enabled || initial.RelayNodeIDs == nil || initial.ActiveRelays == nil || initial.MaxRelayNodes != MaxNetworkRelayNodes {
		t.Fatalf("unexpected initial relay document=%#v err=%v", initial, err)
	}
	relay, err := service.CreateNode(network.ID, CreateNodeInput{Name: "relay-lighthouse", Role: "lighthouse", PublicEndpoint: "198.51.100.85:4242"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-second"})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := service.UpdateNetworkRelays(network.ID, UpdateNetworkRelaysInput{
		ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{relay.Node.ID},
	})
	if err != nil || !enabled.Enabled || !slices.Equal(enabled.RelayNodeIDs, []string{relay.Node.ID}) || len(enabled.ActiveRelays) != 0 || enabled.ConfigRevision != network.ConfigRevision+1 {
		t.Fatalf("enable pending relay=%#v err=%v", enabled, err)
	}
	replayed, err := service.UpdateNetworkRelays(network.ID, UpdateNetworkRelaysInput{
		ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{relay.Node.ID},
	})
	if err != nil || replayed.ConfigRevision != enabled.ConfigRevision {
		t.Fatalf("idempotent relay retry=%#v err=%v", replayed, err)
	}

	relayToken := strings.Repeat("r", 42) + "A"
	relayBundle, err := service.Enroll(context.Background(), relay.EnrollmentToken, testNebulaPublicKey('R'), HashToken(relayToken))
	if err != nil {
		t.Fatal(err)
	}
	expectedRelayConfig := "relay:\n  am_relay: true\n  use_relays: false\n"
	if !strings.Contains(relayBundle.Config, expectedRelayConfig) || strings.Contains(relayBundle.Config, "  relays:\n") {
		t.Fatalf("relay config omitted exact server-only settings:\n%s", relayBundle.Config)
	}
	firstToken := strings.Repeat("f", 42) + "A"
	firstBundle, err := service.Enroll(context.Background(), first.EnrollmentToken, testNebulaPublicKey('F'), HashToken(firstToken))
	if err != nil {
		t.Fatal(err)
	}
	secondToken := strings.Repeat("s", 42) + "A"
	secondBundle, err := service.Enroll(context.Background(), second.EnrollmentToken, testNebulaPublicKey('S'), HashToken(secondToken))
	if err != nil {
		t.Fatal(err)
	}
	expectedClientConfig := fmt.Sprintf("relay:\n  relays:\n    - %q\n  am_relay: false\n  use_relays: true\n", relay.Node.IP)
	for label, config := range map[string]string{"first": firstBundle.Config, "second": secondBundle.Config} {
		if !strings.Contains(config, expectedClientConfig) || strings.Contains(config, "  am_relay: true") {
			t.Fatalf("%s member config omitted exact relay advertisement:\n%s", label, config)
		}
	}
	document, err := service.NetworkRelays(network.ID)
	wantActive := []NetworkRelay{{NodeID: relay.Node.ID, Name: relay.Node.Name, IP: relay.Node.IP, Role: relay.Node.Role}}
	if err != nil || !slices.Equal(document.ActiveRelays, wantActive) {
		t.Fatalf("active relay projection=%#v err=%v", document, err)
	}

	revoked, err := service.RevokeNode(relay.Node.ID)
	if err != nil || revoked.Status != "revoked" {
		t.Fatalf("revoke relay=%#v err=%v", revoked, err)
	}
	after, err := service.NetworkRelays(network.ID)
	if err != nil || after.Enabled || len(after.RelayNodeIDs) != 0 || len(after.ActiveRelays) != 0 || after.ConfigRevision != document.ConfigRevision+1 {
		t.Fatalf("relay revocation did not disable the empty assignment: %#v err=%v", after, err)
	}
	for label, token := range map[string]string{"first": firstToken, "second": secondToken} {
		config, configErr := service.AgentConfig(token)
		if configErr != nil || config.Revision != after.ConfigRevision || strings.Contains(config.Config, "\nrelay:\n") {
			t.Fatalf("%s member retained relay config after revocation: %#v err=%v", label, config, configErr)
		}
	}
}

func TestNetworkRelaySelectionRejectsInvalidCrossNetworkAndStaleChanges(t *testing.T) {
	service, _ := newNetworkRelayTestService(t, true)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "relay-validation", CIDR: "10.86.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "relay-other", CIDR: "10.87.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := service.CreateNode(network.ID, CreateNodeInput{Name: "relay-candidate"})
	if err != nil {
		t.Fatal(err)
	}
	otherNode, err := service.CreateNode(other.ID, CreateNodeInput{Name: "other-candidate"})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]UpdateNetworkRelaysInput{
		"missing array":      {ExpectedConfigRevision: network.ConfigRevision, Enabled: true},
		"empty enabled":      {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{}},
		"disabled with node": {ExpectedConfigRevision: network.ConfigRevision, RelayNodeIDs: []string{node.Node.ID}},
		"duplicate":          {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{node.Node.ID, node.Node.ID}},
		"cross network":      {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{otherNode.Node.ID}},
		"unknown":            {ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{"missing-node"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.UpdateNetworkRelays(network.ID, input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid relay selection returned %v", err)
			}
		})
	}
	updated, err := service.UpdateNetworkRelays(network.ID, UpdateNetworkRelaysInput{ExpectedConfigRevision: network.ConfigRevision, Enabled: true, RelayNodeIDs: []string{node.Node.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateNetworkRelays(network.ID, UpdateNetworkRelaysInput{ExpectedConfigRevision: network.ConfigRevision, RelayNodeIDs: []string{}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale relay mutation returned %v after revision %d", err, updated.ConfigRevision)
	}
}
