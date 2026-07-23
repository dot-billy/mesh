package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeriveAdminCredentialVerifierIsKeyedCanonicalAndStrict(t *testing.T) {
	master := bytes.Repeat([]byte{0x41}, 32)
	token := bytes.Repeat([]byte{'A'}, 43)
	verifier, err := DeriveAdminCredentialVerifier(master, token)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidAdminCredentialVerifier(verifier) || !strings.HasPrefix(verifier, "v1:") {
		t.Fatalf("verifier is not canonical: %q", verifier)
	}
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil || !ValidMasterKeyVerifier(masterVerifier) {
		t.Fatalf("master verifier is not canonical: %q %v", masterVerifier, err)
	}
	changedMasterVerifier, err := DeriveMasterKeyVerifier(bytes.Repeat([]byte{0x42}, 32))
	if err != nil || masterKeyVerifierEqual(masterVerifier, changedMasterVerifier) {
		t.Fatal("different master key produced the same master verifier")
	}
	repeated, err := DeriveAdminCredentialVerifier(master, token)
	if err != nil || !adminCredentialVerifierEqual(verifier, repeated) {
		t.Fatalf("derivation is not deterministic: %q %v", repeated, err)
	}
	changedToken, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'B'}, 43))
	if err != nil || adminCredentialVerifierEqual(verifier, changedToken) {
		t.Fatal("different administrator token produced the same verifier")
	}
	changedMaster, err := DeriveAdminCredentialVerifier(bytes.Repeat([]byte{0x42}, 32), token)
	if err != nil || adminCredentialVerifierEqual(verifier, changedMaster) {
		t.Fatal("different master key produced the same verifier")
	}
	for _, test := range []struct {
		name   string
		master []byte
		token  []byte
	}{
		{name: "short master", master: master[:31], token: token},
		{name: "short token", master: master, token: token[:31]},
		{name: "oversized token", master: master, token: bytes.Repeat([]byte{'A'}, 4097)},
		{name: "space", master: master, token: append(bytes.Repeat([]byte{'A'}, 32), ' ')},
		{name: "non ASCII", master: master, token: append(bytes.Repeat([]byte{'A'}, 32), 0x80)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DeriveAdminCredentialVerifier(test.master, test.token); err == nil {
				t.Fatal("invalid credential material was accepted")
			}
		})
	}
}

func TestEnsureAdminCredentialVerifierBindsRotatesAndPersistsWithoutToken(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	store, err := OpenStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x51}, 32)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, box, NebulaIssuer{})
	boundAt := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return boundAt }
	firstToken := bytes.Repeat([]byte{'C'}, 43)
	first, err := DeriveAdminCredentialVerifier(master, firstToken)
	if err != nil {
		t.Fatal(err)
	}
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, first, false); err != nil {
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
	if err := service.EnsureCARotationSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallScopeSchema(); err != nil {
		t.Fatal(err)
	}
	firstInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CheckCurrentRecoveryCredentialBinding(masterVerifier, first); err != nil {
		t.Fatalf("current recovery credential binding was not ready: %v", err)
	}
	checkedInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(firstInfo, checkedInfo) {
		t.Fatal("read-only current-binding check rewrote the state file")
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, first, false); err != nil {
		t.Fatal(err)
	}
	secondInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(firstInfo, secondInfo) {
		t.Fatal("idempotent credential binding rewrote the state file")
	}

	secondToken := bytes.Repeat([]byte{'D'}, 43)
	second, err := DeriveAdminCredentialVerifier(master, secondToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CheckRecoveryCredentialBinding(masterVerifier, second, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("read-only preflight accepted an unauthorized rotation: %v", err)
	}
	service.now = func() time.Time { return boundAt.Add(time.Minute) }
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, second, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("credential changed without explicit rotation authority: %v", err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, second, true); err != nil {
		t.Fatal(err)
	}
	if err := service.CheckCurrentRecoveryCredentialBinding(masterVerifier, first); !errors.Is(err, ErrConflict) {
		t.Fatalf("current-binding check accepted the rotated administrator verifier: %v", err)
	}
	if err := service.CheckCurrentRecoveryCredentialBinding(masterVerifier, second); err != nil {
		t.Fatalf("current-binding check rejected the rotated administrator verifier: %v", err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, "not-canonical", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid verifier was not rejected: %v", err)
	}
	wrongMasterVerifier, err := DeriveMasterKeyVerifier(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(wrongMasterVerifier, second, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("administrator rotation authority replaced the master-key binding: %v", err)
	}
	var observed State
	if err := store.View(func(state State) error { observed = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if observed.Version != ControlStateVersionFirewallScopes || !masterKeyVerifierEqual(observed.MasterKeyVerifier, masterVerifier) || !adminCredentialVerifierEqual(observed.AdminCredentialVerifier, second) || len(observed.Audit) != 13 || observed.Audit[0].Action != "admin.credential_bound" || observed.Audit[1].Action != "control.topology_schema_migrated" || observed.Audit[2].Action != "control.network_dns_schema_migrated" || observed.Audit[3].Action != "control.network_relay_schema_migrated" || observed.Audit[4].Action != "control.ca_rotation_schema_migrated" || observed.Audit[5].Action != "control.firewall_rollout_schema_migrated" || observed.Audit[6].Action != "control.firewall_rollout_pause_schema_migrated" || observed.Audit[7].Action != "control.route_transfer_schema_migrated" || observed.Audit[8].Action != "control.route_profile_edit_schema_migrated" || observed.Audit[9].Action != "control.route_policy_schema_migrated" || observed.Audit[10].Action != "control.native_dns_schema_migrated" || observed.Audit[11].Action != "control.firewall_scope_schema_migrated" || observed.Audit[12].Action != "admin.credential_rotated" {
		t.Fatalf("unexpected credential binding state: verifier=%q audit=%+v", observed.AdminCredentialVerifier, observed.Audit)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, firstToken) || bytes.Contains(raw, secondToken) {
		t.Fatal("raw administrator credential was persisted")
	}
	if !strings.Contains(string(raw), `"master_key_verifier"`) || !strings.Contains(string(raw), `"admin_credential_verifier"`) {
		t.Fatal("recovery credential verifiers were not persisted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.View(func(state State) error {
		if !adminCredentialVerifierEqual(state.AdminCredentialVerifier, second) {
			return errors.New("persisted verifier changed across reopen")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureManagedNetworksAuthenticatesCAKeyBeforeLegacyMigration(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	store, err := OpenStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	correctBox, err := NewSecretBox(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	correct := NewService(store, correctBox, &countingIssuer{})
	network, err := correct.CreateNetwork(context.Background(), CreateNetworkInput{Name: "legacy-empty", CIDR: "10.120.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(state *State) error {
		for index := range state.Networks {
			if state.Networks[index].ID == network.ID {
				state.Networks[index].ConfigSigningPublicKey = ""
				state.Networks[index].EncryptedConfigSigningKey = ""
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	wrongBox, err := NewSecretBox(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrong := NewService(store, wrongBox, &countingIssuer{})
	if err := wrong.EnsureManagedNetworks(); err == nil || !strings.Contains(err.Error(), "CA key") {
		t.Fatalf("wrong master key reached legacy migration: %v", err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("wrong master key mutated legacy network state")
	}
	if err := correct.EnsureManagedNetworks(); err != nil {
		t.Fatalf("correct master did not migrate legacy network: %v", err)
	}
}
