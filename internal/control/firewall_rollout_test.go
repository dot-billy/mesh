package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func newFirewallRolloutTestService(t *testing.T, current bool) (*Service, *Store) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x47}, 32)
	box, err := NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 21, 19, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := NewService(store, box, issuer)
	service.now = func() time.Time { return now }
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'R'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema,
		service.EnsureNetworkDNSSchema,
		service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if current {
		if err := service.EnsureFirewallRolloutSchema(); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureFirewallPauseSchema(); err != nil {
			t.Fatal(err)
		}
	}
	return service, store
}

func TestEnsureFirewallRolloutSchemaPreservesSignedStateAndIsWriteFree(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, false)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rollout-migration", CIDR: "10.91.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-1"})
	if err != nil {
		t.Fatal(err)
	}
	var before State
	if err := store.View(func(state State) error { before = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if before.Version != ControlStateVersionCARotation {
		t.Fatalf("fixture version=%d", before.Version)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		t.Fatal(err)
	}
	var after State
	if err := store.View(func(state State) error { after = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if after.Version != ControlStateVersionFirewallRollout || after.Networks[0].ConfigRevision != before.Networks[0].ConfigRevision || !after.Networks[0].ConfigUpdatedAt.Equal(before.Networks[0].ConfigUpdatedAt) || after.Nodes[0].ID != created.Node.ID || !zeroNetworkFirewallRollout(after.Networks[0].FirewallRollout) {
		t.Fatalf("v7 migration changed signed or identity state: before=%+v after=%+v", before, after)
	}
	if len(after.Audit) != len(before.Audit)+1 {
		t.Fatalf("migration wrote %d audits, want one", len(after.Audit)-len(before.Audit))
	}
	last := after.Audit[len(after.Audit)-1]
	if last.Action != "control.firewall_rollout_schema_migrated" || last.Details["from_version"] != ControlStateVersionCARotation || last.Details["to_version"] != ControlStateVersionFirewallRollout {
		t.Fatalf("unexpected migration audit: %+v", last)
	}
	rawBefore, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		t.Fatal(err)
	}
	rawAfter, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawBefore, rawAfter) {
		t.Fatal("repeated current-schema startup rewrote firewall rollout v7 state")
	}
}

func TestEnsureFirewallPauseSchemaPreservesInflightCanaryAndIsWriteFree(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	// Reconstruct the exact v7 boundary so the migration proves an in-flight
	// canary remains byte-for-byte equivalent in its rendered signed configs.
	if err := store.Update(func(state *State) error {
		state.Version = ControlStateVersionFirewallRollout
		state.Audit = state.Audit[:len(state.Audit)-1]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "pause-migration", CIDR: "10.90.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "canary"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("m", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('M'), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	// v7 still owns the canary lifecycle, so build the persisted in-flight
	// fixture transactionally instead of invoking the v8-only mutation API.
	if err := store.Update(func(state *State) error {
		state.Networks[0].FirewallRollout = NetworkFirewallRollout{
			Phase: FirewallRolloutPhaseCanary, TargetPolicy: FirewallPolicy{Mode: FirewallPolicyModeManaged, RendererVersion: FirewallRendererVersionV2, Inbound: []FirewallRule{}, Outbound: []FirewallRule{}},
			CanaryNodeIDs: []string{created.Node.ID}, StartedAt: state.Networks[0].ConfigUpdatedAt, StageConfigRevision: state.Networks[0].ConfigRevision,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	beforeConfig, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	var before State
	if err := store.View(func(state State) error { before = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		t.Fatal(err)
	}
	afterConfig, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	var after State
	if err := store.View(func(state State) error { after = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if after.Version != ControlStateVersionFirewallPause || after.Networks[0].FirewallRollout.Phase != FirewallRolloutPhaseCanary || !after.Networks[0].FirewallRollout.PausedAt.IsZero() || afterConfig.Revision != beforeConfig.Revision || afterConfig.IssuedAt != beforeConfig.IssuedAt || afterConfig.SHA256 != beforeConfig.SHA256 || len(after.Audit) != len(before.Audit)+1 {
		t.Fatalf("v8 migration changed in-flight signed state: before=%+v after=%+v", beforeConfig, afterConfig)
	}
	last := after.Audit[len(after.Audit)-1]
	if last.Action != "control.firewall_rollout_pause_schema_migrated" || last.Details["from_version"] != ControlStateVersionFirewallRollout || last.Details["to_version"] != ControlStateVersionFirewallPause {
		t.Fatalf("unexpected pause migration audit: %+v", last)
	}
	rawBefore, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		t.Fatal(err)
	}
	rawAfter, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawBefore, rawAfter) {
		t.Fatal("repeated current-schema startup rewrote firewall pause v8 state")
	}
}

func TestFirewallRolloutCanaryConvergencePromotionAndRollback(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rollout", CIDR: "10.92.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	createActive := func(name, token string, fill byte) (CreatedNode, EnrollmentBundle) {
		created, err := service.CreateNode(network.ID, CreateNodeInput{Name: name, Groups: []string{"operators"}})
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey(fill), HashToken(token))
		if err != nil {
			t.Fatal(err)
		}
		return created, bundle
	}
	canaryToken, peerToken := strings.Repeat("c", 42)+"A", strings.Repeat("d", 42)+"A"
	canary, canaryBundle := createActive("canary", canaryToken, 'C')
	peer, _ := createActive("peer", peerToken, 'D')
	restrictive := FirewallPolicyInput{
		Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Group: "all"}},
		Outbound: []FirewallRule{{Proto: "tcp", Port: "443", Host: "any"}},
	}
	started, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: 1, CanaryNodeIDs: []string{canary.Node.ID},
		Inbound: restrictive.Inbound, Outbound: restrictive.Outbound,
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.Phase != FirewallRolloutPhaseCanary || started.ConfigRevision != 2 || started.StageConfigRevision != 2 || started.CanaryNodes != 1 || started.ConvergedCanaries != 0 || started.TargetPolicy == nil || !slices.Equal(started.AvailableActions, []string{"pause", "rollback"}) {
		t.Fatalf("unexpected started rollout: %+v", started)
	}
	canaryConfig, err := service.AgentConfig(canaryToken)
	if err != nil {
		t.Fatal(err)
	}
	peerConfig, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	if canaryConfig.Revision != 2 || peerConfig.Revision != 2 || !strings.Contains(canaryConfig.Config, "port: 443") || strings.Contains(peerConfig.Config, "port: 443") || canaryConfig.SHA256 == peerConfig.SHA256 {
		t.Fatalf("rollout did not isolate target bytes to canary:\ncanary=%s\npeer=%s", canaryConfig.Config, peerConfig.Config)
	}
	if _, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "promote", ExpectedConfigRevision: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unconverged promotion returned %v", err)
	}
	if _, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: 2, Inbound: restrictive.Inbound, Outbound: restrictive.Outbound}); !errors.Is(err, ErrConflict) {
		t.Fatalf("direct policy mutation during rollout returned %v", err)
	}
	if _, err := service.UpdateNetworkDNS(network.ID, UpdateNetworkDNSInput{ExpectedConfigRevision: 2, Enabled: true, ListenPort: 53}); !errors.Is(err, ErrConflict) {
		t.Fatalf("DNS mutation during rollout returned %v", err)
	}
	if _, err := service.UpdateNetworkRelays(network.ID, UpdateNetworkRelaysInput{ExpectedConfigRevision: 2, Enabled: true, RelayNodeIDs: []string{peer.Node.ID}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("relay mutation during rollout returned %v", err)
	}
	if _, err := service.UpdateNetworkCARotation(context.Background(), network.ID, UpdateNetworkCARotationInput{Action: "prepare", ExpectedConfigRevision: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CA prepare during rollout returned %v", err)
	}

	now = now.Add(6 * time.Second)
	if _, err := service.Heartbeat(canaryToken, HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: canaryConfig.Revision,
		CertificateGeneration: canaryBundle.CertificateGeneration, AppliedConfigSHA256: canaryConfig.SHA256,
		CertificateFingerprint: canaryBundle.CertificateFingerprint, NebulaRunning: true, Status: "healthy",
		BootID: "rollout-canary", Sequence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	converged, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || converged.ConvergedCanaries != 1 || !slices.Equal(converged.AvailableActions, []string{"promote", "pause", "rollback"}) {
		t.Fatalf("canary convergence was not authoritative: document=%+v err=%v", converged, err)
	}
	now = now.Add(time.Minute)
	paused, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "pause", ExpectedConfigRevision: 2})
	if err != nil || paused.Phase != FirewallRolloutPhasePaused || paused.ConfigRevision != 3 || paused.StageConfigRevision != 2 || paused.PausedAt == nil || paused.ConvergedCanaries != 0 || !slices.Equal(paused.AvailableActions, []string{"resume", "rollback"}) || paused.LastTransition == nil || paused.LastTransition.Action != "paused" {
		t.Fatalf("unexpected paused rollout: document=%+v err=%v", paused, err)
	}
	pausedCanary, err := service.AgentConfig(canaryToken)
	if err != nil {
		t.Fatal(err)
	}
	if pausedCanary.Revision != 3 || strings.Contains(pausedCanary.Config, "port: 443") {
		t.Fatalf("paused canary did not return to retained policy: %+v", pausedCanary)
	}
	if _, err := service.ReportConfigApplyFailure(canaryToken, ConfigApplyFailureInput{AttemptedConfigRevision: canaryConfig.Revision, AttemptedConfigSHA256: canaryConfig.SHA256, FailureCode: ConfigApplyFailureCodeActivation}); !errors.Is(err, ErrConflict) {
		t.Fatalf("paused rollout accepted activation-failure rollback evidence: %v", err)
	}
	if _, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "promote", ExpectedConfigRevision: 3}); !errors.Is(err, ErrConflict) {
		t.Fatalf("paused rollout promoted: %v", err)
	}
	now = now.Add(time.Minute)
	resumed, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "resume", ExpectedConfigRevision: 3})
	if err != nil || resumed.Phase != FirewallRolloutPhaseCanary || resumed.ConfigRevision != 4 || resumed.StageConfigRevision != 4 || resumed.PausedAt != nil || resumed.ConvergedCanaries != 0 || !slices.Equal(resumed.AvailableActions, []string{"pause", "rollback"}) || resumed.LastTransition == nil || resumed.LastTransition.Action != "resumed" {
		t.Fatalf("unexpected resumed rollout: document=%+v err=%v", resumed, err)
	}
	resumedCanary, err := service.AgentConfig(canaryToken)
	if err != nil || resumedCanary.Revision != 4 || !strings.Contains(resumedCanary.Config, "port: 443") {
		t.Fatalf("resumed canary did not receive staged target: config=%+v err=%v", resumedCanary, err)
	}
	now = now.Add(6 * time.Second)
	if _, err := service.Heartbeat(canaryToken, HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: resumedCanary.Revision,
		CertificateGeneration: canaryBundle.CertificateGeneration, AppliedConfigSHA256: resumedCanary.SHA256,
		CertificateFingerprint: canaryBundle.CertificateFingerprint, NebulaRunning: true, Status: "healthy",
		BootID: "rollout-canary", Sequence: 2,
	}); err != nil {
		t.Fatal(err)
	}
	resumedConverged, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || resumedConverged.ConvergedCanaries != 1 || !slices.Equal(resumedConverged.AvailableActions, []string{"promote", "pause", "rollback"}) {
		t.Fatalf("resumed canary did not require fresh convergence: document=%+v err=%v", resumedConverged, err)
	}
	now = now.Add(time.Minute)
	promoted, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "promote", ExpectedConfigRevision: 4})
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Phase != "stable" || promoted.ConfigRevision != 5 || promoted.TargetPolicy != nil || promoted.TargetPolicySHA256 != "" || !slices.Equal(promoted.AvailableActions, []string{"start"}) {
		t.Fatalf("unexpected promoted rollout: %+v", promoted)
	}
	canaryPromoted, _ := service.AgentConfig(canaryToken)
	peerPromoted, _ := service.AgentConfig(peerToken)
	if canaryPromoted.Revision != 5 || peerPromoted.Revision != 5 || !strings.Contains(canaryPromoted.Config, "port: 443") || canaryPromoted.SHA256 != peerPromoted.SHA256 {
		t.Fatal("promotion did not publish target policy to every node")
	}

	fullMesh := defaultManagedFirewallPolicy()
	now = now.Add(time.Minute)
	second, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: 5, CanaryNodeIDs: []string{peer.Node.ID},
		Inbound: fullMesh.Inbound, Outbound: fullMesh.Outbound,
	})
	if err != nil || second.Phase != FirewallRolloutPhaseCanary || second.ConfigRevision != 6 {
		t.Fatalf("second rollout=%+v err=%v", second, err)
	}
	now = now.Add(time.Minute)
	rolledBack, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "rollback", ExpectedConfigRevision: 6})
	if err != nil || rolledBack.Phase != "stable" || rolledBack.ConfigRevision != 7 {
		t.Fatalf("rollback=%+v err=%v", rolledBack, err)
	}
	policy, err := service.GetFirewallPolicy(network.ID)
	if err != nil || !slices.Equal(policy.Inbound, restrictive.Inbound) || !slices.Equal(policy.Outbound, restrictive.Outbound) {
		t.Fatalf("rollback did not retain promoted policy: policy=%+v err=%v", policy, err)
	}
	var state State
	if err := store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	for _, event := range state.Audit {
		if strings.HasPrefix(event.Action, "network.firewall_rollout_") {
			actions = append(actions, event.Action)
		}
	}
	if !slices.Equal(actions, []string{"network.firewall_rollout_started", "network.firewall_rollout_paused", "network.firewall_rollout_resumed", "network.firewall_rollout_promoted", "network.firewall_rollout_started", "network.firewall_rollout_rolled_back"}) {
		t.Fatalf("unexpected rollout audits: %v", actions)
	}
}

func TestRevokingFirewallCanariesPreservesSecurityAndAutoRollsBackLast(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	now := time.Date(2026, 7, 21, 21, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rollout-revoke", CIDR: "10.93.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	createActive := func(name, token string, fill byte) CreatedNode {
		created, err := service.CreateNode(network.ID, CreateNodeInput{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey(fill), HashToken(token)); err != nil {
			t.Fatal(err)
		}
		return created
	}
	first := createActive("canary-a", strings.Repeat("e", 42)+"A", 'E')
	second := createActive("canary-b", strings.Repeat("f", 42)+"A", 'F')
	target := FirewallPolicyInput{Inbound: []FirewallRule{}, Outbound: []FirewallRule{}}
	started, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: 1, CanaryNodeIDs: []string{second.Node.ID, first.Node.ID},
		Inbound: target.Inbound, Outbound: target.Outbound,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	paused, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{Action: "pause", ExpectedConfigRevision: started.ConfigRevision})
	if err != nil || paused.Phase != FirewallRolloutPhasePaused {
		t.Fatalf("pause before revocation=%+v err=%v", paused, err)
	}
	now = now.Add(time.Minute)
	if _, err := service.RevokeNode(first.Node.ID); err != nil {
		t.Fatal(err)
	}
	afterFirst, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || afterFirst.Phase != FirewallRolloutPhasePaused || afterFirst.ConfigRevision != paused.ConfigRevision+1 || afterFirst.CanaryNodes != 1 || afterFirst.PausedAt == nil {
		t.Fatalf("revoking one canary corrupted rollout: document=%+v err=%v", afterFirst, err)
	}
	now = now.Add(time.Minute)
	if _, err := service.RevokeNode(second.Node.ID); err != nil {
		t.Fatal(err)
	}
	afterLast, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || afterLast.Phase != "stable" || afterLast.ConfigRevision != afterFirst.ConfigRevision+1 || afterLast.CanaryNodes != 0 || afterLast.TargetPolicy != nil {
		t.Fatalf("last-canary revocation did not auto rollback: document=%+v err=%v", afterLast, err)
	}
	var state State
	if err := store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	foundRemoved, foundAutoRollback := false, false
	for _, event := range state.Audit {
		foundRemoved = foundRemoved || event.Action == "network.firewall_rollout_canary_removed"
		foundAutoRollback = foundAutoRollback || event.Action == "network.firewall_rollout_auto_rolled_back"
	}
	if !foundRemoved || !foundAutoRollback || len(state.Revocations) != 2 {
		t.Fatalf("revocation rollout audits or blocklist evidence missing: removed=%t rollback=%t revocations=%d", foundRemoved, foundAutoRollback, len(state.Revocations))
	}
}

func TestFirewallRolloutAutomaticRollbackRequiresExactCanaryActivationFailure(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	now := time.Date(2026, 7, 21, 22, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rollout-auto", CIDR: "10.94.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	createActive := func(name, token string, fill byte) (CreatedNode, EnrollmentBundle) {
		created, err := service.CreateNode(network.ID, CreateNodeInput{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey(fill), HashToken(token))
		if err != nil {
			t.Fatal(err)
		}
		return created, bundle
	}
	canaryToken := strings.Repeat("g", 42) + "A"
	peerToken := strings.Repeat("h", 42) + "A"
	canary, canaryBundle := createActive("canary", canaryToken, 'G')
	_, _ = createActive("peer", peerToken, 'H')
	baseConfig, err := service.AgentConfig(canaryToken)
	if err != nil {
		t.Fatal(err)
	}
	target := FirewallPolicyInput{
		Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Group: "all"}},
		Outbound: []FirewallRule{{Proto: "tcp", Port: "443", Host: "any"}},
	}
	started, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: 1, CanaryNodeIDs: []string{canary.Node.ID},
		Inbound: target.Inbound, Outbound: target.Outbound,
	})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := service.AgentConfig(canaryToken)
	if err != nil {
		t.Fatal(err)
	}
	if started.LastTransition == nil || started.LastTransition.Action != "started" || desired.Revision != started.ConfigRevision {
		t.Fatalf("rollout start transition or desired artifact missing: document=%+v desired=%+v", started, desired)
	}

	// A current degraded heartbeat on the previous known-good artifact is
	// operational evidence, not proof that this target failed activation.
	now = now.Add(6 * time.Second)
	if _, err := service.Heartbeat(canaryToken, HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: baseConfig.Revision,
		AppliedConfigSHA256: baseConfig.SHA256, CertificateGeneration: canaryBundle.CertificateGeneration,
		CertificateFingerprint: canaryBundle.CertificateFingerprint, NebulaRunning: false, Status: "degraded",
		LastError: "local runtime remains on the prior bundle", BootID: "rollout-auto", Sequence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	stillCanary, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || stillCanary.Phase != FirewallRolloutPhaseCanary {
		t.Fatalf("degraded heartbeat triggered rollback: document=%+v err=%v", stillCanary, err)
	}

	valid := ConfigApplyFailureInput{
		AttemptedConfigRevision: desired.Revision, AttemptedConfigSHA256: desired.SHA256,
		FailureCode: ConfigApplyFailureCodeActivation,
	}
	if _, err := service.ReportConfigApplyFailure(peerToken, valid); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-canary failure report returned %v", err)
	}
	stale := valid
	stale.AttemptedConfigRevision--
	if _, err := service.ReportConfigApplyFailure(canaryToken, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale failure report returned %v", err)
	}
	forged := valid
	forged.AttemptedConfigSHA256 = strings.Repeat("f", 64)
	if _, err := service.ReportConfigApplyFailure(canaryToken, forged); !errors.Is(err, ErrConflict) {
		t.Fatalf("forged failure report returned %v", err)
	}
	unsupported := valid
	unsupported.FailureCode = "heartbeat_missing"
	if _, err := service.ReportConfigApplyFailure(canaryToken, unsupported); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported failure code returned %v", err)
	}

	now = now.Add(time.Minute)
	rolledBack, err := service.ReportConfigApplyFailure(canaryToken, valid)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Phase != "stable" || rolledBack.ConfigRevision != started.ConfigRevision+1 || rolledBack.TargetPolicy != nil || rolledBack.LastTransition == nil || rolledBack.LastTransition.Action != "auto_rolled_back" || rolledBack.LastTransition.ReasonCode != "canary_config_activation_failed" || rolledBack.LastTransition.NodeID != canary.Node.ID {
		t.Fatalf("exact activation failure did not auto rollback: %+v", rolledBack)
	}
	if _, err := service.ReportConfigApplyFailure(canaryToken, valid); !errors.Is(err, ErrConflict) {
		t.Fatalf("replayed activation failure returned %v", err)
	}
	active, err := service.GetFirewallPolicy(network.ID)
	defaults := defaultManagedFirewallPolicy()
	if err != nil || !slices.Equal(active.Inbound, defaults.Inbound) || !slices.Equal(active.Outbound, defaults.Outbound) {
		t.Fatalf("automatic rollback did not retain the active policy: policy=%+v err=%v", active, err)
	}
	var state State
	if err := store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	last := state.Audit[len(state.Audit)-1]
	if last.Action != "network.firewall_rollout_auto_rolled_back" || last.Details["actor_id"] != canary.Node.ID || last.Details["actor_kind"] != ActorKindNodeAgent || last.Details["reason_code"] != "canary_config_activation_failed" || last.Details["failure_code"] != ConfigApplyFailureCodeActivation {
		t.Fatalf("automatic rollback audit is not exact and node-attributed: %+v", last)
	}
}

func TestFirewallRolloutAutomaticRollbackRequiresExactFreshStoppedTargetHeartbeat(t *testing.T) {
	service, store := newFirewallRolloutTestService(t, true)
	now := time.Date(2026, 7, 22, 1, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "rollout-runtime-guard", CIDR: "10.95.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "guarded-canary"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("j", 42) + "A"
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('J'), HashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.UpdateNetworkFirewallRollout(network.ID, UpdateNetworkFirewallRolloutInput{
		Action: "start", ExpectedConfigRevision: network.ConfigRevision, CanaryNodeIDs: []string{created.Node.ID},
		Inbound: []FirewallRule{{Proto: "tcp", Port: "443", Group: "all"}}, Outbound: []FirewallRule{{Proto: "tcp", Port: "443", Host: "any"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: desired.Revision,
		AppliedConfigSHA256: desired.SHA256, CertificateGeneration: bundle.CertificateGeneration,
		CertificateFingerprint: bundle.CertificateFingerprint, NebulaRunning: false, Status: "degraded",
		LastError: "sensitive local runtime diagnostic", BootID: "runtime-guard", Sequence: 1,
	}
	healthyContradiction := heartbeat
	healthyContradiction.Status = "healthy"
	if _, err := service.Heartbeat(token, healthyContradiction); !errors.Is(err, ErrConflict) {
		t.Fatalf("healthy stopped heartbeat returned %v", err)
	}
	missingGeneration := heartbeat
	missingGeneration.CertificateGeneration = 0
	if _, err := service.Heartbeat(token, missingGeneration); !errors.Is(err, ErrConflict) {
		t.Fatalf("generation-free stopped heartbeat returned %v", err)
	}
	genericDegraded := heartbeat
	genericDegraded.NebulaRunning = true
	if _, err := service.Heartbeat(token, genericDegraded); err != nil {
		t.Fatalf("exact running degraded heartbeat was rejected: %v", err)
	}
	stillCanary, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || stillCanary.Phase != FirewallRolloutPhaseCanary || stillCanary.ConfigRevision != started.ConfigRevision {
		t.Fatalf("generic degradation triggered rollback: document=%+v err=%v", stillCanary, err)
	}
	now = now.Add(6 * time.Second)
	heartbeat.Sequence = 2
	updated, err := service.Heartbeat(token, heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if updated.NebulaRunning || updated.AgentStatus != "degraded" || updated.HeartbeatSequence != 2 {
		t.Fatalf("stopped heartbeat was not durably recorded: %+v", updated)
	}
	rolledBack, err := service.NetworkFirewallRollout(network.ID)
	if err != nil || rolledBack.Phase != "stable" || rolledBack.ConfigRevision != started.ConfigRevision+1 || rolledBack.LastTransition == nil || rolledBack.LastTransition.Action != "auto_rolled_back" || rolledBack.LastTransition.ReasonCode != "canary_target_runtime_stopped" || rolledBack.LastTransition.NodeID != created.Node.ID {
		t.Fatalf("exact stopped-target heartbeat did not auto rollback: document=%+v err=%v", rolledBack, err)
	}
	var state State
	if err := store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	last := state.Audit[len(state.Audit)-1]
	if last.Action != "network.firewall_rollout_auto_rolled_back" || last.Details["reason_code"] != "canary_target_runtime_stopped" || last.Details["heartbeat_sequence"] != int64(2) || last.Details["nebula_running"] != false || last.Details["agent_status"] != "degraded" || last.Details["failed_config_revision"] != desired.Revision || last.Details["failed_config_sha256"] != desired.SHA256 || last.Details["actor_id"] != created.Node.ID || last.Details["actor_kind"] != ActorKindNodeAgent {
		t.Fatalf("runtime health rollback audit is incomplete: %+v", last)
	}
	if _, leaked := last.Details["last_error"]; leaked {
		t.Fatalf("runtime health rollback leaked raw local diagnostics: %+v", last)
	}
}
