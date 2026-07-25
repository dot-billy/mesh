package control

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func migrateRouteProfileEditPrerequisites(t *testing.T, service *Service) {
	t.Helper()
	master := make([]byte, 32)
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'P'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

func migrateRouteProfileEditTestService(t *testing.T, service *Service) {
	t.Helper()
	migrateRouteProfileEditPrerequisites(t, service)
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRouteProfileTransitionBoundsCertificateFirstUnion(t *testing.T) {
	original := []string{
		"192.168.140.0/24", "192.168.141.0/24", "192.168.142.0/24", "192.168.143.0/24",
		"192.168.144.0/24", "192.168.145.0/24", "192.168.146.0/24", "192.168.147.0/24",
	}
	desired := slices.Clone(original[1:])
	desired = append(desired, "192.168.148.0/24")
	slices.Sort(desired)
	if err := validateRouteProfileTransition(original, desired); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nine-prefix staged union was accepted: %v", err)
	}
	safeDesired := append(slices.Clone(original[:7]), "192.168.148.0/24")
	slices.Sort(safeDesired)
	if err := validateRouteProfileTransition(original[:7], safeDesired); err != nil {
		t.Fatalf("eight-prefix staged union was rejected: %v", err)
	}
}

func TestEnsureRouteProfileEditSchemaPreservesSignedStateAndIsWriteFree(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRouteProfileEditPrerequisites(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "profile-schema", CIDR: "10.130.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "profile-schema-node", RoutedSubnets: []string{"192.168.130.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("m", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('M'), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	before, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	after, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("v10 migration changed signed desired artifact: before=%#v after=%#v", before, after)
	}
	var state State
	if err := service.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	if state.Version != ControlStateVersionRouteProfileEdit || len(state.Networks) != 1 || !zeroNetworkRouteProfileEdit(state.Networks[0].RouteProfileEdit) || state.Audit[len(state.Audit)-1].Action != "control.route_profile_edit_schema_migrated" {
		t.Fatalf("unexpected v10 migration state: %#v", state)
	}
	infoBefore, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("repeated v10 migration rewrote durable state")
	}
}

func TestRouteProfileEditPrepareSurvivesDurableReopen(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRouteProfileEditTestService(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "profile-reopen", CIDR: "10.135.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "profile-reopen-owner", RoutedSubnets: []string{"192.168.138.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("d", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('D'), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("networks=%#v err=%v", networks, err)
	}
	started, err := service.StartRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, StartRouteProfileEditInput{
		RoutedSubnets: []string{"192.168.138.0/24", "192.168.139.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "route-profile-durable-reopen-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := service.store.path
	if err := service.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedStore, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedStore.Close() })
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	reopened := NewService(reopenedStore, box, &countingIssuer{})
	document, err := reopened.NodeRouteProfileEdit(created.Node.ID)
	if err != nil || document.Phase != RouteProfileEditPhasePreparingOwner || document.RequestID != started.RequestID || document.ConfigRevision != started.ConfigRevision || !slices.Contains(document.AvailableActions, "cancel") {
		t.Fatalf("reopened route profile=%#v err=%v", document, err)
	}
}

func TestRouteProfileEditMixedChangeStagesUnionThenCleansOwner(t *testing.T) {
	if _, err := exec.LookPath("nebula-cert"); err != nil {
		t.Skip("nebula-cert is not installed")
	}
	service := testService(t)
	migrateRouteProfileEditTestService(t, service)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "profile-mixed", CIDR: "10.131.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	ownerCreated, err := service.CreateNode(network.ID, CreateNodeInput{Name: "profile-owner", Groups: []string{"routers"}, RoutedSubnets: []string{"192.168.131.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	peerCreated, err := service.CreateNode(network.ID, CreateNodeInput{Name: "profile-peer"})
	if err != nil {
		t.Fatal(err)
	}
	ownerKey := generateRoutedTestPublicKey(t, "profile-owner")
	peerKey := generateRoutedTestPublicKey(t, "profile-peer")
	ownerToken, peerToken := strings.Repeat("o", 42)+"A", strings.Repeat("e", 42)+"A"
	ownerInitial, err := service.Enroll(context.Background(), ownerCreated.EnrollmentToken, ownerKey, HashToken(ownerToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), peerCreated.EnrollmentToken, peerKey, HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	if _, err := service.StartRouteProfileEditAs(LegacyAdminActor(), ownerCreated.Node.ID, StartRouteProfileEditInput{
		RoutedSubnets: []string{"192.168.131.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "route-profile-no-change-0001",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no-op profile edit was accepted: %v", err)
	}
	if _, err := service.StartRouteProfileEditAs(LegacyAdminActor(), ownerCreated.Node.ID, StartRouteProfileEditInput{
		RoutedSubnets: []string{"192.168.131.0/25"}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "route-profile-overlap-0001",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlapping old/new certificate profile was accepted: %v", err)
	}
	input := StartRouteProfileEditInput{
		RoutedSubnets: []string{"192.168.132.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "route-profile-mixed-request-0001",
	}
	started, err := service.StartRouteProfileEditAs(LegacyAdminActor(), ownerCreated.Node.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if started.Phase != RouteProfileEditPhasePreparingOwner || started.ConfigRevision != input.ExpectedConfigRevision+1 || started.Owner == nil || started.Owner.DesiredCertificateGeneration != ownerInitial.CertificateGeneration+1 || !slices.Equal(started.Additions, []string{"192.168.132.0/24"}) || !slices.Equal(started.Removals, []string{"192.168.131.0/24"}) || slices.Contains(started.AvailableActions, "advance") {
		t.Fatalf("unexpected mixed prepare: %#v", started)
	}
	replayed, err := service.StartRouteProfileEditAs(LegacyAdminActor(), ownerCreated.Node.ID, input)
	if err != nil || replayed.Phase != started.Phase || replayed.ConfigRevision != started.ConfigRevision {
		t.Fatalf("start replay=%#v err=%v", replayed, err)
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "staged-conflict", RoutedSubnets: []string{"192.168.132.128/25"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("staged addition was not reserved: %v", err)
	}
	if _, err := service.RevokeNode(ownerCreated.Node.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("active owner lifecycle was not fenced: %v", err)
	}
	if _, err := service.StartRouteTransferAs(LegacyAdminActor(), network.ID, StartRouteTransferInput{
		SourceNodeID: ownerCreated.Node.ID, TargetNodeID: peerCreated.Node.ID, RoutedSubnets: []string{"192.168.131.0/24"},
		ExpectedConfigRevision: started.ConfigRevision, RequestID: "route-transfer-during-profile-0001",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("route transfer overlapped active profile edit: %v", err)
	}
	if _, err := service.UpdateNetworkCARotation(context.Background(), network.ID, UpdateNetworkCARotationInput{Action: "prepare", ExpectedConfigRevision: started.ConfigRevision}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CA rotation overlapped active profile edit: %v", err)
	}
	if _, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: started.ConfigRevision,
		Inbound:                []FirewallRule{}, Outbound: []FirewallRule{},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("firewall update overlapped active profile edit: %v", err)
	}
	ownerDesired, err := service.AgentConfig(ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	if !ownerDesired.CertificateProfileRenewalRequired || strings.Count(ownerDesired.Config, "local_cidr: 192.168.13") != 2 || strings.Contains(ownerDesired.Config, "unsafe_routes:") {
		t.Fatalf("owner did not receive staged union profile:\n%#v\n%s", ownerDesired, ownerDesired.Config)
	}
	peerBefore, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	assertUnsafeRouteVia(t, peerBefore.Config, "192.168.131.0/24", ownerCreated.Node.IP)
	if strings.Contains(peerBefore.Config, "192.168.132.0/24") {
		t.Fatalf("peer published staged addition before promotion:\n%s", peerBefore.Config)
	}
	prepared, err := service.Renew(context.Background(), ownerToken, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	assertCertificateUnsafeNetworks(t, prepared.Certificate, []netip.Prefix{netip.MustParsePrefix("192.168.131.0/24"), netip.MustParsePrefix("192.168.132.0/24")})
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, ownerToken, prepared.ConfigRevision, prepared.ConfigSHA256, prepared.CertificateGeneration, prepared.CertificateFingerprint, 1)
	ready, err := service.NodeRouteProfileEdit(ownerCreated.Node.ID)
	if err != nil || ready.Owner == nil || !ready.Owner.Ready || !slices.Contains(ready.AvailableActions, "advance") {
		t.Fatalf("prepared edit=%#v err=%v", ready, err)
	}
	promoted, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), ownerCreated.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Phase != RouteProfileEditPhaseCleaningOwner || promoted.ConfigRevision != ready.ConfigRevision+1 || promoted.Owner == nil || promoted.Owner.DesiredCertificateGeneration != prepared.CertificateGeneration+1 {
		t.Fatalf("unexpected mixed promotion: %#v", promoted)
	}
	peerAfter, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	assertUnsafeRouteVia(t, peerAfter.Config, "192.168.132.0/24", ownerCreated.Node.IP)
	if strings.Contains(peerAfter.Config, "192.168.131.0/24") {
		t.Fatalf("peer retained removed route after promotion:\n%s", peerAfter.Config)
	}
	cleaned, err := service.Renew(context.Background(), ownerToken, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	assertCertificateUnsafeNetworks(t, cleaned.Certificate, []netip.Prefix{netip.MustParsePrefix("192.168.132.0/24")})
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, ownerToken, cleaned.ConfigRevision, cleaned.ConfigSHA256, cleaned.CertificateGeneration, cleaned.CertificateFingerprint, 2)
	clean, err := service.NodeRouteProfileEdit(ownerCreated.Node.ID)
	if err != nil || clean.Owner == nil || !clean.Owner.Ready {
		t.Fatalf("cleaned edit=%#v err=%v", clean, err)
	}
	completed, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), ownerCreated.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: clean.ConfigRevision, RequestID: clean.RequestID})
	if err != nil || completed.Phase != RouteProfileEditPhaseCompleted || completed.ConfigRevision != clean.ConfigRevision {
		t.Fatalf("completed edit=%#v err=%v", completed, err)
	}
}

func TestRouteProfileEditAddOnlyCompletesAtPromotionAndRemovalStartsWithCleanup(t *testing.T) {
	t.Run("add only", func(t *testing.T) {
		now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
		service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
		migrateRouteProfileEditTestService(t, service)
		service.now = func() time.Time { return now }
		network, _ := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "profile-add", CIDR: "10.132.0.0/24"})
		created, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "add-owner"})
		token := strings.Repeat("a", 42) + "A"
		initial, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('A'), HashToken(token))
		if err != nil {
			t.Fatal(err)
		}
		networks, _ := service.Networks()
		started, err := service.StartRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, StartRouteProfileEditInput{RoutedSubnets: []string{"192.168.133.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision, RequestID: "route-profile-add-only-0001"})
		if err != nil || started.Phase != RouteProfileEditPhasePreparingOwner {
			t.Fatalf("start=%#v err=%v", started, err)
		}
		renewed, err := service.Renew(context.Background(), token, testNebulaPublicKey('A'))
		if err != nil || renewed.CertificateGeneration != initial.CertificateGeneration+1 {
			t.Fatalf("renew=%#v err=%v", renewed, err)
		}
		now = now.Add(6 * time.Second)
		heartbeatApplied(t, service, token, renewed.ConfigRevision, renewed.ConfigSHA256, renewed.CertificateGeneration, renewed.CertificateFingerprint, 1)
		ready, _ := service.NodeRouteProfileEdit(created.Node.ID)
		completed, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
		if err != nil || completed.Phase != RouteProfileEditPhaseCompleted || completed.ConfigRevision != ready.ConfigRevision+1 || completed.Owner == nil || !slices.Equal(completed.DesiredRoutedSubnets, []string{"192.168.133.0/24"}) {
			t.Fatalf("completed=%#v err=%v", completed, err)
		}
		beforeReplay, err := os.Stat(service.store.path)
		if err != nil {
			t.Fatal(err)
		}
		var auditBefore int
		if err := service.store.View(func(state State) error { auditBefore = len(state.Audit); return nil }); err != nil {
			t.Fatal(err)
		}
		replayed, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
		if err != nil || replayed.Phase != RouteProfileEditPhaseCompleted || replayed.ConfigRevision != completed.ConfigRevision {
			t.Fatalf("completed promotion replay=%#v err=%v", replayed, err)
		}
		afterReplay, err := os.Stat(service.store.path)
		if err != nil {
			t.Fatal(err)
		}
		var auditAfter int
		if err := service.store.View(func(state State) error { auditAfter = len(state.Audit); return nil }); err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(beforeReplay, afterReplay) || !beforeReplay.ModTime().Equal(afterReplay.ModTime()) || auditAfter != auditBefore {
			t.Fatal("completed promotion replay rewrote durable state")
		}
		if completed.ConfigRevision > 2 {
			if _, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: completed.ConfigRevision - 2, RequestID: ready.RequestID}); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale terminal replay revision was accepted: %v", err)
			}
		}
	})

	t.Run("removal only", func(t *testing.T) {
		now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
		service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
		migrateRouteProfileEditTestService(t, service)
		service.now = func() time.Time { return now }
		network, _ := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "profile-remove", CIDR: "10.133.0.0/24"})
		created, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "remove-owner", RoutedSubnets: []string{"192.168.134.0/24"}})
		peer, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "remove-peer"})
		token, peerToken := strings.Repeat("r", 42)+"A", strings.Repeat("p", 42)+"A"
		if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('R'), HashToken(token)); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Enroll(context.Background(), peer.EnrollmentToken, testNebulaPublicKey('P'), HashToken(peerToken)); err != nil {
			t.Fatal(err)
		}
		networks, _ := service.Networks()
		started, err := service.StartRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, StartRouteProfileEditInput{RoutedSubnets: []string{}, ExpectedConfigRevision: networks[0].ConfigRevision, RequestID: "route-profile-remove-only-0001"})
		if err != nil || started.Phase != RouteProfileEditPhaseCleaningOwner || started.PromotedAt == nil || len(started.DesiredRoutedSubnets) != 0 {
			t.Fatalf("start=%#v err=%v", started, err)
		}
		peerConfig, err := service.AgentConfig(peerToken)
		if err != nil || strings.Contains(peerConfig.Config, "192.168.134.0/24") {
			t.Fatalf("removed route remained published: err=%v\n%s", err, peerConfig.Config)
		}
		if _, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: started.ConfigRevision, RequestID: started.RequestID}); !errors.Is(err, ErrConflict) {
			t.Fatalf("unconverged removal advanced: %v", err)
		}
		renewed, err := service.Renew(context.Background(), token, testNebulaPublicKey('R'))
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(6 * time.Second)
		heartbeatApplied(t, service, token, renewed.ConfigRevision, renewed.ConfigSHA256, renewed.CertificateGeneration, renewed.CertificateFingerprint, 1)
		ready, _ := service.NodeRouteProfileEdit(created.Node.ID)
		completed, err := service.AdvanceRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
		if err != nil || completed.Phase != RouteProfileEditPhaseCompleted || completed.ConfigRevision != ready.ConfigRevision {
			t.Fatalf("completed=%#v err=%v", completed, err)
		}
	})
}

func TestRouteProfileEditCancellationBeforeAndAfterPreparedIssuance(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	migrateRouteProfileEditTestService(t, service)
	service.now = func() time.Time { return now }
	network, _ := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "profile-cancel", CIDR: "10.134.0.0/24"})
	created, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "cancel-owner", RoutedSubnets: []string{"192.168.135.0/24"}})
	token := strings.Repeat("c", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('C'), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	first, err := service.StartRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, StartRouteProfileEditInput{RoutedSubnets: []string{"192.168.135.0/24", "192.168.136.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision, RequestID: "route-profile-cancel-before-0001"})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := service.CancelRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: first.ConfigRevision, RequestID: first.RequestID})
	if err != nil || cancelled.Phase != RouteProfileEditPhaseCancelled || cancelled.ConfigRevision != first.ConfigRevision+1 {
		t.Fatalf("pre-issuance cancel=%#v err=%v", cancelled, err)
	}
	replayedCancellation, err := service.CancelRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: first.ConfigRevision, RequestID: first.RequestID})
	if err != nil || replayedCancellation.Phase != RouteProfileEditPhaseCancelled || replayedCancellation.ConfigRevision != cancelled.ConfigRevision {
		t.Fatalf("cancel replay=%#v err=%v", replayedCancellation, err)
	}
	networks, _ = service.Networks()
	second, err := service.StartRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, StartRouteProfileEditInput{RoutedSubnets: []string{"192.168.135.0/24", "192.168.136.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision, RequestID: "route-profile-cancel-after-0002"})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.Renew(context.Background(), token, testNebulaPublicKey('C'))
	if err != nil {
		t.Fatal(err)
	}
	cancelling, err := service.CancelRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: second.ConfigRevision, RequestID: second.RequestID})
	if err != nil || cancelling.Phase != RouteProfileEditPhaseCleaningCancelledOwner || cancelling.Owner == nil || cancelling.Owner.DesiredCertificateGeneration != prepared.CertificateGeneration+1 {
		t.Fatalf("post-issuance cancel=%#v err=%v", cancelling, err)
	}
	cleaned, err := service.Renew(context.Background(), token, testNebulaPublicKey('C'))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, token, cleaned.ConfigRevision, cleaned.ConfigSHA256, cleaned.CertificateGeneration, cleaned.CertificateFingerprint, 1)
	ready, _ := service.NodeRouteProfileEdit(created.Node.ID)
	cancelled, err = service.CancelRouteProfileEditAs(LegacyAdminActor(), created.Node.ID, UpdateRouteProfileEditInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
	if err != nil || cancelled.Phase != RouteProfileEditPhaseCancelled || cancelled.ConfigRevision != ready.ConfigRevision || !slices.Equal(cancelled.OriginalRoutedSubnets, []string{"192.168.135.0/24"}) {
		t.Fatalf("cleanup cancel=%#v err=%v", cancelled, err)
	}
}
