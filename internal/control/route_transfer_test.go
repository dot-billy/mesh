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

	nebulacert "github.com/slackhq/nebula/cert"
)

func migrateRouteTransferTestService(t *testing.T, service *Service) {
	t.Helper()
	master := make([]byte, 32)
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
		service.EnsureFirewallRolloutSchema,
		service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema,
		service.EnsureRouteProfileEditSchema,
		service.EnsureRoutePolicySchema,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

func migrateRouteTransferPrerequisites(t *testing.T, service *Service) {
	t.Helper()
	master := make([]byte, 32)
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'Q'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnsureRouteTransferSchemaPreservesSignedStateAndIsWriteFree(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRouteTransferPrerequisites(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "route-schema", CIDR: "10.123.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "route-schema-node"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("q", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('Q'), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	before, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		t.Fatal(err)
	}
	after, err := service.AgentConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("v9 migration changed signed desired artifact: before=%#v after=%#v", before, after)
	}
	var state State
	if err := service.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	if state.Version != ControlStateVersionRouteTransfer || len(state.Networks) != 1 || !zeroNetworkRouteTransfer(state.Networks[0].RouteTransfer) || state.Audit[len(state.Audit)-1].Action != "control.route_transfer_schema_migrated" {
		t.Fatalf("unexpected v9 migration state: %#v", state)
	}
	infoBefore, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("repeated v9 migration rewrote the durable state")
	}
}

func TestRouteTransferStagesCertificateBeforeCutoverAndCleansSource(t *testing.T) {
	if _, err := exec.LookPath("nebula-cert"); err != nil {
		t.Skip("nebula-cert is not installed")
	}
	service := testService(t)
	migrateRouteTransferTestService(t, service)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	service.now = func() time.Time { return now }

	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "route-transfer", CIDR: "10.124.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	sourceCreated, err := service.CreateNode(network.ID, CreateNodeInput{Name: "gateway-old", Groups: []string{"routers"}, RoutedSubnets: []string{"192.168.124.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	targetCreated, err := service.CreateNode(network.ID, CreateNodeInput{Name: "gateway-new", Groups: []string{"routers"}})
	if err != nil {
		t.Fatal(err)
	}
	peerCreated, err := service.CreateNode(network.ID, CreateNodeInput{Name: "route-peer"})
	if err != nil {
		t.Fatal(err)
	}
	sourcePublicKey := generateRoutedTestPublicKey(t, "transfer-source")
	targetPublicKey := generateRoutedTestPublicKey(t, "transfer-target")
	peerPublicKey := generateRoutedTestPublicKey(t, "transfer-peer")
	sourceToken, targetToken, peerToken := strings.Repeat("s", 42)+"A", strings.Repeat("t", 42)+"A", strings.Repeat("p", 42)+"A"
	sourceInitial, err := service.Enroll(context.Background(), sourceCreated.EnrollmentToken, sourcePublicKey, HashToken(sourceToken))
	if err != nil {
		t.Fatal(err)
	}
	targetInitial, err := service.Enroll(context.Background(), targetCreated.EnrollmentToken, targetPublicKey, HashToken(targetToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), peerCreated.EnrollmentToken, peerPublicKey, HashToken(peerToken)); err != nil {
		t.Fatal(err)
	}

	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("networks=%#v err=%v", networks, err)
	}
	actor := Actor{ID: "service_route_transfer_operator", Kind: ActorKindServiceAccount, SessionID: "route-transfer-session"}
	input := StartRouteTransferInput{
		SourceNodeID: sourceCreated.Node.ID, TargetNodeID: targetCreated.Node.ID,
		RoutedSubnets: []string{"192.168.124.0/24"}, ExpectedConfigRevision: networks[0].ConfigRevision,
		RequestID: "route-transfer-request-0001",
	}
	started, err := service.StartRouteTransferAs(actor, network.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if started.Phase != RouteTransferPhasePreparingTarget || started.ConfigRevision != input.ExpectedConfigRevision+1 || started.Target == nil || started.Target.DesiredCertificateGeneration != targetInitial.CertificateGeneration+1 || slices.Contains(started.AvailableActions, "advance") {
		t.Fatalf("unexpected started transfer: %#v", started)
	}
	replayed, err := service.StartRouteTransferAs(actor, network.ID, input)
	if err != nil || replayed.Phase != started.Phase || replayed.ConfigRevision != started.ConfigRevision {
		t.Fatalf("start replay=%#v err=%v", replayed, err)
	}

	targetDesired, err := service.AgentConfig(targetToken)
	if err != nil {
		t.Fatal(err)
	}
	if !targetDesired.CertificateProfileRenewalRequired || targetDesired.CARotationRequired || !strings.Contains(targetDesired.Config, "local_cidr: 192.168.124.0/24") || strings.Contains(targetDesired.Config, "unsafe_routes:") {
		t.Fatalf("target did not receive an authenticated staged profile renewal:\n%#v\n%s", targetDesired, targetDesired.Config)
	}
	if err := VerifyConfig(targetInitial.ConfigSigningPublicKey, targetDesired.SignatureMetadata(), targetDesired.Config, targetDesired.SHA256, targetDesired.Signature); err != nil {
		t.Fatalf("verify staged target artifact: %v", err)
	}
	peerBefore, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	assertUnsafeRouteVia(t, peerBefore.Config, "192.168.124.0/24", sourceCreated.Node.IP)

	targetRenewed, err := service.Renew(context.Background(), targetToken, targetPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if targetRenewed.CertificateGeneration != targetInitial.CertificateGeneration+1 || targetRenewed.CertificateProfileRenewalRequired {
		t.Fatalf("unexpected target renewal: %#v", targetRenewed)
	}
	assertCertificateUnsafeNetworks(t, targetRenewed.Certificate, []netip.Prefix{netip.MustParsePrefix("192.168.124.0/24")})
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, targetToken, targetRenewed.ConfigRevision, targetRenewed.ConfigSHA256, targetRenewed.CertificateGeneration, targetRenewed.CertificateFingerprint, 1)

	ready, err := service.NetworkRouteTransfer(network.ID)
	if err != nil || ready.Target == nil || !ready.Target.Ready || !slices.Contains(ready.AvailableActions, "advance") {
		t.Fatalf("prepared transfer=%#v err=%v", ready, err)
	}
	now = now.Add(6 * time.Second)
	promoted, err := service.AdvanceRouteTransferAs(actor, network.ID, UpdateRouteTransferInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Phase != RouteTransferPhaseCleaningSource || promoted.ConfigRevision != ready.ConfigRevision+1 || promoted.Source == nil || promoted.Source.DesiredCertificateGeneration != sourceInitial.CertificateGeneration+1 {
		t.Fatalf("unexpected promotion: %#v", promoted)
	}
	peerAfter, err := service.AgentConfig(peerToken)
	if err != nil {
		t.Fatal(err)
	}
	assertUnsafeRouteVia(t, peerAfter.Config, "192.168.124.0/24", targetCreated.Node.IP)
	if strings.Contains(peerAfter.Config, "via: \""+sourceCreated.Node.IP+"\"") {
		t.Fatalf("peer retained source route after promotion:\n%s", peerAfter.Config)
	}

	sourceDesired, err := service.AgentConfig(sourceToken)
	if err != nil || !sourceDesired.CertificateProfileRenewalRequired {
		t.Fatalf("source cleanup desired=%#v err=%v", sourceDesired, err)
	}
	sourceRenewed, err := service.Renew(context.Background(), sourceToken, sourcePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	assertCertificateUnsafeNetworks(t, sourceRenewed.Certificate, nil)
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, sourceToken, sourceRenewed.ConfigRevision, sourceRenewed.ConfigSHA256, sourceRenewed.CertificateGeneration, sourceRenewed.CertificateFingerprint, 1)
	clean, err := service.NetworkRouteTransfer(network.ID)
	if err != nil || clean.Source == nil || !clean.Source.Ready {
		t.Fatalf("source cleanup=%#v err=%v", clean, err)
	}
	now = now.Add(6 * time.Second)
	completed, err := service.AdvanceRouteTransferAs(actor, network.ID, UpdateRouteTransferInput{ExpectedConfigRevision: clean.ConfigRevision, RequestID: clean.RequestID})
	if err != nil || completed.Phase != RouteTransferPhaseCompleted || completed.ConfigRevision != clean.ConfigRevision {
		t.Fatalf("completed transfer=%#v err=%v", completed, err)
	}
}

func TestRouteTransferCancelBeforeIssuanceAndParticipantLifecycleFence(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	migrateRouteTransferTestService(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "route-cancel", CIDR: "10.125.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.CreateNode(network.ID, CreateNodeInput{Name: "cancel-source", RoutedSubnets: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, CreateNodeInput{Name: "cancel-target"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), source.EnrollmentToken, testNebulaPublicKey('S'), HashToken(strings.Repeat("s", 42)+"B")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('T'), HashToken(strings.Repeat("t", 42)+"B")); err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	actor := LegacyAdminActor()
	started, err := service.StartRouteTransferAs(actor, network.ID, StartRouteTransferInput{
		SourceNodeID: source.Node.ID, TargetNodeID: target.Node.ID, RoutedSubnets: []string{"198.51.100.0/24"},
		ExpectedConfigRevision: networks[0].ConfigRevision, RequestID: "route-transfer-cancel-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNode(source.Node.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("participant revocation returned %v", err)
	}
	cancelled, err := service.CancelRouteTransferAs(actor, network.ID, UpdateRouteTransferInput{ExpectedConfigRevision: started.ConfigRevision, RequestID: started.RequestID})
	if err != nil || cancelled.Phase != RouteTransferPhaseCancelled || cancelled.ConfigRevision != started.ConfigRevision+1 {
		t.Fatalf("cancelled transfer=%#v err=%v", cancelled, err)
	}
	if _, err := service.RevokeNode(source.Node.ID); err != nil {
		t.Fatalf("terminal receipt continued fencing node lifecycle: %v", err)
	}
}

func TestRouteTransferCancelAfterTargetIssuanceRequiresCleanupConvergence(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	migrateRouteTransferTestService(t, service)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "route-clean-cancel", CIDR: "10.127.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.CreateNode(network.ID, CreateNodeInput{Name: "cleanup-source", RoutedSubnets: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, CreateNodeInput{Name: "cleanup-target"})
	if err != nil {
		t.Fatal(err)
	}
	sourceToken, targetToken := strings.Repeat("c", 42)+"A", strings.Repeat("d", 42)+"A"
	if _, err := service.Enroll(context.Background(), source.EnrollmentToken, testNebulaPublicKey('C'), HashToken(sourceToken)); err != nil {
		t.Fatal(err)
	}
	targetInitial, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('D'), HashToken(targetToken))
	if err != nil {
		t.Fatal(err)
	}
	networks, _ := service.Networks()
	actor := LegacyAdminActor()
	started, err := service.StartRouteTransferAs(actor, network.ID, StartRouteTransferInput{
		SourceNodeID: source.Node.ID, TargetNodeID: target.Node.ID, RoutedSubnets: []string{"192.0.2.0/24"},
		ExpectedConfigRevision: networks[0].ConfigRevision, RequestID: "route-transfer-clean-cancel-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.Renew(context.Background(), targetToken, testNebulaPublicKey('D'))
	if err != nil || prepared.CertificateGeneration != targetInitial.CertificateGeneration+1 {
		t.Fatalf("prepared renewal=%#v err=%v", prepared, err)
	}
	now = now.Add(6 * time.Second)
	cancelling, err := service.CancelRouteTransferAs(actor, network.ID, UpdateRouteTransferInput{ExpectedConfigRevision: started.ConfigRevision, RequestID: started.RequestID})
	if err != nil || cancelling.Phase != RouteTransferPhaseCleaningTarget || cancelling.Target == nil || cancelling.Target.DesiredCertificateGeneration != prepared.CertificateGeneration+1 {
		t.Fatalf("cancelling transfer=%#v err=%v", cancelling, err)
	}
	if _, err := service.CancelRouteTransferAs(actor, network.ID, UpdateRouteTransferInput{ExpectedConfigRevision: cancelling.ConfigRevision, RequestID: cancelling.RequestID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unconverged cleanup cancellation returned %v", err)
	}
	cleaned, err := service.Renew(context.Background(), targetToken, testNebulaPublicKey('D'))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	heartbeatApplied(t, service, targetToken, cleaned.ConfigRevision, cleaned.ConfigSHA256, cleaned.CertificateGeneration, cleaned.CertificateFingerprint, 1)
	ready, err := service.NetworkRouteTransfer(network.ID)
	if err != nil || ready.Target == nil || !ready.Target.Ready {
		t.Fatalf("cleanup readiness=%#v err=%v", ready, err)
	}
	now = now.Add(6 * time.Second)
	cancelled, err := service.CancelRouteTransferAs(actor, network.ID, UpdateRouteTransferInput{ExpectedConfigRevision: ready.ConfigRevision, RequestID: ready.RequestID})
	if err != nil || cancelled.Phase != RouteTransferPhaseCancelled || cancelled.ConfigRevision != ready.ConfigRevision {
		t.Fatalf("cancelled=%#v err=%v", cancelled, err)
	}
}

func heartbeatApplied(t *testing.T, service *Service, token string, revision int64, digest string, generation int64, fingerprint string, sequence int64) {
	t.Helper()
	if _, err := service.Heartbeat(token, HeartbeatInput{
		AgentVersion: "route-transfer-test", NebulaVersion: "test", AppliedConfigRevision: revision,
		CertificateGeneration: generation, AppliedConfigSHA256: digest, CertificateFingerprint: fingerprint,
		NebulaRunning: true, Status: "healthy", BootID: "route-transfer-boot", Sequence: sequence,
	}); err != nil {
		t.Fatal(err)
	}
}

func assertUnsafeRouteVia(t *testing.T, config, route, via string) {
	t.Helper()
	want := "- route: \"" + route + "\"\n      via: \"" + via + "\""
	if !strings.Contains(config, want) {
		t.Fatalf("config does not route %s via %s:\n%s", route, via, config)
	}
}

func assertCertificateUnsafeNetworks(t *testing.T, certificatePEM string, want []netip.Prefix) {
	t.Helper()
	certificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certificatePEM))
	if err != nil || len(remainder) != 0 {
		t.Fatalf("parse certificate: remainder=%q err=%v", remainder, err)
	}
	if got := certificate.UnsafeNetworks(); !slices.Equal(got, want) {
		t.Fatalf("certificate unsafe networks=%v, want %v", got, want)
	}
}
