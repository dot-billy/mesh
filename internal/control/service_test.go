package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkNodeEnrollmentLifecycle(t *testing.T) {
	if _, err := exec.LookPath("nebula-cert"); err != nil {
		t.Skip("nebula-cert is not installed")
	}
	service := testService(t)
	ctx := context.Background()
	network, err := service.CreateNetwork(ctx, CreateNetworkInput{Name: "production", CIDR: "10.42.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "lighthouse-01", Role: "lighthouse", PublicEndpoint: "vpn.example.com:4242", Groups: []string{"infra"}})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	dir := t.TempDir()
	keyPath, pubPath := filepath.Join(dir, "host.key"), filepath.Join(dir, "host.pub")
	if output, err := exec.Command("nebula-cert", "keygen", "-out-key", keyPath, "-out-pub", pubPath).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v: %s", err, output)
	}
	publicKey, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("a", 42) + "A"
	bundle, err := service.Enroll(ctx, created.EnrollmentToken, string(publicKey), HashToken(agentToken))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	persisted, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), agentToken) || strings.Contains(string(persisted), created.EnrollmentToken) {
		t.Fatal("plaintext node credential or enrollment token was persisted")
	}
	if bundle.Node.Status != "active" || !strings.Contains(bundle.Config, "am_lighthouse: true") || !strings.Contains(bundle.Config, "vpn.example.com:4242") {
		t.Fatalf("unexpected bundle: %#v\n%s", bundle.Node, bundle.Config)
	}
	if len(bundle.Node.CertificateFingerprint) != 64 {
		t.Fatalf("certificate fingerprint is not SHA-256 hex: %q", bundle.Node.CertificateFingerprint)
	}
	if bundle.NodeID != bundle.Node.ID || bundle.NetworkID != network.ID || bundle.CACertificateSHA256 != ConfigDigest(bundle.CA) || bundle.CertificateFingerprint != bundle.Node.CertificateFingerprint || bundle.PublicKeyHash != HashToken(string(publicKey)) {
		t.Fatalf("enrollment response omitted signed artifact metadata: %#v", bundle)
	}
	if want := bundle.CertificateExpiresAt.Add(-8 * time.Hour); !bundle.CertificateRenewAfter.Equal(want) {
		t.Fatalf("24h certificate renew-after=%s, want expiry-8h=%s", bundle.CertificateRenewAfter, want)
	}
	if err := VerifyConfig(bundle.ConfigSigningPublicKey, bundle.SignatureMetadata(), bundle.Config, bundle.ConfigSHA256, bundle.ConfigSignature); err != nil {
		t.Fatalf("verify signed config: %v", err)
	}
	currentTime := service.now()
	service.now = func() time.Time { return currentTime }
	replayed, err := service.Enroll(ctx, created.EnrollmentToken, string(publicKey), HashToken(agentToken))
	if err != nil || replayed.Certificate != bundle.Certificate {
		t.Fatalf("identical enrollment retry was not idempotent: err=%v", err)
	}
	if _, err := service.Enroll(ctx, created.EnrollmentToken, string(publicKey)+"changed", HashToken(agentToken)); err == nil {
		t.Fatal("used enrollment token accepted a changed request")
	}
	managed, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatalf("get managed config: %v", err)
	}
	if managed.SHA256 != bundle.ConfigSHA256 || managed.Signature != bundle.ConfigSignature {
		t.Fatal("same config revision did not produce a stable signed artifact")
	}
	if managed.CACertificateSHA256 != bundle.CACertificateSHA256 || managed.CertificateFingerprint != bundle.CertificateFingerprint || managed.PublicKeyHash != bundle.PublicKeyHash || !managed.CertificateExpiresAt.Equal(bundle.CertificateExpiresAt) {
		t.Fatal("managed response did not reproduce the signed certificate metadata")
	}
	heartbeat := HeartbeatInput{AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: managed.Revision, AppliedConfigSHA256: managed.SHA256, CertificateFingerprint: bundle.Node.CertificateFingerprint, NebulaRunning: true, Status: "healthy", BootID: "boot-1", Sequence: 1}
	if _, err := service.Heartbeat(agentToken, heartbeat); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, err := service.Heartbeat(agentToken, heartbeat); err == nil {
		t.Fatal("replayed heartbeat sequence was accepted")
	}
	newAgentToken := strings.Repeat("b", 42) + "A"
	rotation, err := service.RotateAgentCredential(agentToken, HashToken(newAgentToken))
	if err != nil || rotation.Generation != 2 {
		t.Fatalf("rotate credential: rotation=%#v err=%v", rotation, err)
	}
	heartbeat.Sequence = 2
	currentTime = currentTime.Add(6 * time.Second)
	if _, err := service.Heartbeat(newAgentToken, heartbeat); err != nil {
		t.Fatalf("heartbeat with rotated credential: %v", err)
	}
	if _, err := service.AgentConfig(agentToken); err == nil {
		t.Fatal("superseded credential remained valid after replacement was used")
	}
	if _, err := service.RevokeNode(created.Node.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 1 || nodes[0].Status != "revoked" {
		t.Fatalf("revocation not persisted: nodes=%#v err=%v", nodes, err)
	}
	var afterRevoke State
	_ = service.store.View(func(state State) error { afterRevoke = state; return nil })
	if len(afterRevoke.Revocations) != 1 {
		t.Fatalf("revocation did not blocklist all unexpired issuances: %#v", afterRevoke.Revocations)
	}
}

func TestRejectsOverlappingNetworksAndDuplicateNodes(t *testing.T) {
	service := testService(t)
	ctx := context.Background()
	network, err := service.CreateNetwork(ctx, CreateNetworkInput{Name: "one", CIDR: "10.50.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNetwork(ctx, CreateNetworkInput{Name: "two", CIDR: "10.50.0.128/25"}); err == nil {
		t.Fatal("overlapping network was accepted")
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "host-01"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "host-01"}); err == nil {
		t.Fatal("duplicate node name was accepted")
	}
}

func TestReissueEnrollmentReplacesExpiredCredentialAndRejectsWrongLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "reissue", CIDR: "10.71.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-01"})
	if err != nil {
		t.Fatal(err)
	}

	// Even after expiry, the replacement generator must not revive the exact
	// raw token the operator is trying to invalidate.
	now = now.Add(31 * time.Minute)
	replacement := strings.Repeat("r", 42) + "A"
	generated := []string{created.EnrollmentToken, replacement}
	generateCalls := 0
	service.generateBearer = func() (string, error) {
		if generateCalls >= len(generated) {
			return "", errors.New("unexpected enrollment bearer generation")
		}
		value := generated[generateCalls]
		generateCalls++
		return value, nil
	}
	reissued, err := service.ReissueEnrollment(created.Node.ID)
	if err != nil {
		t.Fatalf("reissue enrollment: %v", err)
	}
	service.generateBearer = func() (string, error) { return RandomToken(32) }
	if reissued.Node.ID != created.Node.ID || reissued.Node.Status != "pending" || reissued.EnrollmentToken != replacement || generateCalls != 2 {
		t.Fatalf("unexpected replacement enrollment: result=%#v generate_calls=%d", reissued, generateCalls)
	}
	if want := now.Add(30 * time.Minute); !reissued.ExpiresAt.Equal(want) {
		t.Fatalf("replacement expires at %s, want %s", reissued.ExpiresAt, want)
	}

	var snapshot State
	if err := service.store.View(func(state State) error { snapshot = state; return nil }); err != nil {
		t.Fatal(err)
	}
	matching := 0
	for _, enrollment := range snapshot.Enrollments {
		if enrollment.NodeID == created.Node.ID {
			matching++
			if !TokenEqual(enrollment.TokenHash, replacement) || !enrollment.ExpiresAt.Equal(reissued.ExpiresAt) {
				t.Fatalf("wrong replacement enrollment persisted: %#v", enrollment)
			}
			if TokenEqual(enrollment.TokenHash, created.EnrollmentToken) {
				t.Fatal("prior enrollment token remained usable")
			}
		}
	}
	if matching != 1 {
		t.Fatalf("pending node has %d enrollment records, want exactly one", matching)
	}
	lastAudit := snapshot.Audit[len(snapshot.Audit)-1]
	if lastAudit.Action != "node.enrollment_reissued" || lastAudit.ResourceID != created.Node.ID || lastAudit.Details["invalidated_tokens"] != 1 {
		t.Fatalf("reissue audit was not persisted: %#v", lastAudit)
	}
	persisted, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), replacement) || strings.Contains(string(persisted), created.EnrollmentToken) {
		t.Fatal("raw enrollment credential was persisted")
	}

	publicKey := testNebulaPublicKey('R')
	agentToken := strings.Repeat("s", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalidated enrollment token returned %v, want unauthorized", err)
	}
	if _, err := service.Enroll(context.Background(), replacement, publicKey, HashToken(agentToken)); err != nil {
		t.Fatalf("replacement token could not enroll: %v", err)
	}
	if _, err := service.ReissueEnrollment(created.Node.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("active node reissue returned %v, want conflict", err)
	}

	revoked, err := service.CreateNode(network.ID, CreateNodeInput{Name: "revoked-pending"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNode(revoked.Node.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReissueEnrollment(revoked.Node.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked node reissue returned %v, want conflict", err)
	}
	if _, err := service.ReissueEnrollment("missing-node"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing node reissue returned %v, want not found", err)
	}
}

func TestReissueEnrollmentInvalidatesAnInFlightClaim(t *testing.T) {
	now := time.Date(2026, 7, 19, 19, 0, 0, 0, time.UTC)
	issuer := &enrollmentBarrierIssuer{now: func() time.Time { return now }, entered: make(chan struct{}), release: make(chan struct{})}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "claim-race", CIDR: "10.72.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('T')
	oldAgentToken := strings.Repeat("t", 42) + "A"
	enrollResult := make(chan error, 1)
	go func() {
		_, enrollErr := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(oldAgentToken))
		enrollResult <- enrollErr
	}()
	<-issuer.entered
	reissued, err := service.ReissueEnrollment(created.Node.ID)
	if err != nil {
		t.Fatalf("reissue claimed enrollment: %v", err)
	}
	close(issuer.release)
	if err := <-enrollResult; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalidated in-flight enrollment committed with err=%v", err)
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 1 || nodes[0].Status != "pending" {
		t.Fatalf("in-flight invalidation changed node lifecycle: nodes=%#v err=%v", nodes, err)
	}
	newAgentToken := strings.Repeat("u", 42) + "A"
	if _, err := service.Enroll(context.Background(), reissued.EnrollmentToken, publicKey, HashToken(newAgentToken)); err != nil {
		t.Fatalf("replacement enrollment after invalidated claim: %v", err)
	}
	var issuanceCount int
	if err := service.store.View(func(state State) error { issuanceCount = len(state.Issuances); return nil }); err != nil {
		t.Fatal(err)
	}
	if issuanceCount != 1 {
		t.Fatalf("invalidated claim persisted an orphan issuance: got %d", issuanceCount)
	}
}

func TestAgentRecoveryLifecycleIsSignedBoundAndIdempotent(t *testing.T) {
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery", CIDR: "10.73.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('U')
	oldAgentToken := strings.Repeat("u", 42) + "A"
	initial, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(oldAgentToken))
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatalf("issue first recovery: %v", err)
	}
	if !ValidBearerToken(first.RecoveryToken) || !first.ExpiresAt.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("invalid recovery issuance: %#v", first)
	}
	reissued, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatalf("reissue recovery: %v", err)
	}
	var unusedAfterReissue []AgentRecoveryToken
	if err := service.store.View(func(state State) error {
		for _, candidate := range state.AgentRecoveries {
			if candidate.NodeID == created.Node.ID {
				unusedAfterReissue = append(unusedAfterReissue, candidate)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(unusedAfterReissue) != 1 || unusedAfterReissue[0].UsedAt != nil || !TokenEqual(unusedAfterReissue[0].TokenHash, reissued.RecoveryToken) {
		t.Fatalf("unused recovery reissue did not invalidate the prior token: %#v", unusedAfterReissue)
	}
	newAgentToken := strings.Repeat("v", 42) + "A"
	if _, err := service.RecoverAgent(first.RecoveryToken, publicKey, HashToken(newAgentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalidated recovery returned %v, want unauthorized", err)
	}

	recovered, err := service.RecoverAgent(reissued.RecoveryToken, publicKey, HashToken(newAgentToken))
	if err != nil {
		t.Fatalf("recover agent: %v", err)
	}
	if recovered.AgentCredentialGeneration != initial.AgentCredentialGeneration+1 || !recovered.AgentCredentialExpiresAt.Equal(now.Add(90*24*time.Hour)) {
		t.Fatalf("unexpected recovered credential metadata: %#v", recovered.EnrollmentBundle)
	}
	if recovered.RecoveryReceipt.NewAgentTokenHash != HashToken(newAgentToken) || recovered.RecoveryReceipt.ConfigSHA256 != recovered.ConfigSHA256 || recovered.RecoveryReceipt.ConfigSignature != recovered.ConfigSignature {
		t.Fatalf("receipt is not linked to recovery/bootstrap: %#v", recovered.RecoveryReceipt)
	}
	if err := VerifyConfig(recovered.ConfigSigningPublicKey, recovered.SignatureMetadata(), recovered.Config, recovered.ConfigSHA256, recovered.ConfigSignature); err != nil {
		t.Fatalf("verify recovery bootstrap: %v", err)
	}
	if err := VerifyRecoveryReceipt(recovered.ConfigSigningPublicKey, recovered.RecoveryReceipt); err != nil {
		t.Fatalf("verify recovery receipt: %v", err)
	}
	if _, err := service.AgentConfig(oldAgentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old current credential survived recovery: %v", err)
	}
	if _, err := service.AgentConfig(newAgentToken); err != nil {
		t.Fatalf("new recovered credential is not current: %v", err)
	}

	persisted, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), first.RecoveryToken) || strings.Contains(string(persisted), reissued.RecoveryToken) || strings.Contains(string(persisted), newAgentToken) {
		t.Fatal("raw recovery or agent credential was persisted")
	}
	// Prove the idempotence receipt survives a real close/reopen rather than
	// depending on fields present only in the in-memory transaction clone.
	storePath := service.store.path
	if err := service.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(storePath)
	if err != nil {
		t.Fatalf("reopen recovered state: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	service = NewService(reopened, service.box, issuer)
	service.now = func() time.Time { return now }

	// A response-loss retry remains exact after the 30-minute issuance window;
	// it returns the persisted signed result and does not increment twice.
	now = now.Add(31 * time.Minute)
	replayed, err := service.RecoverAgent(reissued.RecoveryToken, publicKey, HashToken(newAgentToken))
	if err != nil {
		t.Fatalf("exact recovery retry after issuance expiry: %v", err)
	}
	if replayed.AgentCredentialGeneration != recovered.AgentCredentialGeneration || replayed.Config != recovered.Config || replayed.ConfigSignature != recovered.ConfigSignature || replayed.RecoveryReceipt.Signature != recovered.RecoveryReceipt.Signature {
		t.Fatal("exact recovery retry did not return the committed signed result")
	}
	if err := service.store.Update(func(state *State) error {
		state.AgentRecoveries[0].Result.RecoveryReceipt.Signature = strings.Repeat("A", len(state.AgentRecoveries[0].Result.RecoveryReceipt.Signature))
		return nil
	}); err == nil || !strings.Contains(err.Error(), "invalid receipt") {
		t.Fatalf("store accepted a corrupt persisted recovery receipt: %v", err)
	}
	if _, err := service.RecoverAgent(reissued.RecoveryToken, publicKey+"changed", HashToken(newAgentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("used recovery accepted changed public key: %v", err)
	}
	changedAgentToken := strings.Repeat("w", 42) + "A"
	if _, err := service.RecoverAgent(reissued.RecoveryToken, publicKey, HashToken(changedAgentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("used recovery accepted changed agent hash: %v", err)
	}

	// Once a normal rotation advances the current credential, the old used
	// recovery record may no longer replay an actionable historic receipt.
	rotatedToken := strings.Repeat("x", 42) + "A"
	if _, err := service.RotateAgentCredential(newAgentToken, HashToken(rotatedToken)); err != nil {
		t.Fatalf("rotate recovered credential: %v", err)
	}
	if _, err := service.RotateAgentCredential(rotatedToken, HashToken(newAgentToken)); !errors.Is(err, ErrConflict) {
		t.Fatalf("rotation revived retained historic recovery credential with %v", err)
	}
	if _, err := service.RecoverAgent(reissued.RecoveryToken, publicKey, HashToken(newAgentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("historic recovery replay after rotation returned %v, want unauthorized", err)
	}
}

func TestAgentRecoveryReplacementPreservesCommittedReplayUntilNewCommit(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-replacement", CIDR: "10.78.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('1')
	originalBearer := strings.Repeat("G", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(originalBearer)); err != nil {
		t.Fatal(err)
	}

	committedToken, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	firstRecoveredBearer := strings.Repeat("H", 42) + "A"
	committed, err := service.RecoverAgent(committedToken.RecoveryToken, publicKey, HashToken(firstRecoveredBearer))
	if err != nil {
		t.Fatalf("commit first recovery: %v", err)
	}
	replacement, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatalf("issue replacement after lost response: %v", err)
	}

	var afterIssue []AgentRecoveryToken
	if err := service.store.View(func(state State) error {
		for _, candidate := range state.AgentRecoveries {
			if candidate.NodeID == created.Node.ID {
				afterIssue = append(afterIssue, candidate)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(afterIssue) != 2 {
		t.Fatalf("replacement retained %d recovery records, want committed result plus replacement", len(afterIssue))
	}
	used, unused := 0, 0
	for _, candidate := range afterIssue {
		if candidate.UsedAt != nil {
			used++
			if candidate.Result == nil || !TokenEqual(candidate.TokenHash, committedToken.RecoveryToken) {
				t.Fatalf("wrong committed recovery result was retained: %#v", candidate)
			}
		} else {
			unused++
			if !TokenEqual(candidate.TokenHash, replacement.RecoveryToken) {
				t.Fatalf("wrong unused replacement was retained: %#v", candidate)
			}
		}
	}
	if used != 1 || unused != 1 {
		t.Fatalf("recovery retention used=%d unused=%d, want one each", used, unused)
	}

	// The response-loss client can still obtain the exact signed result even
	// after an administrator has issued a newer unused token.
	replayed, err := service.RecoverAgent(committedToken.RecoveryToken, publicKey, HashToken(firstRecoveredBearer))
	if err != nil {
		t.Fatalf("replay committed recovery after replacement issuance: %v", err)
	}
	if replayed.RecoveryReceipt.Signature != committed.RecoveryReceipt.Signature || replayed.ConfigSignature != committed.ConfigSignature || replayed.AgentCredentialGeneration != committed.AgentCredentialGeneration {
		t.Fatal("retained committed recovery did not replay its exact signed result")
	}
	if _, err := service.RecoverAgent(committedToken.RecoveryToken, publicKey, HashToken(strings.Repeat("I", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retained used token accepted a changed retry: %v", err)
	}

	secondRecoveredBearer := strings.Repeat("J", 42) + "A"
	newer, err := service.RecoverAgent(replacement.RecoveryToken, publicKey, HashToken(secondRecoveredBearer))
	if err != nil {
		t.Fatalf("commit replacement recovery: %v", err)
	}
	if newer.AgentCredentialGeneration != committed.AgentCredentialGeneration+1 {
		t.Fatalf("replacement generation=%d, want %d", newer.AgentCredentialGeneration, committed.AgentCredentialGeneration+1)
	}
	var afterCommit []AgentRecoveryToken
	if err := service.store.View(func(state State) error {
		for _, candidate := range state.AgentRecoveries {
			if candidate.NodeID == created.Node.ID {
				afterCommit = append(afterCommit, candidate)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(afterCommit) != 1 || afterCommit[0].UsedAt == nil || afterCommit[0].Result == nil || !TokenEqual(afterCommit[0].TokenHash, replacement.RecoveryToken) {
		t.Fatalf("new recovery commit did not prune obsolete records: %#v", afterCommit)
	}
	if _, err := service.RecoverAgent(committedToken.RecoveryToken, publicKey, HashToken(firstRecoveredBearer)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pruned recovery token returned %v, want unauthorized", err)
	}
	if replay, err := service.RecoverAgent(replacement.RecoveryToken, publicKey, HashToken(secondRecoveredBearer)); err != nil || replay.RecoveryReceipt.Signature != newer.RecoveryReceipt.Signature {
		t.Fatalf("current committed recovery no longer replayed exactly: err=%v", err)
	}

	persisted, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	for label, raw := range map[string]string{
		"committed recovery token":   committedToken.RecoveryToken,
		"replacement recovery token": replacement.RecoveryToken,
		"first recovered bearer":     firstRecoveredBearer,
		"second recovered bearer":    secondRecoveredBearer,
	} {
		if strings.Contains(string(persisted), raw) {
			t.Fatalf("raw %s was persisted", label)
		}
	}
}

func TestAgentRecoveryReissueAndRevocationInvalidateInflightClaims(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-race", CIDR: "10.74.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('V')
	oldAgentToken := strings.Repeat("y", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(oldAgentToken)); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	service.recoveryClaimed = func() { close(entered); <-release }
	newAgentToken := strings.Repeat("z", 42) + "A"
	recovered := make(chan error, 1)
	go func() {
		_, recoverErr := service.RecoverAgent(issued.RecoveryToken, publicKey, HashToken(newAgentToken))
		recovered <- recoverErr
	}()
	<-entered
	if _, err := service.RecoverAgent(issued.RecoveryToken, publicKey, HashToken(newAgentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("concurrent identical recovery returned %v, want one in-flight winner", err)
	}
	if _, err := service.RecoverAgent(issued.RecoveryToken, publicKey, HashToken(strings.Repeat("Q", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("concurrent changed recovery returned %v, want one in-flight winner", err)
	}
	replacement, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatalf("invalidate in-flight recovery: %v", err)
	}
	close(release)
	if err := <-recovered; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalidated in-flight recovery committed with err=%v", err)
	}
	service.recoveryClaimed = nil
	if _, err := service.AgentConfig(oldAgentToken); err != nil {
		t.Fatalf("failed recovery changed current credential: %v", err)
	}
	if _, err := service.RecoverAgent(replacement.RecoveryToken, publicKey, HashToken(newAgentToken)); err != nil {
		t.Fatalf("replacement recovery failed: %v", err)
	}

	revocationToken, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	revocationEntered, releaseRevocation := make(chan struct{}), make(chan struct{})
	service.recoveryClaimed = func() { close(revocationEntered); <-releaseRevocation }
	revokedRecoveryResult := make(chan error, 1)
	go func() {
		_, recoverErr := service.RecoverAgent(revocationToken.RecoveryToken, publicKey, HashToken(strings.Repeat("0", 42)+"A"))
		revokedRecoveryResult <- recoverErr
	}()
	<-revocationEntered
	if _, err := service.RevokeNode(created.Node.ID); err != nil {
		t.Fatal(err)
	}
	close(releaseRevocation)
	if err := <-revokedRecoveryResult; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("in-flight recovery survived revocation with %v", err)
	}
	service.recoveryClaimed = nil
	var recoveryCount int
	if err := service.store.View(func(state State) error { recoveryCount = len(state.AgentRecoveries); return nil }); err != nil {
		t.Fatal(err)
	}
	if recoveryCount != 0 {
		t.Fatalf("revocation retained %d agent recovery records", recoveryCount)
	}
}

func TestAgentRecoveryAndNormalRotationHaveOneOrderedWinner(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 30, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-rotation-race", CIDR: "10.76.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}

	enroll := func(name, keyCharacter, tokenCharacter string) (CreatedNode, string, string) {
		t.Helper()
		created, createErr := service.CreateNode(network.ID, CreateNodeInput{Name: name})
		if createErr != nil {
			t.Fatal(createErr)
		}
		publicKey := testNebulaPublicKey(keyCharacter[0])
		agentToken := strings.Repeat(tokenCharacter, 42) + "A"
		if _, enrollErr := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken)); enrollErr != nil {
			t.Fatal(enrollErr)
		}
		return created, publicKey, agentToken
	}

	// Rotation commits between recovery claim and final commit. The generation
	// compare makes recovery lose without disturbing the rotated credential.
	first, firstKey, firstToken := enroll("rotation-first", "Y", "7")
	firstRecovery, err := service.IssueAgentRecovery(first.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimEntered, releaseClaim := make(chan struct{}), make(chan struct{})
	service.recoveryClaimed = func() { close(claimEntered); <-releaseClaim }
	recoveryToken := strings.Repeat("8", 42) + "A"
	recoveryResult := make(chan error, 1)
	go func() {
		_, recoverErr := service.RecoverAgent(firstRecovery.RecoveryToken, firstKey, HashToken(recoveryToken))
		recoveryResult <- recoverErr
	}()
	<-claimEntered
	rotatedToken := strings.Repeat("9", 42) + "A"
	if _, err := service.RotateAgentCredential(firstToken, HashToken(rotatedToken)); err != nil {
		t.Fatalf("rotation did not win while recovery was claimed: %v", err)
	}
	close(releaseClaim)
	if err := <-recoveryResult; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("recovery overwrote intervening rotation: %v", err)
	}
	service.recoveryClaimed = nil
	if _, err := service.AgentConfig(rotatedToken); err != nil {
		t.Fatalf("winning rotation credential is unusable: %v", err)
	}
	if _, err := service.AgentConfig(recoveryToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("losing recovery credential returned %v", err)
	}

	// Recovery commits after rotation's read-only preflight but before its store
	// transaction. Clearing old current+grace makes the stale rotation lose.
	second, secondKey, secondToken := enroll("recovery-first", "Z", "A")
	secondRecovery, err := service.IssueAgentRecovery(second.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	rotationEntered, releaseRotation := make(chan struct{}), make(chan struct{})
	service.credentialRotationPreflighted = func() { close(rotationEntered); <-releaseRotation }
	staleRotationToken := strings.Repeat("B", 42) + "A"
	rotationResult := make(chan error, 1)
	go func() {
		_, rotateErr := service.RotateAgentCredential(secondToken, HashToken(staleRotationToken))
		rotationResult <- rotateErr
	}()
	<-rotationEntered
	winningRecoveryToken := strings.Repeat("C", 42) + "A"
	if _, err := service.RecoverAgent(secondRecovery.RecoveryToken, secondKey, HashToken(winningRecoveryToken)); err != nil {
		t.Fatalf("recovery did not win after rotation preflight: %v", err)
	}
	close(releaseRotation)
	if err := <-rotationResult; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("preflighted old-bearer rotation survived recovery: %v", err)
	}
	service.credentialRotationPreflighted = nil
	if _, err := service.AgentConfig(winningRecoveryToken); err != nil {
		t.Fatalf("winning recovery credential is unusable: %v", err)
	}
}

func TestAgentRecoveryRejectsCrossDomainCredentialCollisions(t *testing.T) {
	now := time.Date(2026, 7, 19, 22, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-collisions", CIDR: "10.75.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('W')
	currentToken := strings.Repeat("1", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(currentToken)); err != nil {
		t.Fatal(err)
	}
	previousToken := currentToken
	currentToken = strings.Repeat("2", 42) + "A"
	if _, err := service.RotateAgentCredential(previousToken, HashToken(currentToken)); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, hash := range map[string]string{
		"current":        HashToken(currentToken),
		"grace":          HashToken(previousToken),
		"enrollment":     HashToken(created.EnrollmentToken),
		"recovery token": HashToken(issued.RecoveryToken),
	} {
		if _, err := service.RecoverAgent(issued.RecoveryToken, publicKey, hash); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s collision returned %v, want conflict", name, err)
		}
	}

	// Recovery-token generation retries collisions across retained domains
	// instead of letting graph validation turn one into an internal error.
	unique := strings.Repeat("3", 42) + "A"
	generated := []string{previousToken, created.EnrollmentToken, issued.RecoveryToken, unique}
	calls := 0
	service.generateBearer = func() (string, error) {
		value := generated[calls]
		calls++
		return value, nil
	}
	replacement, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatalf("recovery generator collision retry: %v", err)
	}
	if replacement.RecoveryToken != unique || calls != len(generated) {
		t.Fatalf("recovery generator did not retry all domains: token=%q calls=%d", replacement.RecoveryToken, calls)
	}
}

func TestAgentRecoveryExpiryAndGenerationOverflowFailWithoutMutation(t *testing.T) {
	now := time.Date(2026, 7, 19, 23, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-boundaries", CIDR: "10.77.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('0')
	oldAgentToken := strings.Repeat("D", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(oldAgentToken)); err != nil {
		t.Fatal(err)
	}
	expired, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	now = expired.ExpiresAt
	if _, err := service.RecoverAgent(expired.RecoveryToken, publicKey, HashToken(strings.Repeat("E", 42)+"A")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unused recovery at exact expiry returned %v, want unauthorized", err)
	}

	now = now.Add(time.Second)
	overflow, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.store.Update(func(state *State) error {
		for i := range state.Nodes {
			if state.Nodes[i].ID == created.Node.ID {
				state.Nodes[i].AgentCredentialGeneration = int64(^uint64(0) >> 1)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	newHash := HashToken(strings.Repeat("F", 42) + "A")
	if _, err := service.RecoverAgent(overflow.RecoveryToken, publicKey, newHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("generation overflow recovery returned %v, want conflict", err)
	}
	var persisted Node
	var claim AgentRecoveryToken
	if err := service.store.View(func(state State) error {
		persisted, _ = findNode(state, created.Node.ID)
		for _, candidate := range state.AgentRecoveries {
			if candidate.NodeID == created.Node.ID {
				claim = candidate
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if persisted.AgentCredentialGeneration != int64(^uint64(0)>>1) || persisted.AgentTokenHash != HashToken(oldAgentToken) || claim.ClaimID != "" || claim.ClaimedCredentialGeneration != 0 || claim.UsedAt != nil {
		t.Fatalf("overflow recovery mutated credential or retained claim: node=%#v recovery=%#v", persisted, claim)
	}
}

func TestRandomCredentialsAreRejectedBeforeCloningState(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	randomToken := strings.Repeat("x", 42) + "A"
	publicKey := testNebulaPublicKey('I')
	before := service.store.cloneCount.Load()

	checks := []error{}
	_, err := service.AgentConfig(randomToken)
	checks = append(checks, err)
	_, err = service.AgentBootstrap(randomToken)
	checks = append(checks, err)
	_, err = service.Heartbeat(randomToken, HeartbeatInput{AgentVersion: "0.1.0", NebulaVersion: "1.10.3", Status: "healthy", BootID: "boot-preflight", Sequence: 1})
	checks = append(checks, err)
	_, err = service.RotateAgentCredential(randomToken, HashToken("next-token"))
	checks = append(checks, err)
	_, err = service.Renew(context.Background(), randomToken, publicKey)
	checks = append(checks, err)
	_, err = service.Enroll(context.Background(), randomToken, publicKey, HashToken("agent-token"))
	checks = append(checks, err)

	for i, checkErr := range checks {
		if !errors.Is(checkErr, ErrUnauthorized) {
			t.Fatalf("preflight %d returned %v, want unauthorized", i, checkErr)
		}
	}
	if after := service.store.cloneCount.Load(); after != before {
		t.Fatalf("random credentials caused full-state clones: before=%d after=%d", before, after)
	}
}

func TestHeartbeatRejectsUnattainableAndPoisoningCounters(t *testing.T) {
	now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "heartbeat-bounds", CIDR: "10.73.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('J')
	agentToken := strings.Repeat("v", 42) + "A"
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	valid := HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3",
		AppliedConfigRevision: bundle.ConfigRevision, CertificateGeneration: bundle.CertificateGeneration,
		AppliedConfigSHA256: bundle.ConfigSHA256, CertificateFingerprint: bundle.CertificateFingerprint,
		NebulaRunning: true, Status: "healthy", BootID: "boot-bounds", Sequence: 1,
	}

	invalid := map[string]HeartbeatInput{
		"future revision":               func() HeartbeatInput { value := valid; value.AppliedConfigRevision++; return value }(),
		"future certificate generation": func() HeartbeatInput { value := valid; value.CertificateGeneration++; return value }(),
		"negative revision":             func() HeartbeatInput { value := valid; value.AppliedConfigRevision = -1; return value }(),
		"negative certificate generation": func() HeartbeatInput {
			value := valid
			value.CertificateGeneration = -1
			return value
		}(),
		"sequence poisoning": func() HeartbeatInput {
			value := valid
			value.Sequence = maxPersistedHeartbeatSequence + 1
			return value
		}(),
		"digest without revision": func() HeartbeatInput {
			value := valid
			value.AppliedConfigRevision = 0
			return value
		}(),
	}
	for name, heartbeat := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, heartbeatErr := service.Heartbeat(agentToken, heartbeat); !errors.Is(heartbeatErr, ErrInvalid) {
				t.Fatalf("heartbeat returned %v, want invalid input", heartbeatErr)
			}
		})
	}

	accepted, err := service.Heartbeat(agentToken, valid)
	if err != nil {
		t.Fatalf("valid bounded heartbeat: %v", err)
	}
	if accepted.HeartbeatSequence != 1 || accepted.AppliedConfigRevision != bundle.ConfigRevision || accepted.AppliedCertificateGeneration != bundle.CertificateGeneration {
		t.Fatalf("valid heartbeat did not commit its exact applied state: %#v", accepted)
	}

	// Zero is retained solely as the legacy omitted-field value. An exact
	// authoritative fingerprint lets the server infer and persist the current
	// certificate generation without weakening the upper bound.
	now = now.Add(6 * time.Second)
	legacy := valid
	legacy.CertificateGeneration = 0
	legacy.Sequence = 2
	accepted, err = service.Heartbeat(agentToken, legacy)
	if err != nil || accepted.AppliedCertificateGeneration != bundle.CertificateGeneration {
		t.Fatalf("legacy heartbeat was not safely inferred: node=%#v err=%v", accepted, err)
	}
}

func TestRuntimeTelemetryAuthorizationRequiresExactAcceptedHeartbeat(t *testing.T) {
	now := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "telemetry-auth", CIDR: "10.75.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("w", 42) + "A"
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('K'), HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizeRuntimeTelemetry(agentToken, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-heartbeat authorization returned %v", err)
	}
	heartbeat := HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: bundle.ConfigRevision,
		CertificateGeneration: bundle.CertificateGeneration, AppliedConfigSHA256: bundle.ConfigSHA256,
		CertificateFingerprint: bundle.CertificateFingerprint, NebulaRunning: true, Status: "healthy",
		BootID: "boot-telemetry", Sequence: 1,
	}
	if _, err := service.Heartbeat(agentToken, heartbeat); err != nil {
		t.Fatal(err)
	}
	node, err := service.AuthorizeRuntimeTelemetry(agentToken, 1)
	if err != nil || node.ID != created.Node.ID {
		t.Fatalf("authorized node=%+v err=%v", node, err)
	}
	if _, err := service.AuthorizeRuntimeTelemetry(agentToken, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("future heartbeat authorization returned %v", err)
	}
	if _, err := service.AuthorizeRuntimeTelemetry(strings.Repeat("x", 42)+"A", 1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong bearer authorization returned %v", err)
	}
	if _, err := service.RevokeNode(created.Node.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizeRuntimeTelemetry(agentToken, 1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked authorization returned %v", err)
	}
}

func TestCredentialHashesRemainGloballyUniqueAndMonotonic(t *testing.T) {
	now := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "credential-bounds", CIDR: "10.74.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-02"})
	if err != nil {
		t.Fatal(err)
	}
	firstPublicKey := testNebulaPublicKey('K')
	secondPublicKey := testNebulaPublicKey('L')
	oldToken := strings.Repeat("m", 42) + "A"
	currentToken := strings.Repeat("n", 42) + "A"
	secondToken := strings.Repeat("o", 42) + "A"
	uniqueEnrollmentToken := strings.Repeat("p", 42) + "A"
	if _, err := service.Enroll(context.Background(), first.EnrollmentToken, firstPublicKey, HashToken(oldToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RotateAgentCredential(oldToken, HashToken(currentToken)); err != nil {
		t.Fatal(err)
	}
	signsBeforeCollision := issuer.signCalls.Load()
	if _, err := service.Enroll(context.Background(), second.EnrollmentToken, secondPublicKey, HashToken(currentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("enrollment reused another node's current credential: %v", err)
	}
	if issuer.signCalls.Load() != signsBeforeCollision {
		t.Fatal("credential collision reached certificate issuance")
	}
	if _, err := service.Enroll(context.Background(), second.EnrollmentToken, secondPublicKey, HashToken(secondToken)); err != nil {
		t.Fatalf("enroll with unique credential: %v", err)
	}

	generated := []string{currentToken, oldToken, uniqueEnrollmentToken}
	generateCalls := 0
	service.generateBearer = func() (string, error) {
		if generateCalls >= len(generated) {
			return "", errors.New("unexpected extra generation attempt")
		}
		value := generated[generateCalls]
		generateCalls++
		return value, nil
	}
	third, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-03"})
	if err != nil {
		t.Fatalf("generate unique enrollment bearer: %v", err)
	}
	if third.EnrollmentToken != uniqueEnrollmentToken || generateCalls != 3 {
		t.Fatalf("bearer generator did not retry current and grace collisions: token=%q calls=%d", third.EnrollmentToken, generateCalls)
	}

	if _, err := service.RotateAgentCredential(currentToken, HashToken(secondToken)); !errors.Is(err, ErrConflict) {
		t.Fatalf("rotation aliased another node's credential: %v", err)
	}
	if _, err := service.RotateAgentCredential(currentToken, HashToken(oldToken)); !errors.Is(err, ErrConflict) {
		t.Fatalf("rotation regressed to the grace credential: %v", err)
	}
	nextToken := strings.Repeat("q", 42) + "A"
	rotation, err := service.RotateAgentCredential(currentToken, HashToken(nextToken))
	if err != nil || rotation.Generation != 3 {
		t.Fatalf("unique rotation did not advance exactly once: rotation=%#v err=%v", rotation, err)
	}
	replayed, err := service.RotateAgentCredential(nextToken, HashToken(nextToken))
	if err != nil || replayed.Generation != rotation.Generation || !replayed.ExpiresAt.Equal(rotation.ExpiresAt) {
		t.Fatalf("idempotent rotation changed authoritative state: replay=%#v err=%v", replayed, err)
	}

	if err := service.store.Update(func(state *State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID == first.Node.ID {
				state.Nodes[index].AgentCredentialGeneration = int64(^uint64(0) >> 1)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RotateAgentCredential(nextToken, HashToken(strings.Repeat("s", 42)+"A")); !errors.Is(err, ErrConflict) {
		t.Fatalf("overflowing rotation was accepted: %v", err)
	}
	var persisted Node
	if err := service.store.View(func(state State) error {
		persisted, _ = findNode(state, first.Node.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if persisted.AgentCredentialGeneration != int64(^uint64(0)>>1) || persisted.AgentTokenHash != HashToken(nextToken) {
		t.Fatalf("rejected rotation regressed authoritative credential state: %#v", persisted)
	}
}

func TestEncryptedCAKeyIsNotPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, _ := NewSecretBox(make([]byte, 32))
	service := NewService(store, box, NebulaIssuer{})
	if _, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "secure", CIDR: "10.60.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "NEBULA ED25519 PRIVATE KEY") || strings.Contains(string(b), "NEBULA P256 PRIVATE KEY") {
		t.Fatal("plaintext CA private key was persisted")
	}
}

func TestEnsureManagedNetworksValidatesAndMigratesSigningState(t *testing.T) {
	t.Run("rejects mismatched complete key pair", func(t *testing.T) {
		service := testServiceWithIssuer(t, &countingIssuer{})
		network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "mismatch", CIDR: "10.61.0.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		_, wrongPrivateKey, err := GenerateConfigSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := service.box.SealFor("config-signing-key-v1", wrongPrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		for i := range wrongPrivateKey {
			wrongPrivateKey[i] = 0
		}
		if err := service.store.Update(func(state *State) error {
			for i := range state.Networks {
				if state.Networks[i].ID == network.ID {
					state.Networks[i].EncryptedConfigSigningKey = encrypted
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureManagedNetworks(); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("mismatched signing key pair was accepted: %v", err)
		}
	})

	t.Run("rejects missing signing state on a network with nodes", func(t *testing.T) {
		service := testServiceWithIssuer(t, &countingIssuer{})
		network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "in-use", CIDR: "10.62.0.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"}); err != nil {
			t.Fatal(err)
		}
		if err := service.store.Update(func(state *State) error {
			for i := range state.Networks {
				if state.Networks[i].ID == network.ID {
					state.Networks[i].ConfigSigningPublicKey = ""
					state.Networks[i].EncryptedConfigSigningKey = ""
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureManagedNetworks(); err == nil || !strings.Contains(err.Error(), "has nodes") {
			t.Fatalf("missing signing key pair on an in-use network was accepted: %v", err)
		}
	})

	t.Run("rejects a partial signing key pair", func(t *testing.T) {
		service := testServiceWithIssuer(t, &countingIssuer{})
		network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "partial", CIDR: "10.65.0.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"}); err != nil {
			t.Fatal(err)
		}
		if err := service.store.Update(func(state *State) error {
			for i := range state.Networks {
				if state.Networks[i].ID == network.ID {
					state.Networks[i].EncryptedConfigSigningKey = ""
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureManagedNetworks(); err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("partial signing key pair was accepted: %v", err)
		}
	})

	t.Run("generates signing state only for an empty legacy network", func(t *testing.T) {
		service := testServiceWithIssuer(t, &countingIssuer{})
		network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "empty", CIDR: "10.63.0.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.store.Update(func(state *State) error {
			for i := range state.Networks {
				if state.Networks[i].ID == network.ID {
					state.Networks[i].ConfigSigningPublicKey = ""
					state.Networks[i].EncryptedConfigSigningKey = ""
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureManagedNetworks(); err != nil {
			t.Fatalf("migrate empty legacy network: %v", err)
		}
		if err := service.EnsureManagedNetworks(); err != nil {
			t.Fatalf("validate migrated signing state: %v", err)
		}
	})

	t.Run("migrates an enrolled node to certificate generation one", func(t *testing.T) {
		service := testServiceWithIssuer(t, &countingIssuer{})
		network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "generation", CIDR: "10.66.0.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
		if err != nil {
			t.Fatal(err)
		}
		publicKey := testNebulaPublicKey('G')
		agentToken := strings.Repeat("v", 42) + "A"
		if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken)); err != nil {
			t.Fatal(err)
		}
		if err := service.store.Update(func(state *State) error {
			for i := range state.Nodes {
				if state.Nodes[i].ID == created.Node.ID {
					state.Nodes[i].CertificateGeneration = 0
					state.Nodes[i].CertificateRenewAfter = nil
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := service.EnsureManagedNetworks(); err != nil {
			t.Fatalf("migrate certificate generation: %v", err)
		}
		desired, err := service.AgentConfig(agentToken)
		if err != nil || desired.CertificateGeneration != 1 {
			t.Fatalf("legacy certificate generation was not migrated: generation=%d err=%v", desired.CertificateGeneration, err)
		}
		if want := desired.CertificateExpiresAt.Add(-renewalWindow(time.Duration(network.CertificateTTL) * time.Hour)); !desired.CertificateRenewAfter.Equal(want) {
			t.Fatalf("legacy renew-after was not migrated: got=%s want=%s", desired.CertificateRenewAfter, want)
		}
	})
}

func TestConcurrentNetworkCreationRechecksUniquenessInTransaction(t *testing.T) {
	issuer := &networkBarrierIssuer{ready: make(chan struct{})}
	service := testServiceWithIssuer(t, issuer)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "same", CIDR: "10.64.0.0/24"})
			errs <- err
		}()
	}
	var succeeded, conflicted int
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected network creation error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent duplicate creation results: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("duplicate network was committed: networks=%d err=%v", len(networks), err)
	}
}

func TestConcurrentEnrollmentSignsOnlyOnce(t *testing.T) {
	issuer := &countingIssuer{delay: 25 * time.Millisecond}
	service := testServiceWithIssuer(t, issuer)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "race", CIDR: "10.70.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('A')
	agentToken := strings.Repeat("r", 42) + "A"
	const attempts = 20
	start := make(chan struct{})
	results := make(chan EnrollmentBundle, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken))
			if err == nil {
				results <- bundle
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	if issuer.signCalls.Load() != 1 {
		t.Fatalf("concurrent enrollment signed %d certificates", issuer.signCalls.Load())
	}
	var certificate string
	successes := 0
	for result := range results {
		successes++
		if certificate == "" {
			certificate = result.Certificate
		} else if certificate != result.Certificate {
			t.Fatal("idempotent enrollment returned different certificates")
		}
	}
	if successes == 0 {
		t.Fatal("no concurrent enrollment request succeeded")
	}
}

func TestEnrollmentRejectsCertificateShorterThanRenewalWindow(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }, expiresAfter: 4 * time.Hour}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "short-cert", CIDR: "10.67.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('H')
	agentToken := strings.Repeat("w", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken)); err == nil || !strings.Contains(err.Error(), "renewal metadata") {
		t.Fatalf("certificate shorter than renewal window was accepted: %v", err)
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 1 || nodes[0].Status != "pending" || nodes[0].Certificate != "" {
		t.Fatalf("rejected short certificate mutated the node: nodes=%#v err=%v", nodes, err)
	}
}

func TestRenewalOverlapAndRevocationHistory(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, _ := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "renew", CIDR: "10.71.0.0/24", CertificateTTL: 24})
	created, _ := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01"})
	publicKey := testNebulaPublicKey('B')
	agentToken := strings.Repeat("s", 42) + "A"
	first, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(23 * time.Hour)
	renewed, err := service.Renew(context.Background(), agentToken, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Certificate == first.Certificate || issuer.signCalls.Load() != 2 {
		t.Fatalf("renewal did not issue exactly one replacement: calls=%d", issuer.signCalls.Load())
	}
	if renewed.ConfigRevision != first.ConfigRevision || !renewed.ConfigIssuedAt.Equal(first.ConfigIssuedAt) || renewed.CertificateGeneration != first.CertificateGeneration+1 {
		t.Fatalf("renewal changed the network revision or failed to advance certificate generation: first_rev=%d renewed_rev=%d first_gen=%d renewed_gen=%d", first.ConfigRevision, renewed.ConfigRevision, first.CertificateGeneration, renewed.CertificateGeneration)
	}
	if want := renewed.CertificateExpiresAt.Add(-8 * time.Hour); !renewed.CertificateRenewAfter.Equal(want) || !renewed.CertificateRenewAfter.After(first.CertificateRenewAfter) {
		t.Fatalf("renewal did not advance exact renew-after: first=%s renewed=%s want=%s", first.CertificateRenewAfter, renewed.CertificateRenewAfter, want)
	}
	if renewed.CACertificateSHA256 != ConfigDigest(renewed.CA) || renewed.CertificateFingerprint == first.CertificateFingerprint || renewed.PublicKeyHash != first.PublicKeyHash {
		t.Fatalf("renewal response metadata was not bound to the replacement certificate: %#v", renewed)
	}
	if err := VerifyConfig(first.ConfigSigningPublicKey, renewed.SignatureMetadata(), renewed.Config, renewed.ConfigSHA256, renewed.ConfigSignature); err != nil {
		t.Fatalf("verify renewal artifact: %v", err)
	}
	replayed, err := service.Renew(context.Background(), agentToken, publicKey)
	if err != nil || replayed.Certificate != renewed.Certificate || replayed.ConfigRevision != renewed.ConfigRevision || replayed.ConfigSignature != renewed.ConfigSignature || issuer.signCalls.Load() != 2 {
		t.Fatalf("renewal replay was not idempotent: err=%v calls=%d", err, issuer.signCalls.Load())
	}
	var state State
	_ = service.store.View(func(value State) error { state = value; return nil })
	if len(state.Issuances) != 2 || len(state.Revocations) != 0 {
		t.Fatalf("renewal did not retain an unblocked overlap: issuances=%d revocations=%d", len(state.Issuances), len(state.Revocations))
	}
	if _, err := service.RevokeNode(created.Node.ID); err != nil {
		t.Fatal(err)
	}
	_ = service.store.View(func(value State) error { state = value; return nil })
	if len(state.Revocations) != 2 {
		t.Fatalf("node revocation missed issuance history: %#v", state.Revocations)
	}
}

func TestRenewalCommitSignsLatestConcurrentNetworkRevision(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	issuer := &renewalBarrierIssuer{
		now:     func() time.Time { return now },
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "concurrent-renew", CIDR: "10.72.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member-01"})
	if err != nil {
		t.Fatal(err)
	}
	memberPublicKey := testNebulaPublicKey('E')
	memberToken := strings.Repeat("t", 42) + "A"
	memberBundle, err := service.Enroll(context.Background(), member.EnrollmentToken, memberPublicKey, HashToken(memberToken))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(23 * time.Hour)
	lighthouse, err := service.CreateNode(network.ID, CreateNodeInput{Name: "lighthouse-01", Role: "lighthouse", PublicEndpoint: "vpn.example.com:4242"})
	if err != nil {
		t.Fatal(err)
	}
	type renewalResult struct {
		bundle RenewalBundle
		err    error
	}
	renewed := make(chan renewalResult, 1)
	go func() {
		bundle, renewErr := service.Renew(context.Background(), memberToken, memberPublicKey)
		renewed <- renewalResult{bundle: bundle, err: renewErr}
	}()
	<-issuer.entered

	lighthousePublicKey := testNebulaPublicKey('F')
	lighthouseToken := strings.Repeat("u", 42) + "A"
	lighthouseBundle, err := service.Enroll(context.Background(), lighthouse.EnrollmentToken, lighthousePublicKey, HashToken(lighthouseToken))
	if err != nil {
		t.Fatal(err)
	}
	close(issuer.release)
	result := <-renewed
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.bundle.ConfigRevision != lighthouseBundle.ConfigRevision || result.bundle.ConfigRevision != memberBundle.ConfigRevision+1 {
		t.Fatalf("renewal signed stale network revision: before=%d lighthouse=%d renewal=%d", memberBundle.ConfigRevision, lighthouseBundle.ConfigRevision, result.bundle.ConfigRevision)
	}
	if !strings.Contains(result.bundle.Config, "vpn.example.com:4242") {
		t.Fatal("renewal signed a config that omitted the concurrently enrolled lighthouse")
	}
	if err := VerifyConfig(memberBundle.ConfigSigningPublicKey, result.bundle.SignatureMetadata(), result.bundle.Config, result.bundle.ConfigSHA256, result.bundle.ConfigSignature); err != nil {
		t.Fatalf("verify concurrent renewal artifact: %v", err)
	}
}

type countingIssuer struct {
	signCalls    atomic.Int32
	delay        time.Duration
	now          func() time.Time
	expiresAfter time.Duration
}

type networkBarrierIssuer struct {
	calls atomic.Int32
	ready chan struct{}
}

type renewalBarrierIssuer struct {
	calls   atomic.Int32
	now     func() time.Time
	entered chan struct{}
	release chan struct{}
}

type enrollmentBarrierIssuer struct {
	calls   atomic.Int32
	now     func() time.Time
	entered chan struct{}
	release chan struct{}
}

func (i *enrollmentBarrierIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	return "test-ca", "test-ca-private-key", nil
}

func (i *enrollmentBarrierIssuer) SignPublicKey(_ context.Context, _, _, _, _, _, _, _ string, ttl time.Duration) (string, string, time.Time, error) {
	call := i.calls.Add(1)
	if call == 1 {
		close(i.entered)
		<-i.release
	}
	return fmt.Sprintf("certificate-%d", call), fmt.Sprintf("%064x", call), i.now().Add(ttl).UTC(), nil
}

func (i *renewalBarrierIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	return "test-ca", "test-ca-private-key", nil
}

func (i *renewalBarrierIssuer) SignPublicKey(_ context.Context, _, _, _, _, _, _, _ string, ttl time.Duration) (string, string, time.Time, error) {
	call := i.calls.Add(1)
	if call == 2 {
		close(i.entered)
		<-i.release
	}
	return fmt.Sprintf("certificate-%d", call), fmt.Sprintf("%064x", call), i.now().Add(ttl).UTC(), nil
}

func (i *networkBarrierIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	if i.calls.Add(1) == 2 {
		close(i.ready)
	}
	<-i.ready
	return "test-ca", "test-ca-private-key", nil
}

func (i *networkBarrierIssuer) SignPublicKey(context.Context, string, string, string, string, string, string, string, time.Duration) (string, string, time.Time, error) {
	return "", "", time.Time{}, errors.New("not implemented")
}

func (f *countingIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	return "test-ca", "test-ca-private-key", nil
}

func (f *countingIssuer) SignPublicKey(_ context.Context, _, _, _, _, _, _, _ string, ttl time.Duration) (string, string, time.Time, error) {
	call := f.signCalls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	now := time.Now().UTC()
	if f.now != nil {
		now = f.now()
	}
	validity := ttl
	if f.expiresAfter > 0 {
		validity = f.expiresAfter
	}
	return fmt.Sprintf("certificate-%d", call), fmt.Sprintf("%064x", call), now.Add(validity).UTC(), nil
}

func testService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewService(store, box, NebulaIssuer{})
}

func testServiceWithIssuer(t *testing.T, issuer CertificateIssuer) *Service {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewService(store, box, issuer)
}
