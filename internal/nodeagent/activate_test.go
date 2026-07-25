package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mesh/internal/control"
)

func TestActivatorStagesValidatesAndAtomicallySwitches(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	runner := newFakeCommandRunner()
	reloader := &fakeReloader{}
	activator := testActivator(outputDir, signer, runner, reloader)
	bundle := signer.bundle(t, 1, testNebulaConfig("revision-one"), "certificate-one")
	activation, err := activator.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatalf("apply bundle: %v", err)
	}
	if activation.CertificateExpiresAt != runner.expiryFor("certificate-one") {
		t.Fatalf("certificate expiry = %s", activation.CertificateExpiresAt)
	}
	target, err := os.Readlink(filepath.Join(outputDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.ToSlash(target), "versions/r00000000000000000001-") {
		t.Fatalf("current target = %q", target)
	}
	runtimeConfig, err := os.ReadFile(filepath.Join(outputDir, "current", "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtimeConfig), filepath.ToSlash(filepath.Join(outputDir, "current", "host.key"))) || strings.Contains(string(runtimeConfig), "/etc/nebula/host.key") {
		t.Fatalf("runtime config did not target the current symlink:\n%s", runtimeConfig)
	}
	if _, err := os.Stat(filepath.Join(activation.VersionDir, "config.validate.yml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validation-only config remained live: %v", err)
	}
	current, err := activator.CurrentBundle(context.Background())
	if err != nil {
		t.Fatalf("read current bundle: %v", err)
	}
	if current.Revision != 1 || current.Digest != bundle.Digest || current.PrivateKey != bundle.PrivateKey {
		t.Fatalf("unexpected current bundle: %#v", current)
	}
	if reloader.Calls() != 1 {
		t.Fatalf("reload calls = %d, want 1", reloader.Calls())
	}
	if err := PreflightManagedOutput(outputDir); err != nil {
		t.Fatalf("preflight rejected valid managed output: %v", err)
	}
	quiet := runner.QuietCalls()
	if len(quiet) != 4 || quiet[0][1] != "verify" || quiet[1][1] != "-test" {
		t.Fatalf("validator commands = %#v", quiet)
	}
}

func TestPreflightManagedOutputRejectsUnsafeParentAndTarget(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := PreflightManagedOutput(filepath.Join(shared, "nebula")); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("world-writable parent error = %v", err)
	}

	realParent := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(realParent, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := PreflightManagedOutput(filepath.Join(linkedParent, "private", "nebula")); err == nil || !strings.Contains(err.Error(), "traverse symlinks") {
		t.Fatalf("symlink-ancestor parent error = %v", err)
	}

	privateParent := filepath.Join(root, "private")
	if err := os.Mkdir(privateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(privateParent, "occupied")
	if err := os.Mkdir(occupied, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "user-data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreflightManagedOutput(occupied); err == nil || !strings.Contains(err.Error(), "unused") {
		t.Fatalf("occupied target error = %v", err)
	}
}

func TestActivatorRollsBackReloadFailure(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	runner := newFakeCommandRunner()
	reloader := &fakeReloader{failAt: map[int]error{2: errors.New("reload rejected")}}
	activator := testActivator(outputDir, signer, runner, reloader)
	first := signer.bundle(t, 1, testNebulaConfig("one"), "certificate-one")
	if _, err := activator.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	originalTarget, _ := os.Readlink(filepath.Join(outputDir, "current"))
	second := signer.bundle(t, 2, testNebulaConfig("two"), "certificate-two")
	if _, err := activator.Apply(context.Background(), second); err == nil || !strings.Contains(err.Error(), "reload staged") {
		t.Fatalf("reload failure = %v", err)
	}
	restoredTarget, _ := os.Readlink(filepath.Join(outputDir, "current"))
	if restoredTarget != originalTarget {
		t.Fatalf("current target = %q, want rollback to %q", restoredTarget, originalTarget)
	}
	if reloader.Calls() != 3 {
		t.Fatalf("reload calls = %d, want new failure plus rollback reload", reloader.Calls())
	}
	current, err := activator.CurrentBundle(context.Background())
	if err != nil || current.Revision != 1 {
		t.Fatalf("current after rollback = %#v, err=%v", current, err)
	}
}

func TestActivatorRollsBackPostSwapSyncFailure(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	runner := newFakeCommandRunner()
	reloader := &fakeReloader{}
	activator := testActivator(outputDir, signer, runner, reloader)
	if _, err := activator.Apply(context.Background(), signer.bundle(t, 1, testNebulaConfig("one"), "certificate-one")); err != nil {
		t.Fatal(err)
	}
	originalTarget, _ := os.Readlink(filepath.Join(outputDir, "current"))
	failed := false
	activator.syncFn = func(path string) error {
		if filepath.Clean(path) == filepath.Clean(outputDir) && !failed {
			failed = true
			return errors.New("injected directory sync failure")
		}
		return syncDir(path)
	}
	if _, err := activator.Apply(context.Background(), signer.bundle(t, 2, testNebulaConfig("two"), "certificate-two")); err == nil || !strings.Contains(err.Error(), "sync activated") {
		t.Fatalf("sync failure = %v", err)
	}
	restoredTarget, _ := os.Readlink(filepath.Join(outputDir, "current"))
	if restoredTarget != originalTarget {
		t.Fatalf("post-sync-failure target = %q, want %q", restoredTarget, originalTarget)
	}
	if reloader.Calls() != 2 {
		t.Fatalf("reload calls = %d, want initial plus rollback reload", reloader.Calls())
	}
}

func TestActivatorRetainsNewestCompleteVersionsAndLeavesStaging(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	activator := testActivator(outputDir, signer, newFakeCommandRunner(), &fakeReloader{})
	for revision := int64(1); revision <= 2; revision++ {
		bundle := signer.bundle(t, revision, testNebulaConfig(fmt.Sprintf("revision-%d", revision)), "certificate-one")
		if _, err := activator.Apply(context.Background(), bundle); err != nil {
			t.Fatalf("apply revision %d: %v", revision, err)
		}
	}
	stagingDir := filepath.Join(outputDir, "versions", ".staging-crashjournal")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "partial"), []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	for revision := int64(3); revision <= 9; revision++ {
		bundle := signer.bundle(t, revision, testNebulaConfig(fmt.Sprintf("revision-%d", revision)), "certificate-one")
		if _, err := activator.Apply(context.Background(), bundle); err != nil {
			t.Fatalf("apply revision %d: %v", revision, err)
		}
	}
	versions := completeVersionEntries(t, filepath.Join(outputDir, "versions"))
	if len(versions) != maxRetainedBundleVersions {
		t.Fatalf("retained complete versions = %d, want %d: %v", len(versions), maxRetainedBundleVersions, versions)
	}
	currentTarget, err := os.Readlink(filepath.Join(outputDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, currentTarget)); err != nil {
		t.Fatalf("current retained version is missing: %v", err)
	}
	partial, err := os.ReadFile(filepath.Join(stagingDir, "partial"))
	if err != nil || string(partial) != "preserve" {
		t.Fatalf("crash staging directory was altered: content=%q err=%v", partial, err)
	}
}

func TestActivatorRetentionPreservesCurrentRollbackTarget(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	activator := testActivator(outputDir, signer, newFakeCommandRunner(), &fakeReloader{})
	var firstVersion string
	for revision := int64(1); revision <= maxRetainedBundleVersions; revision++ {
		bundle := signer.bundle(t, revision, testNebulaConfig(fmt.Sprintf("revision-%d", revision)), "certificate-one")
		activation, err := activator.Apply(context.Background(), bundle)
		if err != nil {
			t.Fatalf("apply revision %d: %v", revision, err)
		}
		if revision == 1 {
			firstVersion = activation.VersionDir
		}
	}
	oldestTarget := filepath.Join("versions", filepath.Base(firstVersion))
	if err := replaceSymlink(filepath.Join(outputDir, "current"), oldestTarget); err != nil {
		t.Fatalf("simulate rollback to oldest retained version: %v", err)
	}
	bundle := signer.bundle(t, maxRetainedBundleVersions+1, testNebulaConfig("after-rollback"), "certificate-one")
	activation, err := activator.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatalf("apply after rollback: %v", err)
	}
	if activation.PreviousTarget != oldestTarget {
		t.Fatalf("previous target = %q, want %q", activation.PreviousTarget, oldestTarget)
	}
	if _, err := os.Stat(firstVersion); err != nil {
		t.Fatalf("active rollback target was pruned: %v", err)
	}
	if versions := completeVersionEntries(t, filepath.Join(outputDir, "versions")); len(versions) != maxRetainedBundleVersions {
		t.Fatalf("retained complete versions = %d, want %d: %v", len(versions), maxRetainedBundleVersions, versions)
	}
}

func TestActivatorRetentionRejectsMaliciousVersionWithoutFollowingLinks(t *testing.T) {
	signer := newTestSigner(t)
	root := t.TempDir()
	outputDir := filepath.Join(root, "nebula")
	activator := testActivator(outputDir, signer, newFakeCommandRunner(), &fakeReloader{})
	if _, err := activator.Apply(context.Background(), signer.bundle(t, 1, testNebulaConfig("one"), "certificate-one")); err != nil {
		t.Fatal(err)
	}
	originalTarget, err := os.Readlink(filepath.Join(outputDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external-secret")
	if err := os.WriteFile(external, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	maliciousDir := filepath.Join(outputDir, "versions", "r00000000000000000002-cccccccccccccccc-attackentry1")
	if err := os.Mkdir(maliciousDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range completeBundleFileNames {
		path := filepath.Join(maliciousDir, name)
		if name == "host.key" {
			if err := os.Symlink(external, path); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, []byte("malicious"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	second := signer.bundle(t, 2, testNebulaConfig("two"), "certificate-one")
	if _, err := activator.Apply(context.Background(), second); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("malicious retention entry error = %v", err)
	}
	currentTarget, err := os.Readlink(filepath.Join(outputDir, "current"))
	if err != nil || currentTarget != originalTarget {
		t.Fatalf("current target changed after malicious entry: target=%q err=%v", currentTarget, err)
	}
	content, err := os.ReadFile(external)
	if err != nil || string(content) != "do-not-touch" {
		t.Fatalf("external symlink target was altered: content=%q err=%v", content, err)
	}
}

func TestActivatorSurfacesRetentionSyncFailureBeforeLiveSwitch(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	reloader := &fakeReloader{}
	activator := testActivator(outputDir, signer, newFakeCommandRunner(), reloader)
	for revision := int64(1); revision <= maxRetainedBundleVersions; revision++ {
		bundle := signer.bundle(t, revision, testNebulaConfig(fmt.Sprintf("revision-%d", revision)), "certificate-one")
		if _, err := activator.Apply(context.Background(), bundle); err != nil {
			t.Fatalf("apply revision %d: %v", revision, err)
		}
	}
	originalTarget, err := os.Readlink(filepath.Join(outputDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	activator.syncFn = func(path string) error {
		if filepath.Clean(path) == filepath.Clean(filepath.Join(outputDir, "versions")) && !failed {
			failed = true
			return errors.New("injected retention sync failure")
		}
		return syncDir(path)
	}
	next := signer.bundle(t, maxRetainedBundleVersions+1, testNebulaConfig("not-activated"), "certificate-one")
	if _, err := activator.Apply(context.Background(), next); err == nil || !strings.Contains(err.Error(), "sync pruned") {
		t.Fatalf("retention sync failure = %v", err)
	}
	currentTarget, err := os.Readlink(filepath.Join(outputDir, "current"))
	if err != nil || currentTarget != originalTarget {
		t.Fatalf("current target changed after retention failure: target=%q err=%v", currentTarget, err)
	}
	if reloader.Calls() != maxRetainedBundleVersions {
		t.Fatalf("reload calls = %d, want %d", reloader.Calls(), maxRetainedBundleVersions)
	}
}

func completeVersionEntries(t *testing.T, versionsDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		t.Fatal(err)
	}
	var versions []string
	for _, entry := range entries {
		if validVersionName(entry.Name()) {
			versions = append(versions, entry.Name())
		}
	}
	return versions
}

func TestActivatorRejectsUnsafeOutputAndUnsignedBundle(t *testing.T) {
	signer := newTestSigner(t)
	runner := newFakeCommandRunner()
	bundle := signer.bundle(t, 1, testNebulaConfig("safe"), "certificate-one")
	before, err := os.Stat("/etc")
	if err != nil {
		t.Fatal(err)
	}
	unsafe := testActivator("/etc", signer, runner, &fakeReloader{})
	if _, err := unsafe.Apply(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "dedicated leaf") {
		t.Fatalf("unsafe output error = %v", err)
	}
	after, err := os.Stat("/etc")
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("/etc permissions changed from %04o to %04o", before.Mode().Perm(), after.Mode().Perm())
	}

	outputDir := filepath.Join(t.TempDir(), "unsigned")
	tampered := bundle
	tampered.SignedConfig += "# tampered\n"
	activator := testActivator(outputDir, signer, runner, &fakeReloader{})
	if _, err := activator.Apply(context.Background(), tampered); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered bundle error = %v", err)
	}
	if _, err := os.Stat(outputDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsigned bundle created output directory: %v", err)
	}

	wrongCA := bundle
	wrongCA.CACertificate = "attacker-ca"
	if _, err := activator.Apply(context.Background(), wrongCA); err == nil || !strings.Contains(err.Error(), "enrollment pin") {
		t.Fatalf("substituted CA error = %v", err)
	}

	wrongPublicKey := bundle
	wrongPublicKey.PublicKey = "attacker-public-key"
	if _, err := activator.Apply(context.Background(), wrongPublicKey); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("substituted public key error = %v", err)
	}

	wrongCertificate := bundle
	wrongCertificate.Certificate = "certificate-two"
	if _, err := activator.Apply(context.Background(), wrongCertificate); err == nil || !strings.Contains(err.Error(), "signed artifact metadata") {
		t.Fatalf("substituted certificate error = %v", err)
	}

	occupied := filepath.Join(t.TempDir(), "occupied")
	if err := os.Mkdir(occupied, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "user-file"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	activator = testActivator(occupied, signer, runner, &fakeReloader{})
	if _, err := activator.Apply(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "unused") {
		t.Fatalf("occupied output error = %v", err)
	}
	if content, _ := os.ReadFile(filepath.Join(occupied, "user-file")); string(content) != "keep" {
		t.Fatal("occupied directory content was changed")
	}
}

func TestCurrentBundleRejectsRuntimeConfigDrift(t *testing.T) {
	signer := newTestSigner(t)
	outputDir := filepath.Join(t.TempDir(), "nebula")
	activator := testActivator(outputDir, signer, newFakeCommandRunner(), &fakeReloader{})
	if _, err := activator.Apply(context.Background(), signer.bundle(t, 1, testNebulaConfig("signed"), "certificate-one")); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(outputDir, "current", "config.yml")
	if err := os.WriteFile(runtimePath, []byte(testNebulaConfig("locally-tampered")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := activator.CurrentBundle(context.Background()); err == nil || !strings.Contains(err.Error(), "differs from the pinned signed config") {
		t.Fatalf("runtime config drift error = %v", err)
	}
}

func TestMinimumNebulaVersion(t *testing.T) {
	for _, version := range []string{"Version: 1.10.3", "nebula v1.11.0", "2.0.0"} {
		if err := EnforceMinimumNebulaVersion(version); err != nil {
			t.Errorf("version %q rejected: %v", version, err)
		}
	}
	for _, version := range []string{"1.10.2", "1.9.99", "not-a-version"} {
		if err := EnforceMinimumNebulaVersion(version); err == nil {
			t.Errorf("version %q accepted", version)
		}
	}
}

type testConfigSigner struct {
	publicKey  string
	privateKey []byte
	nodeID     string
	networkID  string
}

func newTestSigner(t *testing.T) testConfigSigner {
	t.Helper()
	publicKey, privateKey, err := control.GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return testConfigSigner{publicKey: publicKey, privateKey: privateKey, nodeID: "node-1", networkID: "network-1"}
}

func (s testConfigSigner) bundle(t *testing.T, revision int64, config, certificate string) Bundle {
	t.Helper()
	issuedAt := time.Date(2026, 7, 19, 12, int(revision), 0, 0, time.UTC)
	generation := int64(1)
	if strings.Contains(certificate, "two") || strings.Contains(certificate, "new") {
		generation = 2
	}
	metadata := control.ConfigSignatureMetadata{
		NodeID: s.nodeID, NetworkID: s.networkID, Revision: revision, IssuedAt: issuedAt,
		CACertificateSHA256: control.ConfigDigest("ca-certificate"), CertificateFingerprint: testCertificateFingerprint(certificate),
		CertificateExpiresAt: testCertificateExpiry(certificate), CertificateRenewAfter: testCertificateRenewAfter(certificate),
		CertificateGeneration: generation,
		PublicKeyHash:         canonicalPublicKeyHash("public-key"),
	}
	digest, signature, err := control.SignConfig(s.privateKey, metadata, config)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{
		NodeID: s.nodeID, NetworkID: s.networkID, Revision: revision, IssuedAt: issuedAt,
		Digest: digest, Signature: signature, SignedConfig: config,
		CACertificateSHA256: metadata.CACertificateSHA256, CertificateFingerprint: metadata.CertificateFingerprint,
		CertificateExpiresAt: metadata.CertificateExpiresAt, CertificateRenewAfter: metadata.CertificateRenewAfter,
		CertificateGeneration: metadata.CertificateGeneration,
		PublicKeyHash:         metadata.PublicKeyHash,
		CACertificate:         "ca-certificate", Certificate: certificate,
		PrivateKey: "private-key", PublicKey: "public-key",
	}
}

func (s testConfigSigner) resignBundle(t *testing.T, source Bundle, mutate func(*Bundle)) Bundle {
	t.Helper()
	bundle := source
	mutate(&bundle)
	metadata := control.ConfigSignatureMetadata{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID, Revision: bundle.Revision, IssuedAt: bundle.IssuedAt,
		CACertificateSHA256: bundle.CACertificateSHA256, PreviousCACertificateSHA256: bundle.PreviousCACertificateSHA256,
		CARotationRequired: bundle.CARotationRequired, CertificateProfileRenewalRequired: bundle.CertificateProfileRenewalRequired, CertificateFingerprint: bundle.CertificateFingerprint,
		CertificateExpiresAt: bundle.CertificateExpiresAt, CertificateRenewAfter: bundle.CertificateRenewAfter,
		CertificateGeneration: bundle.CertificateGeneration,
		PublicKeyHash:         bundle.PublicKeyHash,
	}
	digest, signature, err := control.SignConfig(s.privateKey, metadata, bundle.SignedConfig)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Digest = digest
	bundle.Signature = signature
	return bundle
}

func testNebulaConfig(marker string) string {
	return fmt.Sprintf("pki:\n  ca: /etc/nebula/ca.crt\n  cert: /etc/nebula/host.crt\n  key: /etc/nebula/host.key\nstatic_host_map: {}\nlighthouse:\n  am_lighthouse: false\n  hosts: []\nlisten:\n  host: 0.0.0.0\n  port: 4242\nfirewall:\n  outbound: []\n  inbound: []\n# %s\n", marker)
}

func testActivator(outputDir string, signer testConfigSigner, runner *fakeCommandRunner, reloader *fakeReloader) *Activator {
	return &Activator{
		OutputDir: outputDir, NodeID: signer.nodeID, NetworkID: signer.networkID,
		ConfigSigningPublicKey: signer.publicKey,
		CACertificateSHA256:    control.ConfigDigest("ca-certificate"),
		PublicKeyHash:          canonicalPublicKeyHash("public-key"),
		Validator:              BundleValidator{Runner: runner}, Reloader: reloader,
	}
}

type fakeCommandRunner struct {
	mu               sync.Mutex
	version          string
	quietCalls       [][]string
	failCertificates map[string]error
}

func newFakeCommandRunner() *fakeCommandRunner {
	return &fakeCommandRunner{version: "Version: 1.10.3", failCertificates: make(map[string]error)}
}

func (r *fakeCommandRunner) expiryFor(certificate string) time.Time {
	return testCertificateExpiry(certificate)
}

func testCertificateExpiry(certificate string) time.Time {
	hour := 24
	if strings.Contains(certificate, "two") || strings.Contains(certificate, "new") {
		hour = 48
	}
	return time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC).Add(time.Duration(hour) * time.Hour)
}

func testCertificateRenewAfter(certificate string) time.Time {
	return testCertificateExpiry(certificate).Add(-8 * time.Hour)
}

func testCertificateFingerprint(certificate string) string {
	if strings.Contains(certificate, "two") || strings.Contains(certificate, "new") {
		return strings.Repeat("b", 64)
	}
	return strings.Repeat("a", 64)
}

func (r *fakeCommandRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "nebula" && len(args) == 1 && args[0] == "-version" {
		return []byte(r.version), nil
	}
	if name == "nebula-cert" && len(args) == 4 && args[0] == "print" {
		certificate, err := os.ReadFile(args[3])
		if err != nil {
			return nil, err
		}
		payload := []map[string]any{{
			"fingerprint": testCertificateFingerprint(string(certificate)),
			"details":     map[string]any{"notAfter": r.expiryFor(string(certificate))},
		}}
		return json.Marshal(payload)
	}
	return nil, fmt.Errorf("unexpected output command %s %v", name, args)
}

func (r *fakeCommandRunner) RunQuiet(_ context.Context, name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.quietCalls = append(r.quietCalls, append([]string{name}, args...))
	if name == "nebula-cert" && len(args) == 5 && args[0] == "verify" {
		certificate, err := os.ReadFile(args[4])
		if err != nil {
			return err
		}
		if err := r.failCertificates[string(certificate)]; err != nil {
			return err
		}
	}
	return nil
}

func (r *fakeCommandRunner) QuietCalls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]string(nil), r.quietCalls...)
}

type fakeReloader struct {
	mu     sync.Mutex
	calls  int
	failAt map[int]error
}

func (r *fakeReloader) Reload(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.failAt[r.calls]
}

func (r *fakeReloader) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}
