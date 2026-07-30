package appleapprelease

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNativeReceiptCanonicalRoundTripAndMatch(t *testing.T) {
	now := time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC)
	receipt := testNativeReceipt(now, true)
	raw, err := EncodeNativeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNativeReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Match(now, nativeExpectation(receipt, true)); err != nil {
		t.Fatal(err)
	}
	if err := parsed.Match(now, nativeExpectation(receipt, false)); err != nil {
		t.Fatal(err)
	}
}

func TestNativeReceiptRejectsStaleNoncanonicalOrMissingIsolation(t *testing.T) {
	now := time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC)
	online := testNativeReceipt(now, false)
	if err := online.Match(now, nativeExpectation(online, true)); err == nil {
		t.Fatal("online native receipt accepted as network-isolated evidence")
	}
	if err := online.Match(now.Add(25*time.Hour), nativeExpectation(online, false)); err == nil {
		t.Fatal("stale native receipt accepted")
	}
	raw, err := EncodeNativeReceipt(online)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeReceipt(bytes.Replace(raw, []byte(`"schema"`), []byte(`"unknown"`), 1)); err == nil {
		t.Fatal("unknown native receipt field accepted")
	}
	online.ReleaseMetadata.SignatureSHA256 = []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}
	if _, err := EncodeNativeReceipt(online); err == nil {
		t.Fatal("unordered native signature evidence accepted")
	}
}

func testNativeReceipt(now time.Time, isolated bool) NativeReceipt {
	protected := testReceipt(now)
	isolation := "not-requested"
	isolationTools := map[string]string{}
	if isolated {
		isolation = "pre-and-post-no-default-route-or-nonloopback-unicast"
		isolationTools = map[string]string{
			"ifconfig_sha256": strings.Repeat("1", 64),
			"route_sha256":    strings.Repeat("2", 64),
		}
	}
	return NativeReceipt{
		Application: NativeApplicationEvidence{
			Architectures:    []string{"arm64", "x86_64"},
			BundleIdentifier: ApplicationIdentifier,
			SignedTreeSHA256: strings.Repeat("3", 64),
		},
		Archive: NativeFileEvidence{SHA256: strings.Repeat("4", 64), Size: 8192},
		MeshReleaseVerifier: NativeFileEvidence{
			SHA256: strings.Repeat("5", 64), Size: 4096,
		},
		MetadataVerificationStdoutSHA256: strings.Repeat("6", 64),
		Native: NativePlatformEvidence{
			GatekeeperAssessment:  "accepted",
			NetworkIsolationCheck: isolation,
			NetworkIsolationTools: isolationTools,
			Staple:                "validated",
		},
		ProtectedReceiptSHA256: strings.Repeat("7", 64),
		ReleaseMetadata: ReleaseMetadataEvidence{
			ManifestSHA256:  strings.Repeat("8", 64),
			RootSHA256:      strings.Repeat("9", 64),
			SignatureSHA256: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)},
		},
		Schema: NativeReceiptSchema,
		Signing: NativeSigningEvidence{
			ApplicationEntitlementsSHA256: ApplicationEntitlementsSHA,
			NestedCode:                    protected.Signing.NestedCode,
			TeamID:                        protected.Signing.TeamID,
		},
		Tools:      protected.Tools,
		VerifiedAt: now.Format(time.RFC3339),
	}
}

func nativeExpectation(receipt NativeReceipt, requireIsolation bool) NativeExpectation {
	return NativeExpectation{
		Archive: ArtifactIdentity{
			SHA256: receipt.Archive.SHA256,
			Size:   receipt.Archive.Size,
		},
		ManifestSHA256: receipt.ReleaseMetadata.ManifestSHA256,
		MeshReleaseVerifier: ArtifactIdentity{
			SHA256: receipt.MeshReleaseVerifier.SHA256,
			Size:   receipt.MeshReleaseVerifier.Size,
		},
		ProtectedReceiptSHA256: receipt.ProtectedReceiptSHA256,
		RequireNetworkIsolated: requireIsolation,
		RootSHA256:             receipt.ReleaseMetadata.RootSHA256,
		TeamID:                 receipt.Signing.TeamID,
	}
}
