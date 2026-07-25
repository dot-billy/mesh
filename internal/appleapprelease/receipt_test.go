package appleapprelease

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReceiptCanonicalRoundTripAndArchiveMatch(t *testing.T) {
	now := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC)
	receipt := testReceipt(now)
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Match(now,
		ArtifactIdentity{SHA256: receipt.Distribution.SHA256, Size: receipt.Distribution.Size},
		receipt.Source.ReceiptSHA256, receipt.Signing.TeamID,
	); err != nil {
		t.Fatal(err)
	}
	if err := parsed.Match(now,
		ArtifactIdentity{SHA256: strings.Repeat("9", 64), Size: receipt.Distribution.Size},
		receipt.Source.ReceiptSHA256, receipt.Signing.TeamID,
	); err == nil {
		t.Fatal("drifted protected archive matched receipt")
	}
	if err := parsed.MatchForPublication(
		now.Add(25*time.Hour),
		ArtifactIdentity{SHA256: receipt.Distribution.SHA256, Size: receipt.Distribution.Size},
		receipt.Source.ReceiptSHA256,
		receipt.Signing.TeamID,
	); err == nil {
		t.Fatal("stale protected receipt accepted for publication")
	}
}

func TestReceiptRejectsUnknownNoncanonicalAndIncompleteEvidence(t *testing.T) {
	now := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC)
	receipt := testReceipt(now)
	receipt.Signing.NestedCode = receipt.Signing.NestedCode[:2]
	if _, err := EncodeReceipt(receipt); err == nil {
		t.Fatal("incomplete nested-code inventory accepted")
	}
	receipt = testReceipt(now)
	receipt.Distribution.RoundTripVerified = false
	if _, err := EncodeReceipt(receipt); err == nil {
		t.Fatal("unverified archive round trip accepted")
	}
	receipt = testReceipt(now)
	receipt.Distribution.ExtractedTreeSHA256 = strings.Repeat("9", 64)
	if _, err := EncodeReceipt(receipt); err == nil {
		t.Fatal("mismatched extracted application tree accepted")
	}

	raw, err := EncodeReceipt(testReceipt(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReceipt(bytes.Replace(raw, []byte(`"schema"`), []byte(`"unknown"`), 1)); err == nil {
		t.Fatal("unknown protected receipt field accepted")
	}
	pretty := bytes.Replace(raw, []byte(`{"application"`), []byte("{\n  \"application\""), 1)
	if _, err := ParseReceipt(pretty); err == nil {
		t.Fatal("noncanonical protected receipt accepted")
	}
}

func TestReceiptRejectsFutureEvidenceOrWrongAuthority(t *testing.T) {
	now := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC)
	receipt := testReceipt(now.Add(6 * time.Minute))
	artifact := ArtifactIdentity{
		SHA256: receipt.Distribution.SHA256,
		Size:   receipt.Distribution.Size,
	}
	if err := receipt.Match(now, artifact, receipt.Source.ReceiptSHA256, receipt.Signing.TeamID); err == nil {
		t.Fatal("future protected receipt accepted")
	}
	receipt = testReceipt(now)
	if err := receipt.Match(now, artifact, strings.Repeat("8", 64), receipt.Signing.TeamID); err == nil {
		t.Fatal("wrong source receipt authority accepted")
	}
}

func testReceipt(now time.Time) Receipt {
	nested := []NestedCodeEvidence{
		{
			Architectures: []string{"arm64", "x86_64"}, EntitlementsSHA256: EmptyEntitlementsSHA,
			Identifier: "io.flutter.flutter.app", Path: "Contents/Frameworks/App.framework",
		},
		{
			Architectures: []string{"arm64", "x86_64"}, EntitlementsSHA256: EmptyEntitlementsSHA,
			Identifier: "io.flutter.flutter-macos", Path: "Contents/Frameworks/FlutterMacOS.framework",
		},
		{
			Architectures: []string{"arm64", "x86_64"}, EntitlementsSHA256: EmptyEntitlementsSHA,
			Identifier: "io.flutter.flutter.native-assets.objective-c", Path: "Contents/Frameworks/objective_c.framework",
		},
	}
	tools := map[string]ToolEvidence{}
	for _, name := range []string{
		"/usr/bin/codesign", "/usr/bin/ditto", "/usr/bin/lipo", "/usr/bin/security",
		"/usr/bin/xcrun", "/usr/sbin/spctl", "notarytool", "stapler",
	} {
		tools[name] = ToolEvidence{SHA256: strings.Repeat("a", 64), Size: 1024}
	}
	return Receipt{
		Application: ApplicationEvidence{
			Architectures: []string{"arm64", "x86_64"}, Build: "1",
			BundleIdentifier: ApplicationIdentifier, MinimumMacOS: "14.0",
			SignedRegularFiles: 12, SignedRegularBytes: 4096,
			SignedTreeSHA256: strings.Repeat("b", 64), Version: "0.1.0",
		},
		Distribution: DistributionEvidence{
			ExtractedRegularBytes: 4096, ExtractedRegularFiles: 12,
			ExtractedTreeSHA256: strings.Repeat("b", 64), Format: "ditto-zip",
			RoundTripVerified: true, SHA256: strings.Repeat("c", 64), Size: 8192,
		},
		Notarization: NotarizationEvidence{
			GatekeeperAssessment: "accepted", Staple: "validated", Status: "Accepted",
			SubmissionID: "12345678-1234-4234-8234-123456789abc",
		},
		Schema: ReceiptSchema,
		Signing: SigningEvidence{
			ApplicationEntitlementsSHA256: ApplicationEntitlementsSHA,
			HardenedRuntime:               true, IdentitySHA1: strings.Repeat("A", 40),
			NestedCode: nested, TeamID: "AB12CD34EF",
		},
		Source: SourceEvidence{
			ReceiptSHA256: strings.Repeat("d", 64), SecurityReceiptSHA256: strings.Repeat("f", 64),
			TreeSHA256: strings.Repeat("e", 64),
		},
		Tools: tools, VerifiedAt: now.Format(time.RFC3339),
	}
}
