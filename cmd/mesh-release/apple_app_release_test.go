package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/appleapprelease"
	releasetrust "mesh/internal/release"
)

func TestVerifyAppleAppReleaseBindsFinalArchive(t *testing.T) {
	directory := t.TempDir()
	archivePath := filepath.Join(directory, "Mesh-Admin.zip")
	archive := []byte("final stapled Mesh Admin archive")
	if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	receipt := appleReleaseTestReceipt(t, archive)
	raw, err := appleapprelease.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(receiptPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	arguments := []string{
		"--archive", archivePath,
		"--receipt", receiptPath,
		"--source-receipt-sha256", receipt.Source.ReceiptSHA256,
		"--team-id", receipt.Signing.TeamID,
	}
	if err := verifyAppleAppRelease(arguments, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "does not replace native Apple signature") {
		t.Fatalf("unexpected verification output %q", output.String())
	}
	if err := os.WriteFile(archivePath, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppleAppRelease(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("changed protected Apple archive accepted")
	}
}

func TestVerifyPublishedAppleAppAuthenticatesArchiveAndReceipt(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	archive := []byte("downloaded final stapled Mesh Admin archive")
	archivePath := filepath.Join(directory, "Mesh-Admin.zip")
	if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	receipt := appleReleaseTestReceipt(t, archive)
	receipt.VerifiedAt = now.Format(time.RFC3339)
	receiptRaw, err := appleapprelease.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "protected-receipt.json")
	if err := os.WriteFile(receiptPath, receiptRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archive)
	receiptDigest := sha256.Sum256(receiptRaw)
	manifest := releasetrust.ReleaseManifest{
		Schema: releasetrust.ReleaseSchemaV2, Channel: "apple-admin-stable",
		ReleaseEpoch: 1, Version: receipt.Application.Version, Sequence: 1,
		MinimumSecurityFloor: 1,
		IssuedAt:             now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:            now.Add(time.Hour).Format(time.RFC3339),
		Artifacts: []releasetrust.Artifact{
			{
				OS: "macos-admin", Arch: "universal",
				URL:  "https://releases.example/Mesh-Admin.zip",
				Size: int64(len(archive)), SHA256: hex.EncodeToString(archiveDigest[:]),
			},
			{
				OS: "macos-admin-evidence", Arch: "portable",
				URL:  "https://releases.example/Mesh-Admin.receipt.json",
				Size: int64(len(receiptRaw)), SHA256: hex.EncodeToString(receiptDigest[:]),
			},
		},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	manifestPath := filepath.Join(directory, "release.json")
	if err := os.WriteFile(manifestPath, manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	publicFiles := make([]releasetrust.PublicKeyFile, 0, 4)
	privateKeys := make([][]byte, 0, 4)
	for range 4 {
		_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		publicFile, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicFiles = append(publicFiles, publicFile)
		privateKeys = append(privateKeys, privateKey)
	}
	rootRaw, err := releasetrust.EncodeRoot(releasetrust.Root{
		Schema: releasetrust.RootSchema, Version: 1, Channel: manifest.Channel,
		ReleaseEpoch: 1, MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt:  now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		Keys:      publicFiles,
		Roles: releasetrust.RootRoles{
			Root: releasetrust.RootRole{
				Threshold: 2, KeyIDs: []string{publicFiles[0].KeyID, publicFiles[1].KeyID},
			},
			Release: releasetrust.RootRole{
				Threshold: 2, KeyIDs: []string{publicFiles[2].KeyID, publicFiles[3].KeyID},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(directory, "root.json")
	if err := os.WriteFile(rootPath, rootRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	rootDigest := sha256.Sum256(rootRaw)
	signaturePaths := make([]string, 0, 2)
	for index := 2; index < 4; index++ {
		raw, err := releasetrust.SignManifest(
			releasetrust.ReleaseManifestKind,
			manifestRaw,
			privateKeys[index],
		)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, fmt.Sprintf("release-%d.sig.json", index))
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		signaturePaths = append(signaturePaths, path)
	}
	for _, privateKey := range privateKeys {
		clear(privateKey)
	}
	arguments := []string{
		"--root", rootPath,
		"--root-sha256", hex.EncodeToString(rootDigest[:]),
		"--manifest", manifestPath,
		"--archive", archivePath,
		"--receipt", receiptPath,
		"--source-receipt-sha256", receipt.Source.ReceiptSHA256,
		"--team-id", receipt.Signing.TeamID,
	}
	for _, path := range signaturePaths {
		arguments = append(arguments, "--signature", path)
	}
	var output bytes.Buffer
	if err := verifyPublishedAppleApp(arguments, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Native Apple signature") {
		t.Fatalf("unexpected published verification output %q", output.String())
	}
	if err := os.WriteFile(receiptPath, append(receiptRaw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublishedAppleApp(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered published Mesh Admin receipt accepted")
	}
}

func appleReleaseTestReceipt(t *testing.T, archive []byte) appleapprelease.Receipt {
	t.Helper()
	tools := map[string]appleapprelease.ToolEvidence{}
	for _, name := range []string{
		"/usr/bin/codesign", "/usr/bin/ditto", "/usr/bin/lipo", "/usr/bin/security",
		"/usr/bin/xcrun", "/usr/sbin/spctl", "notarytool", "stapler",
	} {
		tools[name] = appleapprelease.ToolEvidence{SHA256: strings.Repeat("a", 64), Size: 1024}
	}
	nested := []appleapprelease.NestedCodeEvidence{
		{
			Architectures:      []string{"arm64", "x86_64"},
			EntitlementsSHA256: appleapprelease.EmptyEntitlementsSHA,
			Identifier:         "io.flutter.flutter.app",
			Path:               "Contents/Frameworks/App.framework",
		},
		{
			Architectures:      []string{"arm64", "x86_64"},
			EntitlementsSHA256: appleapprelease.EmptyEntitlementsSHA,
			Identifier:         "io.flutter.flutter-macos",
			Path:               "Contents/Frameworks/FlutterMacOS.framework",
		},
		{
			Architectures:      []string{"arm64", "x86_64"},
			EntitlementsSHA256: appleapprelease.EmptyEntitlementsSHA,
			Identifier:         "io.flutter.flutter.native-assets.objective-c",
			Path:               "Contents/Frameworks/objective_c.framework",
		},
	}
	sum := sha256.Sum256(archive)
	return appleapprelease.Receipt{
		Application: appleapprelease.ApplicationEvidence{
			Architectures: []string{"arm64", "x86_64"},
			Build:         "1", BundleIdentifier: appleapprelease.ApplicationIdentifier,
			MinimumMacOS: "14.0", SignedRegularBytes: 4096,
			SignedRegularFiles: 12, SignedTreeSHA256: strings.Repeat("b", 64),
			Version: "0.1.0",
		},
		Distribution: appleapprelease.DistributionEvidence{
			ExtractedRegularBytes: 4096,
			ExtractedRegularFiles: 12,
			ExtractedTreeSHA256:   strings.Repeat("b", 64),
			Format:                "ditto-zip",
			RoundTripVerified:     true,
			SHA256:                hex.EncodeToString(sum[:]),
			Size:                  int64(len(archive)),
		},
		Notarization: appleapprelease.NotarizationEvidence{
			GatekeeperAssessment: "accepted", Staple: "validated", Status: "Accepted",
			SubmissionID: "12345678-1234-4234-8234-123456789abc",
		},
		Schema: appleapprelease.ReceiptSchema,
		Signing: appleapprelease.SigningEvidence{
			ApplicationEntitlementsSHA256: appleapprelease.ApplicationEntitlementsSHA,
			HardenedRuntime:               true, IdentitySHA1: strings.Repeat("A", 40),
			NestedCode: nested, TeamID: "AB12CD34EF",
		},
		Source: appleapprelease.SourceEvidence{
			ReceiptSHA256: strings.Repeat("d", 64), SecurityReceiptSHA256: strings.Repeat("f", 64),
			TreeSHA256: strings.Repeat("e", 64),
		},
		Tools: tools, VerifiedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
}
