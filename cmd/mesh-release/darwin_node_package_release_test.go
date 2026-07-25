package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/darwincodesign"
	"mesh/internal/darwinnodepackage"
)

func TestVerifyDarwinNodePackageReleaseBindsFinalBytesAndPolicies(t *testing.T) {
	originalPackagePolicy := loadDarwinNodePackageReleasePolicy
	originalCodesignPolicy := loadDarwinNodeCodesignPolicy
	t.Cleanup(func() {
		loadDarwinNodePackageReleasePolicy = originalPackagePolicy
		loadDarwinNodeCodesignPolicy = originalCodesignPolicy
	})
	_, packagePolicy, err := darwinnodepackage.EncodePolicy(darwinnodepackage.PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, codesignPolicy, err := darwincodesign.EncodePolicy(darwincodesign.PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl", NebulaIdentifier: "io.mesh.node.nebula",
		NebulaCertIdentifier: "io.mesh.node.nebula-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	loadDarwinNodePackageReleasePolicy = func() (darwinnodepackage.Policy, error) {
		return packagePolicy, nil
	}
	loadDarwinNodeCodesignPolicy = func() (darwincodesign.Policy, error) {
		return codesignPolicy, nil
	}
	directory := t.TempDir()
	packageRaw := []byte("protected-node-package")
	packageDigest := sha256.Sum256(packageRaw)
	packagePath := filepath.Join(directory, "MeshNode.pkg")
	if err := os.WriteFile(packagePath, packageRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	codesignReceiptSHA := strings.Repeat("b", 64)
	bundleSecurityReceiptSHA := strings.Repeat("9", 64)
	receipt := packageReleaseCommandReceipt(
		time.Now().UTC().Truncate(time.Second), packagePolicy, codesignPolicy,
		hex.EncodeToString(packageDigest[:]), int64(len(packageRaw)),
		codesignReceiptSHA, bundleSecurityReceiptSHA,
	)
	receiptRaw, err := darwinnodepackage.EncodeReleaseReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(receiptPath, receiptRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--package", packagePath, "--receipt", receiptPath,
		"--arch", "arm64", "--version", "1.2.3",
		"--codesign-receipt-sha256", codesignReceiptSHA,
		"--bundle-security-receipt-sha256", bundleSecurityReceiptSHA,
	}
	var output bytes.Buffer
	if err := verifyDarwinNodePackageRelease(args, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), receipt.Package.SHA256) ||
		!strings.Contains(output.String(), receipt.Notarization.SubmissionID) {
		t.Fatalf("unexpected verification output: %q", output.String())
	}
	args[len(args)-1] = strings.Repeat("0", 64)
	if err := verifyDarwinNodePackageRelease(args, &bytes.Buffer{}); err == nil {
		t.Fatal("mismatched bundle-security receipt accepted")
	}
}

func packageReleaseCommandReceipt(
	now time.Time,
	packagePolicy darwinnodepackage.Policy,
	codesignPolicy darwincodesign.Policy,
	packageSHA string,
	packageSize int64,
	codesignReceiptSHA string,
	bundleSecurityReceiptSHA string,
) darwinnodepackage.ReleaseReceipt {
	digest := func(character string, size int64) darwinnodepackage.DigestEvidence {
		return darwinnodepackage.DigestEvidence{SHA256: strings.Repeat(character, 64), Size: size}
	}
	tools := make(map[string]darwinnodepackage.PackageToolEvidence)
	for _, name := range []string{
		"/usr/bin/codesign", "/usr/bin/lsbom", "/usr/bin/lipo",
		"/usr/bin/pkgbuild", "/usr/bin/productsign", "/usr/bin/security",
		"/usr/bin/xcrun", "/usr/sbin/pkgutil", "/usr/sbin/spctl",
		"notarytool", "stapler",
	} {
		tools[name] = darwinnodepackage.PackageToolEvidence{SHA256: strings.Repeat("e", 64), Size: 4096}
	}
	return darwinnodepackage.ReleaseReceipt{
		Schema: darwinnodepackage.ReceiptSchema,
		Bootstrap: darwinnodepackage.BootstrapEvidence{
			CodeIdentifier: codesignPolicy.MeshInstallIdentifier,
			SHA256:         strings.Repeat("a", 64), Size: 8192,
		},
		Contents: darwinnodepackage.PackageContentsEvidence{
			BOM: digest("1", 1024), DirectoryCount: 2, FileCount: 4,
			PackageInfo: digest("2", 1024), PayloadTreeSHA256: strings.Repeat("3", 64),
			PostinstallSHA256: strings.Repeat("a", 64), ScriptsArchive: digest("4", 1024),
		},
		Notarization: darwinnodepackage.PackageNotarizationEvidence{
			GatekeeperAssessment: "accepted", Staple: "validated", Status: "Accepted",
			SubmissionID: "12345678-1234-1234-1234-123456789abc",
		},
		Package: darwinnodepackage.PackageEvidence{
			Architecture: "arm64", Identifier: packagePolicy.PackageIdentifier,
			InstallLocation: packagePolicy.PackageInstallLocation,
			PackageRoot:     packagePolicy.PackageRootPath,
			SHA256:          packageSHA, Size: packageSize, Version: "1.2.3",
		},
		Signing: darwinnodepackage.PackageSigningEvidence{
			InstallerCertificateSHA256: strings.Repeat("a", 64),
			InstallerIdentitySHA1:      strings.Repeat("A", 40),
			TeamID:                     codesignPolicy.TeamID,
		},
		Snapshot: darwinnodepackage.SnapshotEvidence{
			Artifact: digest("6", 8192), BundleJSON: digest("7", 2048),
			InstallJSON: digest("8", 1024),
		},
		Source: darwinnodepackage.PackageSourceEvidence{
			BundleSecurityReceipt: darwinnodepackage.DigestEvidence{SHA256: bundleSecurityReceiptSHA, Size: 4096},
			CodesignPolicySHA256:  codesignPolicy.SHA256,
			CodesignReceipt:       darwinnodepackage.DigestEvidence{SHA256: codesignReceiptSHA, Size: 4096},
			PackagePolicySHA256:   packagePolicy.SHA256,
		},
		Tools: tools, VerifiedAt: now.Format(time.RFC3339),
	}
}
