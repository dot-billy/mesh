package darwinnodepackage

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReleaseReceiptCanonicalRoundTripAndPublicationMatch(t *testing.T) {
	now := time.Date(2026, 7, 24, 14, 0, 0, 0, time.UTC)
	policy := releaseReceiptPolicy(t)
	receipt := validReleaseReceipt(now, policy)
	raw, err := EncodeReleaseReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReleaseReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	artifact := PackageArtifactIdentity{
		SHA256: receipt.Package.SHA256,
		Size:   receipt.Package.Size,
	}
	if err := parsed.MatchForPublication(
		now, artifact, policy, strings.Repeat("c", 64), "io.mesh.node.mesh-install",
		"arm64", "1.2.3", "AB12CD34EF", strings.Repeat("b", 64), strings.Repeat("9", 64),
	); err != nil {
		t.Fatal(err)
	}
	artifact.Size++
	if err := parsed.MatchForPublication(
		now, artifact, policy, strings.Repeat("c", 64), "io.mesh.node.mesh-install",
		"arm64", "1.2.3", "AB12CD34EF", strings.Repeat("b", 64), strings.Repeat("9", 64),
	); err == nil {
		t.Fatal("drifted package matched protected receipt")
	}
}

func TestReleaseReceiptRejectsStaleNoncanonicalOrIncompleteEvidence(t *testing.T) {
	now := time.Date(2026, 7, 24, 14, 0, 0, 0, time.UTC)
	policy := releaseReceiptPolicy(t)
	receipt := validReleaseReceipt(now.Add(-25*time.Hour), policy)
	err := receipt.MatchForPublication(
		now,
		PackageArtifactIdentity{SHA256: receipt.Package.SHA256, Size: receipt.Package.Size},
		policy, strings.Repeat("c", 64), "io.mesh.node.mesh-install",
		"arm64", "1.2.3", "AB12CD34EF", strings.Repeat("b", 64), strings.Repeat("9", 64),
	)
	if err == nil {
		t.Fatal("stale protected package receipt accepted for publication")
	}
	invalid := validReleaseReceipt(now, policy)
	invalid.Contents.UnexpectedXattrs = 1
	if _, err := EncodeReleaseReceipt(invalid); err == nil {
		t.Fatal("package receipt with unexpected xattrs accepted")
	}
	raw, err := EncodeReleaseReceipt(validReleaseReceipt(now, policy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReleaseReceipt(bytes.Replace(raw, []byte(`"schema"`), []byte(`"unknown"`), 1)); err == nil {
		t.Fatal("unknown package receipt field accepted")
	}
}

func releaseReceiptPolicy(t *testing.T) Policy {
	t.Helper()
	_, policy, err := EncodePolicy(PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func validReleaseReceipt(now time.Time, policy Policy) ReleaseReceipt {
	digest := func(character string, size int64) DigestEvidence {
		return DigestEvidence{SHA256: strings.Repeat(character, 64), Size: size}
	}
	tools := make(map[string]PackageToolEvidence)
	for _, name := range []string{
		"/usr/bin/codesign", "/usr/bin/lsbom", "/usr/bin/lipo",
		"/usr/bin/pkgbuild", "/usr/bin/productsign", "/usr/bin/security",
		"/usr/bin/xcrun", "/usr/sbin/pkgutil", "/usr/sbin/spctl",
		"notarytool", "stapler",
	} {
		tools[name] = PackageToolEvidence{SHA256: strings.Repeat("e", 64), Size: 4096}
	}
	return ReleaseReceipt{
		Schema: ReceiptSchema,
		Bootstrap: BootstrapEvidence{
			CodeIdentifier: "io.mesh.node.mesh-install",
			SHA256:         strings.Repeat("a", 64),
			Size:           8192,
		},
		Contents: PackageContentsEvidence{
			BOM: digest("1", 1024), DirectoryCount: 2, FileCount: 4,
			PackageInfo:       digest("2", 1024),
			PayloadTreeSHA256: strings.Repeat("3", 64),
			PostinstallSHA256: strings.Repeat("a", 64),
			ScriptsArchive:    digest("4", 1024),
		},
		Notarization: PackageNotarizationEvidence{
			GatekeeperAssessment: "accepted", Staple: "validated", Status: "Accepted",
			SubmissionID: "12345678-1234-1234-1234-123456789abc",
		},
		Package: PackageEvidence{
			Architecture: "arm64", Identifier: policy.PackageIdentifier,
			InstallLocation: policy.PackageInstallLocation,
			PackageRoot:     policy.PackageRootPath,
			SHA256:          strings.Repeat("5", 64), Size: 65536, Version: "1.2.3",
		},
		Signing: PackageSigningEvidence{
			InstallerCertificateSHA256: strings.Repeat("a", 64),
			InstallerIdentitySHA1:      strings.Repeat("A", 40),
			TeamID:                     "AB12CD34EF",
		},
		Snapshot: SnapshotEvidence{
			Artifact: digest("6", 8192), BundleJSON: digest("7", 2048),
			InstallJSON: digest("8", 1024),
		},
		Source: PackageSourceEvidence{
			BundleSecurityReceipt: digest("9", 4096),
			CodesignPolicySHA256:  strings.Repeat("c", 64),
			CodesignReceipt:       digest("b", 4096),
			PackagePolicySHA256:   policy.SHA256,
		},
		Tools: tools, VerifiedAt: now.UTC().Format(time.RFC3339),
	}
}
