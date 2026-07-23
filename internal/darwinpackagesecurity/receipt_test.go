package darwinpackagesecurity

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReceiptRoundTripAndArtifactBinding(t *testing.T) {
	receipt := fixtureReceipt("amd64")
	raw := encodeFixture(t, receipt)
	parsed, err := ParseReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	if err := parsed.MatchArtifact(now, "amd64", "1.2.3", 2, 1024, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := parsed.MatchArtifact(now, "arm64", "1.2.3", 2, 1024, strings.Repeat("a", 64)); err == nil {
		t.Fatal("receipt matched the wrong release artifact")
	}
}

func TestReceiptRejectsStaleAndFutureReleaseUse(t *testing.T) {
	parsed, err := ParseReceipt(encodeFixture(t, fixtureReceipt("amd64")))
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.MatchArtifact(time.Date(2026, 7, 22, 17, 0, 1, 0, time.UTC), "amd64", "1.2.3", 2, 1024, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "older than 24 hours") {
		t.Fatalf("stale receipt returned %v", err)
	}
	if err := parsed.MatchArtifact(time.Date(2026, 7, 21, 16, 54, 59, 0, time.UTC), "amd64", "1.2.3", 2, 1024, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future receipt returned %v", err)
	}
}

func TestReceiptSupportsBothLockedArchitectures(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			if _, err := ParseReceipt(encodeFixture(t, fixtureReceipt(arch))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCanonicalUTCAcceptsScannerMicroseconds(t *testing.T) {
	if !canonicalUTC("2026-07-21T17:43:14.839650Z") {
		t.Fatal("canonical scanner timestamp was rejected")
	}
}

func TestReceiptRejectsCanonicalAndPolicyDrift(t *testing.T) {
	valid := encodeFixture(t, fixtureReceipt("amd64"))
	for name, mutate := range map[string]func([]byte) []byte{
		"missing LF": func(raw []byte) []byte { return bytes.TrimSuffix(raw, []byte{'\n'}) },
		"unknown field": func(raw []byte) []byte {
			var document map[string]any
			_ = json.Unmarshal(raw, &document)
			document["unknown"] = true
			result, _ := json.Marshal(document)
			return append(result, '\n')
		},
		"high severity": func(raw []byte) []byte {
			var receipt Receipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.VulnerabilityScan.CountsBySeverity = map[string]int{"High": 3}
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
		"runtime provenance": func(raw []byte) []byte {
			var receipt Receipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.Candidate.Runtime.DarwinBuildLockSHA256 = strings.Repeat("9", 64)
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
		"stale database at verification": func(raw []byte) []byte {
			var receipt Receipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.VulnerabilityScan.DatabaseBuilt = "2026-07-18T16:59:59Z"
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
		"nonempty secret report": func(raw []byte) []byte {
			var receipt Receipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.SecretScan.TextReport = DigestRecord{SHA256: strings.Repeat("f", 64), Size: 4}
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReceipt(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("drifted receipt was accepted")
			}
		})
	}
}

func fixtureReceipt(arch string) Receipt {
	record := func(character string, size int64) DigestRecord {
		return DigestRecord{SHA256: strings.Repeat(character, 64), Size: size}
	}
	var receipt Receipt
	receipt.Schema = Schema
	receipt.VerifiedAt = "2026-07-21T17:00:00Z"
	receipt.Artifact = record("a", 1024)
	receipt.Candidate.Architecture = arch
	receipt.Candidate.BuildTime = "2026-07-21T16:00:00Z"
	receipt.Candidate.Commit = strings.Repeat("b", 40)
	receipt.Candidate.DirectoryCount = 9
	receipt.Candidate.FileCount = 7
	receipt.Candidate.GoVersion = "go1.26.5"
	receipt.Candidate.Inspection = record("c", 1024)
	receipt.Candidate.PackageJSONSHA256 = strings.Repeat("e", 64)
	receipt.Candidate.Runtime = expectedRuntime
	receipt.Candidate.Schema = "mesh-darwin-node-staging-bundle-v1"
	receipt.Candidate.SecurityFloor = 2
	receipt.Candidate.Verifier = record("f", 1024)
	receipt.Candidate.Version = "1.2.3"
	paths := []string{
		"Library/LaunchDaemons/io.mesh.node-agent.plist", "bin/meshctl", "bin/nebula-cert",
		"bin/nebula", "package.json", "share/doc/mesh/launchd/README.md", "share/licenses/nebula/LICENSE",
	}
	receipt.Candidate.Files = make(map[string]DigestRecord, len(paths))
	for _, name := range paths {
		receipt.Candidate.Files[name] = record("1", 1)
	}
	receipt.Candidate.Files["package.json"] = record("e", 1)
	receipt.Candidate.TotalBytes = int64(len(paths))
	receipt.SBOM.SyftVersion = "1.44.0"
	receipt.SBOM.SyftSchema = "16.1.3"
	receipt.SBOM.SyftPackageCount = 52
	receipt.SBOM.SyftJSON = record("2", 1024)
	receipt.SBOM.SPDXVersion = "SPDX-2.3"
	receipt.SBOM.SPDXPackageCount = 53
	receipt.SBOM.SPDXJSON = record("3", 1024)
	receipt.ScannerBoundary.ArtifactAndScan = "stable candidate, networkless read-only non-root scanners, no Docker socket"
	receipt.ScannerBoundary.DatabaseUpdate = "networked scanner with only an empty private database cache mounted"
	receipt.SecretScan.GitleaksVersion = "v8.30.1"
	receipt.SecretScan.Policy = "default rules over exact package metadata, launchd assets, license, and all three Mach-O executables' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted"
	receipt.SecretScan.TextReport = DigestRecord{SHA256: emptyReportSHA, Size: 3}
	receipt.SecretScan.BinaryStringsReport = DigestRecord{SHA256: emptyReportSHA, Size: 3}
	receipt.VulnerabilityScan.GrypeVersion = "0.112.0"
	receipt.VulnerabilityScan.Policy = "reject High or Critical matches and every match with a published fix"
	receipt.VulnerabilityScan.DatabaseBuilt = "2026-07-21T07:05:18Z"
	receipt.VulnerabilityScan.DatabaseSchema = "v6.1.9"
	receipt.VulnerabilityScan.DatabaseStatus = record("4", 1024)
	receipt.VulnerabilityScan.Report = record("5", 1024)
	receipt.VulnerabilityScan.MatchCount = 3
	receipt.VulnerabilityScan.CountsBySeverity = map[string]int{"Unknown": 3}
	receipt.VulnerabilityScan.RemainingNonfixedIDs = []string{"GO-2026-5932"}
	return receipt
}

func encodeFixture(t *testing.T, receipt Receipt) []byte {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}
