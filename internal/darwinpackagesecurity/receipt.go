// Package darwinpackagesecurity parses the canonical local security evidence
// produced for one exact Darwin node staging-bundle candidate.
package darwinpackagesecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	releasetrust "mesh/internal/release"
)

const (
	Schema         = "mesh-darwin-package-security-receipt-v1"
	MaxReceiptSize = 128 << 10
	emptyReportSHA = "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
	maxReceiptAge  = 24 * time.Hour
	maxDatabaseAge = 72 * time.Hour
	maxFutureSkew  = 5 * time.Minute
)

type DigestRecord struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type RuntimeIdentity struct {
	Commit                string `json:"commit"`
	DarwinBuildLockSHA256 string `json:"darwin_build_lock_sha256"`
	GoVersion             string `json:"go_version"`
	PatchSetSHA256        string `json:"patch_set_sha256"`
	PatchedTreeSHA256     string `json:"patched_tree_sha256"`
	SourceBuildLockSHA256 string `json:"source_build_lock_sha256"`
	SourceTreeSHA256      string `json:"source_tree_sha256"`
	UpstreamLockSHA256    string `json:"upstream_lock_sha256"`
	Version               string `json:"version"`
}

// Fields follow lexicographic JSON-key order because the Python producer uses
// sort_keys canonical JSON and parsing requires exact byte equivalence.
type Receipt struct {
	Artifact  DigestRecord `json:"artifact"`
	Candidate struct {
		Architecture      string                  `json:"architecture"`
		BuildTime         string                  `json:"build_time"`
		Commit            string                  `json:"commit"`
		DirectoryCount    int                     `json:"directory_count"`
		FileCount         int                     `json:"file_count"`
		Files             map[string]DigestRecord `json:"files"`
		GoVersion         string                  `json:"go_version"`
		Inspection        DigestRecord            `json:"inspection"`
		PackageJSONSHA256 string                  `json:"package_json_sha256"`
		Runtime           RuntimeIdentity         `json:"runtime"`
		Schema            string                  `json:"schema"`
		SecurityFloor     uint64                  `json:"security_floor"`
		TotalBytes        int64                   `json:"total_bytes"`
		Verifier          DigestRecord            `json:"verifier"`
		Version           string                  `json:"version"`
	} `json:"candidate"`
	SBOM struct {
		SPDXJSON         DigestRecord `json:"spdx_json"`
		SPDXPackageCount int          `json:"spdx_package_count"`
		SPDXVersion      string       `json:"spdx_version"`
		SyftJSON         DigestRecord `json:"syft_json"`
		SyftPackageCount int          `json:"syft_package_count"`
		SyftSchema       string       `json:"syft_schema"`
		SyftVersion      string       `json:"syft_version"`
	} `json:"sbom"`
	ScannerBoundary struct {
		ArtifactAndScan string `json:"artifact_and_scan"`
		DatabaseUpdate  string `json:"database_update"`
	} `json:"scanner_boundary"`
	Schema     string `json:"schema"`
	SecretScan struct {
		BinaryStringsReport DigestRecord `json:"binary_strings_report"`
		GitleaksVersion     string       `json:"gitleaks_version"`
		Policy              string       `json:"policy"`
		TextReport          DigestRecord `json:"text_report"`
	} `json:"secret_scan"`
	VerifiedAt        string `json:"verified_at"`
	VulnerabilityScan struct {
		CountsBySeverity     map[string]int `json:"counts_by_severity"`
		DatabaseBuilt        string         `json:"database_built"`
		DatabaseSchema       string         `json:"database_schema"`
		DatabaseStatus       DigestRecord   `json:"database_status"`
		GrypeVersion         string         `json:"grype_version"`
		MatchCount           int            `json:"match_count"`
		Policy               string         `json:"policy"`
		RemainingNonfixedIDs []string       `json:"remaining_nonfixed_ids"`
		Report               DigestRecord   `json:"report"`
	} `json:"vulnerability_scan"`
}

var expectedRuntime = RuntimeIdentity{
	Commit:                "f573e8a26695278f9d71587390fbfe0d0933aa21",
	GoVersion:             "go1.26.5",
	PatchSetSHA256:        "5e8a928b2c5c9cc95666642881a853b557b5b1fa8972acdee9c1c74641fcfb5e",
	PatchedTreeSHA256:     "c35f432bd15d40346b12ec19a33b7a9e6844514f228b4dc5e3853f9033b2f5c6",
	SourceBuildLockSHA256: "18935f949438c52803309d0b78730531a7947717bdd6e5f37b0c88ff0cb458d9",
	SourceTreeSHA256:      "1d1aefeda0b2d9708dfb9bd39d25393351bace2b5e1a91a2021315fe8b410478",
	UpstreamLockSHA256:    "9f0515702d74a0911263a160754948220e41b5da7048f48adf67355b3816dd7c",
	Version:               "v1.10.3",
	DarwinBuildLockSHA256: "007f2ede3ef625ee48de3b5c616c43b3d5698903c09649f2b6a1cbed8d9392b7",
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) < 1 || len(raw) > MaxReceiptSize {
		return Receipt{}, fmt.Errorf("Darwin package security receipt size must be between 1 and %d bytes", MaxReceiptSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Receipt{}, fmt.Errorf("invalid Darwin package security receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode Darwin package security receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("Darwin package security receipt contains trailing content")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, fmt.Errorf("encode Darwin package security receipt: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return Receipt{}, errors.New("Darwin package security receipt must be canonical sorted compact JSON followed by one LF")
	}
	return receipt, nil
}

// MatchArtifact proves the receipt covers the exact Darwin artifact identity
// and release selection about to enter threshold-signed metadata.
func (receipt Receipt) MatchArtifact(now time.Time, arch, version string, securityFloor uint64, size int64, sha256 string) error {
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	verifiedAt, _ := time.Parse(time.RFC3339Nano, receipt.VerifiedAt)
	now = now.UTC()
	if now.IsZero() || verifiedAt.After(now.Add(maxFutureSkew)) {
		return errors.New("Darwin package security receipt verification time is in the future")
	}
	if now.Sub(verifiedAt) > maxReceiptAge {
		return errors.New("Darwin package security receipt is older than 24 hours")
	}
	if receipt.Candidate.Architecture != arch || receipt.Candidate.Version != version ||
		receipt.Candidate.SecurityFloor != securityFloor || receipt.Artifact.Size != size || receipt.Artifact.SHA256 != sha256 {
		return errors.New("Darwin package security receipt differs from the release-selected artifact identity")
	}
	return nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != Schema || receipt.Candidate.Schema != "mesh-darwin-node-staging-bundle-v1" {
		return errors.New("unsupported Darwin package security receipt schema")
	}
	arch := receipt.Candidate.Architecture
	if arch != "amd64" && arch != "arm64" {
		return errors.New("Darwin package security receipt architecture is invalid")
	}
	if receipt.Candidate.Version == "" || len(receipt.Candidate.Version) > 128 || strings.TrimSpace(receipt.Candidate.Version) != receipt.Candidate.Version ||
		!validHex(receipt.Candidate.Commit, 40) || !canonicalUTC(receipt.Candidate.BuildTime) || receipt.Candidate.SecurityFloor == 0 ||
		receipt.Candidate.GoVersion != "go1.26.5" || receipt.Candidate.FileCount != 7 || receipt.Candidate.DirectoryCount != 9 ||
		receipt.Candidate.TotalBytes < 1 || receipt.Candidate.TotalBytes > 256<<20 || receipt.Candidate.Runtime != expectedRuntime ||
		!validDigest(receipt.Candidate.PackageJSONSHA256) {
		return errors.New("Darwin package security candidate identity, provenance, or bounds are invalid")
	}
	if err := validRecord(receipt.Artifact, 1, 272<<20, "artifact"); err != nil {
		return err
	}
	expectedFiles := []string{
		"Library/LaunchDaemons/io.mesh.node-agent.plist", "bin/meshctl", "bin/nebula-cert",
		"bin/nebula", "package.json", "share/doc/mesh/launchd/README.md", "share/licenses/nebula/LICENSE",
	}
	if len(receipt.Candidate.Files) != len(expectedFiles) {
		return errors.New("Darwin package security receipt file set is incomplete")
	}
	var total int64
	for _, name := range expectedFiles {
		record, found := receipt.Candidate.Files[name]
		if !found {
			return fmt.Errorf("Darwin package security receipt is missing %s", name)
		}
		if err := validRecord(record, 1, 128<<20, "candidate file "+name); err != nil {
			return err
		}
		total += record.Size
	}
	if total != receipt.Candidate.TotalBytes || receipt.Candidate.Files["package.json"].SHA256 != receipt.Candidate.PackageJSONSHA256 {
		return errors.New("Darwin package security receipt file totals or package identity are inconsistent")
	}
	for label, record := range map[string]DigestRecord{
		"candidate inspection": receipt.Candidate.Inspection, "candidate verifier": receipt.Candidate.Verifier,
		"Syft JSON": receipt.SBOM.SyftJSON, "SPDX JSON": receipt.SBOM.SPDXJSON,
		"Grype database": receipt.VulnerabilityScan.DatabaseStatus, "Grype report": receipt.VulnerabilityScan.Report,
	} {
		if err := validRecord(record, 1, 128<<20, label); err != nil {
			return err
		}
	}
	if receipt.SBOM.SyftVersion != "1.44.0" || receipt.SBOM.SyftSchema != "16.1.3" || receipt.SBOM.SyftPackageCount != 52 ||
		receipt.SBOM.SPDXVersion != "SPDX-2.3" || receipt.SBOM.SPDXPackageCount != 53 {
		return errors.New("Darwin package security SBOM versions or exact package counts are invalid")
	}
	if receipt.ScannerBoundary.ArtifactAndScan != "stable candidate, networkless read-only non-root scanners, no Docker socket" ||
		receipt.ScannerBoundary.DatabaseUpdate != "networked scanner with only an empty private database cache mounted" {
		return errors.New("Darwin package scanner isolation boundary is invalid")
	}
	if receipt.SecretScan.GitleaksVersion != "v8.30.1" ||
		receipt.SecretScan.Policy != "default rules over exact package metadata, launchd assets, license, and all three Mach-O executables' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted" ||
		receipt.SecretScan.TextReport != (DigestRecord{SHA256: emptyReportSHA, Size: 3}) ||
		receipt.SecretScan.BinaryStringsReport != (DigestRecord{SHA256: emptyReportSHA, Size: 3}) {
		return errors.New("Darwin package secret-scan policy or empty reports are invalid")
	}
	if receipt.VulnerabilityScan.GrypeVersion != "0.112.0" ||
		receipt.VulnerabilityScan.Policy != "reject High or Critical matches and every match with a published fix" ||
		receipt.VulnerabilityScan.MatchCount != 3 || len(receipt.VulnerabilityScan.CountsBySeverity) != 1 ||
		receipt.VulnerabilityScan.CountsBySeverity["Unknown"] != 3 ||
		len(receipt.VulnerabilityScan.RemainingNonfixedIDs) != 1 || receipt.VulnerabilityScan.RemainingNonfixedIDs[0] != "GO-2026-5932" ||
		!validDatabaseSchema(receipt.VulnerabilityScan.DatabaseSchema) || !canonicalUTC(receipt.VulnerabilityScan.DatabaseBuilt) {
		return errors.New("Darwin package vulnerability-scan policy, database, or exact admitted results are invalid")
	}
	if !canonicalUTC(receipt.VerifiedAt) {
		return errors.New("Darwin package security verification time must be canonical UTC RFC3339")
	}
	databaseBuilt, _ := time.Parse(time.RFC3339Nano, receipt.VulnerabilityScan.DatabaseBuilt)
	verifiedAt, _ := time.Parse(time.RFC3339Nano, receipt.VerifiedAt)
	if databaseBuilt.After(verifiedAt) || verifiedAt.Sub(databaseBuilt) > maxDatabaseAge {
		return errors.New("Darwin package vulnerability database was not current at verification time")
	}
	return nil
}

func validRecord(record DigestRecord, minimum, maximum int64, label string) error {
	if !validDigest(record.SHA256) || record.Size < minimum || record.Size > maximum {
		return fmt.Errorf("Darwin package security %s digest or size is invalid", label)
	}
	return nil
}

func validDigest(value string) bool { return validHex(value, 64) }

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func canonicalUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC &&
		(parsed.Format(time.RFC3339Nano) == value || parsed.Format("2006-01-02T15:04:05.000000Z") == value)
}

func validDatabaseSchema(value string) bool {
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 || !strings.HasPrefix(value, "v") {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}
