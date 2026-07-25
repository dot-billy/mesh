package origindeploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	originSecurityReceiptSchema = "mesh-origin-image-security-receipt-v1"
	originArchiveEvidenceSchema = "mesh-origin-image-archive-evidence-v1"
	maxSecurityReceiptSize      = 64 << 10
	emptyGitleaksSHA256         = "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
	emptyFileSHA256             = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type securityDigestRecord struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Fields are declared in lexicographic JSON-key order because the producer
// writes Python sort_keys canonical JSON and Parse requires byte-for-byte
// canonical equivalence.
type originSecurityReceipt struct {
	Image struct {
		Archive              securityDigestRecord            `json:"archive"`
		ConfigDigest         string                          `json:"config_digest"`
		DockerImageID        string                          `json:"docker_image_id"`
		Files                map[string]securityDigestRecord `json:"files"`
		FilesystemEntryCount int                             `json:"filesystem_entry_count"`
		Platform             string                          `json:"platform"`
		Schema               string                          `json:"schema"`
	} `json:"image"`
	SBOM struct {
		SPDXJSON         securityDigestRecord `json:"spdx_json"`
		SPDXPackageCount int                  `json:"spdx_package_count"`
		SPDXVersion      string               `json:"spdx_version"`
		SyftJSON         securityDigestRecord `json:"syft_json"`
		SyftPackageCount int                  `json:"syft_package_count"`
		SyftSchema       string               `json:"syft_schema"`
		SyftVersion      string               `json:"syft_version"`
	} `json:"sbom"`
	ScannerBoundary struct {
		DatabaseUpdate      string `json:"database_update"`
		ImageArchiveAndScan string `json:"image_archive_and_scan"`
	} `json:"scanner_boundary"`
	Schema     string `json:"schema"`
	SecretScan struct {
		BinaryStringsReport securityDigestRecord `json:"binary_strings_report"`
		GitleaksVersion     string               `json:"gitleaks_version"`
		Policy              string               `json:"policy"`
		RootfsReport        securityDigestRecord `json:"rootfs_report"`
	} `json:"secret_scan"`
	VerifiedAt        string `json:"verified_at"`
	VulnerabilityScan struct {
		CountsBySeverity     map[string]int       `json:"counts_by_severity"`
		DatabaseBuilt        string               `json:"database_built"`
		DatabaseSchema       string               `json:"database_schema"`
		DatabaseStatus       securityDigestRecord `json:"database_status"`
		GrypeVersion         string               `json:"grype_version"`
		MatchCount           int                  `json:"match_count"`
		Policy               string               `json:"policy"`
		RemainingNonfixedIDs []string             `json:"remaining_nonfixed_ids"`
		Report               securityDigestRecord `json:"report"`
	} `json:"vulnerability_scan"`
}

func readOriginSecurityReceipt(path string) (originSecurityReceipt, string, error) {
	raw, digest, err := readStableFile(path, "origin image security receipt", maxSecurityReceiptSize)
	if err != nil {
		return originSecurityReceipt{}, "", err
	}
	receipt, err := parseOriginSecurityReceipt(raw)
	if err != nil {
		return originSecurityReceipt{}, "", err
	}
	return receipt, digest, nil
}

func parseOriginSecurityReceipt(raw []byte) (originSecurityReceipt, error) {
	if len(raw) < 1 || len(raw) > maxSecurityReceiptSize {
		return originSecurityReceipt{}, fmt.Errorf("origin image security receipt size must be between 1 and %d bytes", maxSecurityReceiptSize)
	}
	if err := validateStrictJSON(raw); err != nil {
		return originSecurityReceipt{}, fmt.Errorf("invalid origin image security receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt originSecurityReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return originSecurityReceipt{}, fmt.Errorf("decode origin image security receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return originSecurityReceipt{}, errors.New("origin image security receipt contains trailing content")
	}
	if err := validateOriginSecurityReceipt(receipt); err != nil {
		return originSecurityReceipt{}, err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return originSecurityReceipt{}, fmt.Errorf("encode origin image security receipt: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return originSecurityReceipt{}, errors.New("origin image security receipt must be canonical sorted compact JSON followed by one LF")
	}
	return receipt, nil
}

func validateOriginSecurityReceipt(receipt originSecurityReceipt) error {
	if receipt.Schema != originSecurityReceiptSchema || receipt.Image.Schema != originArchiveEvidenceSchema {
		return errors.New("unsupported origin image security receipt schema")
	}
	if receipt.Image.Platform != "linux/amd64" || receipt.Image.FilesystemEntryCount != 18 ||
		!strings.HasPrefix(receipt.Image.DockerImageID, "sha256:") ||
		!validDigest(strings.TrimPrefix(receipt.Image.DockerImageID, "sha256:")) ||
		!validDigest(receipt.Image.ConfigDigest) {
		return errors.New("origin image security identity, platform, or filesystem count is invalid")
	}
	if err := validateSecurityRecord(receipt.Image.Archive, 1<<20, 256<<20, "origin image archive"); err != nil {
		return err
	}
	expectedFiles := map[string][2]int64{
		"etc/ssl/certs/ca-certificates.crt": {64 << 10, 1 << 20},
		"run/origin/index.json":             {0, 0},
		"run/tls/ca.crt":                    {0, 0},
		"run/tls/server.crt":                {0, 0},
		"run/tls/server.key":                {0, 0},
		"usr/local/bin/mesh-healthcheck":    {1 << 20, 32 << 20},
		"usr/local/bin/mesh-origin":         {1 << 20, 32 << 20},
	}
	if len(receipt.Image.Files) != len(expectedFiles) {
		return errors.New("origin image security file evidence differs from the exact allowlist")
	}
	for name, bounds := range expectedFiles {
		record, ok := receipt.Image.Files[name]
		if !ok {
			return fmt.Errorf("origin image security file evidence is missing %s", name)
		}
		if err := validateSecurityRecord(record, bounds[0], bounds[1], "origin image file "+name); err != nil {
			return err
		}
		if bounds == [2]int64{0, 0} && record.SHA256 != emptyFileSHA256 {
			return fmt.Errorf("origin image placeholder %s is not proven empty", name)
		}
	}
	if receipt.SBOM.SyftVersion != "1.44.0" || receipt.SBOM.SyftSchema != "16.1.3" ||
		receipt.SBOM.SyftPackageCount != 5 || receipt.SBOM.SPDXVersion != "SPDX-2.3" ||
		receipt.SBOM.SPDXPackageCount != 6 {
		return errors.New("origin image SBOM versions or exact package counts are invalid")
	}
	for label, record := range map[string]securityDigestRecord{
		"Syft JSON": receipt.SBOM.SyftJSON, "SPDX JSON": receipt.SBOM.SPDXJSON,
		"Grype database status": receipt.VulnerabilityScan.DatabaseStatus,
		"Grype report":          receipt.VulnerabilityScan.Report,
	} {
		if err := validateSecurityRecord(record, 1, 64<<20, label); err != nil {
			return err
		}
	}
	if receipt.ScannerBoundary.DatabaseUpdate != "networked scanner with only an empty private database cache mounted" ||
		receipt.ScannerBoundary.ImageArchiveAndScan != "networkless, read-only, non-root, capability-free containers without a Docker socket" {
		return errors.New("origin image scanner isolation boundary is invalid")
	}
	if receipt.SecretScan.GitleaksVersion != "v8.30.1" ||
		receipt.SecretScan.Policy != "default rules over exact origin rootfs text and both binaries' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted" ||
		receipt.SecretScan.RootfsReport != (securityDigestRecord{SHA256: emptyGitleaksSHA256, Size: 3}) ||
		receipt.SecretScan.BinaryStringsReport != (securityDigestRecord{SHA256: emptyGitleaksSHA256, Size: 3}) {
		return errors.New("origin image secret-scan policy or empty reports are invalid")
	}
	if receipt.VulnerabilityScan.GrypeVersion != "0.112.0" ||
		receipt.VulnerabilityScan.Policy != "reject High or Critical matches and every match with a published fix" ||
		receipt.VulnerabilityScan.MatchCount < 0 || receipt.VulnerabilityScan.MatchCount > 4096 ||
		len(receipt.VulnerabilityScan.RemainingNonfixedIDs) > receipt.VulnerabilityScan.MatchCount {
		return errors.New("origin image vulnerability-scan policy or counts are invalid")
	}
	if !validDatabaseSchema(receipt.VulnerabilityScan.DatabaseSchema) ||
		!canonicalUTCTime(receipt.VulnerabilityScan.DatabaseBuilt) {
		return errors.New("origin image vulnerability database identity is invalid")
	}
	totalMatches := 0
	for severity, count := range receipt.VulnerabilityScan.CountsBySeverity {
		if !slices.Contains([]string{"Unknown", "Negligible", "Low", "Medium"}, severity) || count < 1 {
			return errors.New("origin image vulnerability receipt contains a rejected severity or invalid count")
		}
		totalMatches += count
	}
	if totalMatches != receipt.VulnerabilityScan.MatchCount {
		return errors.New("origin image vulnerability severity counts do not equal the match count")
	}
	seenIDs := make(map[string]struct{}, len(receipt.VulnerabilityScan.RemainingNonfixedIDs))
	for _, identifier := range receipt.VulnerabilityScan.RemainingNonfixedIDs {
		if len(identifier) < 3 || len(identifier) > 128 || strings.TrimSpace(identifier) != identifier {
			return errors.New("origin image vulnerability receipt contains an invalid nonfixed identifier")
		}
		if _, exists := seenIDs[identifier]; exists {
			return errors.New("origin image vulnerability receipt repeats a nonfixed identifier")
		}
		seenIDs[identifier] = struct{}{}
	}
	if !canonicalUTCTime(receipt.VerifiedAt) {
		return errors.New("origin image security verification time must be canonical UTC RFC3339")
	}
	return nil
}

func validateSecurityRecord(record securityDigestRecord, minimum, maximum int64, label string) error {
	if !validDigest(record.SHA256) || record.Size < minimum || record.Size > maximum {
		return fmt.Errorf("%s digest or size is invalid", label)
	}
	return nil
}

func canonicalUTCTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
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
