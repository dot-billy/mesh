package darwinnodepackage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"time"
)

const (
	ReceiptSchema               = "mesh-darwin-node-package-release-receipt-v1"
	MaximumReceiptSize          = 96 << 10
	maximumPackageSize    int64 = 512 << 20
	maximumFutureSkew           = 5 * time.Minute
	maximumPublicationAge       = 24 * time.Hour
)

var (
	receiptSHA1Pattern    = regexp.MustCompile(`^[0-9A-F]{40}$`)
	receiptTeamIDPattern  = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	receiptVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)
	receiptUUIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type DigestEvidence struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type BootstrapEvidence struct {
	CodeIdentifier string `json:"code_identifier"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
}

type PackageContentsEvidence struct {
	BOM               DigestEvidence `json:"bom"`
	DirectoryCount    int            `json:"directory_count"`
	FileCount         int            `json:"file_count"`
	PackageInfo       DigestEvidence `json:"package_info"`
	PayloadTreeSHA256 string         `json:"payload_tree_sha256"`
	PostinstallSHA256 string         `json:"postinstall_sha256"`
	ScriptsArchive    DigestEvidence `json:"scripts_archive"`
	UnexpectedXattrs  int            `json:"unexpected_xattrs"`
}

type PackageEvidence struct {
	Architecture    string `json:"architecture"`
	Identifier      string `json:"identifier"`
	InstallLocation string `json:"install_location"`
	PackageRoot     string `json:"package_root"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	Version         string `json:"version"`
}

type SnapshotEvidence struct {
	Artifact    DigestEvidence `json:"artifact"`
	BundleJSON  DigestEvidence `json:"bundle_json"`
	InstallJSON DigestEvidence `json:"install_json"`
}

type PackageSigningEvidence struct {
	InstallerCertificateSHA256 string `json:"installer_certificate_sha256"`
	InstallerIdentitySHA1      string `json:"installer_identity_sha1"`
	TeamID                     string `json:"team_id"`
}

type PackageNotarizationEvidence struct {
	GatekeeperAssessment string `json:"gatekeeper_assessment"`
	Staple               string `json:"staple"`
	Status               string `json:"status"`
	SubmissionID         string `json:"submission_id"`
}

type PackageSourceEvidence struct {
	BundleSecurityReceipt DigestEvidence `json:"bundle_security_receipt"`
	CodesignPolicySHA256  string         `json:"codesign_policy_sha256"`
	CodesignReceipt       DigestEvidence `json:"codesign_receipt"`
	PackagePolicySHA256   string         `json:"package_policy_sha256"`
}

type PackageToolEvidence struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type ReleaseReceipt struct {
	Bootstrap    BootstrapEvidence              `json:"bootstrap"`
	Contents     PackageContentsEvidence        `json:"contents"`
	Notarization PackageNotarizationEvidence    `json:"notarization"`
	Package      PackageEvidence                `json:"package"`
	Schema       string                         `json:"schema"`
	Signing      PackageSigningEvidence         `json:"signing"`
	Snapshot     SnapshotEvidence               `json:"snapshot"`
	Source       PackageSourceEvidence          `json:"source"`
	Tools        map[string]PackageToolEvidence `json:"tools"`
	VerifiedAt   string                         `json:"verified_at"`
}

type PackageArtifactIdentity struct {
	SHA256 string
	Size   int64
}

func EncodeReleaseReceipt(receipt ReleaseReceipt) ([]byte, error) {
	if err := validateReleaseReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode Darwin node package release receipt: %w", err)
	}
	if len(raw)+1 > MaximumReceiptSize {
		return nil, errors.New("Darwin node package release receipt exceeds its size bound")
	}
	return append(raw, '\n'), nil
}

func ParseReleaseReceipt(raw []byte) (ReleaseReceipt, error) {
	if len(raw) < 2 || len(raw) > MaximumReceiptSize {
		return ReleaseReceipt{}, errors.New("Darwin node package release receipt is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt ReleaseReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return ReleaseReceipt{}, fmt.Errorf("decode Darwin node package release receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ReleaseReceipt{}, errors.New("Darwin node package release receipt contains trailing data")
	}
	if err := validateReleaseReceipt(receipt); err != nil {
		return ReleaseReceipt{}, err
	}
	canonical, err := EncodeReleaseReceipt(receipt)
	if err != nil {
		return ReleaseReceipt{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return ReleaseReceipt{}, errors.New("Darwin node package release receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func (receipt ReleaseReceipt) MatchForPublication(
	now time.Time,
	artifact PackageArtifactIdentity,
	policy Policy,
	codesignPolicySHA256, meshInstallIdentifier, architecture, version, teamID string,
	codesignReceiptSHA256, bundleSecurityReceiptSHA256 string,
) error {
	if err := validateReleaseReceipt(receipt); err != nil {
		return err
	}
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	now = now.UTC()
	if now.IsZero() || verifiedAt.After(now.Add(maximumFutureSkew)) {
		return errors.New("Darwin node package release receipt verification time is in the future")
	}
	if now.Sub(verifiedAt) > maximumPublicationAge {
		return errors.New("Darwin node package release receipt is older than 24 hours for publication")
	}
	if artifact.Size != receipt.Package.Size || artifact.SHA256 != receipt.Package.SHA256 {
		return errors.New("Darwin node package differs from its protected release receipt")
	}
	if architecture != receipt.Package.Architecture ||
		version != receipt.Package.Version ||
		teamID != receipt.Signing.TeamID ||
		policy.PackageIdentifier != receipt.Package.Identifier ||
		policy.PackageInstallLocation != receipt.Package.InstallLocation ||
		policy.PackageRootPath != receipt.Package.PackageRoot ||
		policy.SHA256 != receipt.Source.PackagePolicySHA256 ||
		codesignPolicySHA256 != receipt.Source.CodesignPolicySHA256 ||
		meshInstallIdentifier != receipt.Bootstrap.CodeIdentifier ||
		codesignReceiptSHA256 != receipt.Source.CodesignReceipt.SHA256 ||
		bundleSecurityReceiptSHA256 != receipt.Source.BundleSecurityReceipt.SHA256 {
		return errors.New("Darwin node package release authority differs from its receipt")
	}
	return nil
}

func validateReleaseReceipt(receipt ReleaseReceipt) error {
	if receipt.Schema != ReceiptSchema {
		return errors.New("Darwin node package release receipt schema is invalid")
	}
	if (receipt.Package.Architecture != "arm64" && receipt.Package.Architecture != "amd64") ||
		!canonicalIdentifier(receipt.Package.Identifier) ||
		receipt.Package.InstallLocation != PackageInstallLocation ||
		!boundedPath(receipt.Package.PackageRoot, receipt.Package.InstallLocation) ||
		path.Dir(receipt.Package.PackageRoot) != receipt.Package.InstallLocation ||
		!receiptVersionPattern.MatchString(receipt.Package.Version) ||
		receipt.Package.Size < 1 || receipt.Package.Size > maximumPackageSize ||
		!canonicalSHA256(receipt.Package.SHA256) {
		return errors.New("Darwin node package identity or artifact evidence is invalid")
	}
	if receipt.Bootstrap.Size < 512 || receipt.Bootstrap.Size > 132<<20 ||
		!canonicalIdentifier(receipt.Bootstrap.CodeIdentifier) ||
		!canonicalSHA256(receipt.Bootstrap.SHA256) {
		return errors.New("Darwin node package bootstrap evidence is invalid")
	}
	if receipt.Contents.DirectoryCount != 2 || receipt.Contents.FileCount != 4 ||
		!canonicalSHA256(receipt.Contents.PayloadTreeSHA256) ||
		receipt.Contents.PostinstallSHA256 != receipt.Bootstrap.SHA256 ||
		receipt.Contents.UnexpectedXattrs != 0 {
		return errors.New("Darwin node package exact payload evidence is invalid")
	}
	for label, evidence := range map[string]DigestEvidence{
		"BOM":                     receipt.Contents.BOM,
		"PackageInfo":             receipt.Contents.PackageInfo,
		"scripts archive":         receipt.Contents.ScriptsArchive,
		"snapshot artifact":       receipt.Snapshot.Artifact,
		"snapshot bundle":         receipt.Snapshot.BundleJSON,
		"snapshot descriptor":     receipt.Snapshot.InstallJSON,
		"bundle security receipt": receipt.Source.BundleSecurityReceipt,
		"code-signing receipt":    receipt.Source.CodesignReceipt,
	} {
		if evidence.Size < 1 || evidence.Size > maximumPackageSize ||
			!canonicalSHA256(evidence.SHA256) {
			return fmt.Errorf("Darwin node package %s evidence is invalid", label)
		}
	}
	if !canonicalSHA256(receipt.Source.CodesignPolicySHA256) ||
		!canonicalSHA256(receipt.Source.PackagePolicySHA256) {
		return errors.New("Darwin node package compiled policy evidence is invalid")
	}
	if !canonicalSHA256(receipt.Signing.InstallerCertificateSHA256) ||
		!receiptSHA1Pattern.MatchString(receipt.Signing.InstallerIdentitySHA1) ||
		!receiptTeamIDPattern.MatchString(receipt.Signing.TeamID) {
		return errors.New("Darwin node package signing evidence is invalid")
	}
	if receipt.Notarization.GatekeeperAssessment != "accepted" ||
		receipt.Notarization.Staple != "validated" ||
		receipt.Notarization.Status != "Accepted" ||
		!receiptUUIDPattern.MatchString(receipt.Notarization.SubmissionID) {
		return errors.New("Darwin node package notarization evidence is invalid")
	}
	if err := validatePackageTools(receipt.Tools); err != nil {
		return err
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if err != nil || verifiedAt.UTC().Format(time.RFC3339) != receipt.VerifiedAt {
		return errors.New("Darwin node package release time is not canonical UTC RFC3339")
	}
	return nil
}

func validatePackageTools(tools map[string]PackageToolEvidence) error {
	expected := []string{
		"/usr/bin/codesign",
		"/usr/bin/lipo",
		"/usr/bin/lsbom",
		"/usr/bin/pkgbuild",
		"/usr/bin/productsign",
		"/usr/bin/security",
		"/usr/bin/xcrun",
		"/usr/sbin/pkgutil",
		"/usr/sbin/spctl",
		"notarytool",
		"stapler",
	}
	if len(tools) != len(expected) {
		return errors.New("Darwin node package protected-tool inventory is incomplete")
	}
	observed := make([]string, 0, len(tools))
	for name, evidence := range tools {
		if evidence.Size < 1 || evidence.Size > 256<<20 ||
			!canonicalSHA256(evidence.SHA256) {
			return fmt.Errorf("Darwin node package protected-tool evidence is invalid for %q", name)
		}
		observed = append(observed, name)
	}
	sort.Strings(observed)
	for index := range expected {
		if observed[index] != expected[index] {
			return errors.New("Darwin node package protected-tool inventory is unexpected")
		}
	}
	return nil
}
