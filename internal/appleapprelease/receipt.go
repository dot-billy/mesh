// Package appleapprelease validates the portable receipt for a protected
// Mesh Admin macOS application release. The receipt binds final archive bytes
// to native signing, notarization, staple, Gatekeeper, source, and tool
// evidence; it is not itself a signature or a substitute for native recheck.
package appleapprelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

const (
	ReceiptSchema               = "mesh-apple-macos-protected-release-receipt-v3"
	MaximumReceiptSize          = 128 << 10
	maximumArchiveSize    int64 = 1 << 30
	maximumFutureSkew           = 5 * time.Minute
	maximumPublicationAge       = 24 * time.Hour

	ApplicationIdentifier      = "io.rw0.mesh.admin"
	ApplicationEntitlementsSHA = "7d5e6186db50b75a29407055e71b8d78099ffd4035fde4f624ea29f9a0b584d0"
	EmptyEntitlementsSHA       = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identityPattern   = regexp.MustCompile(`^[0-9A-F]{40}$`)
	teamIDPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)
	buildPattern      = regexp.MustCompile(`^[0-9]+$`)
	submissionPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type ApplicationEvidence struct {
	Architectures      []string `json:"architectures"`
	Build              string   `json:"build"`
	BundleIdentifier   string   `json:"bundle_identifier"`
	MinimumMacOS       string   `json:"minimum_macos"`
	SignedRegularBytes int64    `json:"signed_regular_file_bytes"`
	SignedRegularFiles int      `json:"signed_regular_files"`
	SignedTreeSHA256   string   `json:"signed_tree_sha256"`
	Version            string   `json:"version"`
}

type DistributionEvidence struct {
	ExtractedRegularBytes int64  `json:"extracted_regular_file_bytes"`
	ExtractedRegularFiles int    `json:"extracted_regular_files"`
	ExtractedTreeSHA256   string `json:"extracted_tree_sha256"`
	Format                string `json:"format"`
	RoundTripVerified     bool   `json:"round_trip_verified"`
	SHA256                string `json:"sha256"`
	Size                  int64  `json:"size"`
}

type NotarizationEvidence struct {
	GatekeeperAssessment string `json:"gatekeeper_assessment"`
	Staple               string `json:"staple"`
	Status               string `json:"status"`
	SubmissionID         string `json:"submission_id"`
}

type NestedCodeEvidence struct {
	Architectures      []string `json:"architectures"`
	EntitlementsSHA256 string   `json:"entitlements_sha256"`
	Identifier         string   `json:"identifier"`
	Path               string   `json:"path"`
}

type SigningEvidence struct {
	ApplicationEntitlementsSHA256 string               `json:"application_entitlements_sha256"`
	HardenedRuntime               bool                 `json:"hardened_runtime"`
	IdentitySHA1                  string               `json:"identity_sha1"`
	NestedCode                    []NestedCodeEvidence `json:"nested_code"`
	TeamID                        string               `json:"team_id"`
}

type SourceEvidence struct {
	ReceiptSHA256         string `json:"receipt_sha256"`
	SecurityReceiptSHA256 string `json:"security_receipt_sha256"`
	TreeSHA256            string `json:"tree_sha256"`
}

type ToolEvidence struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Receipt struct {
	Application  ApplicationEvidence     `json:"application"`
	Distribution DistributionEvidence    `json:"distribution"`
	Notarization NotarizationEvidence    `json:"notarization"`
	Schema       string                  `json:"schema"`
	Signing      SigningEvidence         `json:"signing"`
	Source       SourceEvidence          `json:"source"`
	Tools        map[string]ToolEvidence `json:"tools"`
	VerifiedAt   string                  `json:"verified_at"`
}

type ArtifactIdentity struct {
	SHA256 string
	Size   int64
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode Apple application release receipt: %w", err)
	}
	if len(raw)+1 > MaximumReceiptSize {
		return nil, errors.New("Apple application release receipt exceeds its size bound")
	}
	return append(raw, '\n'), nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) < 2 || len(raw) > MaximumReceiptSize {
		return Receipt{}, errors.New("Apple application release receipt is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode Apple application release receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("Apple application release receipt contains trailing data")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Receipt{}, errors.New("Apple application release receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func (receipt Receipt) Match(now time.Time, artifact ArtifactIdentity, sourceReceiptSHA256, teamID string) error {
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	now = now.UTC()
	if now.IsZero() || verifiedAt.After(now.Add(maximumFutureSkew)) {
		return errors.New("Apple application release receipt verification time is in the future")
	}
	if !digestPattern.MatchString(sourceReceiptSHA256) || !teamIDPattern.MatchString(teamID) {
		return errors.New("expected Apple source receipt digest or Team ID is invalid")
	}
	if artifact.Size != receipt.Distribution.Size || artifact.SHA256 != receipt.Distribution.SHA256 {
		return errors.New("Apple application archive differs from its protected release receipt")
	}
	if sourceReceiptSHA256 != receipt.Source.ReceiptSHA256 || teamID != receipt.Signing.TeamID {
		return errors.New("Apple application release source receipt or Team ID differs")
	}
	return nil
}

// MatchForPublication applies Match and additionally requires release
// authoring to happen within 24 hours of the protected native verification.
// Old published receipts remain independently verifiable through Match.
func (receipt Receipt) MatchForPublication(now time.Time, artifact ArtifactIdentity, sourceReceiptSHA256, teamID string) error {
	if err := receipt.Match(now, artifact, sourceReceiptSHA256, teamID); err != nil {
		return err
	}
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if now.UTC().Sub(verifiedAt) > maximumPublicationAge {
		return errors.New("Apple application protected receipt is older than 24 hours for publication")
	}
	return nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema {
		return errors.New("Apple application release receipt schema is invalid")
	}
	if !sameArchitectures(receipt.Application.Architectures) ||
		receipt.Application.BundleIdentifier != ApplicationIdentifier ||
		receipt.Application.MinimumMacOS != "14.0" ||
		!versionPattern.MatchString(receipt.Application.Version) ||
		!buildPattern.MatchString(receipt.Application.Build) ||
		receipt.Application.SignedRegularFiles < 1 ||
		receipt.Application.SignedRegularFiles > 4096 ||
		receipt.Application.SignedRegularBytes < 1 ||
		receipt.Application.SignedRegularBytes > maximumArchiveSize ||
		!digestPattern.MatchString(receipt.Application.SignedTreeSHA256) {
		return errors.New("Apple application identity or signed tree evidence is invalid")
	}
	if receipt.Distribution.Format != "ditto-zip" ||
		!receipt.Distribution.RoundTripVerified ||
		receipt.Distribution.Size < 1 ||
		receipt.Distribution.Size > maximumArchiveSize ||
		!digestPattern.MatchString(receipt.Distribution.SHA256) ||
		receipt.Distribution.ExtractedTreeSHA256 != receipt.Application.SignedTreeSHA256 ||
		receipt.Distribution.ExtractedRegularFiles != receipt.Application.SignedRegularFiles ||
		receipt.Distribution.ExtractedRegularBytes != receipt.Application.SignedRegularBytes {
		return errors.New("Apple application distribution evidence is invalid")
	}
	if receipt.Notarization.GatekeeperAssessment != "accepted" ||
		receipt.Notarization.Staple != "validated" ||
		receipt.Notarization.Status != "Accepted" ||
		!submissionPattern.MatchString(receipt.Notarization.SubmissionID) {
		return errors.New("Apple application notarization evidence is invalid")
	}
	if receipt.Signing.ApplicationEntitlementsSHA256 != ApplicationEntitlementsSHA ||
		!receipt.Signing.HardenedRuntime ||
		!identityPattern.MatchString(receipt.Signing.IdentitySHA1) ||
		!teamIDPattern.MatchString(receipt.Signing.TeamID) {
		return errors.New("Apple application signing evidence is invalid")
	}
	if err := validateNestedCode(receipt.Signing.NestedCode); err != nil {
		return err
	}
	if !digestPattern.MatchString(receipt.Source.ReceiptSHA256) ||
		!digestPattern.MatchString(receipt.Source.SecurityReceiptSHA256) ||
		!digestPattern.MatchString(receipt.Source.TreeSHA256) {
		return errors.New("Apple application source evidence is invalid")
	}
	if err := validateTools(receipt.Tools); err != nil {
		return err
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if err != nil || verifiedAt.UTC().Format(time.RFC3339) != receipt.VerifiedAt {
		return errors.New("Apple application release time is not canonical UTC RFC3339")
	}
	return nil
}

func sameArchitectures(architectures []string) bool {
	return len(architectures) == 2 && architectures[0] == "arm64" && architectures[1] == "x86_64"
}

func validateNestedCode(code []NestedCodeEvidence) error {
	expected := []struct {
		path       string
		identifier string
	}{
		{"Contents/Frameworks/App.framework", "io.flutter.flutter.app"},
		{"Contents/Frameworks/FlutterMacOS.framework", "io.flutter.flutter-macos"},
		{"Contents/Frameworks/objective_c.framework", "io.flutter.flutter.native-assets.objective-c"},
	}
	if len(code) != len(expected) {
		return errors.New("Apple application nested-code inventory is incomplete")
	}
	for index, item := range code {
		if item.Path != expected[index].path ||
			item.Identifier != expected[index].identifier ||
			!sameArchitectures(item.Architectures) ||
			item.EntitlementsSHA256 != EmptyEntitlementsSHA {
			return fmt.Errorf("Apple application nested-code evidence %d is invalid or unordered", index)
		}
	}
	return nil
}

func validateTools(tools map[string]ToolEvidence) error {
	expected := []string{
		"/usr/bin/codesign",
		"/usr/bin/ditto",
		"/usr/bin/lipo",
		"/usr/bin/security",
		"/usr/bin/xcrun",
		"/usr/sbin/spctl",
		"notarytool",
		"stapler",
	}
	if len(tools) != len(expected) {
		return errors.New("Apple application protected-tool inventory is incomplete")
	}
	observed := make([]string, 0, len(tools))
	for name, evidence := range tools {
		if evidence.Size < 1 || evidence.Size > 256<<20 || !digestPattern.MatchString(evidence.SHA256) {
			return fmt.Errorf("Apple application protected-tool evidence is invalid for %q", name)
		}
		observed = append(observed, name)
	}
	sort.Strings(observed)
	for index := range expected {
		if observed[index] != expected[index] {
			return errors.New("Apple application protected-tool inventory is unexpected")
		}
	}
	return nil
}
