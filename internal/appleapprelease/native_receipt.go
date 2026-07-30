package appleapprelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	NativeReceiptSchema      = "mesh-apple-macos-public-native-verification-receipt-v1"
	MaximumNativeReceiptSize = 128 << 10
	maximumNativeSignatures  = 64
)

type NativeApplicationEvidence struct {
	Architectures    []string `json:"architectures"`
	BundleIdentifier string   `json:"bundle_identifier"`
	SignedTreeSHA256 string   `json:"signed_tree_sha256"`
}

type NativeFileEvidence struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type NativePlatformEvidence struct {
	GatekeeperAssessment  string            `json:"gatekeeper_assessment"`
	NetworkIsolationCheck string            `json:"network_isolation_check"`
	NetworkIsolationTools map[string]string `json:"network_isolation_tools"`
	Staple                string            `json:"staple"`
}

type ReleaseMetadataEvidence struct {
	ManifestSHA256  string   `json:"manifest_sha256"`
	RootSHA256      string   `json:"root_sha256"`
	SignatureSHA256 []string `json:"signature_sha256"`
}

type NativeSigningEvidence struct {
	ApplicationEntitlementsSHA256 string               `json:"application_entitlements_sha256"`
	NestedCode                    []NestedCodeEvidence `json:"nested_code"`
	TeamID                        string               `json:"team_id"`
}

type NativeReceipt struct {
	Application                      NativeApplicationEvidence `json:"application"`
	Archive                          NativeFileEvidence        `json:"archive"`
	MeshReleaseVerifier              NativeFileEvidence        `json:"mesh_release_verifier"`
	MetadataVerificationStdoutSHA256 string                    `json:"metadata_verification_stdout_sha256"`
	Native                           NativePlatformEvidence    `json:"native"`
	ProtectedReceiptSHA256           string                    `json:"protected_receipt_sha256"`
	ReleaseMetadata                  ReleaseMetadataEvidence   `json:"release_metadata"`
	Schema                           string                    `json:"schema"`
	Signing                          NativeSigningEvidence     `json:"signing"`
	Tools                            map[string]ToolEvidence   `json:"tools"`
	VerifiedAt                       string                    `json:"verified_at"`
}

type NativeExpectation struct {
	Archive                ArtifactIdentity
	ManifestSHA256         string
	MeshReleaseVerifier    ArtifactIdentity
	ProtectedReceiptSHA256 string
	RequireNetworkIsolated bool
	RootSHA256             string
	TeamID                 string
}

func EncodeNativeReceipt(receipt NativeReceipt) ([]byte, error) {
	if err := validateNativeReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode native Apple application receipt: %w", err)
	}
	if len(raw)+1 > MaximumNativeReceiptSize {
		return nil, errors.New("native Apple application receipt exceeds its size bound")
	}
	return append(raw, '\n'), nil
}

func ParseNativeReceipt(raw []byte) (NativeReceipt, error) {
	if len(raw) < 2 || len(raw) > MaximumNativeReceiptSize {
		return NativeReceipt{}, errors.New("native Apple application receipt is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt NativeReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return NativeReceipt{}, fmt.Errorf("decode native Apple application receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return NativeReceipt{}, errors.New("native Apple application receipt contains trailing data")
	}
	if err := validateNativeReceipt(receipt); err != nil {
		return NativeReceipt{}, err
	}
	canonical, err := EncodeNativeReceipt(receipt)
	if err != nil {
		return NativeReceipt{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return NativeReceipt{}, errors.New("native Apple application receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func (receipt NativeReceipt) Match(now time.Time, expected NativeExpectation) error {
	if err := validateNativeReceipt(receipt); err != nil {
		return err
	}
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	now = now.UTC()
	if now.IsZero() || verifiedAt.After(now.Add(maximumFutureSkew)) {
		return errors.New("native Apple application receipt verification time is in the future")
	}
	if now.Sub(verifiedAt) > maximumPublicationAge {
		return errors.New("native Apple application receipt is older than 24 hours")
	}
	if expected.Archive.Size != receipt.Archive.Size ||
		expected.Archive.SHA256 != receipt.Archive.SHA256 ||
		expected.MeshReleaseVerifier.Size != receipt.MeshReleaseVerifier.Size ||
		expected.MeshReleaseVerifier.SHA256 != receipt.MeshReleaseVerifier.SHA256 ||
		expected.ProtectedReceiptSHA256 != receipt.ProtectedReceiptSHA256 ||
		expected.ManifestSHA256 != receipt.ReleaseMetadata.ManifestSHA256 ||
		expected.RootSHA256 != receipt.ReleaseMetadata.RootSHA256 ||
		expected.TeamID != receipt.Signing.TeamID {
		return errors.New("native Apple application receipt differs from expected release evidence")
	}
	if expected.RequireNetworkIsolated &&
		receipt.Native.NetworkIsolationCheck != "pre-and-post-no-default-route-or-nonloopback-unicast" {
		return errors.New("native Apple application receipt lacks network-isolation evidence")
	}
	return nil
}

func validateNativeReceipt(receipt NativeReceipt) error {
	if receipt.Schema != NativeReceiptSchema ||
		!sameArchitectures(receipt.Application.Architectures) ||
		receipt.Application.BundleIdentifier != ApplicationIdentifier ||
		!digestPattern.MatchString(receipt.Application.SignedTreeSHA256) {
		return errors.New("native Apple application identity evidence is invalid")
	}
	if err := validateNativeFile(receipt.Archive, maximumArchiveSize); err != nil {
		return fmt.Errorf("native Apple application archive evidence: %w", err)
	}
	if err := validateNativeFile(receipt.MeshReleaseVerifier, 256<<20); err != nil {
		return fmt.Errorf("native Apple application verifier evidence: %w", err)
	}
	if !digestPattern.MatchString(receipt.MetadataVerificationStdoutSHA256) ||
		!digestPattern.MatchString(receipt.ProtectedReceiptSHA256) ||
		!digestPattern.MatchString(receipt.ReleaseMetadata.ManifestSHA256) ||
		!digestPattern.MatchString(receipt.ReleaseMetadata.RootSHA256) {
		return errors.New("native Apple application metadata evidence is invalid")
	}
	if err := validateSignatureDigests(receipt.ReleaseMetadata.SignatureSHA256); err != nil {
		return err
	}
	if receipt.Signing.ApplicationEntitlementsSHA256 != ApplicationEntitlementsSHA ||
		!teamIDPattern.MatchString(receipt.Signing.TeamID) {
		return errors.New("native Apple application signing evidence is invalid")
	}
	if err := validateNestedCode(receipt.Signing.NestedCode); err != nil {
		return err
	}
	if receipt.Native.GatekeeperAssessment != "accepted" ||
		receipt.Native.Staple != "validated" {
		return errors.New("native Apple application platform evidence is invalid")
	}
	switch receipt.Native.NetworkIsolationCheck {
	case "not-requested":
		if len(receipt.Native.NetworkIsolationTools) != 0 {
			return errors.New("native Apple application has isolation tools without isolation evidence")
		}
	case "pre-and-post-no-default-route-or-nonloopback-unicast":
		if len(receipt.Native.NetworkIsolationTools) != 2 ||
			!digestPattern.MatchString(receipt.Native.NetworkIsolationTools["ifconfig_sha256"]) ||
			!digestPattern.MatchString(receipt.Native.NetworkIsolationTools["route_sha256"]) {
			return errors.New("native Apple application network-isolation tool evidence is invalid")
		}
	default:
		return errors.New("native Apple application network-isolation classification is invalid")
	}
	if err := validateTools(receipt.Tools); err != nil {
		return err
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if err != nil || verifiedAt.UTC().Format(time.RFC3339) != receipt.VerifiedAt {
		return errors.New("native Apple application verification time is not canonical UTC RFC3339")
	}
	return nil
}

func validateNativeFile(file NativeFileEvidence, maximum int64) error {
	if file.Size < 1 || file.Size > maximum || !digestPattern.MatchString(file.SHA256) {
		return errors.New("file size or SHA-256 is invalid")
	}
	return nil
}

func validateSignatureDigests(digests []string) error {
	if len(digests) < 1 || len(digests) > maximumNativeSignatures {
		return errors.New("native Apple application release signature evidence is incomplete")
	}
	copy := append([]string(nil), digests...)
	sort.Strings(copy)
	for index, digest := range digests {
		if !digestPattern.MatchString(digest) ||
			digest != copy[index] ||
			(index > 0 && digest == digests[index-1]) {
			return errors.New("native Apple application release signature evidence is invalid or unordered")
		}
	}
	return nil
}
