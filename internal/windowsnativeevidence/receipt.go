// Package windowsnativeevidence validates the create-only receipts emitted by
// the isolated-host Windows bootstrap and runtime proof harnesses.
package windowsnativeevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"time"

	"mesh/internal/bootstrapverify"
	releasetrust "mesh/internal/release"
)

const (
	BootstrapSchema        = "mesh-windows-native-bootstrap-receipt-v2"
	RuntimeSchema          = "mesh-windows-native-runtime-receipt-v4"
	MaximumBootstrapSize   = 128 << 10
	MaximumRuntimeSize     = 256 << 10
	maximumEvidenceAge     = 24 * time.Hour
	maximumFutureClockSkew = 5 * time.Minute
)

var (
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	goVersionPattern = regexp.MustCompile(`^go version go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.-]*) windows/(amd64|arm64)$`)
)

type BootstrapReceipt struct {
	Schema                string                 `json:"schema"`
	Architecture          string                 `json:"architecture"`
	VerifiedAt            string                 `json:"verified_at"`
	VerifierPackageSHA256 string                 `json:"verifier_package_sha256"`
	VerifierSHA256        string                 `json:"verifier_sha256"`
	AnchorSHA256          string                 `json:"anchor_sha256"`
	HandoffSHA256         string                 `json:"handoff_sha256"`
	RootSHA256            string                 `json:"root_sha256"`
	InstallerSHA256       string                 `json:"installer_sha256"`
	Verification          bootstrapverify.Result `json:"verification"`
	Proofs                []string               `json:"proofs"`
	SourceSHA256          map[string]string      `json:"source_sha256"`
}

type RuntimeReceipt struct {
	Schema              string            `json:"schema"`
	Architecture        string            `json:"architecture"`
	GoVersion           string            `json:"go_version"`
	NativeFaultGate     string            `json:"native_fault_gate"`
	BundlePath          string            `json:"bundle_path"`
	BundleSHA256        string            `json:"bundle_sha256"`
	UpgradeBundlePath   string            `json:"upgrade_bundle_path"`
	UpgradeBundleSHA256 string            `json:"upgrade_bundle_sha256"`
	PolicySHA256        string            `json:"authenticode_policy_sha256"`
	NativeDNSLocalIP    string            `json:"native_dns_local_ip"`
	StartedAt           string            `json:"started_at"`
	VerifiedAt          string            `json:"verified_at"`
	Proofs              []string          `json:"proofs"`
	SourceSHA256        map[string]string `json:"source_sha256"`
}

func ParseBootstrapReceipt(raw []byte) (BootstrapReceipt, error) {
	var receipt BootstrapReceipt
	if err := parseCanonicalReceipt(raw, MaximumBootstrapSize, &receipt); err != nil {
		return BootstrapReceipt{}, fmt.Errorf("parse Windows native bootstrap receipt: %w", err)
	}
	if err := validateBootstrapReceipt(receipt); err != nil {
		return BootstrapReceipt{}, err
	}
	return receipt, nil
}

func ParseRuntimeReceipt(raw []byte) (RuntimeReceipt, error) {
	var receipt RuntimeReceipt
	if err := parseCanonicalReceipt(raw, MaximumRuntimeSize, &receipt); err != nil {
		return RuntimeReceipt{}, fmt.Errorf("parse Windows native runtime receipt: %w", err)
	}
	if err := validateRuntimeReceipt(receipt); err != nil {
		return RuntimeReceipt{}, err
	}
	return receipt, nil
}

func MatchPair(now time.Time, bootstrap BootstrapReceipt, runtime RuntimeReceipt, arch, policySHA256, installerSHA256, initialBundleSHA256, upgradeBundleSHA256 string) error {
	if err := validateBootstrapReceipt(bootstrap); err != nil {
		return err
	}
	if err := validateRuntimeReceipt(runtime); err != nil {
		return err
	}
	if arch != "amd64" && arch != "arm64" {
		return errors.New("expected Windows native evidence architecture is invalid")
	}
	for label, digest := range map[string]string{
		"policy": policySHA256, "installer": installerSHA256,
		"initial bundle": initialBundleSHA256, "upgrade bundle": upgradeBundleSHA256,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("expected Windows native evidence %s SHA-256 is invalid", label)
		}
	}
	if bootstrap.Architecture != arch || runtime.Architecture != arch ||
		bootstrap.Verification.Arch != arch || bootstrap.InstallerSHA256 != installerSHA256 ||
		bootstrap.Verification.InstallerSHA256 != installerSHA256 ||
		bootstrap.Verification.AuthenticodePolicySHA256 != policySHA256 || runtime.PolicySHA256 != policySHA256 ||
		runtime.BundleSHA256 != initialBundleSHA256 || runtime.UpgradeBundleSHA256 != upgradeBundleSHA256 {
		return errors.New("Windows native evidence differs from the expected host, policy, installer, or bundles")
	}
	now = now.UTC()
	if now.IsZero() {
		return errors.New("Windows native evidence comparison time is required")
	}
	for label, value := range map[string]string{"bootstrap": bootstrap.VerifiedAt, "runtime": runtime.VerifiedAt} {
		verified, _ := time.Parse(time.RFC3339, value)
		if verified.After(now.Add(maximumFutureClockSkew)) {
			return fmt.Errorf("Windows native %s receipt time is in the future", label)
		}
		if now.Sub(verified) > maximumEvidenceAge {
			return fmt.Errorf("Windows native %s receipt is older than 24 hours", label)
		}
	}
	return nil
}

func parseCanonicalReceipt(raw []byte, maximum int, destination any) error {
	if len(raw) < 2 || len(raw) > maximum {
		return errors.New("receipt is empty or oversized")
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("receipt contains trailing content")
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return errors.New("receipt must be canonical compact JSON followed by one LF")
	}
	return nil
}

func validateBootstrapReceipt(receipt BootstrapReceipt) error {
	if receipt.Schema != BootstrapSchema || !validArch(receipt.Architecture) || !canonicalTime(receipt.VerifiedAt) ||
		!allDigests(receipt.VerifierPackageSHA256, receipt.VerifierSHA256, receipt.AnchorSHA256, receipt.HandoffSHA256, receipt.RootSHA256, receipt.InstallerSHA256) {
		return errors.New("Windows native bootstrap receipt identity is invalid")
	}
	verification := receipt.Verification
	if verification.Schema != bootstrapverify.AnchorResultSchema || verification.OS != "windows" || verification.Arch != receipt.Architecture ||
		verification.AnchorSHA256 != receipt.AnchorSHA256 || verification.HandoffSHA256 != receipt.HandoffSHA256 ||
		verification.VerifierPackageSHA256 != receipt.VerifierPackageSHA256 || verification.RootSHA256 != receipt.RootSHA256 ||
		verification.InstallerSHA256 != receipt.InstallerSHA256 ||
		!allDigests(verification.ManifestSHA256, verification.InstallerBootstrapSHA256, verification.AuthenticodePolicySHA256, verification.AuthenticodeSignerSPKI, verification.AuthenticodeCertificate) ||
		verification.Version == "" || len(verification.Version) > 128 || len(verification.SignerKeyIDs) == 0 || len(verification.SignerKeyIDs) > 16 {
		return errors.New("Windows native bootstrap verifier evidence is invalid or inconsistent")
	}
	for _, keyID := range verification.SignerKeyIDs {
		if !digestPattern.MatchString(keyID) {
			return errors.New("Windows native bootstrap signer identity is invalid")
		}
	}
	if !reflect.DeepEqual(receipt.Proofs, bootstrapProofs) || !validSourceSet(receipt.SourceSHA256, bootstrapSources) {
		return errors.New("Windows native bootstrap proof or source inventory is invalid")
	}
	return nil
}

func validateRuntimeReceipt(receipt RuntimeReceipt) error {
	if receipt.Schema != RuntimeSchema || !validArch(receipt.Architecture) || receipt.NativeFaultGate != "1" ||
		!goVersionPattern.MatchString(receipt.GoVersion) || !allDigests(receipt.BundleSHA256, receipt.UpgradeBundleSHA256, receipt.PolicySHA256) ||
		receipt.BundleSHA256 == receipt.UpgradeBundleSHA256 || !validWindowsPath(receipt.BundlePath) || !validWindowsPath(receipt.UpgradeBundlePath) ||
		receipt.BundlePath == receipt.UpgradeBundlePath || !canonicalTime(receipt.StartedAt) || !canonicalTime(receipt.VerifiedAt) {
		return errors.New("Windows native runtime receipt identity is invalid")
	}
	started, _ := time.Parse(time.RFC3339, receipt.StartedAt)
	verified, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if verified.Before(started) || verified.Sub(started) > 2*time.Hour {
		return errors.New("Windows native runtime proof duration is invalid")
	}
	address, err := netip.ParseAddr(receipt.NativeDNSLocalIP)
	if err != nil || !address.Is4() || address.String() != receipt.NativeDNSLocalIP || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return errors.New("Windows native runtime DNS address is invalid")
	}
	if !reflect.DeepEqual(receipt.Proofs, runtimeProofs) || !validSourceSet(receipt.SourceSHA256, runtimeSources) {
		return errors.New("Windows native runtime proof or source inventory is invalid")
	}
	return nil
}

func validArch(value string) bool { return value == "amd64" || value == "arm64" }

func canonicalTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

func allDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validWindowsPath(value string) bool {
	return len(value) >= 4 && len(value) <= 32767 && value[1] == ':' && value[2] == '\\' &&
		((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validSourceSet(observed map[string]string, expected []string) bool {
	if len(observed) != len(expected) {
		return false
	}
	for _, name := range expected {
		if !digestPattern.MatchString(observed[name]) {
			return false
		}
	}
	return true
}

var bootstrapProofs = []string{
	"independently supplied exact verifier-package digest",
	"canonical two-member Windows verifier USTAR",
	"private LocalSystem and Administrators extraction DACL",
	"native Windows verifier execution",
	"v2 handoff and v2 anchor exact host selection",
	"root-role threshold authorization without installer execution",
	"online whole-chain Authenticode verification with exact policy, signer SPKI, and certificate binding",
}

var bootstrapSources = []string{
	"internal/bootstrapanchor/anchor.go", "internal/bootstraphandoff/handoff.go",
	"internal/bootstrapverify/authenticode.go", "internal/bootstrapverify/authenticode_windows.go",
	"internal/bootstrapverify/files.go", "internal/bootstrapverify/files_other.go", "internal/bootstrapverify/verify.go",
	"internal/installerinspect/inspect_pe.go", "internal/installerinspect/inspect_verifier.go",
	"internal/verifierbundle/model.go", "scripts/windows-bootstrap-verifier-smoke.ps1",
}

var runtimeProofs = []string{
	"suspended process creation",
	"kill-on-close non-breakaway job policy",
	"exact process image and argument identity",
	"whole-job termination and idempotent wait",
	"component-by-component reparse rejection",
	"DACL drift rejection and exact repair",
	"ephemeral 2-of-2 release threshold acceptance",
	"exact signed online-bundle intake persistence",
	"exact LocalSystem-private offline snapshot intake",
	"operator-path exact private offline snapshot preparation",
	"append-only root-history replay and durable high-water authority",
	"cross-process installer transaction locking",
	"bounded signed artifact capture, recovery, and terminal discard",
	"deterministic accepted-stage restart recovery",
	"single-link candidate intake and published-tree enforcement",
	"canonical bundle expansion and write-through no-replace publication",
	"finalized-stage recovery before publication",
	"journaled current-selector and SCM service lifecycle",
	"authority-bound active-state and intake finalization replay",
	"distinct signed-v3 sequence-2 upgrade with exact persisted-previous selection",
	"native rollback to the exact prior release with upgrade authority retained as high water",
	"recovery-safe runtime uninstall with retained release and anti-rollback authority",
	"role-pinned online-revocation Authenticode enforcement for every activated PE",
	"native Windows NRPT split-DNS activation, packet resolution, effective-policy readback, and exact cleanup",
}

var runtimeSources = []string{
	"cmd/meshctl/agent_entry_windows.go", "cmd/meshctl/agent_supervised_runtime_windows.go", "cmd/meshctl/agent_supervised_runtime_windows_test.go",
	"internal/control/dns.go", "internal/nodeagent/native_dns.go", "internal/nodeagent/native_dns_nrpt.go",
	"internal/nodeagent/native_dns_proxy.go", "internal/nodeagent/native_dns_windows.go", "internal/nodeagent/native_dns_windows_test.go",
	"internal/windowsauthenticode/pe.go", "internal/windowsauthenticode/policy.go", "internal/windowsauthenticode/receipt.go", "internal/windowsauthenticode/verify_windows.go",
	"internal/windowsbundle/candidate.go", "internal/windowsbundle/model.go", "internal/windowsbundle/policy.go", "internal/windowsbundle/signed_build.go",
	"internal/windowsinstall/accepted_stage_windows.go", "internal/windowsinstall/activation_authority_windows.go",
	"internal/windowsinstall/activation_journal_core.go", "internal/windowsinstall/activation_journal_windows.go", "internal/windowsinstall/activation_windows.go",
	"internal/windowsinstall/artifact_capture_windows.go", "internal/windowsinstall/authority_core.go", "internal/windowsinstall/candidate_intake_production_windows.go",
	"internal/windowsinstall/candidate_intake_windows.go", "internal/windowsinstall/install_state_codec.go", "internal/windowsinstall/install_state_core.go",
	"internal/windowsinstall/install_state_store_windows.go", "internal/windowsinstall/current_core.go", "internal/windowsinstall/current_switch_core.go",
	"internal/windowsinstall/installer_lock_windows.go", "internal/windowsinstall/installer_windows.go", "internal/windowsinstall/layout_windows.go",
	"internal/windowsinstall/intake_record_core.go", "internal/windowsinstall/intake_record_store_windows.go", "internal/windowsinstall/offline_snapshot_core.go",
	"internal/windowsinstall/offline_snapshot_prepare_windows.go", "internal/windowsinstall/offline_snapshot_windows.go", "internal/windowsinstall/publication_core.go",
	"internal/windowsinstall/publication_windows.go", "internal/windowsinstall/root_history_core.go", "internal/windowsinstall/root_history_store_windows.go",
	"internal/windowsinstall/runtime_uninstall_codec.go", "internal/windowsinstall/runtime_uninstall_core.go",
	"internal/windowsinstall/runtime_uninstall_journal_windows.go", "internal/windowsinstall/runtime_uninstall_windows.go",
	"internal/windowsinstall/service_core.go", "internal/windowsinstall/service_windows.go", "internal/windowsinstall/windows_native_test.go",
	"internal/windowsinstallercompat/compat.go",
	"internal/windowssecurity/descriptor.go", "internal/windowssecurity/inspect_windows.go",
	"scripts/windows-native-runtime-smoke.ps1",
}
