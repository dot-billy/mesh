package windowsbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"time"

	"mesh/internal/windowsauthenticode"
)

type SignedBuildOptions struct {
	UnsignedBundlePath      string
	SignedMeshctlPath       string
	SignedNebulaPath        string
	SignedNebulaCertPath    string
	AuthenticodeReceiptPath string
	ExpectedPolicySHA256    string
	OutputPath              string
}

// BuildSigned transforms one fully authenticated reproducible unsigned v2
// staging bundle into the final signed v3 release artifact. The three replaced
// PEs must reconstruct byte-for-byte to the unsigned members, and one fresh
// native receipt must bind all three plus the unchanged signed Wintun DLL.
func BuildSigned(options SignedBuildOptions) (BuildResult, error) {
	if err := requireBuildHost(runtime.GOOS); err != nil {
		return BuildResult{}, err
	}
	return buildSignedWithPolicies(options, time.Now(), productionPolicy, productionPolicy)
}

func buildSignedWithPolicies(options SignedBuildOptions, now time.Time, unsignedPolicyResolver, signedPolicyResolver candidatePolicyResolver) (BuildResult, error) {
	if unsignedPolicyResolver == nil || signedPolicyResolver == nil {
		return BuildResult{}, errors.New("signed Windows bundle policy resolvers are required")
	}
	unsignedRaw, err := snapshotRegularFile(options.UnsignedBundlePath, MaxArchiveSize)
	if err != nil {
		return BuildResult{}, fmt.Errorf("snapshot unsigned Windows staging bundle: %w", err)
	}
	inspection, packageJSON, unsignedContents, err := inspectCandidateArchiveWithPolicy(unsignedRaw, unsignedPolicyResolver)
	if err != nil {
		return BuildResult{}, fmt.Errorf("authenticate unsigned Windows staging bundle: %w", err)
	}
	unsigned := expandedCandidateFromParts(inspection, packageJSON, unsignedContents)
	if unsigned.Inspection.Package.Schema != Schema {
		return BuildResult{}, errors.New("signed Windows bundle input must be an unsigned staging bundle v2")
	}
	contents := make(map[string][]byte, len(unsigned.Inspection.Package.Entries))
	for _, file := range unsigned.Files {
		if file.Path != packageJSONPath {
			contents[file.Path] = append([]byte(nil), file.Content...)
		}
	}
	replacements := map[string]string{
		"bin/meshctl.exe":     options.SignedMeshctlPath,
		"bin/nebula-cert.exe": options.SignedNebulaCertPath,
		"bin/nebula.exe":      options.SignedNebulaPath,
	}
	for name, inputPath := range replacements {
		signed, err := snapshotRegularFile(inputPath, maxPayloadFileSize)
		if err != nil {
			return BuildResult{}, fmt.Errorf("snapshot signed %s: %w", name, err)
		}
		original := contents[name]
		originalDigest := sha256.Sum256(original)
		reconstructed, _, err := windowsauthenticode.ReconstructUnsignedPE(
			signed, int64(len(original)), hex.EncodeToString(originalDigest[:]),
		)
		if err != nil || !bytes.Equal(reconstructed, original) {
			return BuildResult{}, errors.Join(err, fmt.Errorf("signed %s does not reconstruct to the exact unsigned staging member", name))
		}
		contents[name] = signed
	}
	arch := unsigned.Inspection.Package.Target.Arch
	wintunName := "bin/dist/windows/wintun/bin/" + arch + "/wintun.dll"
	if _, err := windowsauthenticode.InspectPEEnvelope(contents[wintunName]); err != nil {
		return BuildResult{}, fmt.Errorf("authenticate locked Wintun Authenticode envelope: %w", err)
	}
	receiptRaw, err := snapshotRegularFile(options.AuthenticodeReceiptPath, windowsauthenticode.MaximumReceiptSize)
	if err != nil {
		return BuildResult{}, fmt.Errorf("snapshot Windows Authenticode receipt: %w", err)
	}
	receipt, err := windowsauthenticode.ParseReceipt(receiptRaw)
	if err != nil {
		return BuildResult{}, err
	}
	identities := make([]windowsauthenticode.ArtifactIdentity, 0, len(receipt.Files))
	for _, name := range []string{wintunName, "bin/meshctl.exe", "bin/nebula-cert.exe", "bin/nebula.exe"} {
		content := contents[name]
		digest := sha256.Sum256(content)
		identities = append(identities, windowsauthenticode.ArtifactIdentity{
			Path: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)),
		})
	}
	if err := receipt.Match(now, options.ExpectedPolicySHA256, arch, identities); err != nil {
		return BuildResult{}, err
	}
	metadata := clonePackage(unsigned.Inspection.Package)
	metadata.Schema = SignedSchema
	for index, entry := range metadata.Entries {
		content := contents[entry.Path]
		digest := sha256.Sum256(content)
		metadata.Entries[index].Size = int64(len(content))
		metadata.Entries[index].SHA256 = hex.EncodeToString(digest[:])
	}
	buildTime, err := validatePackage(metadata)
	if err != nil {
		return BuildResult{}, err
	}
	policy, err := signedPolicyResolver(arch)
	if err != nil {
		return BuildResult{}, err
	}
	if err := policy.validateMetadata(metadata); err != nil {
		return BuildResult{}, err
	}
	for _, entry := range metadata.Entries {
		if err := policy.validateContent(entry.Path, contents[entry.Path], metadata); err != nil {
			return BuildResult{}, err
		}
	}
	return publishBundle(metadata, contents, options.OutputPath, buildTime)
}
