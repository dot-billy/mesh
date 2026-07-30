package darwinbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"mesh/internal/darwincodesign"
)

type SignedBuildOptions struct {
	UnsignedBundlePath   string
	SignedMeshctlPath    string
	SignedNebulaPath     string
	SignedNebulaCertPath string
	CodesignReceiptPath  string
	ExpectedPolicySHA256 string
	OutputPath           string
}

// BuildSigned transforms one authenticated reproducible staging bundle into
// the final signed v2 release artifact. Each replacement must differ only by
// the existing Mach-O signature and its exact describing size fields, and one
// fresh native receipt must bind all final bytes to the compiled Developer ID
// policy.
func BuildSigned(options SignedBuildOptions) (BuildResult, error) {
	if err := requireBuildHost(runtime.GOOS); err != nil {
		return BuildResult{}, err
	}
	policy, err := darwincodesign.LoadPolicy()
	if err != nil {
		return BuildResult{}, fmt.Errorf("load compiled Darwin code-signing policy: %w", err)
	}
	return buildSignedWithPolicy(options, time.Now(), policy, productionPolicy)
}

func buildSignedWithPolicy(options SignedBuildOptions, now time.Time, codesignPolicy darwincodesign.Policy, policyResolver candidatePolicyResolver) (BuildResult, error) {
	if policyResolver == nil {
		return BuildResult{}, errors.New("signed Darwin bundle policy resolver is required")
	}
	if !digestPattern.MatchString(options.ExpectedPolicySHA256) ||
		options.ExpectedPolicySHA256 != codesignPolicy.SHA256 {
		return BuildResult{}, errors.New("expected Darwin code-signing policy digest differs from the compiled policy")
	}
	_, outputParent, _, err := prepareOutputPath(options.OutputPath)
	if err != nil {
		return BuildResult{}, err
	}
	stage, err := os.MkdirTemp(outputParent, ".mesh-darwin-unsigned-stage-")
	if err != nil {
		return BuildResult{}, fmt.Errorf("create private unsigned Darwin inspection stage: %w", err)
	}
	defer removeSignedInspectionStage(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return BuildResult{}, err
	}
	unsignedRaw, err := snapshotRegularFile(options.UnsignedBundlePath, MaxArchiveSize)
	if err != nil {
		return BuildResult{}, fmt.Errorf("snapshot unsigned Darwin staging bundle: %w", err)
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		return BuildResult{}, fmt.Errorf("anchor private unsigned Darwin inspection stage: %w", err)
	}
	inspection, inspectErr := inspectAndStageCandidateWithPolicy(unsignedRaw, root, policyResolver)
	closeErr := root.Close()
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return BuildResult{}, fmt.Errorf("authenticate unsigned Darwin staging bundle: %w", err)
	}
	if err := ValidateCandidateInspection(inspection); err != nil {
		return BuildResult{}, fmt.Errorf("authenticate unsigned Darwin staging bundle: %w", err)
	}
	if inspection.Package.Schema != Schema {
		return BuildResult{}, errors.New("signed Darwin bundle input must be an unsigned staging bundle v1")
	}
	contents := make(map[string][]byte, len(inspection.Package.Entries))
	for _, entry := range inspection.Package.Entries {
		content, err := snapshotRegularFile(filepath.Join(stage, filepath.FromSlash(entry.Path)), maxPayloadFileSize)
		if err != nil {
			return BuildResult{}, fmt.Errorf("snapshot authenticated unsigned payload %q: %w", entry.Path, err)
		}
		contents[entry.Path] = content
	}
	replacements := map[string]string{
		"bin/meshctl":     options.SignedMeshctlPath,
		"bin/nebula":      options.SignedNebulaPath,
		"bin/nebula-cert": options.SignedNebulaCertPath,
	}
	for name, inputPath := range replacements {
		signed, err := snapshotRegularFile(inputPath, maxPayloadFileSize)
		if err != nil {
			return BuildResult{}, fmt.Errorf("snapshot signed %s: %w", name, err)
		}
		if _, err := darwincodesign.VerifySignedMachOReplacement(signed, contents[name]); err != nil {
			return BuildResult{}, fmt.Errorf("bind signed %s to exact linker-signed staging bytes: %w", name, err)
		}
		contents[name] = signed
	}
	receiptRaw, err := snapshotRegularFile(options.CodesignReceiptPath, darwincodesign.MaximumReceiptSize)
	if err != nil {
		return BuildResult{}, fmt.Errorf("snapshot Darwin code-signing receipt: %w", err)
	}
	receipt, err := darwincodesign.ParseReceipt(receiptRaw)
	if err != nil {
		return BuildResult{}, err
	}
	identities := make([]darwincodesign.ArtifactIdentity, 0, len(replacements))
	for _, name := range []string{"bin/meshctl", "bin/nebula", "bin/nebula-cert"} {
		content := contents[name]
		digest := sha256.Sum256(content)
		identities = append(identities, darwincodesign.ArtifactIdentity{
			Path: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)),
		})
	}
	arch := inspection.Package.Target.Arch
	if err := receipt.Match(now, codesignPolicy, arch, identities); err != nil {
		return BuildResult{}, err
	}
	buildTime, err := time.Parse(time.RFC3339, inspection.Package.BuildTime)
	if err != nil {
		return BuildResult{}, err
	}
	bundlePolicy, err := policyResolver(arch)
	if err != nil {
		return BuildResult{}, err
	}
	return buildWithSchema(BuildOptions{
		Version: inspection.Package.Version, Commit: inspection.Package.Commit,
		SourceDateEpoch: buildTime.Unix(), SecurityFloor: inspection.Package.SecurityFloor,
		Arch: arch, OutputPath: options.OutputPath,
	}, bundlePolicy, contents, SignedSchema)
}

func removeSignedInspectionStage(stage string) {
	_ = filepath.WalkDir(stage, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	})
	_ = os.RemoveAll(stage)
}
