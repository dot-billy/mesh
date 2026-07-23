package linuxbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const CandidateInspectionSchema = "mesh-linux-security-candidate-inspection-v1"

// CandidateInspection is structural and build-policy evidence for an unsigned
// candidate. It deliberately derives expected release identity from the
// package itself; threshold release metadata remains the authority when the
// installer later calls StageAuthenticated.
type CandidateInspection struct {
	Schema            string  `json:"schema"`
	ArtifactSHA256    string  `json:"artifact_sha256"`
	ArtifactSize      int64   `json:"artifact_size"`
	PackageJSONSHA256 string  `json:"package_json_sha256"`
	FileCount         int     `json:"file_count"`
	TotalBytes        int64   `json:"total_bytes"`
	Package           Package `json:"package"`
}

// InspectCandidateFile stably hashes one exact candidate archive, fully stages
// it through the compiled production bundle policy into an existing empty 0700
// directory, and returns the observed identity. It grants no release authority.
func InspectCandidateFile(artifactPath, outputDirectory string) (CandidateInspection, error) {
	if !cleanAbsolutePath(artifactPath) || !cleanAbsolutePath(outputDirectory) {
		return CandidateInspection{}, errors.New("candidate artifact and output directory must be clean absolute non-root paths")
	}
	if resolved, err := filepath.EvalSymlinks(artifactPath); err != nil || resolved != artifactPath {
		return CandidateInspection{}, errors.New("candidate artifact path cannot traverse symlinks")
	}
	if resolved, err := filepath.EvalSymlinks(outputDirectory); err != nil || resolved != outputDirectory {
		return CandidateInspection{}, errors.New("candidate output path cannot traverse symlinks")
	}
	before, err := os.Lstat(artifactPath)
	if err != nil || !before.Mode().IsRegular() || !singleLink(before) || before.Size() < 1 || before.Size() > MaxArchiveSize ||
		before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Mode().Perm()&0o022 != 0 {
		return CandidateInspection{}, errors.New("candidate artifact must be one bounded single-link regular file without special bits or group/other write access")
	}
	outputBefore, err := os.Lstat(outputDirectory)
	if err != nil || !exactDirectoryMode(outputBefore, 0o700) {
		return CandidateInspection{}, errors.New("candidate output must be an existing real 0700 directory")
	}
	archive, err := os.Open(artifactPath)
	if err != nil {
		return CandidateInspection{}, fmt.Errorf("open candidate artifact: %w", err)
	}
	defer archive.Close()
	opened, err := archive.Stat()
	if err != nil || !stableRegularInfo(before, opened) {
		return CandidateInspection{}, errors.New("candidate artifact changed while opening")
	}
	identity, err := hashCandidateArchive(archive, opened.Size())
	if err != nil {
		return CandidateInspection{}, err
	}
	root, err := os.OpenRoot(outputDirectory)
	if err != nil {
		return CandidateInspection{}, fmt.Errorf("anchor candidate output: %w", err)
	}
	defer root.Close()
	anchoredOutput, err := root.Stat(".")
	if err != nil || !os.SameFile(outputBefore, anchoredOutput) {
		return CandidateInspection{}, errors.New("candidate output changed while anchoring")
	}
	stage, err := StageCandidate(archive, root, identity)
	if err != nil {
		return CandidateInspection{}, err
	}
	after, err := archive.Stat()
	if err != nil || !stableRegularInfo(opened, after) {
		return CandidateInspection{}, errors.New("candidate artifact changed during inspection")
	}
	rechecked, err := hashCandidateArchive(archive, after.Size())
	if err != nil || rechecked != identity {
		return CandidateInspection{}, errors.New("candidate artifact changed during final rehash")
	}
	return CandidateInspection{
		Schema: CandidateInspectionSchema, ArtifactSHA256: identity.SHA256,
		ArtifactSize: identity.Size, PackageJSONSHA256: stage.PackageJSONSHA256,
		FileCount: stage.FileCount, TotalBytes: stage.TotalBytes, Package: stage.Package,
	}, nil
}

// StageCandidate applies the complete production archive, metadata, binary,
// embedded-asset, and staged-tree validation while deriving only the release
// selection fields from the unsigned candidate. It is for security analysis,
// not installation or release authorization.
func StageCandidate(archive *os.File, root *os.Root, artifact ArtifactIdentity) (StageResult, error) {
	metadata, err := inspectCandidateMetadata(archive)
	if err != nil {
		return StageResult{}, err
	}
	policy, err := productionPolicy(metadata.Target.Arch)
	if err != nil {
		return StageResult{}, err
	}
	return stageCandidateWithPolicy(archive, root, artifact, metadata, policy)
}

func stageCandidateWithPolicy(archive *os.File, root *os.Root, artifact ArtifactIdentity, metadata Package, policy bundlePolicy) (StageResult, error) {
	expected := Expected{
		Version: metadata.Version, OS: metadata.Target.OS, Arch: metadata.Target.Arch,
		MinimumSecurityFloor:         metadata.SecurityFloor,
		InstallerBootstrapRootSHA256: metadata.InstallerBootstrapRootSHA256,
		InstallerStateSchemaVersion:  metadata.InstallerStateWriteVersion,
	}
	if metadata.Schema == LegacySchema {
		expected.InstallerStateSchemaVersion = 3
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return StageResult{}, fmt.Errorf("rewind candidate archive: %w", err)
	}
	return stageWithPolicy(archive, root, expected, artifact, policy)
}

func inspectCandidateMetadata(archive *os.File) (Package, error) {
	if archive == nil {
		return Package{}, errors.New("candidate archive is required")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return Package{}, fmt.Errorf("rewind candidate archive: %w", err)
	}
	headerBlock := make([]byte, tarBlockSize)
	if err := readExact(archive, headerBlock, "candidate package.json header"); err != nil {
		return Package{}, err
	}
	header, err := parseHeaderBlock(headerBlock)
	if err != nil || header.Name != packageJSONPath || header.Size < 1 || header.Size > maxPackageJSONSize {
		return Package{}, errors.New("candidate archive must begin with bounded USTAR package.json")
	}
	raw := make([]byte, header.Size)
	if err := readExact(archive, raw, "candidate package.json"); err != nil {
		return Package{}, err
	}
	metadata, err := parsePackage(raw)
	if err != nil {
		return Package{}, err
	}
	return metadata, nil
}

func hashCandidateArchive(archive *os.File, expectedSize int64) (ArtifactIdentity, error) {
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return ArtifactIdentity{}, fmt.Errorf("rewind candidate artifact: %w", err)
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(archive, MaxArchiveSize+1))
	if err != nil || written != expectedSize || written < 1 || written > MaxArchiveSize {
		return ArtifactIdentity{}, errors.New("candidate artifact size changed during hashing")
	}
	return ArtifactIdentity{Size: written, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func cleanAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator)
}
