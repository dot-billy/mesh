// Package nebulaobserverartifact builds and verifies the exact Linux Nebula
// observer fork selected by Mesh's source-controlled build lock.
package nebulaobserverartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	nebulasource "mesh/third_party/nebula"
	observerassets "mesh/third_party/nebula-observer"
)

const (
	policySchema        = "mesh.nebula-observer-build-lock.v1"
	ManifestSchema      = "mesh.nebula-observer-stage.v1"
	lockedModule        = "github.com/slackhq/nebula"
	lockedVersion       = "v1.10.3"
	lockedCommit        = "f573e8a26695278f9d71587390fbfe0d0933aa21"
	lockedModuleSum     = "h1:EstYj8ODEcv6T0R9X5BVq1zgWZnyU5gtPzk99QF1PMU="
	lockedGoModSum      = "h1:IL5TUQm4x9IFx2kCKPYm1gP47pwd5b8QGnnBH2RHnvs="
	lockedToolchain     = "go1.26.5"
	manifestName        = "observer-build.json"
	manifestMode        = 0o444
	maximumPolicySize   = 256 << 10
	maximumManifestSize = 64 << 10
	maximumBinarySize   = 96 << 20
)

var lockedBuildFlags = []string{"-trimpath", "-buildvcs=false", "-ldflags=-buildid= -X main.Build=1.10.3"}

var lockedSecurityDependencies = []DependencyLock{
	{Path: "golang.org/x/crypto", Version: "v0.53.0", Sum: "h1:QZ4Muo8THX6CizN2vPPd5fBGHyogrdK9fG4wLPFUsto="},
	{Path: "golang.org/x/net", Version: "v0.56.0", Sum: "h1:Rw8j/hFzGvJUZwNBXnAtf5sVDVt+65SK2C7IxCxZt5o="},
	{Path: "golang.org/x/sys", Version: "v0.46.0", Sum: "h1:noSf2Fq6F8DBgS+LysIkx7rIExoNHJsxOAtPp4rthXw="},
	{Path: "golang.org/x/term", Version: "v0.44.0", Sum: "h1:0rLvDRCtNj0gZkyIXhCyOb2OAzEhLVqc4B+hrsBhrmc="},
}

type Policy struct {
	Schema               string           `json:"schema"`
	Module               string           `json:"module"`
	Version              string           `json:"version"`
	Commit               string           `json:"commit"`
	ModuleSum            string           `json:"module_sum"`
	GoModSum             string           `json:"go_mod_sum"`
	UpstreamLockSHA256   string           `json:"upstream_lock_sha256"`
	SourceTreeSHA256     string           `json:"source_tree_sha256"`
	PatchedTreeSHA256    string           `json:"patched_tree_sha256"`
	SeriesSHA256         string           `json:"series_sha256"`
	PatchSetSHA256       string           `json:"patch_set_sha256"`
	Toolchain            string           `json:"toolchain"`
	BuildFlags           []string         `json:"build_flags"`
	SecurityDependencies []DependencyLock `json:"security_dependencies"`
	Patches              []PatchLock      `json:"patches"`
	Targets              []TargetLock     `json:"targets"`
}

type DependencyLock struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

type PatchLock struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type TargetLock struct {
	OS      string      `json:"os"`
	Arch    string      `json:"arch"`
	Entries []EntryLock `json:"entries"`
}

type EntryLock struct {
	Name     string `json:"name"`
	Mode     uint32 `json:"mode"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	MainPath string `json:"main_path"`
}

type Manifest struct {
	Schema       string      `json:"schema"`
	PolicySHA256 string      `json:"policy_sha256"`
	Target       Target      `json:"target"`
	GoVersion    string      `json:"go_version"`
	Entries      []EntryLock `json:"entries"`
}

type Identity struct {
	Version            string
	Commit             string
	UpstreamLockSHA256 string
	ObserverLockSHA256 string
	SourceTreeSHA256   string
	PatchedTreeSHA256  string
	PatchSetSHA256     string
	Toolchain          string
}

var (
	embeddedOnce   sync.Once
	embeddedPolicy Policy
	embeddedDigest string
	embeddedErr    error
)

// EmbeddedPolicy parses and validates the immutable observer build lock.
func EmbeddedPolicy() (Policy, string, error) {
	embeddedOnce.Do(func() {
		raw := observerassets.BuildLock()
		embeddedPolicy, embeddedErr = ParsePolicy(raw)
		digest := sha256.Sum256(raw)
		embeddedDigest = hex.EncodeToString(digest[:])
	})
	return clonePolicy(embeddedPolicy), embeddedDigest, embeddedErr
}

// ParsePolicy is exported for review tooling and adversarial tests. Production
// builds and verifiers always select EmbeddedPolicy and accept no alternate
// lock, patch series, source location, build flag, or output digest.
func ParsePolicy(raw []byte) (Policy, error) {
	var policy Policy
	if len(raw) == 0 || len(raw) > maximumPolicySize {
		return policy, fmt.Errorf("observer build lock size must be between 1 and %d bytes", maximumPolicySize)
	}
	if err := decodeStrict(raw, &policy); err != nil {
		return policy, fmt.Errorf("invalid observer build lock: %w", err)
	}
	canonical, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return policy, fmt.Errorf("encode observer build lock: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return policy, errors.New("observer build lock is not canonically encoded")
	}
	if err := validatePolicy(policy); err != nil {
		return policy, err
	}
	return clonePolicy(policy), nil
}

func validatePolicy(policy Policy) error {
	if policy.Schema != policySchema || policy.Module != lockedModule || policy.Version != lockedVersion ||
		policy.Commit != lockedCommit || policy.ModuleSum != lockedModuleSum || policy.GoModSum != lockedGoModSum ||
		policy.Toolchain != lockedToolchain {
		return errors.New("observer build lock identity differs from the compiled policy")
	}
	if !equalStrings(policy.BuildFlags, lockedBuildFlags) {
		return errors.New("observer build flags differ from the compiled policy")
	}
	if !equalDependencies(policy.SecurityDependencies, lockedSecurityDependencies) {
		return errors.New("observer security dependencies differ from the compiled policy")
	}
	for name, digest := range map[string]string{
		"upstream_lock_sha256": policy.UpstreamLockSHA256,
		"source_tree_sha256":   policy.SourceTreeSHA256,
		"patched_tree_sha256":  policy.PatchedTreeSHA256,
		"series_sha256":        policy.SeriesSHA256,
		"patch_set_sha256":     policy.PatchSetSHA256,
	} {
		if !lowerHex(digest) {
			return fmt.Errorf("%s is not a canonical SHA-256", name)
		}
	}
	upstreamDigest := sha256.Sum256(nebulasource.V1103Lock())
	if policy.UpstreamLockSHA256 != hex.EncodeToString(upstreamDigest[:]) {
		return errors.New("observer build lock does not bind the embedded upstream dependency lock")
	}
	series := observerassets.Series()
	seriesDigest := sha256.Sum256(series)
	if policy.SeriesSHA256 != hex.EncodeToString(seriesDigest[:]) {
		return errors.New("observer build lock series digest does not match the embedded series")
	}
	names, err := parseSeries(series)
	if err != nil {
		return err
	}
	if len(policy.Patches) != len(names) || len(names) == 0 {
		return errors.New("observer build lock patch list does not match the embedded series")
	}
	patchBytes := make([][]byte, len(names))
	for index, name := range names {
		locked := policy.Patches[index]
		if locked.Name != name || !lowerHex(locked.SHA256) {
			return fmt.Errorf("observer patch %d identity is invalid", index)
		}
		raw, err := observerassets.Patch(name)
		if err != nil {
			return fmt.Errorf("read embedded observer patch %q: %w", name, err)
		}
		digest := sha256.Sum256(raw)
		if locked.SHA256 != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("observer patch %q digest differs from the build lock", name)
		}
		patchBytes[index] = raw
	}
	actualPatchSet := patchSetDigest(series, names, patchBytes)
	if policy.PatchSetSHA256 != actualPatchSet {
		return fmt.Errorf("observer patch-set digest is %s, lock records %s", actualPatchSet, policy.PatchSetSHA256)
	}
	if len(policy.Targets) != 2 {
		return errors.New("observer build lock must contain exactly two Linux targets")
	}
	for index, arch := range []string{"amd64", "arm64"} {
		target := policy.Targets[index]
		if target.OS != "linux" || target.Arch != arch || len(target.Entries) != 2 {
			return fmt.Errorf("observer target %d is not exact linux/%s policy", index, arch)
		}
		for entryIndex, expected := range []struct{ name, main string }{
			{"nebula", lockedModule + "/cmd/nebula"},
			{"nebula-cert", lockedModule + "/cmd/nebula-cert"},
		} {
			entry := target.Entries[entryIndex]
			if entry.Name != expected.name || entry.MainPath != expected.main || entry.Mode != 0o555 ||
				entry.Size <= 0 || entry.Size > maximumBinarySize || !lowerHex(entry.SHA256) {
				return fmt.Errorf("observer target %s entry %d is invalid", arch, entryIndex)
			}
		}
	}
	return nil
}

func (policy Policy) Select(arch string) (TargetLock, error) {
	for _, target := range policy.Targets {
		if target.OS == "linux" && target.Arch == arch {
			return cloneTarget(target), nil
		}
	}
	return TargetLock{}, fmt.Errorf("unsupported observer target linux/%s", arch)
}

func (policy Policy) identity(policyDigest string) Identity {
	return Identity{
		Version: policy.Version, Commit: policy.Commit,
		UpstreamLockSHA256: policy.UpstreamLockSHA256, ObserverLockSHA256: policyDigest,
		SourceTreeSHA256: policy.SourceTreeSHA256, PatchedTreeSHA256: policy.PatchedTreeSHA256,
		PatchSetSHA256: policy.PatchSetSHA256, Toolchain: policy.Toolchain,
	}
}

func marshalManifest(manifest Manifest) ([]byte, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode observer stage manifest: %w", err)
	}
	return append(raw, '\n'), nil
}

func parseManifest(raw []byte) (Manifest, error) {
	var manifest Manifest
	if len(raw) == 0 || len(raw) > maximumManifestSize {
		return manifest, errors.New("observer stage manifest is empty or oversized")
	}
	if err := decodeStrict(raw, &manifest); err != nil {
		return manifest, fmt.Errorf("decode observer stage manifest: %w", err)
	}
	canonical, err := marshalManifest(manifest)
	if err != nil {
		return manifest, err
	}
	if !bytes.Equal(raw, canonical) {
		return manifest, errors.New("observer stage manifest is not canonically encoded")
	}
	return manifest, nil
}

func decodeStrict(raw []byte, output any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func parseSeries(raw []byte) ([]string, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || strings.ContainsRune(string(raw), '\r') {
		return nil, errors.New("observer patch series must be non-empty canonical LF text")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if line == "" || strings.TrimSpace(line) != line || strings.ContainsAny(line, "/\\") || !strings.HasSuffix(line, ".patch") {
			return nil, fmt.Errorf("invalid observer patch series entry %q", line)
		}
		if _, duplicate := seen[line]; duplicate {
			return nil, fmt.Errorf("duplicate observer patch series entry %q", line)
		}
		seen[line] = struct{}{}
	}
	return lines, nil
}

func patchSetDigest(series []byte, names []string, patches [][]byte) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "mesh.nebula-observer-patch-set.v1\x00")
	writeDigestRecord(hash, "series", series)
	for index, name := range names {
		writeDigestRecord(hash, name, patches[index])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeDigestRecord(writer io.Writer, name string, content []byte) {
	_ = binary.Write(writer, binary.BigEndian, uint32(len(name)))
	_, _ = io.WriteString(writer, name)
	_ = binary.Write(writer, binary.BigEndian, uint64(len(content)))
	_, _ = writer.Write(content)
}

func lowerHex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func clonePolicy(policy Policy) Policy {
	clone := policy
	clone.BuildFlags = append([]string(nil), policy.BuildFlags...)
	clone.SecurityDependencies = append([]DependencyLock(nil), policy.SecurityDependencies...)
	clone.Patches = append([]PatchLock(nil), policy.Patches...)
	clone.Targets = make([]TargetLock, len(policy.Targets))
	for index, target := range policy.Targets {
		clone.Targets[index] = cloneTarget(target)
	}
	return clone
}

func equalDependencies(left, right []DependencyLock) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneTarget(target TargetLock) TargetLock {
	clone := target
	clone.Entries = append([]EntryLock(nil), target.Entries...)
	return clone
}
