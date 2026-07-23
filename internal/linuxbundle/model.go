// Package linuxbundle builds and stages the deterministic, uncompressed Linux
// node-runtime bundle. It deliberately performs no privileged installation or
// service-manager mutation.
package linuxbundle

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"mesh/internal/installercompat"
)

const (
	LegacySchema = "mesh-linux-node-bundle-v2"
	Schema       = "mesh-linux-node-bundle-v3"

	packageJSONPath = "package.json"
	packageJSONMode = 0o444
	directoryMode   = 0o555

	maxPackageJSONSize int64 = 64 << 10
	maxPayloadFileSize int64 = 128 << 20
	maxPayloadSize     int64 = 256 << 20
	MaxArchiveSize     int64 = 272 << 20
)

var (
	commitPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identifierRegex = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
	goVersionRegex  = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.-]*)$`)
)

// Package describes package.json. Entries excludes package.json itself; the
// outer threshold-authenticated artifact digest authenticates that metadata.
type Package struct {
	Schema                     string `json:"schema"`
	Version                    string `json:"version"`
	Commit                     string `json:"commit"`
	BuildTime                  string `json:"build_time"`
	SecurityFloor              uint64 `json:"security_floor"`
	AgentStateReadMin          uint64 `json:"agent_state_read_min"`
	AgentStateReadMax          uint64 `json:"agent_state_read_max"`
	AgentStateWriteVersion     uint64 `json:"agent_state_write_version"`
	InstallerStateReadMin      uint64 `json:"installer_state_read_min,omitempty"`
	InstallerStateReadMax      uint64 `json:"installer_state_read_max,omitempty"`
	InstallerStateWriteVersion uint64 `json:"installer_state_write_version,omitempty"`
	// InstallerBootstrapRootSHA256 retains the established JSON field name so
	// existing bundle-v2 parsers remain compatible, but its value is now the
	// immutable initial-root digest from the compiled v2 bootstrap.
	InstallerBootstrapRootSHA256 string         `json:"installer_trust_policy_sha256"`
	GoVersion                    string         `json:"go_version"`
	Target                       Target         `json:"target"`
	Nebula                       NebulaIdentity `json:"nebula"`
	Entries                      []Entry        `json:"entries"`
}

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type NebulaIdentity struct {
	Version            string `json:"version"`
	UpstreamCommit     string `json:"upstream_commit"`
	UpstreamLockSHA256 string `json:"upstream_lock_sha256"`
	ObserverLockSHA256 string `json:"observer_lock_sha256"`
	SourceTreeSHA256   string `json:"source_tree_sha256"`
	PatchedTreeSHA256  string `json:"patched_tree_sha256"`
	PatchSetSHA256     string `json:"patch_set_sha256"`
	GoVersion          string `json:"go_version"`
}

type Entry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// BuildOptions contains only local build inputs. Build never downloads,
// installs, replaces an existing output, or mutates a service.
type BuildOptions struct {
	Version         string
	Commit          string
	SourceDateEpoch int64
	SecurityFloor   uint64
	Arch            string
	MeshInstallPath string
	MeshctlPath     string
	NebulaDirectory string
	OutputPath      string
}

type BuildResult struct {
	OutputPath        string
	Size              int64
	SHA256            string
	PackageJSONSHA256 string
	Package           Package
}

// Expected carries release-authenticated state that cannot safely be selected
// by package.json itself.
type Expected struct {
	Version                      string
	OS                           string
	Arch                         string
	MinimumSecurityFloor         uint64
	InstallerBootstrapRootSHA256 string
	InstallerStateSchemaVersion  uint64
}

// ArtifactIdentity is the exact outer artifact identity authenticated by the
// threshold release chain. StageAuthenticated re-hashes the same descriptor it
// parses, so callers cannot accidentally separate release verification from
// archive consumption.
type ArtifactIdentity struct {
	Size   int64
	SHA256 string
}

type StageResult struct {
	PackageJSONSHA256 string
	Package           Package
	FileCount         int
	TotalBytes        int64
}

type payloadSpec struct {
	path string
	mode uint32
}

var payloadSpecs = []payloadSpec{
	{path: "bin/mesh-install", mode: 0o555},
	{path: "bin/meshctl", mode: 0o555},
	{path: "bin/nebula", mode: 0o555},
	{path: "bin/nebula-cert", mode: 0o555},
	{path: "lib/systemd/system/mesh-agent.service", mode: 0o444},
	{path: "lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf", mode: 0o444},
	{path: "lib/systemd/system/mesh-nebula.service", mode: 0o444},
	{path: "lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf", mode: 0o444},
	{path: "share/doc/mesh/systemd/README.md", mode: 0o444},
	{path: "share/licenses/nebula/LICENSE", mode: 0o444},
}

var directoryPaths = []string{
	"bin",
	"lib",
	"lib/systemd",
	"lib/systemd/system",
	"lib/systemd/system/mesh-agent.service.d",
	"lib/systemd/system/mesh-nebula.service.d",
	"share",
	"share/doc",
	"share/doc/mesh",
	"share/doc/mesh/systemd",
	"share/licenses",
	"share/licenses/nebula",
}

func validatePackage(metadata Package) (time.Time, error) {
	if metadata.Schema != Schema && metadata.Schema != LegacySchema {
		return time.Time{}, fmt.Errorf("unsupported package schema %q", metadata.Schema)
	}
	if err := validateVersion(metadata.Version); err != nil {
		return time.Time{}, fmt.Errorf("version: %w", err)
	}
	if !commitPattern.MatchString(metadata.Commit) {
		return time.Time{}, errors.New("commit must be exactly 40 lowercase hexadecimal characters")
	}
	buildTime, err := parseCanonicalTime(metadata.BuildTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("build_time: %w", err)
	}
	if metadata.SecurityFloor == 0 {
		return time.Time{}, errors.New("security_floor must be positive")
	}
	if metadata.AgentStateReadMin == 0 || metadata.AgentStateReadMax == 0 || metadata.AgentStateWriteVersion == 0 ||
		metadata.AgentStateReadMin > metadata.AgentStateWriteVersion || metadata.AgentStateWriteVersion > metadata.AgentStateReadMax {
		return time.Time{}, errors.New("agent-state read range and write version must be positive, ordered, and self-readable")
	}
	if metadata.Schema == LegacySchema {
		if metadata.InstallerStateReadMin != 0 || metadata.InstallerStateReadMax != 0 || metadata.InstallerStateWriteVersion != 0 {
			return time.Time{}, errors.New("legacy package cannot declare installer-state compatibility")
		}
	} else if err := installercompat.Validate(installercompat.Contract{
		Schema: installercompat.Schema, ReadMinimum: metadata.InstallerStateReadMin,
		ReadMaximum: metadata.InstallerStateReadMax, WriteVersion: metadata.InstallerStateWriteVersion,
	}); err != nil {
		return time.Time{}, fmt.Errorf("installer-state compatibility: %w", err)
	}
	if !digestPattern.MatchString(metadata.InstallerBootstrapRootSHA256) {
		return time.Time{}, errors.New("installer bootstrap-root SHA-256 is not canonical")
	}
	if !goVersionRegex.MatchString(metadata.GoVersion) || len(metadata.GoVersion) > 64 {
		return time.Time{}, errors.New("go_version is not a canonical release toolchain version")
	}
	if metadata.Target.OS != "linux" || !supportedArch(metadata.Target.Arch) {
		return time.Time{}, errors.New("target must be linux/amd64 or linux/arm64")
	}
	if metadata.Nebula.Version != "v1.10.3" || !commitPattern.MatchString(metadata.Nebula.UpstreamCommit) ||
		!digestPattern.MatchString(metadata.Nebula.UpstreamLockSHA256) || !digestPattern.MatchString(metadata.Nebula.ObserverLockSHA256) ||
		!digestPattern.MatchString(metadata.Nebula.SourceTreeSHA256) || !digestPattern.MatchString(metadata.Nebula.PatchedTreeSHA256) ||
		!digestPattern.MatchString(metadata.Nebula.PatchSetSHA256) || !goVersionRegex.MatchString(metadata.Nebula.GoVersion) || len(metadata.Nebula.GoVersion) > 64 {
		return time.Time{}, errors.New("Nebula dependency identity is invalid")
	}
	if len(metadata.Entries) != len(payloadSpecs) {
		return time.Time{}, fmt.Errorf("entries must contain exactly %d payload files", len(payloadSpecs))
	}
	var total int64
	for index, spec := range payloadSpecs {
		entry := metadata.Entries[index]
		if entry.Path != spec.path {
			return time.Time{}, fmt.Errorf("entry %d path is %q, want %q", index, entry.Path, spec.path)
		}
		if index > 0 && metadata.Entries[index-1].Path >= entry.Path {
			return time.Time{}, errors.New("entries must be strictly path-sorted")
		}
		if path.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "\\") {
			return time.Time{}, fmt.Errorf("entry %q path is not canonical", entry.Path)
		}
		if entry.Mode != spec.mode {
			return time.Time{}, fmt.Errorf("entry %q mode is %04o, want %04o", entry.Path, entry.Mode, spec.mode)
		}
		if entry.Size <= 0 || entry.Size > maxPayloadFileSize {
			return time.Time{}, fmt.Errorf("entry %q size is outside the supported bound", entry.Path)
		}
		if !digestPattern.MatchString(entry.SHA256) {
			return time.Time{}, fmt.Errorf("entry %q SHA-256 is not canonical", entry.Path)
		}
		if total > maxPayloadSize-entry.Size {
			return time.Time{}, errors.New("payload exceeds aggregate size bound")
		}
		total += entry.Size
	}
	return buildTime, nil
}

func validateExpected(expected Expected, metadata Package) error {
	if err := validateVersion(expected.Version); err != nil {
		return fmt.Errorf("expected release version: %w", err)
	}
	if expected.OS != "linux" || !supportedArch(expected.Arch) {
		return errors.New("expected platform must be linux/amd64 or linux/arm64")
	}
	if expected.MinimumSecurityFloor == 0 {
		return errors.New("expected minimum security floor must be positive")
	}
	if expected.InstallerStateSchemaVersion == 0 {
		return errors.New("expected installer-state schema version must be positive")
	}
	if !digestPattern.MatchString(expected.InstallerBootstrapRootSHA256) {
		return errors.New("expected installer bootstrap-root SHA-256 is not canonical")
	}
	if metadata.Version != expected.Version || metadata.Target.OS != expected.OS || metadata.Target.Arch != expected.Arch {
		return errors.New("package identity does not match the release-selected version and platform")
	}
	if metadata.SecurityFloor < expected.MinimumSecurityFloor {
		return fmt.Errorf("package security floor %d is below required floor %d", metadata.SecurityFloor, expected.MinimumSecurityFloor)
	}
	if metadata.InstallerBootstrapRootSHA256 != expected.InstallerBootstrapRootSHA256 {
		return errors.New("package installer bootstrap root differs from the running installer bootstrap")
	}
	readMinimum, readMaximum, _, err := packageInstallerCompatibility(metadata)
	if err != nil {
		return err
	}
	if expected.InstallerStateSchemaVersion < readMinimum || expected.InstallerStateSchemaVersion > readMaximum {
		return fmt.Errorf("package cannot read inherited installer-state schema %d (supported %d through %d)", expected.InstallerStateSchemaVersion, readMinimum, readMaximum)
	}
	return nil
}

// packageInstallerCompatibility keeps one exact bridge for bundle v2: those
// releases were produced by the root-aware installer that reads v2/v3 and
// writes v3. The bridge is deliberately bounded to inherited state v3; a
// future state schema must have an explicit authenticated bundle-v3 contract.
func packageInstallerCompatibility(metadata Package) (uint64, uint64, uint64, error) {
	if metadata.Schema == LegacySchema {
		return 2, 3, 3, nil
	}
	if metadata.Schema != Schema {
		return 0, 0, 0, fmt.Errorf("unsupported package schema %q", metadata.Schema)
	}
	return metadata.InstallerStateReadMin, metadata.InstallerStateReadMax, metadata.InstallerStateWriteVersion, nil
}

func supportedArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 without fractional seconds")
	}
	if parsed.Unix() < 0 || parsed.Unix() >= 1<<33 {
		return time.Time{}, errors.New("is outside canonical USTAR time range")
	}
	return parsed.UTC(), nil
}

func validateVersion(version string) error {
	if version == "" || len(version) > 128 {
		return errors.New("must be a non-empty SemVer string of at most 128 characters")
	}
	if strings.Count(version, "+") > 1 {
		return errors.New("invalid SemVer build metadata")
	}
	mainAndBuild := strings.SplitN(version, "+", 2)
	if len(mainAndBuild) == 2 && !validIdentifiers(mainAndBuild[1], false) {
		return errors.New("invalid SemVer build metadata")
	}
	mainAndPre := strings.SplitN(mainAndBuild[0], "-", 2)
	core := strings.Split(mainAndPre[0], ".")
	if len(core) != 3 {
		return errors.New("version must contain major.minor.patch")
	}
	for _, number := range core {
		if !validNumericIdentifier(number) {
			return errors.New("version core numbers must be canonical")
		}
	}
	if len(mainAndPre) == 2 && !validIdentifiers(mainAndPre[1], true) {
		return errors.New("invalid SemVer prerelease")
	}
	return nil
}

func validIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "" || !identifierRegex.MatchString(part) {
			return false
		}
		if rejectNumericLeadingZero && allDigits(part) && !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validNumericIdentifier(value string) bool {
	return value != "" && allDigits(value) && (len(value) == 1 || value[0] != '0')
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonicalEpoch(value int64) (string, error) {
	if value < 0 || value >= 1<<33 {
		return "", errors.New("SOURCE_DATE_EPOCH is outside canonical USTAR time range")
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339), nil
}

func clonePackage(metadata Package) Package {
	clone := metadata
	clone.Entries = append([]Entry(nil), metadata.Entries...)
	return clone
}

func entryMap(entries []Entry) map[string]Entry {
	result := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		result[entry.Path] = entry
	}
	return result
}
