// Package darwinbundle builds the deterministic, uncompressed Darwin node
// staging bundle. It deliberately performs no installation, service-manager
// mutation, extended-ACL mutation, codesigning, or notarization decision.
package darwinbundle

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	Schema = "mesh-darwin-node-staging-bundle-v1"

	packageJSONPath        = "package.json"
	packageJSONArchiveMode = 0o444

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

// Package is the canonical package.json schema. ArchiveMode is deterministic
// USTAR transport metadata only; it is not a Darwin DACL or installation
// extended-ACL or installation permission claim.
type Package struct {
	Schema                 string          `json:"schema"`
	Version                string          `json:"version"`
	Commit                 string          `json:"commit"`
	BuildTime              string          `json:"build_time"`
	SecurityFloor          uint64          `json:"security_floor"`
	AgentStateReadMin      uint64          `json:"agent_state_read_min"`
	AgentStateReadMax      uint64          `json:"agent_state_read_max"`
	AgentStateWriteVersion uint64          `json:"agent_state_write_version"`
	GoVersion              string          `json:"go_version"`
	Target                 Target          `json:"target"`
	Runtime                RuntimeIdentity `json:"runtime"`
	Entries                []Entry         `json:"entries"`
}

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// RuntimeIdentity binds the source-authenticated, reproducible Darwin Nebula
// Mach-O executables and both the common source policy and Darwin output lock.
type RuntimeIdentity struct {
	Version               string `json:"version"`
	Commit                string `json:"commit"`
	UpstreamLockSHA256    string `json:"upstream_lock_sha256"`
	SourceBuildLockSHA256 string `json:"source_build_lock_sha256"`
	DarwinBuildLockSHA256 string `json:"darwin_build_lock_sha256"`
	SourceTreeSHA256      string `json:"source_tree_sha256"`
	PatchedTreeSHA256     string `json:"patched_tree_sha256"`
	PatchSetSHA256        string `json:"patch_set_sha256"`
	GoVersion             string `json:"go_version"`
}

type Entry struct {
	Path        string `json:"path"`
	ArchiveMode uint32 `json:"archive_mode"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// BuildOptions contains only local inputs. Build never downloads, installs,
// replaces an existing output, mutates a service, or applies macOS ACLs.
type BuildOptions struct {
	Version                string
	Commit                 string
	SourceDateEpoch        int64
	SecurityFloor          uint64
	Arch                   string
	MeshctlPath            string
	NebulaRuntimeDirectory string
	OutputPath             string
}

type BuildResult struct {
	OutputPath        string
	Size              int64
	SHA256            string
	PackageJSONSHA256 string
	Package           Package
}

type payloadSpec struct {
	path        string
	archiveMode uint32
}

func payloadSpecs(_ string) []payloadSpec {
	return []payloadSpec{
		{path: "Library/LaunchDaemons/io.mesh.node-agent.plist", archiveMode: 0o444},
		{path: "bin/meshctl", archiveMode: 0o555},
		{path: "bin/nebula", archiveMode: 0o555},
		{path: "bin/nebula-cert", archiveMode: 0o555},
		{path: "share/doc/mesh/launchd/README.md", archiveMode: 0o444},
		{path: "share/licenses/nebula/LICENSE", archiveMode: 0o444},
	}
}

func validatePackage(metadata Package) (time.Time, error) {
	if metadata.Schema != Schema {
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
	if !goVersionRegex.MatchString(metadata.GoVersion) || len(metadata.GoVersion) > 64 {
		return time.Time{}, errors.New("go_version is not a canonical release toolchain version")
	}
	if metadata.Target.OS != "darwin" || !supportedArch(metadata.Target.Arch) {
		return time.Time{}, errors.New("target must be darwin/amd64 or darwin/arm64")
	}
	if metadata.Runtime.Version != "v1.10.3" || !commitPattern.MatchString(metadata.Runtime.Commit) ||
		!digestPattern.MatchString(metadata.Runtime.UpstreamLockSHA256) ||
		!digestPattern.MatchString(metadata.Runtime.SourceBuildLockSHA256) ||
		!digestPattern.MatchString(metadata.Runtime.DarwinBuildLockSHA256) ||
		!digestPattern.MatchString(metadata.Runtime.SourceTreeSHA256) ||
		!digestPattern.MatchString(metadata.Runtime.PatchedTreeSHA256) ||
		!digestPattern.MatchString(metadata.Runtime.PatchSetSHA256) || metadata.Runtime.GoVersion != "go1.26.5" {
		return time.Time{}, errors.New("Nebula Darwin runtime identity is invalid")
	}
	specs := payloadSpecs(metadata.Target.Arch)
	if len(metadata.Entries) != len(specs) {
		return time.Time{}, fmt.Errorf("entries must contain exactly %d payload files", len(specs))
	}
	var total int64
	for index, spec := range specs {
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
		if entry.ArchiveMode != spec.archiveMode {
			return time.Time{}, fmt.Errorf("entry %q archive_mode is %04o, want %04o", entry.Path, entry.ArchiveMode, spec.archiveMode)
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

func canonicalEpoch(value int64) (string, error) {
	if value < 0 || value >= 1<<33 {
		return "", errors.New("SOURCE_DATE_EPOCH is outside canonical USTAR time range")
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339), nil
}

func validateVersion(version string) error {
	if version == "" || len(version) > 128 || strings.Count(version, "+") > 1 {
		return errors.New("invalid SemVer length or build metadata")
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
		if part == "" || !identifierRegex.MatchString(part) || rejectNumericLeadingZero && allDigits(part) && !validNumericIdentifier(part) {
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
