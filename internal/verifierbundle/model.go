// Package verifierbundle builds a deterministic, non-installing distribution
// artifact containing only the standalone first-installer verifier and its
// canonical metadata. Trust in the artifact digest must arrive independently.
package verifierbundle

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"mesh/internal/buildinfo"
)

const (
	Schema         = "mesh-bootstrap-verifier-bundle-v1"
	MaxArchiveSize = 136 << 20

	packageJSONPath        = "package.json"
	packageJSONMode uint32 = 0o444
	verifierMode    uint32 = 0o555

	maxPackageJSONSize int64 = 64 << 10
	maxVerifierSize    int64 = 128 << 20
)

var (
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	goVersionRegex = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.-]*)$`)
)

type Package struct {
	Schema    string                 `json:"schema"`
	Build     buildinfo.IdentityInfo `json:"build"`
	GoVersion string                 `json:"go_version"`
	Target    Target                 `json:"target"`
	Entries   []Entry                `json:"entries"`
}

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Entry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type BuildOptions struct {
	Version         string
	Commit          string
	SourceDateEpoch int64
	SecurityFloor   uint64
	OS              string
	Arch            string
	VerifierPath    string
	OutputPath      string
}

type BuildResult struct {
	OutputPath        string
	Size              int64
	SHA256            string
	PackageJSONSHA256 string
	Package           Package
}

func validatePackage(metadata Package) (time.Time, error) {
	if metadata.Schema != Schema {
		return time.Time{}, fmt.Errorf("unsupported package schema %q", metadata.Schema)
	}
	if _, err := buildinfo.EncodeIdentity(metadata.Build); err != nil {
		return time.Time{}, fmt.Errorf("build identity: %w", err)
	}
	if metadata.Build.Version == "dev" {
		return time.Time{}, errors.New("bootstrap verifier package requires a production build identity")
	}
	buildTime, err := time.Parse(time.RFC3339, metadata.Build.BuildTime)
	if err != nil || buildTime.UTC().Format(time.RFC3339) != metadata.Build.BuildTime || buildTime.Unix() < 0 || buildTime.Unix() >= 1<<33 {
		return time.Time{}, errors.New("build identity time is outside canonical USTAR range")
	}
	if !goVersionRegex.MatchString(metadata.GoVersion) || len(metadata.GoVersion) > 64 {
		return time.Time{}, errors.New("go_version is not canonical")
	}
	if !supportedOS(metadata.Target.OS) || !supportedArch(metadata.Target.Arch) {
		return time.Time{}, errors.New("target must be linux or windows with amd64 or arm64")
	}
	if len(metadata.Entries) != 1 {
		return time.Time{}, errors.New("entries must contain only the standalone verifier")
	}
	entry := metadata.Entries[0]
	if entry.Path != verifierPath(metadata.Target.OS) || path.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "\\") {
		return time.Time{}, errors.New("verifier entry path is not canonical")
	}
	if entry.Mode != verifierMode {
		return time.Time{}, fmt.Errorf("verifier entry mode is %04o, want %04o", entry.Mode, verifierMode)
	}
	if entry.Size <= 0 || entry.Size > maxVerifierSize {
		return time.Time{}, errors.New("verifier entry size is outside the supported bound")
	}
	if !digestPattern.MatchString(entry.SHA256) {
		return time.Time{}, errors.New("verifier entry SHA-256 is not canonical")
	}
	return buildTime.UTC(), nil
}

func supportedArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

func supportedOS(platformOS string) bool { return platformOS == "linux" || platformOS == "windows" }

func verifierPath(platformOS string) string {
	if platformOS == "windows" {
		return "bin/mesh-bootstrap-verify.exe"
	}
	return "bin/mesh-bootstrap-verify"
}

func supportedVerifierPath(value string) bool {
	return value == verifierPath("linux") || value == verifierPath("windows")
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
