// Package installerinspect statically validates production mesh-install ELF
// bytes. It performs no network, subprocess, signing, extraction, installation,
// or filesystem operation.
package installerinspect

import (
	"bytes"
	gobuildinfo "debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"runtime/debug"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/installtrust"
	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsinstallercompat"
)

const maximumExecutableSize int64 = 128 << 20

var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.-]*)$`)

// Inspection is the static production identity needed to authorize a
// separately distributed first installer.
type Inspection struct {
	Identity      meshbuildinfo.IdentityInfo
	Bootstrap     installtrust.Bootstrap
	Compatibility installercompat.Contract
	GoVersion     string
}

// Inspect applies the bounded ELF, Go-build, production-identity,
// sole-bootstrap, and sole-installer-compatibility checks used by release
// packaging and first-installer verification.
func Inspect(content []byte, arch string) (Inspection, error) {
	if arch != "amd64" && arch != "arm64" {
		return Inspection{}, errors.New("installer architecture must be amd64 or arm64")
	}
	identity, err := InspectMeshIdentity(content)
	if err != nil {
		return Inspection{}, err
	}
	goVersion, err := VerifyMeshBinary(content, "mesh/cmd/mesh-install", arch, identity)
	if err != nil {
		return Inspection{}, err
	}
	bootstrap, err := InspectTrustBootstrap(content)
	if err != nil {
		return Inspection{}, err
	}
	compatibility, err := InspectCompatibility(content)
	if err != nil {
		return Inspection{}, err
	}
	if err := RejectWindowsAuthenticodePolicies(content); err != nil {
		return Inspection{}, err
	}
	return Inspection{Identity: identity, Bootstrap: bootstrap, Compatibility: compatibility, GoVersion: goVersion}, nil
}

func VerifyMeshBinary(content []byte, mainPath, arch string, expected meshbuildinfo.IdentityInfo) (string, error) {
	if len(content) == 0 || int64(len(content)) > maximumExecutableSize {
		return "", errors.New("Mesh executable size is outside the supported bound")
	}
	reader := bytes.NewReader(content)
	parsed, err := elf.NewFile(reader)
	if err != nil {
		return "", fmt.Errorf("parse Mesh ELF: %w", err)
	}
	defer parsed.Close()
	wantMachine := elf.EM_X86_64
	if arch == "arm64" {
		wantMachine = elf.EM_AARCH64
	}
	if parsed.Class != elf.ELFCLASS64 || parsed.Data != elf.ELFDATA2LSB || parsed.Type != elf.ET_EXEC || parsed.Machine != wantMachine {
		return "", fmt.Errorf("Mesh executable is not an ELF64 little-endian %s executable", arch)
	}
	identity, err := inspectMeshIdentity(parsed)
	if err != nil {
		return "", err
	}
	if identity != expected {
		return "", fmt.Errorf("Mesh compiled identity %+v does not match package identity %+v", identity, expected)
	}
	info, err := gobuildinfo.Read(reader)
	if err != nil {
		return "", fmt.Errorf("read Mesh Go build information: %w", err)
	}
	if info.Path != mainPath || info.Main.Path != "mesh" || info.Main.Version != "(devel)" {
		return "", fmt.Errorf("Mesh main package/module/version is %q %q %q, want %q %q %q", info.Path, info.Main.Path, info.Main.Version, mainPath, "mesh", "(devel)")
	}
	settings, err := uniqueBuildSettings(info)
	if err != nil {
		return "", err
	}
	required := map[string]string{
		"GOOS":        "linux",
		"GOARCH":      arch,
		"CGO_ENABLED": "0",
		"-buildmode":  "exe",
		"-compiler":   "gc",
		"-trimpath":   "true",
	}
	for key, want := range required {
		if got, ok := settings[key]; !ok || got != want {
			return "", fmt.Errorf("Mesh Go build setting %q is %q (present=%t), want %q", key, got, ok, want)
		}
	}
	if modified, present := settings["vcs.modified"]; present && modified != "false" {
		return "", errors.New("Mesh executable was built from a modified VCS tree")
	}
	if revision, present := settings["vcs.revision"]; present && revision != expected.Commit {
		return "", errors.New("Mesh executable VCS revision does not match package commit")
	}
	if !goVersionPattern.MatchString(info.GoVersion) || len(info.GoVersion) > 64 {
		return "", fmt.Errorf("Mesh Go toolchain version %q is not canonical", info.GoVersion)
	}
	return info.GoVersion, nil
}

// InspectMeshIdentity performs a static, read-only ELF identity scan.
func InspectMeshIdentity(content []byte) (meshbuildinfo.IdentityInfo, error) {
	if len(content) == 0 || int64(len(content)) > maximumExecutableSize {
		return meshbuildinfo.IdentityInfo{}, errors.New("Mesh executable size is outside the supported bound")
	}
	parsed, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return meshbuildinfo.IdentityInfo{}, fmt.Errorf("parse Mesh ELF: %w", err)
	}
	defer parsed.Close()
	return inspectMeshIdentity(parsed)
}

func inspectMeshIdentity(parsed *elf.File) (meshbuildinfo.IdentityInfo, error) {
	if parsed == nil {
		return meshbuildinfo.IdentityInfo{}, errors.New("Mesh ELF is nil")
	}
	prefix := []byte(meshbuildinfo.FramePrefix)
	suffix := []byte(meshbuildinfo.FrameSuffix)
	const maximumFrameSize = 8 << 10
	var identities []meshbuildinfo.IdentityInfo
	for _, section := range parsed.Sections {
		if !readOnlyAllocatedSection(section) {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return meshbuildinfo.IdentityInfo{}, fmt.Errorf("read Mesh identity section %q: %w", section.Name, err)
		}
		forEachFrame(content, prefix, suffix, maximumFrameSize, func(frame []byte) {
			if identity, err := meshbuildinfo.ParseIdentity(string(frame)); err == nil {
				identities = append(identities, identity)
			}
		})
	}
	if len(identities) != 1 {
		return meshbuildinfo.IdentityInfo{}, fmt.Errorf("Mesh ELF contains %d canonical identities in read-only allocated sections, want exactly one", len(identities))
	}
	return identities[0], nil
}

// InspectTrustBootstrap requires exactly one canonical current bootstrap and
// no legacy trust-policy frame.
func InspectTrustBootstrap(content []byte) (installtrust.Bootstrap, error) {
	parsed, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return installtrust.Bootstrap{}, fmt.Errorf("parse Mesh installer ELF for trust bootstrap: %w", err)
	}
	defer parsed.Close()
	bootstraps, err := installerTrustBootstraps(parsed)
	if err != nil {
		return installtrust.Bootstrap{}, err
	}
	legacy, err := installerLegacyTrustPolicies(parsed)
	if err != nil {
		return installtrust.Bootstrap{}, err
	}
	if len(bootstraps) != 1 || len(legacy) != 0 {
		return installtrust.Bootstrap{}, fmt.Errorf("Mesh installer ELF contains %d canonical v2 bootstraps and %d stale v1 policies in read-only allocated sections, want exactly one v2 bootstrap and no v1 policy", len(bootstraps), len(legacy))
	}
	return bootstraps[0], nil
}

func RejectTrustFrames(content []byte) error {
	parsed, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("parse non-installer Mesh ELF for trust frames: %w", err)
	}
	defer parsed.Close()
	bootstraps, err := installerTrustBootstraps(parsed)
	if err != nil {
		return err
	}
	legacy, err := installerLegacyTrustPolicies(parsed)
	if err != nil {
		return err
	}
	authenticode, err := windowsAuthenticodePolicies(parsed)
	if err != nil {
		return err
	}
	if len(bootstraps) != 0 || len(legacy) != 0 || len(authenticode) != 0 {
		return fmt.Errorf("non-installer Mesh ELF contains %d canonical v2 bootstraps, %d stale v1 policies, and %d Windows Authenticode policies, want none", len(bootstraps), len(legacy), len(authenticode))
	}
	return nil
}

func RejectWindowsAuthenticodePolicies(content []byte) error {
	parsed, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("parse Linux Mesh executable for Windows Authenticode policy: %w", err)
	}
	defer parsed.Close()
	policies, err := windowsAuthenticodePolicies(parsed)
	if err != nil {
		return err
	}
	if len(policies) != 0 {
		return fmt.Errorf("Linux Mesh executable contains %d Windows Authenticode publisher policies, want none", len(policies))
	}
	return nil
}

// InspectCompatibility requires exactly one canonical installer-state
// compatibility frame.
func InspectCompatibility(content []byte) (installercompat.Contract, error) {
	parsed, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return installercompat.Contract{}, fmt.Errorf("parse Mesh installer ELF for installer-state compatibility: %w", err)
	}
	defer parsed.Close()
	contracts, err := installerCompatibilities(parsed)
	if err != nil {
		return installercompat.Contract{}, err
	}
	windowsContracts, err := windowsInstallerCompatibilities(parsed)
	if err != nil {
		return installercompat.Contract{}, err
	}
	if len(contracts) != 1 || len(windowsContracts) != 0 {
		return installercompat.Contract{}, fmt.Errorf("Mesh installer ELF contains %d Linux and %d Windows installer-state compatibility frames, want exactly one Linux frame", len(contracts), len(windowsContracts))
	}
	return contracts[0], nil
}

func RejectCompatibilityFrames(content []byte) error {
	parsed, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("parse non-installer Mesh ELF for installer-state compatibility: %w", err)
	}
	defer parsed.Close()
	contracts, err := installerCompatibilities(parsed)
	if err != nil {
		return err
	}
	windowsContracts, err := windowsInstallerCompatibilities(parsed)
	if err != nil {
		return err
	}
	if len(contracts) != 0 || len(windowsContracts) != 0 {
		return fmt.Errorf("non-installer Mesh ELF contains %d Linux and %d Windows installer-state compatibility frames, want none", len(contracts), len(windowsContracts))
	}
	return nil
}

func installerCompatibilities(parsed *elf.File) ([]installercompat.Contract, error) {
	if parsed == nil {
		return nil, errors.New("Mesh ELF is nil")
	}
	prefix := []byte(installercompat.FramePrefix)
	suffix := []byte(installercompat.FrameSuffix)
	const maximumFrameSize = 4 << 10
	var contracts []installercompat.Contract
	for _, section := range parsed.Sections {
		if !readOnlyAllocatedSection(section) {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Mesh installer-state compatibility section %q: %w", section.Name, err)
		}
		forEachFrame(content, prefix, suffix, maximumFrameSize, func(frame []byte) {
			if contract, err := installercompat.ParseIdentity(string(frame)); err == nil {
				contracts = append(contracts, contract)
			}
		})
	}
	return contracts, nil
}

func windowsInstallerCompatibilities(parsed *elf.File) ([]windowsinstallercompat.Contract, error) {
	if parsed == nil {
		return nil, errors.New("Mesh ELF is nil")
	}
	prefix := []byte(windowsinstallercompat.FramePrefix)
	suffix := []byte(windowsinstallercompat.FrameSuffix)
	const maximumFrameSize = 4 << 10
	var contracts []windowsinstallercompat.Contract
	for _, section := range parsed.Sections {
		if !readOnlyAllocatedSection(section) {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Windows installer-state compatibility section %q: %w", section.Name, err)
		}
		forEachFrame(content, prefix, suffix, maximumFrameSize, func(frame []byte) {
			if contract, err := windowsinstallercompat.ParseIdentity(string(frame)); err == nil {
				contracts = append(contracts, contract)
			}
		})
	}
	return contracts, nil
}

func windowsAuthenticodePolicies(parsed *elf.File) ([]windowsauthenticode.Policy, error) {
	if parsed == nil {
		return nil, errors.New("Mesh ELF is nil")
	}
	var policies []windowsauthenticode.Policy
	for _, section := range parsed.Sections {
		if !readOnlyAllocatedSection(section) {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Windows Authenticode policy section %q: %w", section.Name, err)
		}
		forEachFrame(content, []byte(windowsauthenticode.FramePrefix), []byte(windowsauthenticode.FrameSuffix), 16<<10, func(frame []byte) {
			if policy, err := windowsauthenticode.ParsePolicyIdentity(string(frame)); err == nil {
				policies = append(policies, policy)
			}
		})
	}
	return policies, nil
}

func installerTrustBootstraps(parsed *elf.File) ([]installtrust.Bootstrap, error) {
	if parsed == nil {
		return nil, errors.New("Mesh ELF is nil")
	}
	prefix := []byte(installtrust.BootstrapFramePrefix)
	suffix := []byte(installtrust.BootstrapFrameSuffix)
	const maximumFrameSize = 256 << 10
	var bootstraps []installtrust.Bootstrap
	for _, section := range parsed.Sections {
		if !readOnlyAllocatedSection(section) {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Mesh installer trust section %q: %w", section.Name, err)
		}
		forEachFrame(content, prefix, suffix, maximumFrameSize, func(frame []byte) {
			if bootstrap, err := installtrust.ParseBootstrapIdentity(string(frame)); err == nil {
				bootstraps = append(bootstraps, bootstrap)
			}
		})
	}
	return bootstraps, nil
}

func installerLegacyTrustPolicies(parsed *elf.File) ([]installtrust.Policy, error) {
	if parsed == nil {
		return nil, errors.New("Mesh ELF is nil")
	}
	prefix := []byte(installtrust.FramePrefix)
	suffix := []byte(installtrust.FrameSuffix)
	const maximumFrameSize = 128 << 10
	var policies []installtrust.Policy
	for _, section := range parsed.Sections {
		if !readOnlyAllocatedSection(section) {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Mesh installer legacy trust section %q: %w", section.Name, err)
		}
		forEachFrame(content, prefix, suffix, maximumFrameSize, func(frame []byte) {
			if policy, err := installtrust.ParseIdentity(string(frame)); err == nil {
				policies = append(policies, policy)
			}
		})
	}
	return policies, nil
}

func readOnlyAllocatedSection(section *elf.Section) bool {
	return section != nil && section.Type != elf.SHT_NOBITS && section.Flags&elf.SHF_ALLOC != 0 && section.Flags&elf.SHF_WRITE == 0
}

func forEachFrame(content, prefix, suffix []byte, maximumFrameSize int, visit func([]byte)) {
	for offset := 0; offset < len(content); {
		index := bytes.Index(content[offset:], prefix)
		if index < 0 {
			return
		}
		start := offset + index
		limit := start + maximumFrameSize
		if limit > len(content) {
			limit = len(content)
		}
		endRelative := bytes.Index(content[start+len(prefix):limit], suffix)
		if endRelative >= 0 {
			end := start + len(prefix) + endRelative + len(suffix)
			visit(content[start:end])
		}
		offset = start + len(prefix)
	}
}

func uniqueBuildSettings(info *debug.BuildInfo) (map[string]string, error) {
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return nil, fmt.Errorf("duplicate Go build setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	return settings, nil
}
