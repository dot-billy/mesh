package installerinspect

import (
	"bytes"
	gobuildinfo "debug/buildinfo"
	"debug/pe"
	"errors"
	"fmt"
	"runtime/debug"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/installtrust"
	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsinstallercompat"
)

type WindowsInspection struct {
	Identity      meshbuildinfo.IdentityInfo
	Bootstrap     installtrust.Bootstrap
	Compatibility windowsinstallercompat.Contract
	Authenticode  windowsauthenticode.Policy
	GoVersion     string
}

type BootstrapInspection struct {
	Identity     meshbuildinfo.IdentityInfo
	Bootstrap    installtrust.Bootstrap
	Authenticode windowsauthenticode.Policy
	GoVersion    string
}

// InspectBootstrap applies the platform-specific static executable contract
// while returning only fields shared by root-authorized bootstrap manifests.
func InspectBootstrap(content []byte, platformOS, arch string) (BootstrapInspection, error) {
	switch platformOS {
	case "linux":
		inspection, err := Inspect(content, arch)
		if err != nil {
			return BootstrapInspection{}, err
		}
		return BootstrapInspection{Identity: inspection.Identity, Bootstrap: inspection.Bootstrap, GoVersion: inspection.GoVersion}, nil
	case "windows":
		inspection, err := InspectWindows(content, arch)
		if err != nil {
			return BootstrapInspection{}, err
		}
		return BootstrapInspection{
			Identity: inspection.Identity, Bootstrap: inspection.Bootstrap,
			Authenticode: inspection.Authenticode, GoVersion: inspection.GoVersion,
		}, nil
	default:
		return BootstrapInspection{}, fmt.Errorf("unsupported bootstrap installer platform %q", platformOS)
	}
}

// InspectWindows applies bounded PE64, Go-build, production-identity,
// sole-bootstrap, and Windows install-state compatibility checks without
// executing the binary. The recovery guard contains debug/pe, whose standard
// library documentation does not claim adversarial-input hardening.
func InspectWindows(content []byte, arch string) (result WindowsInspection, returnErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = WindowsInspection{}
			returnErr = fmt.Errorf("parse Windows installer PE: malformed input (%T)", recovered)
		}
	}()
	if arch != "amd64" && arch != "arm64" {
		return result, errors.New("Windows installer architecture must be amd64 or arm64")
	}
	if len(content) == 0 || int64(len(content)) > maximumExecutableSize {
		return result, errors.New("Windows installer executable size is outside the supported bound")
	}
	parsed, err := pe.NewFile(bytes.NewReader(content))
	if err != nil {
		return result, fmt.Errorf("parse Windows installer PE: %w", err)
	}
	defer parsed.Close()
	if err := validateWindowsPEExecutable(parsed, arch, "installer"); err != nil {
		return result, err
	}
	sections, err := windowsReadOnlySections(parsed)
	if err != nil {
		return result, err
	}
	identities := collectWindowsFrames(sections, []byte(meshbuildinfo.FramePrefix), []byte(meshbuildinfo.FrameSuffix), 8<<10, meshbuildinfo.ParseIdentity)
	if len(identities) != 1 {
		return result, fmt.Errorf("Windows installer PE contains %d canonical build identities in read-only sections, want exactly one", len(identities))
	}
	bootstraps := collectWindowsFrames(sections, []byte(installtrust.BootstrapFramePrefix), []byte(installtrust.BootstrapFrameSuffix), 256<<10, installtrust.ParseBootstrapIdentity)
	legacy := collectWindowsFrames(sections, []byte(installtrust.FramePrefix), []byte(installtrust.FrameSuffix), 128<<10, installtrust.ParseIdentity)
	if len(bootstraps) != 1 || len(legacy) != 0 {
		return result, fmt.Errorf("Windows installer PE contains %d canonical v2 bootstraps and %d stale v1 policies, want exactly one v2 bootstrap and no v1 policy", len(bootstraps), len(legacy))
	}
	contracts := collectWindowsFrames(sections, []byte(windowsinstallercompat.FramePrefix), []byte(windowsinstallercompat.FrameSuffix), 4<<10, windowsinstallercompat.ParseIdentity)
	linuxContracts := collectWindowsFrames(sections, []byte(installercompat.FramePrefix), []byte(installercompat.FrameSuffix), 4<<10, installercompat.ParseIdentity)
	if len(contracts) != 1 || contracts[0] != windowsinstallercompat.Supported() || len(linuxContracts) != 0 {
		return result, fmt.Errorf("Windows installer PE has %d supported Windows and %d stale Linux compatibility frames, want exactly one Windows frame", len(contracts), len(linuxContracts))
	}
	authenticodePolicies := collectWindowsFrames(sections, []byte(windowsauthenticode.FramePrefix), []byte(windowsauthenticode.FrameSuffix), 16<<10, windowsauthenticode.ParsePolicyIdentity)
	if len(authenticodePolicies) != 1 {
		return result, fmt.Errorf("Windows installer PE contains %d canonical Authenticode publisher policies, want exactly one", len(authenticodePolicies))
	}
	goVersion, err := verifyWindowsGoBuildForMain(content, "mesh/cmd/mesh-install-windows", arch, identities[0])
	if err != nil {
		return result, err
	}
	return WindowsInspection{Identity: identities[0], Bootstrap: bootstraps[0], Compatibility: contracts[0], Authenticode: authenticodePolicies[0], GoVersion: goVersion}, nil
}

func validateWindowsPEExecutable(parsed *pe.File, arch, label string) error {
	if parsed == nil {
		return fmt.Errorf("Windows %s PE is nil", label)
	}
	wantMachine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if arch == "arm64" {
		wantMachine = pe.IMAGE_FILE_MACHINE_ARM64
	}
	header, ok := parsed.OptionalHeader.(*pe.OptionalHeader64)
	if parsed.Machine != wantMachine || !ok || header.Magic != 0x20b || header.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_CUI ||
		parsed.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || parsed.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		return fmt.Errorf("Windows %s is not a PE32+ console executable for windows/%s", label, arch)
	}
	return nil
}

type windowsReadOnlySection struct {
	name string
	raw  []byte
}

func windowsReadOnlySections(parsed *pe.File) ([]windowsReadOnlySection, error) {
	sections := make([]windowsReadOnlySection, 0, len(parsed.Sections))
	for _, section := range parsed.Sections {
		if section == nil || section.Characteristics&pe.IMAGE_SCN_MEM_READ == 0 || section.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0 || section.Characteristics&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
			continue
		}
		raw, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Windows installer PE section %q: %w", section.Name, err)
		}
		sections = append(sections, windowsReadOnlySection{name: section.Name, raw: raw})
	}
	return sections, nil
}

func collectWindowsFrames[T any](sections []windowsReadOnlySection, prefix, suffix []byte, maximum int, parse func(string) (T, error)) []T {
	var results []T
	for _, section := range sections {
		forEachFrame(section.raw, prefix, suffix, maximum, func(frame []byte) {
			if parsed, err := parse(string(frame)); err == nil {
				results = append(results, parsed)
			}
		})
	}
	return results
}

func verifyWindowsGoBuildForMain(content []byte, mainPath, arch string, expected meshbuildinfo.IdentityInfo) (string, error) {
	info, err := gobuildinfo.Read(bytes.NewReader(content))
	if err != nil {
		return "", fmt.Errorf("read Windows Mesh Go build information: %w", err)
	}
	if info.Path != mainPath || info.Main.Path != "mesh" || info.Main.Version != "(devel)" {
		return "", fmt.Errorf("Windows Mesh main package/module/version is %q %q %q, want %q %q %q", info.Path, info.Main.Path, info.Main.Version, mainPath, "mesh", "(devel)")
	}
	settings, err := uniqueBuildSettings((*debug.BuildInfo)(info))
	if err != nil {
		return "", err
	}
	required := map[string]string{
		"GOOS": "windows", "GOARCH": arch, "CGO_ENABLED": "0",
		"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true",
	}
	for key, want := range required {
		if got, ok := settings[key]; !ok || got != want {
			return "", fmt.Errorf("Windows Mesh Go build setting %q is %q (present=%t), want %q", key, got, ok, want)
		}
	}
	if modified, present := settings["vcs.modified"]; present && modified != "false" {
		return "", errors.New("Windows Mesh executable was built from a modified VCS tree")
	}
	if revision, present := settings["vcs.revision"]; present && revision != expected.Commit {
		return "", errors.New("Windows Mesh executable VCS revision does not match package commit")
	}
	if !goVersionPattern.MatchString(info.GoVersion) || len(info.GoVersion) > 64 {
		return "", fmt.Errorf("Windows Mesh Go toolchain version %q is not canonical", info.GoVersion)
	}
	return info.GoVersion, nil
}
