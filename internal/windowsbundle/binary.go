package windowsbundle

import (
	"bytes"
	gobuildinfo "debug/buildinfo"
	"debug/pe"
	"errors"
	"fmt"
	"runtime/debug"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/nebulaartifact"
)

func verifyMeshBinary(content []byte, mainPath, arch string, expected meshbuildinfo.IdentityInfo) (string, error) {
	parsed, err := parseExecutablePE(content, arch)
	if err != nil {
		return "", err
	}
	defer parsed.Close()
	identity, err := inspectMeshIdentity(parsed)
	if err != nil {
		return "", err
	}
	if identity != expected {
		return "", fmt.Errorf("Mesh compiled identity %+v does not match package identity %+v", identity, expected)
	}
	info, err := gobuildinfo.Read(bytes.NewReader(content))
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
		"GOOS": "windows", "GOARCH": arch, "CGO_ENABLED": "0",
		"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true",
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
	if !goVersionRegex.MatchString(info.GoVersion) || len(info.GoVersion) > 64 {
		return "", fmt.Errorf("Mesh Go toolchain version %q is not canonical", info.GoVersion)
	}
	return info.GoVersion, nil
}

func inspectMeshIdentityBytes(content []byte) (meshbuildinfo.IdentityInfo, error) {
	parsed, err := parseExecutablePE(content, peArch(content))
	if err != nil {
		return meshbuildinfo.IdentityInfo{}, fmt.Errorf("parse Mesh PE: %w", err)
	}
	defer parsed.Close()
	return inspectMeshIdentity(parsed)
}

// peArch derives only the machine selector needed by inspectMeshIdentityBytes.
// Full target matching is repeated later against the requested package arch.
func peArch(content []byte) string {
	parsed, err := pe.NewFile(bytes.NewReader(content))
	if err != nil {
		return ""
	}
	defer parsed.Close()
	switch parsed.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	default:
		return ""
	}
}

func verifyNebulaBinary(content []byte, expectation nebulaartifact.BinaryExpectation, target nebulaartifact.Target) error {
	if expectation.Format != "pe" || len(expectation.Targets) != 1 || expectation.Targets[0] != target || target.OS != "windows" || !supportedArch(target.Arch) {
		return errors.New("Nebula binary expectation is not the exact selected Windows target")
	}
	parsed, err := parseExecutablePE(content, target.Arch)
	if err != nil {
		return err
	}
	defer parsed.Close()
	info, err := gobuildinfo.Read(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("read Nebula Go build information: %w", err)
	}
	if info.Path != expectation.MainPath || info.Main.Path != "github.com/slackhq/nebula" || info.Main.Version != "v1.10.3" {
		return fmt.Errorf("Nebula main package/module/version is %q %q %q", info.Path, info.Main.Path, info.Main.Version)
	}
	settings, err := uniqueBuildSettings(info)
	if err != nil {
		return err
	}
	required := map[string]string{
		"GOOS": target.OS, "GOARCH": target.Arch, "vcs": "git",
		"vcs.revision": "f573e8a26695278f9d71587390fbfe0d0933aa21",
		"vcs.modified": "false", "-buildmode": "exe", "-compiler": "gc", "-trimpath": "true",
	}
	for key, want := range required {
		if got, ok := settings[key]; !ok || got != want {
			return fmt.Errorf("Nebula Go build setting %q is %q (present=%t), want %q", key, got, ok, want)
		}
	}
	return nil
}

func verifyWintunDLL(content []byte, arch string) error {
	if len(content) == 0 || int64(len(content)) > maxPayloadFileSize {
		return errors.New("Wintun DLL size is outside the supported bound")
	}
	parsed, err := pe.NewFile(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("parse Wintun PE: %w", err)
	}
	defer parsed.Close()
	wantMachine, err := peMachine(arch)
	if err != nil {
		return err
	}
	if parsed.Machine != wantMachine || parsed.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || parsed.Characteristics&pe.IMAGE_FILE_DLL == 0 {
		return errors.New("Wintun PE machine or DLL characteristics are unexpected")
	}
	if _, ok := parsed.OptionalHeader.(*pe.OptionalHeader64); !ok {
		return errors.New("Wintun executable is not PE32+")
	}
	return nil
}

func parseExecutablePE(content []byte, arch string) (*pe.File, error) {
	if len(content) == 0 || int64(len(content)) > maxPayloadFileSize {
		return nil, errors.New("executable size is outside the supported bound")
	}
	wantMachine, err := peMachine(arch)
	if err != nil {
		return nil, err
	}
	parsed, err := pe.NewFile(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	optional, ok := parsed.OptionalHeader.(*pe.OptionalHeader64)
	if parsed.Machine != wantMachine || parsed.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || parsed.Characteristics&pe.IMAGE_FILE_DLL != 0 || !ok || optional.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_CUI {
		parsed.Close()
		return nil, fmt.Errorf("executable is not an exact PE32+ Windows CUI %s image", arch)
	}
	return parsed, nil
}

func peMachine(arch string) (uint16, error) {
	switch arch {
	case "amd64":
		return pe.IMAGE_FILE_MACHINE_AMD64, nil
	case "arm64":
		return pe.IMAGE_FILE_MACHINE_ARM64, nil
	default:
		return 0, fmt.Errorf("unsupported Windows architecture %q", arch)
	}
}

func inspectMeshIdentity(parsed *pe.File) (meshbuildinfo.IdentityInfo, error) {
	if parsed == nil {
		return meshbuildinfo.IdentityInfo{}, errors.New("Mesh PE is nil")
	}
	prefix := []byte(meshbuildinfo.FramePrefix)
	suffix := []byte(meshbuildinfo.FrameSuffix)
	const maximumFrameSize = 8 << 10
	var identities []meshbuildinfo.IdentityInfo
	for _, section := range parsed.Sections {
		if section == nil || section.Characteristics&pe.IMAGE_SCN_MEM_READ == 0 || section.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0 {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return meshbuildinfo.IdentityInfo{}, fmt.Errorf("read Mesh identity section %q: %w", section.Name, err)
		}
		for offset := 0; offset < len(content); {
			index := bytes.Index(content[offset:], prefix)
			if index < 0 {
				break
			}
			start := offset + index
			limit := start + maximumFrameSize
			if limit > len(content) {
				limit = len(content)
			}
			endRelative := bytes.Index(content[start+len(prefix):limit], suffix)
			if endRelative >= 0 {
				end := start + len(prefix) + endRelative + len(suffix)
				identity, parseErr := meshbuildinfo.ParseIdentity(string(content[start:end]))
				if parseErr == nil {
					identities = append(identities, identity)
				}
			}
			offset = start + len(prefix)
		}
	}
	if len(identities) != 1 {
		return meshbuildinfo.IdentityInfo{}, fmt.Errorf("Mesh PE contains %d canonical identities in readable non-writable sections, want exactly one", len(identities))
	}
	return identities[0], nil
}

func uniqueBuildSettings(info *debug.BuildInfo) (map[string]string, error) {
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return nil, fmt.Errorf("duplicate Go build setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	return settings, nil
}
