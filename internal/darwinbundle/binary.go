package darwinbundle

import (
	"bytes"
	gobuildinfo "debug/buildinfo"
	"debug/macho"
	"errors"
	"fmt"
	"runtime/debug"

	meshbuildinfo "mesh/internal/buildinfo"
)

func verifyMeshBinary(content []byte, mainPath, arch string, expected meshbuildinfo.IdentityInfo) (string, error) {
	parsed, err := parseExecutableMachO(content, arch)
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
		"GOOS": "darwin", "GOARCH": arch, "CGO_ENABLED": "0",
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
	arch := machoArch(content)
	parsed, err := parseExecutableMachO(content, arch)
	if err != nil {
		return meshbuildinfo.IdentityInfo{}, fmt.Errorf("parse Mesh Mach-O: %w", err)
	}
	defer parsed.Close()
	return inspectMeshIdentity(parsed)
}

// machoArch derives only the CPU selector needed by inspectMeshIdentityBytes.
// Full target matching is repeated against the requested package architecture.
func machoArch(content []byte) string {
	parsed, err := macho.NewFile(bytes.NewReader(content))
	if err != nil {
		return ""
	}
	defer parsed.Close()
	switch parsed.Cpu {
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm64:
		return "arm64"
	default:
		return ""
	}
}

func parseExecutableMachO(content []byte, arch string) (*macho.File, error) {
	if len(content) == 0 || int64(len(content)) > maxPayloadFileSize {
		return nil, errors.New("executable size is outside the supported bound")
	}
	wantCPU, err := machoCPU(arch)
	if err != nil {
		return nil, err
	}
	parsed, err := macho.NewFile(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("parse Mach-O: %w", err)
	}
	if parsed.Magic != macho.Magic64 || parsed.Cpu != wantCPU || parsed.Type != macho.TypeExec ||
		parsed.Flags&macho.FlagPIE == 0 || parsed.Flags&macho.FlagAllowStackExecution != 0 {
		parsed.Close()
		return nil, fmt.Errorf("executable is not an exact 64-bit PIE darwin/%s Mach-O", arch)
	}
	return parsed, nil
}

func machoCPU(arch string) (macho.Cpu, error) {
	switch arch {
	case "amd64":
		return macho.CpuAmd64, nil
	case "arm64":
		return macho.CpuArm64, nil
	default:
		return 0, fmt.Errorf("unsupported Darwin architecture %q", arch)
	}
}

func inspectMeshIdentity(parsed *macho.File) (meshbuildinfo.IdentityInfo, error) {
	if parsed == nil {
		return meshbuildinfo.IdentityInfo{}, errors.New("Mesh Mach-O is nil")
	}
	segmentProtections := make(map[string]uint32)
	for _, load := range parsed.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if _, duplicate := segmentProtections[segment.Name]; duplicate {
			return meshbuildinfo.IdentityInfo{}, fmt.Errorf("Mesh Mach-O repeats segment %q", segment.Name)
		}
		segmentProtections[segment.Name] = segment.Prot
	}
	prefix := []byte(meshbuildinfo.FramePrefix)
	suffix := []byte(meshbuildinfo.FrameSuffix)
	const maximumFrameSize = 8 << 10
	var identities []meshbuildinfo.IdentityInfo
	for _, section := range parsed.Sections {
		if section == nil {
			continue
		}
		protection, present := segmentProtections[section.Seg]
		if !present || protection&1 == 0 || protection&2 != 0 {
			continue
		}
		content, err := section.Data()
		if err != nil {
			return meshbuildinfo.IdentityInfo{}, fmt.Errorf("read Mesh identity section %s/%s: %w", section.Seg, section.Name, err)
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
		return meshbuildinfo.IdentityInfo{}, fmt.Errorf("Mesh Mach-O contains %d canonical identities in readable non-writable sections, want exactly one", len(identities))
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
