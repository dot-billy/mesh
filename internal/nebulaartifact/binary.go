package nebulaartifact

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

func verifyBinary(file *os.File, expectation BinaryExpectation) error {
	if file == nil {
		return errors.New("binary file is nil")
	}
	switch expectation.Format {
	case "elf":
		if len(expectation.Targets) != 1 || expectation.Targets[0].OS != "linux" {
			return errors.New("ELF expectation must identify one Linux target")
		}
		parsed, err := elf.NewFile(file)
		if err != nil {
			return fmt.Errorf("parse ELF: %w", err)
		}
		defer parsed.Close()
		if parsed.Class != elf.ELFCLASS64 || parsed.Data != elf.ELFDATA2LSB || parsed.Type != elf.ET_EXEC {
			return errors.New("ELF class, byte order, or executable type is unexpected")
		}
		wantMachine := elf.EM_X86_64
		if expectation.Targets[0].Arch == "arm64" {
			wantMachine = elf.EM_AARCH64
		}
		if parsed.Machine != wantMachine {
			return fmt.Errorf("ELF machine is %s, want %s", parsed.Machine, wantMachine)
		}
		return verifyBuildInformation(file, expectation, expectation.Targets[0])
	case "pe":
		if len(expectation.Targets) != 1 || expectation.Targets[0].OS != "windows" {
			return errors.New("PE expectation must identify one Windows target")
		}
		parsed, err := pe.NewFile(file)
		if err != nil {
			return fmt.Errorf("parse PE: %w", err)
		}
		defer parsed.Close()
		wantMachine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
		if expectation.Targets[0].Arch == "arm64" {
			wantMachine = pe.IMAGE_FILE_MACHINE_ARM64
		}
		if parsed.Machine != wantMachine || parsed.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
			return errors.New("PE machine or executable characteristic is unexpected")
		}
		if _, ok := parsed.OptionalHeader.(*pe.OptionalHeader64); !ok {
			return errors.New("PE executable is not PE32+")
		}
		return verifyBuildInformation(file, expectation, expectation.Targets[0])
	case "macho-fat":
		if len(expectation.Targets) != 2 {
			return errors.New("Mach-O universal expectation must identify two targets")
		}
		parsed, err := macho.NewFatFile(file)
		if err != nil {
			return fmt.Errorf("parse Mach-O universal binary: %w", err)
		}
		defer parsed.Close()
		if parsed.Magic != macho.MagicFat || len(parsed.Arches) != 2 {
			return errors.New("Mach-O binary is not an exact two-slice universal binary")
		}
		seen := make(map[Target]struct{}, 2)
		for _, arch := range parsed.Arches {
			var target Target
			switch arch.Cpu {
			case macho.CpuAmd64:
				target = Target{OS: "darwin", Arch: "amd64"}
			case macho.CpuArm64:
				target = Target{OS: "darwin", Arch: "arm64"}
			default:
				return fmt.Errorf("unexpected Mach-O CPU %s", arch.Cpu)
			}
			if _, duplicate := seen[target]; duplicate {
				return fmt.Errorf("duplicate Mach-O slice for %s", target.Arch)
			}
			if !containsTarget(expectation.Targets, target) {
				return fmt.Errorf("unlocked Mach-O slice %s/%s", target.OS, target.Arch)
			}
			if arch.Type != macho.TypeExec {
				return fmt.Errorf("Mach-O slice %s is not executable", target.Arch)
			}
			section := io.NewSectionReader(file, int64(arch.Offset), int64(arch.Size))
			if err := verifyBuildInformation(section, expectation, target); err != nil {
				return fmt.Errorf("Mach-O %s slice: %w", target.Arch, err)
			}
			seen[target] = struct{}{}
		}
		if len(seen) != len(expectation.Targets) {
			return errors.New("Mach-O universal binary is missing a locked slice")
		}
		return nil
	default:
		return fmt.Errorf("unsupported executable format %q", expectation.Format)
	}
}

func verifyBuildInformation(reader io.ReaderAt, expectation BinaryExpectation, target Target) error {
	info, err := buildinfo.Read(reader)
	if err != nil {
		return fmt.Errorf("read Go build information: %w", err)
	}
	if info.Path != expectation.MainPath || info.Main.Path != "github.com/slackhq/nebula" || info.Main.Version != lockedVersion {
		return fmt.Errorf("main package/module/version is %q %q %q, want %q %q %q", info.Path, info.Main.Path, info.Main.Version, expectation.MainPath, "github.com/slackhq/nebula", lockedVersion)
	}
	settings, err := uniqueBuildSettings(info)
	if err != nil {
		return err
	}
	required := map[string]string{
		"GOOS":         target.OS,
		"GOARCH":       target.Arch,
		"vcs":          "git",
		"vcs.revision": lockedRevision,
		"vcs.modified": "false",
		"-buildmode":   "exe",
		"-compiler":    "gc",
		"-trimpath":    "true",
	}
	for key, want := range required {
		if got, ok := settings[key]; !ok || got != want {
			return fmt.Errorf("Go build setting %q is %q (present=%t), want %q", key, got, ok, want)
		}
	}
	return nil
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

func containsTarget(targets []Target, target Target) bool {
	for _, candidate := range targets {
		if candidate == target {
			return true
		}
	}
	return false
}
