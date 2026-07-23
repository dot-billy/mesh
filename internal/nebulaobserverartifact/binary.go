package nebulaobserverartifact

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"

	"mesh/internal/windowsauthenticode"
)

// VerifyBinary authenticates one in-memory observer executable against the
// exact output bytes and structural identity selected by the embedded policy.
func VerifyBinary(content []byte, arch, name string) error {
	policy, _, err := EmbeddedPolicy()
	if err != nil {
		return err
	}
	target, err := policy.Select(arch)
	if err != nil {
		return err
	}
	for _, entry := range target.Entries {
		if entry.Name != name {
			continue
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("observer executable %q bytes differ from the embedded policy", name)
		}
		return verifyBinary(content, entry, Target{OS: "linux", Arch: arch}, policy)
	}
	return fmt.Errorf("observer executable %q is not selected for linux/%s", name, arch)
}

// VerifyWindowsBinary authenticates one source-built Windows runtime PE
// against the exact layered Windows output lock.
func VerifyWindowsBinary(content []byte, arch, name string) error {
	target, _, err := selectWindowsTarget(arch)
	if err != nil {
		return err
	}
	policy, _, err := EmbeddedPolicy()
	if err != nil {
		return err
	}
	for _, entry := range target.Entries {
		if entry.Name != name {
			continue
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("Windows runtime executable %q bytes differ from the embedded policy", name)
		}
		return verifyBinary(content, entry, Target{OS: "windows", Arch: arch}, policy)
	}
	return fmt.Errorf("Windows runtime executable %q is not selected for windows/%s", name, arch)
}

// VerifySignedWindowsBinary proves that the only difference between a final
// Authenticode-bearing runtime PE and the exact reproducible Windows output
// lock is the allowed checksum field, certificate-directory entry, alignment
// padding, and sole appended certificate table. Native Windows verification
// remains responsible for trusting that signature and signer.
func VerifySignedWindowsBinary(content []byte, arch, name string) (windowsauthenticode.PEEnvelope, error) {
	target, _, err := selectWindowsTarget(arch)
	if err != nil {
		return windowsauthenticode.PEEnvelope{}, err
	}
	policy, _, err := EmbeddedPolicy()
	if err != nil {
		return windowsauthenticode.PEEnvelope{}, err
	}
	for _, entry := range target.Entries {
		if entry.Name != name {
			continue
		}
		unsigned, envelope, err := windowsauthenticode.ReconstructUnsignedPE(content, entry.Size, entry.SHA256)
		if err != nil {
			return windowsauthenticode.PEEnvelope{}, fmt.Errorf("reconstruct signed Windows runtime executable %q: %w", name, err)
		}
		if err := verifyBinary(unsigned, entry, Target{OS: "windows", Arch: arch}, policy); err != nil {
			return windowsauthenticode.PEEnvelope{}, err
		}
		return envelope, nil
	}
	return windowsauthenticode.PEEnvelope{}, fmt.Errorf("Windows runtime executable %q is not selected for windows/%s", name, arch)
}

// VerifyDarwinBinary authenticates one source-built Darwin runtime Mach-O
// against the exact layered Darwin output lock.
func VerifyDarwinBinary(content []byte, arch, name string) error {
	target, _, err := selectDarwinTarget(arch)
	if err != nil {
		return err
	}
	policy, _, err := EmbeddedPolicy()
	if err != nil {
		return err
	}
	for _, entry := range target.Entries {
		if entry.Name != name {
			continue
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("Darwin runtime executable %q bytes differ from the embedded policy", name)
		}
		return verifyBinary(content, entry, Target{OS: "darwin", Arch: arch}, policy)
	}
	return fmt.Errorf("Darwin runtime executable %q is not selected for darwin/%s", name, arch)
}

func verifyBinary(content []byte, entry EntryLock, target Target, policy Policy) error {
	if len(content) == 0 || int64(len(content)) > maximumBinarySize {
		return errors.New("observer executable size is outside policy")
	}
	reader := bytes.NewReader(content)
	if err := verifyExecutableContainer(reader, target); err != nil {
		return err
	}
	info, err := buildinfo.Read(reader)
	if err != nil {
		return fmt.Errorf("read observer Go build information: %w", err)
	}
	if info.Path != entry.MainPath || info.Main.Path != lockedModule || info.Main.Version != "(devel)" {
		return fmt.Errorf("observer main package/module/version is %q %q %q, want %q %q %q", info.Path, info.Main.Path, info.Main.Version, entry.MainPath, lockedModule, "(devel)")
	}
	if info.GoVersion != policy.Toolchain {
		return fmt.Errorf("observer Go toolchain is %q, want %q", info.GoVersion, policy.Toolchain)
	}
	if err := verifySecurityDependencies(info, entry, policy.SecurityDependencies); err != nil {
		return err
	}
	settings, err := uniqueSettings(info)
	if err != nil {
		return err
	}
	required := map[string]string{
		"GOOS":        target.OS,
		"GOARCH":      target.Arch,
		"CGO_ENABLED": "0",
		"-buildmode":  "exe",
		"-compiler":   "gc",
		"-trimpath":   "true",
	}
	if target.Arch == "amd64" {
		required["GOAMD64"] = "v1"
	} else {
		required["GOARM64"] = "v8.0"
	}
	for key, want := range required {
		if got, ok := settings[key]; !ok || got != want {
			return fmt.Errorf("observer Go build setting %q is %q (present=%t), want %q", key, got, ok, want)
		}
	}
	for _, key := range []string{"vcs", "vcs.revision", "vcs.time", "vcs.modified"} {
		if _, present := settings[key]; present {
			return fmt.Errorf("observer build unexpectedly records VCS setting %q", key)
		}
	}
	return nil
}

func verifyExecutableContainer(reader *bytes.Reader, target Target) error {
	switch target.OS {
	case "linux":
		parsed, err := elf.NewFile(reader)
		if err != nil {
			return fmt.Errorf("parse observer ELF: %w", err)
		}
		defer parsed.Close()
		wantMachine := elf.EM_X86_64
		if target.Arch == "arm64" {
			wantMachine = elf.EM_AARCH64
		}
		if parsed.Class != elf.ELFCLASS64 || parsed.Data != elf.ELFDATA2LSB || parsed.Type != elf.ET_EXEC || parsed.Machine != wantMachine {
			return fmt.Errorf("observer executable is not an ELF64 little-endian %s executable", target.Arch)
		}
		if parsed.Section(".interp") != nil {
			return errors.New("observer executable contains a dynamic interpreter")
		}
		if parsed.Section(".note.go.buildid") != nil {
			return errors.New("observer executable contains a Go build-ID note")
		}
		libraries, err := parsed.ImportedLibraries()
		if err != nil {
			return fmt.Errorf("inspect observer dynamic imports: %w", err)
		}
		if len(libraries) != 0 {
			return fmt.Errorf("observer executable imports dynamic libraries: %v", libraries)
		}
		return nil
	case "windows":
		parsed, err := pe.NewFile(reader)
		if err != nil {
			return fmt.Errorf("parse Windows runtime PE: %w", err)
		}
		defer parsed.Close()
		wantMachine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
		if target.Arch == "arm64" {
			wantMachine = pe.IMAGE_FILE_MACHINE_ARM64
		}
		optional, ok := parsed.OptionalHeader.(*pe.OptionalHeader64)
		if parsed.Machine != wantMachine || parsed.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 ||
			parsed.Characteristics&pe.IMAGE_FILE_DLL != 0 || !ok || optional.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_CUI {
			return fmt.Errorf("Windows runtime is not an exact PE32+ Windows CUI %s image", target.Arch)
		}
		return nil
	case "darwin":
		parsed, err := macho.NewFile(reader)
		if err != nil {
			return fmt.Errorf("parse Darwin runtime Mach-O: %w", err)
		}
		defer parsed.Close()
		wantCPU := macho.CpuAmd64
		if target.Arch == "arm64" {
			wantCPU = macho.CpuArm64
		}
		if parsed.Magic != macho.Magic64 || parsed.Cpu != wantCPU || parsed.Type != macho.TypeExec ||
			parsed.Flags&macho.FlagPIE == 0 || parsed.Flags&macho.FlagAllowStackExecution != 0 {
			return fmt.Errorf("Darwin runtime is not an exact 64-bit PIE %s Mach-O executable", target.Arch)
		}
		return nil
	default:
		return fmt.Errorf("unsupported source-built runtime target %s/%s", target.OS, target.Arch)
	}
}

func verifySecurityDependencies(info *debug.BuildInfo, entry EntryLock, locked []DependencyLock) error {
	actual := make(map[string]*debug.Module, len(info.Deps))
	for _, dependency := range info.Deps {
		if _, duplicate := actual[dependency.Path]; duplicate {
			return fmt.Errorf("duplicate observer dependency %q", dependency.Path)
		}
		actual[dependency.Path] = dependency
	}
	required := map[string]bool{
		"golang.org/x/crypto": true,
		"golang.org/x/sys":    true,
		"golang.org/x/term":   true,
	}
	if entry.Name == "nebula" {
		required["golang.org/x/net"] = true
	}
	for _, expected := range locked {
		dependency, present := actual[expected.Path]
		if !present {
			if required[expected.Path] {
				return fmt.Errorf("observer executable is missing required security dependency %q", expected.Path)
			}
			continue
		}
		if dependency.Version != expected.Version || dependency.Sum != expected.Sum || dependency.Replace != nil {
			return fmt.Errorf("observer security dependency %q is %q %q replaced=%t, want %q %q without replacement", expected.Path, dependency.Version, dependency.Sum, dependency.Replace != nil, expected.Version, expected.Sum)
		}
	}
	return nil
}

func uniqueSettings(info *debug.BuildInfo) (map[string]string, error) {
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return nil, fmt.Errorf("duplicate observer Go build setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	return settings, nil
}
