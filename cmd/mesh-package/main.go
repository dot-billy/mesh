// mesh-package builds deterministic, local release artifacts. It never creates
// a signature, downloads, installs, replaces an existing artifact, or mutates
// a service.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"mesh/internal/darwinbundle"
	"mesh/internal/linuxbundle"
	"mesh/internal/verifierbundle"
	"mesh/internal/windowsbundle"
)

type linuxBuilder func(linuxbundle.BuildOptions) (linuxbundle.BuildResult, error)
type windowsBuilder func(windowsbundle.BuildOptions) (windowsbundle.BuildResult, error)
type windowsSignedBuilder func(windowsbundle.SignedBuildOptions) (windowsbundle.BuildResult, error)
type darwinBuilder func(darwinbundle.BuildOptions) (darwinbundle.BuildResult, error)
type verifierBuilder func(verifierbundle.BuildOptions) (verifierbundle.BuildResult, error)

func main() {
	if err := runWithPlatformBuilders(os.Args[1:], os.Stdout, linuxbundle.Build, windowsbundle.Build, darwinbundle.Build, verifierbundle.Build, windowsbundle.BuildSigned); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-package:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer, builder linuxBuilder) error {
	return runWithAllBuilders(args, output, builder, nil, nil)
}

func runWithBuilders(args []string, output io.Writer, linux linuxBuilder, windows windowsBuilder) error {
	return runWithAllBuilders(args, output, linux, windows, nil)
}

func runWithAllBuilders(args []string, output io.Writer, linux linuxBuilder, windows windowsBuilder, verifier verifierBuilder) error {
	return runWithPlatformBuilders(args, output, linux, windows, nil, verifier, nil)
}

func runWithPlatformBuilders(args []string, output io.Writer, linux linuxBuilder, windows windowsBuilder, darwin darwinBuilder, verifier verifierBuilder, windowsSigned windowsSignedBuilder) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "build-linux":
		return buildLinux(args, output, linux)
	case "inspect-linux":
		return inspectLinux(args, output)
	case "inspect-windows":
		return inspectWindows(args, output)
	case "inspect-darwin":
		return inspectDarwin(args, output)
	case "build-windows":
		return buildWindows(args, output, windows)
	case "build-windows-signed":
		return buildWindowsSigned(args, output, windowsSigned)
	case "build-darwin":
		return buildDarwin(args, output, darwin)
	case "build-bootstrap-verifier":
		return buildBootstrapVerifier(args, output, verifier)
	default:
		return usageError()
	}
}

func inspectDarwin(args []string, output io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("inspect-darwin requires a Linux verification host")
	}
	flags := flag.NewFlagSet("inspect-darwin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact", "", "clean absolute canonical Darwin staging bundle candidate")
	outputDirectory := flags.String("output-dir", "", "existing empty real 0700 staging directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 ||
		strings.TrimSpace(*artifact) == "" || strings.TrimSpace(*outputDirectory) == "" {
		return fmt.Errorf("inspect-darwin requires --artifact and --output-dir with no positional arguments")
	}
	inspection, err := darwinbundle.InspectCandidateFile(strings.TrimSpace(*artifact), strings.TrimSpace(*outputDirectory))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(inspection)
}

func inspectWindows(args []string, output io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("inspect-windows requires a Linux verification host")
	}
	flags := flag.NewFlagSet("inspect-windows", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact", "", "clean absolute canonical Windows staging bundle candidate")
	outputDirectory := flags.String("output-dir", "", "existing empty real 0700 staging directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 ||
		strings.TrimSpace(*artifact) == "" || strings.TrimSpace(*outputDirectory) == "" {
		return fmt.Errorf("inspect-windows requires --artifact and --output-dir with no positional arguments")
	}
	inspection, err := windowsbundle.InspectCandidateFile(strings.TrimSpace(*artifact), strings.TrimSpace(*outputDirectory))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(inspection)
}

func inspectLinux(args []string, output io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("inspect-linux requires a Linux verification host")
	}
	flags := flag.NewFlagSet("inspect-linux", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact", "", "clean absolute canonical Linux bundle candidate")
	outputDirectory := flags.String("output-dir", "", "existing empty real 0700 staging directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 ||
		strings.TrimSpace(*artifact) == "" || strings.TrimSpace(*outputDirectory) == "" {
		return fmt.Errorf("inspect-linux requires --artifact and --output-dir with no positional arguments")
	}
	inspection, err := linuxbundle.InspectCandidateFile(strings.TrimSpace(*artifact), strings.TrimSpace(*outputDirectory))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(inspection)
}

func buildBootstrapVerifier(args []string, output io.Writer, builder verifierBuilder) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("build-bootstrap-verifier requires a Linux packaging host")
	}
	if builder == nil {
		return fmt.Errorf("bootstrap verifier bundle builder is unavailable")
	}
	flags := flag.NewFlagSet("build-bootstrap-verifier", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.String("version", "", "canonical Mesh release SemVer")
	commit := flags.String("commit", "", "40-character lowercase source commit")
	sourceDateEpoch := flags.String("source-date-epoch", "", "canonical decimal SOURCE_DATE_EPOCH")
	securityFloor := flags.String("security-floor", "", "positive decimal security floor")
	platformOS := flags.String("os", "linux", "target operating system (linux or windows)")
	arch := flags.String("arch", "", "target architecture (amd64 or arm64)")
	verifierPath := flags.String("verifier", "", "production mesh-bootstrap-verify executable")
	outputPath := flags.String("output", "", "new uncompressed USTAR output path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("build-bootstrap-verifier does not accept positional arguments")
	}
	values := []struct {
		name, value string
	}{
		{"--version", *version}, {"--commit", *commit}, {"--source-date-epoch", *sourceDateEpoch},
		{"--security-floor", *securityFloor}, {"--arch", *arch}, {"--verifier", *verifierPath}, {"--output", *outputPath},
	}
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	epoch, err := parseCanonicalInt64(*sourceDateEpoch, true)
	if err != nil {
		return fmt.Errorf("--source-date-epoch: %w", err)
	}
	floor, err := parseCanonicalUint64(*securityFloor, false)
	if err != nil {
		return fmt.Errorf("--security-floor: %w", err)
	}
	result, err := builder(verifierbundle.BuildOptions{
		Version: strings.TrimSpace(*version), Commit: strings.TrimSpace(*commit),
		SourceDateEpoch: epoch, SecurityFloor: floor, OS: strings.TrimSpace(*platformOS), Arch: strings.TrimSpace(*arch),
		VerifierPath: strings.TrimSpace(*verifierPath), OutputPath: strings.TrimSpace(*outputPath),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Built canonical standalone bootstrap verifier bundle %s for %s/%s (%d bytes, SHA-256 %s, package.json SHA-256 %s). The artifact was not signed, installed, or trusted; authenticate its exact SHA-256 through the independent operator channel.\n", result.OutputPath, result.Package.Target.OS, result.Package.Target.Arch, result.Size, result.SHA256, result.PackageJSONSHA256)
	return err
}

func buildLinux(args []string, output io.Writer, builder linuxBuilder) error {
	if builder == nil {
		return fmt.Errorf("Linux bundle builder is unavailable")
	}
	flags := flag.NewFlagSet("build-linux", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.String("version", "", "canonical Mesh release SemVer")
	commit := flags.String("commit", "", "40-character lowercase source commit")
	sourceDateEpoch := flags.String("source-date-epoch", "", "canonical decimal SOURCE_DATE_EPOCH")
	securityFloor := flags.String("security-floor", "", "positive decimal security floor")
	arch := flags.String("arch", "", "Linux target architecture (amd64 or arm64)")
	meshInstall := flags.String("mesh-install", "", "local mesh-install executable")
	meshctl := flags.String("meshctl", "", "local meshctl executable")
	nebulaDirectory := flags.String("nebula-dir", "", "exact observer-build-locked Nebula staging directory")
	outputPath := flags.String("output", "", "new uncompressed USTAR output path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("build-linux does not accept positional arguments")
	}
	values := []struct {
		name  string
		value string
	}{
		{"--version", *version}, {"--commit", *commit}, {"--source-date-epoch", *sourceDateEpoch},
		{"--security-floor", *securityFloor}, {"--arch", *arch}, {"--mesh-install", *meshInstall},
		{"--meshctl", *meshctl}, {"--nebula-dir", *nebulaDirectory}, {"--output", *outputPath},
	}
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	epoch, err := parseCanonicalInt64(*sourceDateEpoch, true)
	if err != nil {
		return fmt.Errorf("--source-date-epoch: %w", err)
	}
	floor, err := parseCanonicalUint64(*securityFloor, false)
	if err != nil {
		return fmt.Errorf("--security-floor: %w", err)
	}
	result, err := builder(linuxbundle.BuildOptions{
		Version: strings.TrimSpace(*version), Commit: strings.TrimSpace(*commit),
		SourceDateEpoch: epoch, SecurityFloor: floor, Arch: strings.TrimSpace(*arch),
		MeshInstallPath: strings.TrimSpace(*meshInstall), MeshctlPath: strings.TrimSpace(*meshctl),
		NebulaDirectory: strings.TrimSpace(*nebulaDirectory), OutputPath: strings.TrimSpace(*outputPath),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Built canonical Linux node bundle %s for linux/%s (%d bytes, SHA-256 %s, package.json SHA-256 %s). No software was installed or started.\n", result.OutputPath, result.Package.Target.Arch, result.Size, result.SHA256, result.PackageJSONSHA256)
	return err
}

func buildWindows(args []string, output io.Writer, builder windowsBuilder) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("build-windows requires a Linux packaging host for exact POSIX staged-tree and publication-mode verification")
	}
	if builder == nil {
		return fmt.Errorf("Windows staging-bundle builder is unavailable")
	}
	flags := flag.NewFlagSet("build-windows", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.String("version", "", "canonical Mesh release SemVer")
	commit := flags.String("commit", "", "40-character lowercase source commit")
	sourceDateEpoch := flags.String("source-date-epoch", "", "canonical decimal SOURCE_DATE_EPOCH")
	securityFloor := flags.String("security-floor", "", "positive decimal security floor")
	arch := flags.String("arch", "", "Windows target architecture (amd64 or arm64)")
	meshctl := flags.String("meshctl", "", "local Windows meshctl executable")
	nebulaDirectory := flags.String("nebula-dir", "", "exact lock-verified Windows Nebula staging directory")
	nebulaRuntimeDirectory := flags.String("nebula-runtime-dir", "", "exact source-built security-patched Windows Nebula runtime stage")
	outputPath := flags.String("output", "", "new uncompressed USTAR output path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("build-windows does not accept positional arguments")
	}
	values := []struct {
		name  string
		value string
	}{
		{"--version", *version}, {"--commit", *commit}, {"--source-date-epoch", *sourceDateEpoch},
		{"--security-floor", *securityFloor}, {"--arch", *arch}, {"--meshctl", *meshctl},
		{"--nebula-dir", *nebulaDirectory}, {"--nebula-runtime-dir", *nebulaRuntimeDirectory}, {"--output", *outputPath},
	}
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	epoch, err := parseCanonicalInt64(*sourceDateEpoch, true)
	if err != nil {
		return fmt.Errorf("--source-date-epoch: %w", err)
	}
	floor, err := parseCanonicalUint64(*securityFloor, false)
	if err != nil {
		return fmt.Errorf("--security-floor: %w", err)
	}
	result, err := builder(windowsbundle.BuildOptions{
		Version: strings.TrimSpace(*version), Commit: strings.TrimSpace(*commit),
		SourceDateEpoch: epoch, SecurityFloor: floor, Arch: strings.TrimSpace(*arch),
		MeshctlPath: strings.TrimSpace(*meshctl), NebulaDirectory: strings.TrimSpace(*nebulaDirectory),
		NebulaRuntimeDirectory: strings.TrimSpace(*nebulaRuntimeDirectory),
		OutputPath:             strings.TrimSpace(*outputPath),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Built canonical Windows node staging bundle %s for windows/%s (%d bytes, SHA-256 %s, package.json SHA-256 %s). No software was installed, no service was created or started, and no DACL was applied.\n", result.OutputPath, result.Package.Target.Arch, result.Size, result.SHA256, result.PackageJSONSHA256)
	return err
}

func buildWindowsSigned(args []string, output io.Writer, builder windowsSignedBuilder) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("build-windows-signed requires a Linux packaging host for exact artifact verification and publication")
	}
	if builder == nil {
		return fmt.Errorf("signed Windows bundle builder is unavailable")
	}
	flags := flag.NewFlagSet("build-windows-signed", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	unsignedBundle := flags.String("unsigned-bundle", "", "authenticated unsigned Windows staging bundle v2")
	meshctl := flags.String("meshctl", "", "signed meshctl.exe")
	nebula := flags.String("nebula", "", "signed nebula.exe")
	nebulaCert := flags.String("nebula-cert", "", "signed nebula-cert.exe")
	authenticodeReceipt := flags.String("authenticode-receipt", "", "fresh native Windows Authenticode receipt")
	expectedPolicySHA256 := flags.String("expected-authenticode-policy-sha256", "", "independently authenticated compiled Authenticode policy SHA-256")
	outputPath := flags.String("output", "", "new final signed uncompressed USTAR output path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("build-windows-signed does not accept positional arguments")
	}
	values := []struct {
		name  string
		value string
	}{
		{"--unsigned-bundle", *unsignedBundle}, {"--meshctl", *meshctl}, {"--nebula", *nebula},
		{"--nebula-cert", *nebulaCert}, {"--authenticode-receipt", *authenticodeReceipt},
		{"--expected-authenticode-policy-sha256", *expectedPolicySHA256}, {"--output", *outputPath},
	}
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	result, err := builder(windowsbundle.SignedBuildOptions{
		UnsignedBundlePath:      strings.TrimSpace(*unsignedBundle),
		SignedMeshctlPath:       strings.TrimSpace(*meshctl),
		SignedNebulaPath:        strings.TrimSpace(*nebula),
		SignedNebulaCertPath:    strings.TrimSpace(*nebulaCert),
		AuthenticodeReceiptPath: strings.TrimSpace(*authenticodeReceipt),
		ExpectedPolicySHA256:    strings.TrimSpace(*expectedPolicySHA256),
		OutputPath:              strings.TrimSpace(*outputPath),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Built final signed Windows node bundle %s for windows/%s (%d bytes, SHA-256 %s, package.json SHA-256 %s). Every PE is bound to the native Authenticode receipt; no software was installed and no service or DACL was changed.\n", result.OutputPath, result.Package.Target.Arch, result.Size, result.SHA256, result.PackageJSONSHA256)
	return err
}

func buildDarwin(args []string, output io.Writer, builder darwinBuilder) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("build-darwin requires a Linux packaging host for exact POSIX staged-tree and publication-mode verification")
	}
	if builder == nil {
		return fmt.Errorf("Darwin staging-bundle builder is unavailable")
	}
	flags := flag.NewFlagSet("build-darwin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.String("version", "", "canonical Mesh release SemVer")
	commit := flags.String("commit", "", "40-character lowercase source commit")
	sourceDateEpoch := flags.String("source-date-epoch", "", "canonical decimal SOURCE_DATE_EPOCH")
	securityFloor := flags.String("security-floor", "", "positive decimal security floor")
	arch := flags.String("arch", "", "Darwin target architecture (amd64 or arm64)")
	meshctl := flags.String("meshctl", "", "local Darwin meshctl executable")
	nebulaRuntimeDirectory := flags.String("nebula-runtime-dir", "", "exact source-built security-patched Darwin Nebula runtime stage")
	outputPath := flags.String("output", "", "new uncompressed USTAR output path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("build-darwin does not accept positional arguments")
	}
	values := []struct {
		name  string
		value string
	}{
		{"--version", *version}, {"--commit", *commit}, {"--source-date-epoch", *sourceDateEpoch},
		{"--security-floor", *securityFloor}, {"--arch", *arch}, {"--meshctl", *meshctl},
		{"--nebula-runtime-dir", *nebulaRuntimeDirectory}, {"--output", *outputPath},
	}
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	epoch, err := parseCanonicalInt64(*sourceDateEpoch, true)
	if err != nil {
		return fmt.Errorf("--source-date-epoch: %w", err)
	}
	floor, err := parseCanonicalUint64(*securityFloor, false)
	if err != nil {
		return fmt.Errorf("--security-floor: %w", err)
	}
	result, err := builder(darwinbundle.BuildOptions{
		Version: strings.TrimSpace(*version), Commit: strings.TrimSpace(*commit),
		SourceDateEpoch: epoch, SecurityFloor: floor, Arch: strings.TrimSpace(*arch),
		MeshctlPath: strings.TrimSpace(*meshctl), NebulaRuntimeDirectory: strings.TrimSpace(*nebulaRuntimeDirectory),
		OutputPath: strings.TrimSpace(*outputPath),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Built canonical Darwin node staging bundle %s for darwin/%s (%d bytes, SHA-256 %s, package.json SHA-256 %s). No software was installed, no launchd job was created or started, no extended ACL was applied, and no codesigning or notarization claim was made.\n", result.OutputPath, result.Package.Target.Arch, result.Size, result.SHA256, result.PackageJSONSHA256)
	return err
}

func usageError() error {
	return fmt.Errorf("usage: mesh-package inspect-linux --artifact <absolute-bundle.tar> --output-dir <empty-0700-directory> | mesh-package inspect-windows --artifact <absolute-bundle.tar> --output-dir <empty-0700-directory> | mesh-package inspect-darwin --artifact <absolute-bundle.tar> --output-dir <empty-0700-directory> | mesh-package build-linux --version <semver> --commit <40-lowerhex> --source-date-epoch <seconds> --security-floor <positive> --arch <amd64|arm64> --mesh-install <path> --meshctl <path> --nebula-dir <path> --output <new.tar> | mesh-package build-windows --version <semver> --commit <40-lowerhex> --source-date-epoch <seconds> --security-floor <positive> --arch <amd64|arm64> --meshctl <path> --nebula-dir <path> --nebula-runtime-dir <path> --output <new.tar> | mesh-package build-windows-signed --unsigned-bundle <v2.tar> --meshctl <signed.exe> --nebula <signed.exe> --nebula-cert <signed.exe> --authenticode-receipt <receipt.json> --expected-authenticode-policy-sha256 <sha256> --output <new-v3.tar> | mesh-package build-darwin --version <semver> --commit <40-lowerhex> --source-date-epoch <seconds> --security-floor <positive> --arch <amd64|arm64> --meshctl <path> --nebula-runtime-dir <path> --output <new.tar> | mesh-package build-bootstrap-verifier --version <semver> --commit <40-lowerhex> --source-date-epoch <seconds> --security-floor <positive> --os <linux|windows> --arch <amd64|arm64> --verifier <path> --output <new.tar>")
}

func parseCanonicalInt64(value string, allowZero bool) (int64, error) {
	value = strings.TrimSpace(value)
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != value || parsed < 0 || (!allowZero && parsed == 0) {
		return 0, fmt.Errorf("must be a canonical non-negative decimal integer")
	}
	return parsed, nil
}

func parseCanonicalUint64(value string, allowZero bool) (uint64, error) {
	value = strings.TrimSpace(value)
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value || (!allowZero && parsed == 0) {
		return 0, fmt.Errorf("must be a canonical positive decimal integer")
	}
	return parsed, nil
}
