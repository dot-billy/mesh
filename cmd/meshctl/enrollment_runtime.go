package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"mesh/internal/buildinfo"
	"mesh/internal/nodeagent"
)

type enrollmentRuntime struct {
	nebulaBinary     string
	nebulaCertBinary string
	version          string
}

var installedReleaseIDPattern = regexp.MustCompile(`^(?:s[0-9]{20}|e[0-9]{20}-s[0-9]{20})-r[0-9a-f]{16}-a[0-9a-f]{16}$`)

func prepareEnrollmentRuntime(ctx context.Context, nebula, nebulaCert string, runner nodeagent.CommandRunner) (enrollmentRuntime, error) {
	executable, err := os.Executable()
	if err != nil {
		return enrollmentRuntime{}, runtimePrerequisiteError(fmt.Errorf("resolve meshctl executable: %w", err))
	}
	requireInstalledRelease := buildinfo.Identity != buildinfo.DevelopmentIdentity
	if requireInstalledRelease {
		if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
			return enrollmentRuntime{}, runtimePrerequisiteError(fmt.Errorf("production enrollment has no supported runtime installer for %s", runtime.GOOS))
		}
		if _, err := buildinfo.CurrentProduction(); err != nil {
			return enrollmentRuntime{}, runtimePrerequisiteError(fmt.Errorf("authenticate meshctl build identity: %w", err))
		}
	}
	prepared, err := inspectEnrollmentRuntime(ctx, nebula, nebulaCert, executable, requireInstalledRelease, runner)
	if err != nil {
		return enrollmentRuntime{}, runtimePrerequisiteError(err)
	}
	if requireInstalledRelease {
		if err := validateInstalledRuntimeDirectory(filepath.Dir(prepared.nebulaBinary)); err != nil {
			return enrollmentRuntime{}, runtimePrerequisiteError(err)
		}
	}
	return prepared, nil
}

func inspectEnrollmentRuntime(ctx context.Context, nebula, nebulaCert, meshctlExecutable string, requireInstalledRelease bool, runner nodeagent.CommandRunner) (enrollmentRuntime, error) {
	if ctx == nil {
		return enrollmentRuntime{}, errors.New("runtime inspection context is required")
	}
	if runner == nil {
		runner = nodeagent.ExecCommandRunner{}
	}
	nebulaPath, err := resolveEnrollmentExecutable(nebula, "nebula")
	if err != nil {
		return enrollmentRuntime{}, err
	}
	nebulaCertPath, err := resolveEnrollmentExecutable(nebulaCert, "nebula-cert")
	if err != nil {
		return enrollmentRuntime{}, err
	}
	if samePath(nebulaPath, nebulaCertPath) {
		return enrollmentRuntime{}, errors.New("nebula and nebula-cert resolve to the same executable")
	}

	nebulaOutput, err := runner.Output(ctx, nebulaPath, "-version")
	if err != nil {
		return enrollmentRuntime{}, fmt.Errorf("inspect nebula version: %w", err)
	}
	nebulaVersion, err := nodeagent.ReportedNebulaVersion(string(nebulaOutput))
	if err != nil {
		return enrollmentRuntime{}, fmt.Errorf("inspect nebula version: %w", err)
	}
	if err := nodeagent.EnforceMinimumNebulaVersion(nebulaVersion); err != nil {
		return enrollmentRuntime{}, err
	}

	certOutput, err := runner.Output(ctx, nebulaCertPath, "-version")
	if err != nil {
		return enrollmentRuntime{}, fmt.Errorf("inspect nebula-cert version: %w", err)
	}
	certVersion, err := nodeagent.ReportedNebulaVersion(string(certOutput))
	if err != nil {
		return enrollmentRuntime{}, fmt.Errorf("inspect nebula-cert version: %w", err)
	}
	if err := nodeagent.EnforceMinimumNebulaVersion(certVersion); err != nil {
		return enrollmentRuntime{}, fmt.Errorf("nebula-cert: %w", err)
	}
	if nebulaVersion != certVersion {
		return enrollmentRuntime{}, fmt.Errorf("nebula reports version %s but nebula-cert reports %s", nebulaVersion, certVersion)
	}

	if requireInstalledRelease {
		meshctlPath, err := resolveEnrollmentExecutable(meshctlExecutable, "meshctl")
		if err != nil {
			return enrollmentRuntime{}, err
		}
		releaseDirectory := filepath.Dir(meshctlPath)
		if !samePath(filepath.Dir(nebulaPath), releaseDirectory) || !samePath(filepath.Dir(nebulaCertPath), releaseDirectory) {
			return enrollmentRuntime{}, errors.New("nebula, nebula-cert, and meshctl are not from one authenticated installed release")
		}
	}
	return enrollmentRuntime{
		nebulaBinary: nebulaPath, nebulaCertBinary: nebulaCertPath, version: nebulaVersion,
	}, nil
}

func resolveEnrollmentExecutable(value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s executable is empty", label)
	}
	resolved, err := exec.LookPath(value)
	if err != nil {
		return "", fmt.Errorf("%s executable is not installed or executable: %w", label, err)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve %s executable: %w", label, err)
	}
	absolute = filepath.Clean(absolute)
	resolved, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve %s installed executable: %w", label, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve %s installed executable: %w", label, err)
	}
	resolved = filepath.Clean(resolved)
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s executable is not a real regular file", label)
	}
	return resolved, nil
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func runtimePrerequisiteError(cause error) error {
	return fmt.Errorf("Nebula runtime prerequisite failed before enrollment: %w. %s", cause, runtimeInstallGuidance())
}

func runtimeInstallGuidance() string {
	switch runtime.GOOS {
	case "linux":
		return "Authenticate mesh-install independently, then run `mesh-install install-online EXACT_BUNDLE_URL` or `mesh-install install ABSOLUTE_SNAPSHOT_DIR`; rerun enrollment with the installed /usr/local/bin/nebula and /usr/local/bin/nebula-cert"
	case "windows":
		return "Authenticate mesh-install-windows.exe independently, then run `mesh-install-windows.exe install-online EXACT_BUNDLE_URL` or `mesh-install-windows.exe install ABSOLUTE_PRIVATE_SNAPSHOT_DIR`; rerun enrollment with the installed runtime pair"
	default:
		return "Install one independently authenticated Mesh release containing meshctl, nebula, and nebula-cert for this operating system, or use the signed offline package path; do not download an upstream moving latest release"
	}
}
