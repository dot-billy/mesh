package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

const MinimumNebulaVersion = "1.10.3"

var semanticVersionPattern = regexp.MustCompile(`(^|[^0-9])v?([0-9]+)\.([0-9]+)\.([0-9]+)($|[^0-9])`)

// CommandRunner exists to make bundle validation deterministic in tests. The
// production implementation intentionally discards validator command output so
// configuration and local path details cannot leak into service logs.
type CommandRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
	RunQuiet(context.Context, string, ...string) error
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("command %s failed: %w", name, err)
	}
	return output, nil
}

func (ExecCommandRunner) RunQuiet(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command %s failed: %w", name, err)
	}
	return nil
}

type BundleValidator struct {
	NebulaBinary     string
	NebulaCertBinary string
	Runner           CommandRunner
}

type CertificateDetails struct {
	Fingerprint string
	ExpiresAt   time.Time
}

func (v BundleValidator) Validate(ctx context.Context, bundleDir, configPath string) (CertificateDetails, error) {
	nebula := v.NebulaBinary
	if nebula == "" {
		nebula = "nebula"
	}
	nebulaCert := v.NebulaCertBinary
	if nebulaCert == "" {
		nebulaCert = "nebula-cert"
	}
	runner := v.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	versionOutput, err := runner.Output(ctx, nebula, "-version")
	if err != nil {
		return CertificateDetails{}, fmt.Errorf("inspect Nebula version: %w", err)
	}
	if err := EnforceMinimumNebulaVersion(string(versionOutput)); err != nil {
		return CertificateDetails{}, err
	}
	if err := runner.RunQuiet(ctx, nebulaCert, "verify", "-ca", filepath.Join(bundleDir, "ca.crt"), "-crt", filepath.Join(bundleDir, "host.crt")); err != nil {
		return CertificateDetails{}, fmt.Errorf("verify Nebula certificate: %w", err)
	}
	if err := runner.RunQuiet(ctx, nebula, "-test", "-config", configPath); err != nil {
		return CertificateDetails{}, fmt.Errorf("validate Nebula configuration: %w", err)
	}
	certificateOutput, err := runner.Output(ctx, nebulaCert, "print", "-json", "-path", filepath.Join(bundleDir, "host.crt"))
	if err != nil {
		return CertificateDetails{}, fmt.Errorf("inspect verified Nebula certificate: %w", err)
	}
	details, err := parseCertificateDetails(certificateOutput)
	if err != nil {
		return CertificateDetails{}, err
	}
	return details, nil
}

func parseCertificateDetails(output []byte) (CertificateDetails, error) {
	var certificates []struct {
		Fingerprint string `json:"fingerprint"`
		Details     struct {
			NotAfter time.Time `json:"notAfter"`
		} `json:"details"`
	}
	if err := json.Unmarshal(output, &certificates); err != nil || len(certificates) != 1 {
		return CertificateDetails{}, errors.New("could not inspect verified Nebula certificate")
	}
	if !validDigest(certificates[0].Fingerprint) || certificates[0].Details.NotAfter.IsZero() {
		return CertificateDetails{}, errors.New("verified Nebula certificate metadata is invalid")
	}
	return CertificateDetails{Fingerprint: certificates[0].Fingerprint, ExpiresAt: certificates[0].Details.NotAfter}, nil
}

func EnforceMinimumNebulaVersion(output string) error {
	version, err := parseSemanticVersion(output)
	if err != nil {
		return err
	}
	minimum := [3]int{1, 10, 3}
	for index := range version {
		if version[index] > minimum[index] {
			return nil
		}
		if version[index] < minimum[index] {
			return fmt.Errorf("Nebula %d.%d.%d is unsupported; version %s or newer is required", version[0], version[1], version[2], MinimumNebulaVersion)
		}
	}
	return nil
}

// ReportedNebulaVersion returns the canonical semantic version reported by a
// Nebula executable. Callers that depend on both nebula and nebula-cert use
// this value to prove that the two executables report one exact runtime
// version before any credential-bearing operation begins.
func ReportedNebulaVersion(output string) (string, error) {
	version, err := parseSemanticVersion(output)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d", version[0], version[1], version[2]), nil
}

func parseSemanticVersion(output string) ([3]int, error) {
	match := semanticVersionPattern.FindStringSubmatch(output)
	if len(match) != 6 {
		return [3]int{}, errors.New("could not determine Nebula semantic version")
	}
	var version [3]int
	for index := range version {
		part, err := strconv.Atoi(match[index+2])
		if err != nil {
			return [3]int{}, errors.New("could not determine Nebula semantic version")
		}
		version[index] = part
	}
	return version, nil
}
