//go:build darwin

package darwininstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mesh/internal/nodeagent"
)

const (
	ProductionDarwinAgentStatePath       = "/private/var/db/mesh-agent/state.json"
	ProductionDarwinAgentOutputDirectory = "/private/var/db/mesh-agent/runtime"
	darwinEnrollmentValidationTimeout    = 2 * time.Minute
)

// validateProductionDarwinEnrollment proves that enrollment completed into
// the exact launchd-owned state/output paths before the installer can open its
// persistent runtime gate. It performs no network operation and mutates no
// enrollment or bundle state.
func validateProductionDarwinEnrollment(ctx context.Context, authority AuthenticatedDarwinRelease) error {
	if ctx == nil {
		return errors.New("Darwin enrollment validation requires a context")
	}
	store, err := nodeagent.NewStateStore(ProductionDarwinAgentStatePath)
	if err != nil {
		return fmt.Errorf("open production Darwin agent state: %w", err)
	}
	state, err := store.Load()
	if err != nil {
		return fmt.Errorf("load production Darwin agent state: %w", err)
	}
	if _, err := store.LoadProvisionalEnrollment(); err == nil {
		return errors.New("production Darwin enrollment journal remains after enrollment")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect production Darwin enrollment journal: %w", err)
	}
	privateKey, publicKey, err := store.LoadRecoveryKeyPair()
	if err != nil {
		return fmt.Errorf("load production Darwin recovery keypair: %w", err)
	}
	releaseRoot := filepath.Join(ProductionReleasesRoot, authority.InstalledID)
	nebula := filepath.Join(releaseRoot, "bin", "nebula")
	nebulaCert := filepath.Join(releaseRoot, "bin", "nebula-cert")
	runner := darwinInstallerValidationRunner{nebula: nebula, nebulaCert: nebulaCert}
	validator := nodeagent.BundleValidator{
		NebulaBinary: nebula, NebulaCertBinary: nebulaCert, Runner: runner,
	}
	validationContext, cancel := context.WithTimeout(ctx, darwinEnrollmentValidationTimeout)
	defer cancel()
	bundle, err := (&nodeagent.Activator{
		OutputDir: ProductionDarwinAgentOutputDirectory,
		NodeID:    state.NodeID, NetworkID: state.NetworkID,
		ConfigSigningPublicKey: state.ConfigSigningPublicKey,
		CACertificateSHA256:    state.CACertificateSHA256,
		PublicKeyHash:          state.PublicKeyHash,
		Validator:              validator,
	}).CurrentBundle(validationContext)
	if err != nil {
		return fmt.Errorf("authenticate production Darwin enrolled bundle: %w", err)
	}
	if bundle.PrivateKey != privateKey || bundle.PublicKey != publicKey {
		return errors.New("production Darwin recovery keypair differs from the active enrolled bundle")
	}
	return validateProductionDarwinEnrollmentBinding(authority, state, bundle, time.Now().UTC())
}

func validateProductionDarwinEnrollmentBinding(authority AuthenticatedDarwinRelease, state nodeagent.State, bundle nodeagent.Bundle, now time.Time) error {
	if err := authority.Validate(); err != nil {
		return err
	}
	if err := state.Validate(); err != nil {
		return fmt.Errorf("production Darwin agent state: %w", err)
	}
	if now.IsZero() {
		return errors.New("Darwin enrollment validation time is required")
	}
	if state.OutputDir != ProductionDarwinAgentOutputDirectory {
		return errors.New("production Darwin agent output directory differs from the fixed launchd contract")
	}
	if uint64(state.Version) < authority.AgentStateReadMin || uint64(state.Version) > authority.AgentStateReadMax {
		return errors.New("production Darwin agent state schema is outside the active release read range")
	}
	if state.PendingBearer != "" || state.PendingRecoveryToken != "" || state.PendingRecoveryAllowsGenerationAdvance {
		return errors.New("production Darwin agent recovery is unfinished")
	}
	if state.AppliedConfigRevision < 1 || state.AppliedConfigRevision != bundle.Revision ||
		state.AppliedConfigSHA256 != bundle.Digest ||
		state.NodeID != bundle.NodeID || state.NetworkID != bundle.NetworkID ||
		state.PublicKeyHash != bundle.PublicKeyHash ||
		state.CACertificateSHA256 != bundle.CACertificateSHA256 ||
		state.CertificateGeneration != bundle.CertificateGeneration ||
		state.CertificateFingerprint != bundle.CertificateFingerprint ||
		!state.CertificateExpiresAt.Equal(bundle.CertificateExpiresAt) ||
		!state.CertificateRenewAfter.Equal(bundle.CertificateRenewAfter) {
		return errors.New("production Darwin agent state differs from its authenticated active bundle")
	}
	if state.LastSuccessfulConfigAt.IsZero() {
		return errors.New("production Darwin enrollment has no successful signed-config confirmation")
	}
	if !bundle.CertificateExpiresAt.After(now) {
		return errors.New("production Darwin enrolled certificate is expired")
	}
	if !state.AgentCredentialExpiresAt.After(now) {
		return errors.New("production Darwin agent credential is expired")
	}
	return nil
}

type darwinInstallerValidationRunner struct {
	nebula     string
	nebulaCert string
}

func (runner darwinInstallerValidationRunner) Output(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	if err := runner.validate(name, arguments, true); err != nil {
		return nil, err
	}
	return runner.run(ctx, name, arguments, true)
}

func (runner darwinInstallerValidationRunner) RunQuiet(ctx context.Context, name string, arguments ...string) error {
	if err := runner.validate(name, arguments, false); err != nil {
		return err
	}
	_, err := runner.run(ctx, name, arguments, false)
	return err
}

func (runner darwinInstallerValidationRunner) validate(name string, arguments []string, returnsOutput bool) error {
	switch {
	case name == runner.nebula && returnsOutput && sameStrings(arguments, []string{"-version"}):
		return nil
	case name == runner.nebula && !returnsOutput && len(arguments) == 3 &&
		arguments[0] == "-test" && arguments[1] == "-config" &&
		validDarwinEnrolledBundleFile(arguments[2], "config.yml"):
		return nil
	case name == runner.nebulaCert && !returnsOutput && len(arguments) == 5 &&
		arguments[0] == "verify" && arguments[1] == "-ca" && arguments[3] == "-crt" &&
		validDarwinEnrolledBundleFile(arguments[2], "ca.crt") &&
		validDarwinEnrolledBundleFile(arguments[4], "host.crt") &&
		filepath.Dir(arguments[2]) == filepath.Dir(arguments[4]):
		return nil
	case name == runner.nebulaCert && returnsOutput && len(arguments) == 4 &&
		arguments[0] == "print" && arguments[1] == "-json" && arguments[2] == "-path" &&
		validDarwinEnrolledBundleFile(arguments[3], "host.crt"):
		return nil
	default:
		return errors.New("Darwin installer enrollment validation command is outside its exact contract")
	}
}

func (runner darwinInstallerValidationRunner) run(ctx context.Context, name string, arguments []string, returnsOutput bool) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("Darwin installer enrollment validation command requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := nodeagent.InspectDarwinPackagedExecutable(name); err != nil {
		return nil, fmt.Errorf("authenticate Darwin enrollment validation executable: %w", err)
	}
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	var stdout, stderr boundedLaunchctlOutput
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	after, statErr := os.Lstat(name)
	authErr := nodeagent.InspectDarwinPackagedExecutable(name)
	if statErr != nil || authErr != nil || after == nil || !os.SameFile(before, after) {
		return nil, errors.Join(runErr, statErr, authErr, errors.New("Darwin enrollment validation executable changed while running"))
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("Darwin enrollment validation command exceeded its deadline: %w", ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("Darwin enrollment validation command output exceeded its bound")
	}
	if runErr != nil {
		return nil, fmt.Errorf(
			"Darwin enrollment validation command failed: %w; stdout=%s stderr=%s",
			runErr, launchctlOutputIdentity(stdout.Bytes()), launchctlOutputIdentity(stderr.Bytes()),
		)
	}
	if returnsOutput && stderr.Len() != 0 {
		return nil, fmt.Errorf(
			"Darwin enrollment validation command succeeded with unexpected stderr=%s",
			launchctlOutputIdentity(stderr.Bytes()),
		)
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func validDarwinEnrolledBundleFile(path, basename string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) != basename {
		return false
	}
	versionsRoot := filepath.Join(ProductionDarwinAgentOutputDirectory, "versions") + string(filepath.Separator)
	return strings.HasPrefix(path, versionsRoot) &&
		strings.Count(strings.TrimPrefix(path, versionsRoot), string(filepath.Separator)) == 1
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
