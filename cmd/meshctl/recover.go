package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mesh/internal/control"
	"mesh/internal/nodeagent"
)

const maxRecoveryTokenInput = 4 << 10

// stageOnlyReloader lets the recovery client validate and atomically stage a
// complete bundle while an independently proven systemd quarantine remains in
// force. The normal lifecycle agent is the only process allowed to start the
// packaged Nebula service afterward.
type stageOnlyReloader struct{}

func (stageOnlyReloader) Reload(context.Context) error { return nil }

type recoveryRuntimePlan struct {
	quarantine        runtimeController
	reloader          nodeagent.Reloader
	stageOnly         bool
	failOpen          bool
	quarantineService string
}

func recoverAgent(args []string) error {
	return recoverAgentWithIO(args, os.Stdin, os.Stdout, os.Stderr, os.Getenv)
}

func recoverAgentWithIO(args []string, input io.Reader, output, errorOutput io.Writer, getenv func(string) string) (retErr error) {
	flags := flag.NewFlagSet("recover-agent", flag.ContinueOnError)
	statePath := flags.String("state", defaultAgentState, "persistent agent state file")
	tokenFile := flags.String("token-file", "", "private recovery-token file, or - for stdin")
	resume := flags.Bool("resume", false, "resume the crash-safe pending recovery journal without another token")
	nebula := flags.String("nebula", "nebula", "nebula binary")
	nebulaCert := flags.String("nebula-cert", "nebula-cert", "nebula-cert binary")
	quarantineService := flags.String("quarantine-service", "", "systemd Nebula service to prove stopped while staging recovery")
	restartService := flags.String("restart-service", "", "systemd Nebula service to restart after verified recovery")
	reloadService := flags.String("reload-service", "", "compatibility alias for --restart-service")
	noReload := flags.Bool("no-reload", false, "stage recovery without controlling a runtime")
	failOpen := flags.Bool("fail-open", false, "explicitly continue when runtime quarantine cannot be proven")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("recover-agent does not accept positional arguments")
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	recoveryToken, err := loadAgentRecoveryInput(*resume, strings.TrimSpace(*tokenFile), input, getenv("MESH_AGENT_RECOVERY_TOKEN"))
	if err != nil {
		return err
	}
	defer func() { recoveryToken = "" }()

	store, err := nodeagent.NewStateStore(*statePath)
	if err != nil {
		return err
	}
	stateLock, err := store.AcquireProcessLock()
	if err != nil {
		return fmt.Errorf("acquire agent state for recovery (stop mesh-agent.service first): %w", err)
	}
	defer func() {
		if stateLock != nil {
			retErr = errors.Join(retErr, stateLock.Close())
		}
	}()
	state, err := store.Load()
	if err != nil {
		return err
	}
	outputLock, err := acquireProcessLock(state.OutputDir, "Nebula bundle output")
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, outputLock.Close()) }()
	if err := nodeagent.PreflightManagedOutput(state.OutputDir); err != nil {
		return fmt.Errorf("preflight managed Nebula output before recovery: %w", err)
	}

	commandRunner := nodeagent.ExecCommandRunner{}
	plan, err := selectRecoveryRuntime(recoveryRuntimeOptions{
		quarantineService: *quarantineService,
		restartService:    *restartService,
		reloadService:     *reloadService,
		noReload:          *noReload,
		failOpen:          *failOpen,
		runner:            commandRunner,
		configPath:        filepath.Join(state.OutputDir, "current", "config.yml"),
		nebulaBinary:      *nebula,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	versionOutput, err := commandRunner.Output(ctx, *nebula, "-version")
	if err != nil {
		return fmt.Errorf("inspect Nebula before agent recovery: %w", err)
	}
	if err := nodeagent.EnforceMinimumNebulaVersion(string(versionOutput)); err != nil {
		return err
	}
	if err := enforceRecoveryQuarantine(ctx, plan, errorOutput); err != nil {
		return err
	}
	finalQuarantinePending := plan.stageOnly
	if plan.stageOnly {
		defer func() {
			if !finalQuarantinePending {
				return
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if err := enforceRecoveryQuarantine(cleanupCtx, plan, errorOutput); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("leave Nebula quarantined after recovery: %w", err))
			}
		}()
	} else if !plan.failOpen {
		defer func() {
			if retErr == nil {
				return
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if err := enforceRecoveryQuarantine(cleanupCtx, plan, errorOutput); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("re-quarantine Nebula after failed recovery: %w", err))
			}
		}()
	}

	agentVersion, err := currentMeshAgentVersion()
	if err != nil {
		return err
	}
	agent := &nodeagent.Agent{
		Store: store, HTTPClient: secureHTTPClient(),
		Validator: nodeagent.BundleValidator{NebulaBinary: *nebula, NebulaCertBinary: *nebulaCert, Runner: commandRunner},
		Reloader:  plan.reloader, AgentVersion: agentVersion,
	}
	if err := stateLock.Close(); err != nil {
		return fmt.Errorf("handoff agent state lock for recovery: %w", err)
	}
	stateLock = nil
	defer func() { retErr = errors.Join(retErr, agent.Close()) }()
	result, err := agent.RecoverCredential(ctx, recoveryToken)
	if err != nil {
		after, inspectErr := store.Load()
		return describeRecoveryFailure(err, inspectErr, state.AgentCredentialGeneration, after, plan.stageOnly)
	}
	if plan.stageOnly {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := enforceRecoveryQuarantine(cleanupCtx, plan, errorOutput)
		cleanupCancel()
		if err != nil {
			return fmt.Errorf("the credential reset is durably committed, but Nebula quarantine could not be reconfirmed; do not issue another reset or start mesh-agent.service until quarantine is proven: %w", err)
		}
		finalQuarantinePending = false
		fmt.Fprintf(output, "Recovered the agent credential and staged signed revision %d. Nebula remains quarantined; start mesh-agent.service to resume managed operation.\n", result.Revision)
	} else if *noReload {
		fmt.Fprintf(output, "Recovered the agent credential and staged signed revision %d without runtime activation.\n", result.Revision)
	} else {
		fmt.Fprintf(output, "Recovered the agent credential and applied signed revision %d.\n", result.Revision)
	}
	return nil
}

func describeRecoveryFailure(cause, inspectErr error, previousGeneration int64, after nodeagent.State, stageOnly bool) error {
	if inspectErr != nil {
		return fmt.Errorf("recover agent credential: %w (could not inspect the recovery journal: %v)", cause, inspectErr)
	}
	if after.AgentCredentialGeneration > previousGeneration && after.PendingRecoveryToken == "" && after.PendingBearer == "" {
		if stageOnly {
			return fmt.Errorf("recover agent credential: the credential reset is durably committed; Nebula remains quarantined; start mesh-agent.service to retry fail-closed sync or renewal: %w", cause)
		}
		return fmt.Errorf("recover agent credential: the credential reset is durably committed, but runtime activation did not complete: %w", cause)
	}
	if after.PendingRecoveryToken != "" {
		if errorChainHasAgentAPIStatus(cause, http.StatusUnauthorized) {
			if stageOnly {
				return fmt.Errorf("recover agent credential; Nebula remains quarantined; the pending recovery token was rejected or expired: have an administrator issue a replacement recovery token, then rerun recover-agent with that new token; the client will safely probe the old pending bearer before replacing the journal: %w", cause)
			}
			return fmt.Errorf("recover agent credential; the pending recovery token was rejected or expired: have an administrator issue a replacement recovery token, then rerun recover-agent with that new token; the client will safely probe the old pending bearer before replacing the journal: %w", cause)
		}
		if stageOnly {
			return fmt.Errorf("recover agent credential; Nebula remains quarantined; rerun recover-agent with --resume to continue the private pending recovery journal: %w", cause)
		}
		return fmt.Errorf("recover agent credential; rerun recover-agent with --resume to continue the private pending recovery journal: %w", cause)
	}
	if stageOnly {
		return fmt.Errorf("recover agent credential; Nebula remains quarantined: %w", cause)
	}
	return fmt.Errorf("recover agent credential: %w", cause)
}

func errorChainHasAgentAPIStatus(err error, statusCode int) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := err.(*nodeagent.APIError); ok && apiErr.StatusCode == statusCode {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, nested := range joined.Unwrap() {
			if errorChainHasAgentAPIStatus(nested, statusCode) {
				return true
			}
		}
		return false
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return errorChainHasAgentAPIStatus(wrapped.Unwrap(), statusCode)
	}
	return false
}

type recoveryRuntimeOptions struct {
	quarantineService string
	restartService    string
	reloadService     string
	noReload          bool
	failOpen          bool
	runner            nodeagent.CommandRunner
	configPath        string
	nebulaBinary      string
}

func selectRecoveryRuntime(options recoveryRuntimeOptions) (recoveryRuntimePlan, error) {
	quarantineService := strings.TrimSpace(options.quarantineService)
	if quarantineService != "" {
		if strings.TrimSpace(options.restartService) != "" || strings.TrimSpace(options.reloadService) != "" || options.noReload {
			return recoveryRuntimePlan{}, errors.New("--quarantine-service cannot be combined with --restart-service, --reload-service, or --no-reload")
		}
		if options.failOpen {
			return recoveryRuntimePlan{}, errors.New("--quarantine-service is authoritative and cannot be combined with --fail-open")
		}
		controller, err := selectRuntimeController(runtimeOptions{
			restartService: quarantineService,
			runner:         options.runner,
			configPath:     options.configPath,
			nebulaBinary:   options.nebulaBinary,
		})
		if err != nil {
			return recoveryRuntimePlan{}, err
		}
		return recoveryRuntimePlan{
			quarantine: controller, reloader: stageOnlyReloader{}, stageOnly: true,
			quarantineService: quarantineService,
		}, nil
	}
	if options.noReload && !options.failOpen {
		return recoveryRuntimePlan{}, errors.New("--no-reload requires explicit --fail-open because it cannot prove Nebula quarantine")
	}
	controller, err := selectRuntimeController(runtimeOptions{
		restartService: options.restartService,
		reloadService:  options.reloadService,
		noReload:       options.noReload,
		runner:         options.runner,
		configPath:     options.configPath,
		nebulaBinary:   options.nebulaBinary,
	})
	if err != nil {
		return recoveryRuntimePlan{}, err
	}
	return recoveryRuntimePlan{quarantine: controller, reloader: controller, failOpen: options.failOpen}, nil
}

func enforceRecoveryQuarantine(ctx context.Context, plan recoveryRuntimePlan, errorOutput io.Writer) error {
	if service, ok := plan.quarantine.(*serviceRuntime); ok {
		if err := service.verifyConfiguration(ctx); err != nil {
			if !plan.failOpen {
				return fmt.Errorf("verify recovery runtime: %w", err)
			}
			fmt.Fprintf(errorOutput, "WARNING: recovery is explicitly fail-open; runtime configuration could not be verified: %v\n", err)
		}
	}
	if err := plan.quarantine.Quarantine(ctx); err != nil {
		if !plan.failOpen {
			return fmt.Errorf("quarantine Nebula before recovery: %w", err)
		}
		fmt.Fprintf(errorOutput, "WARNING: recovery is explicitly fail-open; Nebula quarantine could not be proven: %v\n", err)
	}
	return nil
}

func loadAgentRecoveryToken(tokenFile string, input io.Reader, environmentToken string) (string, error) {
	environmentToken = strings.TrimSpace(environmentToken)
	if tokenFile != "" && environmentToken != "" {
		return "", errors.New("choose only one recovery-token source: MESH_AGENT_RECOVERY_TOKEN or --token-file")
	}
	var raw []byte
	var err error
	switch {
	case tokenFile != "" && tokenFile != "-":
		raw, err = readPrivateRecoveryTokenFile(tokenFile)
	case tokenFile == "-":
		raw, err = readBoundedRecoveryToken(input)
	case environmentToken != "":
		raw = []byte(environmentToken)
	default:
		if file, ok := input.(*os.File); ok {
			info, statErr := file.Stat()
			if statErr != nil {
				return "", fmt.Errorf("inspect recovery-token stdin: %w", statErr)
			}
			if info.Mode()&os.ModeCharDevice != 0 {
				return "", errors.New("agent recovery token is required via MESH_AGENT_RECOVERY_TOKEN, --token-file, or piped stdin")
			}
		}
		raw, err = readBoundedRecoveryToken(input)
	}
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	for index := range raw {
		raw[index] = 0
	}
	if !control.ValidBearerToken(token) {
		return "", errors.New("agent recovery token is invalid")
	}
	return token, nil
}

func loadAgentRecoveryInput(resume bool, tokenFile string, input io.Reader, environmentToken string) (string, error) {
	if !resume {
		return loadAgentRecoveryToken(tokenFile, input, environmentToken)
	}
	if tokenFile != "" || strings.TrimSpace(environmentToken) != "" {
		return "", errors.New("--resume cannot be combined with MESH_AGENT_RECOVERY_TOKEN or --token-file")
	}
	stdin, err := recoveryTokenStdinProvided(input)
	if err != nil {
		return "", err
	}
	if stdin {
		return "", errors.New("--resume cannot be combined with piped recovery-token stdin")
	}
	return "", nil
}

func recoveryTokenStdinProvided(input io.Reader) (bool, error) {
	if input == nil {
		return false, nil
	}
	file, ok := input.(*os.File)
	if !ok {
		// An injected reader represents an explicit stdin source. Treat even an
		// empty reader as a conflict so --resume can never consume supplied data.
		return true, nil
	}
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect recovery-token stdin: %w", err)
	}
	return info.Mode()&os.ModeCharDevice == 0, nil
}

func readPrivateRecoveryTokenFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect recovery-token file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("recovery-token file must be a regular file, not a symlink")
	}
	if err := validateRecoveryTokenFileSecurity(before); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recovery-token file: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened recovery-token file: %w", err)
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, errors.New("recovery-token file changed while it was opened")
	}
	if err := validateRecoveryTokenFileSecurity(after); err != nil {
		return nil, err
	}
	return readBoundedRecoveryToken(file)
}

func readBoundedRecoveryToken(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, errors.New("recovery-token input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxRecoveryTokenInput+1))
	if err != nil {
		return nil, fmt.Errorf("read recovery token: %w", err)
	}
	if len(raw) > maxRecoveryTokenInput {
		for index := range raw {
			raw[index] = 0
		}
		return nil, errors.New("recovery-token input exceeds the size limit")
	}
	return raw, nil
}
