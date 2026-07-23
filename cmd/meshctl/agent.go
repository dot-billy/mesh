package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mesh/internal/control"
	"mesh/internal/nodeagent"
)

const (
	lifecycleWindow           = 30 * 24 * time.Hour
	defaultMaxConfigStaleness = 5 * time.Minute
	minimumAgentInterval      = 5 * time.Second
	maxSystemdStateOutput     = 4 * 1024
	runtimeCleanupTimeout     = 2 * time.Minute
)

var (
	reportedVersionPattern   = regexp.MustCompile(`(^|[^0-9])v?([0-9]+\.[0-9]+\.[0-9]+)($|[^0-9])`)
	configDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	serviceNamePattern       = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,128}$`)
	errQuarantineUnsupported = errors.New("runtime controller cannot prove Nebula quarantine")
)

type runtimeObservation struct {
	HeartbeatAllowed bool
	NebulaRunning    bool
	Status           string
	LastError        string
}

type runtimeController interface {
	nodeagent.Reloader
	Observe(context.Context) (runtimeObservation, error)
	Quarantine(context.Context) error
}

// runtimeReadinessMarker is an ephemeral, agent-owned authorization consumed
// by the packaged mesh-nebula.service ConditionPathExists gate. It is separate
// from the installer's persistent runtime gate: reboot or agent teardown must
// make this authorization disappear.
type runtimeReadinessMarker interface {
	Inspect() (bool, error)
	Open() error
	Close() error
}

type agentCycleResult struct {
	Revision            int64
	Renewed             bool
	RenewalDeferred     bool
	CredentialRotated   bool
	HeartbeatSequence   int64
	HeartbeatSkipped    bool
	RuntimeTelemetry    string
	CertificateIdentity string
}

type lifecycleAgent interface {
	Sync(context.Context) (nodeagent.SyncResult, error)
	RenewCertificate(context.Context) (nodeagent.SyncResult, error)
	RotateCredential(context.Context) (control.CredentialRotation, error)
	Heartbeat(context.Context, nodeagent.Health) (int64, error)
}

type runtimeTelemetryReporter interface {
	ReportRuntimeTelemetry(context.Context, int64) error
}

type configApplyFailureReporter interface {
	ReportConfigApplyFailure(context.Context, control.ConfigApplyFailureInput) error
}

type agentRunner struct {
	agent              lifecycleAgent
	store              *nodeagent.StateStore
	validator          nodeagent.BundleValidator
	runtime            runtimeController
	nativeDNS          nodeagent.NativeDNSReconciler
	nativeDNSActive    bool
	runner             nodeagent.CommandRunner
	nebulaBinary       string
	now                func() time.Time
	startup            bool
	maxConfigStaleness time.Duration
	failOpen           bool
	quarantined        bool
	jitter             func(time.Duration) time.Duration
}

func runAgentWithContext(ctx context.Context, args []string) (returnErr error) {
	return runAgentWithReady(ctx, args, nil)
}

func runAgentWithReady(ctx context.Context, args []string, ready func()) (returnErr error) {
	if ctx == nil {
		return errors.New("agent context is required")
	}
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	statePath := flags.String("state", defaultAgentState, "persistent agent state file")
	once := flags.Bool("once", false, "run one lifecycle cycle and exit")
	interval := flags.Duration("interval", time.Minute, "delay between lifecycle cycles")
	maxConfigStaleness := flags.Duration("max-config-staleness", defaultMaxConfigStaleness, "stop managed Nebula when signed config cannot be refreshed within this bound")
	failOpen := flags.Bool("fail-open", false, "explicitly keep Nebula running when config freshness cannot be confirmed")
	nebula := flags.String("nebula", "nebula", "nebula binary")
	nebulaCert := flags.String("nebula-cert", "nebula-cert", "nebula-cert binary")
	restartService := flags.String("restart-service", "", "systemd Nebula service to restart after activation")
	reloadService := flags.String("reload-service", "", "compatibility alias for --restart-service")
	reloadPIDFile := flags.String("reload-pid-file", "", "Nebula PID file to signal with SIGHUP")
	noReload := flags.Bool("no-reload", false, "manage bundles without claiming runtime activation")
	superviseNebula := flags.Bool("supervise-nebula", false, "directly supervise the packaged Nebula child (Darwin package only)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("agent does not accept positional arguments")
	}
	if err := validateAgentTiming(*once, *interval, *maxConfigStaleness, *failOpen); err != nil {
		return err
	}
	if *noReload && !*failOpen {
		return errors.New("--no-reload requires explicit --fail-open because it cannot quarantine Nebula")
	}

	runtimeSettings := runtimeOptions{
		restartService:  *restartService,
		reloadService:   *reloadService,
		pidFile:         *reloadPIDFile,
		noReload:        *noReload,
		superviseNebula: *superviseNebula,
		runner:          nodeagent.ExecCommandRunner{},
	}
	store, err := nodeagent.NewStateStore(*statePath)
	if err != nil {
		return err
	}
	stateLock, err := store.AcquireProcessLock()
	if err != nil {
		return err
	}
	defer stateLock.Close()
	state, err := store.Load()
	if err != nil {
		return err
	}
	outputLock, err := acquireProcessLock(state.OutputDir, "Nebula bundle output")
	if err != nil {
		return err
	}
	defer outputLock.Close()
	runtimeSettings.configPath = filepath.Join(state.OutputDir, "current", "config.yml")
	runtimeSettings.nebulaBinary = *nebula
	controller, err := selectRuntimeController(runtimeSettings)
	if err != nil {
		return err
	}

	commandRunner := nodeagent.ExecCommandRunner{}
	validator := nodeagent.BundleValidator{
		NebulaBinary: *nebula, NebulaCertBinary: *nebulaCert, Runner: commandRunner,
	}
	agentVersion, err := currentMeshAgentVersion()
	if err != nil {
		return err
	}
	agent := &nodeagent.Agent{
		Store: store, HTTPClient: secureHTTPClient(), Validator: validator,
		Reloader: controller, AgentVersion: agentVersion,
		ConfigSuccessPersistInterval: configSuccessPersistence(*maxConfigStaleness),
	}
	var nativeDNS nodeagent.NativeDNSReconciler
	if !*noReload {
		nativeDNS = nodeagent.NewNativeDNSManager(commandRunner)
	}
	if err := stateLock.Close(); err != nil {
		return fmt.Errorf("handoff agent state lock: %w", err)
	}
	defer agent.Close()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if nativeDNS != nil {
			if err := nativeDNS.Disable(cleanupCtx); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("disable native DNS during agent teardown: %w", err))
			}
		}
	}()
	if closer, ok := controller.(interface{ CloseReadinessMarker() error }); ok {
		defer func() {
			if err := closer.CloseReadinessMarker(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close runtime readiness marker during agent teardown: %w", err))
			}
		}()
	}
	runner := &agentRunner{
		agent: agent, store: store, validator: validator, runtime: controller, nativeDNS: nativeDNS,
		runner: commandRunner, nebulaBinary: *nebula, now: time.Now, startup: true,
		maxConfigStaleness: *maxConfigStaleness, failOpen: *failOpen,
		jitter: jitteredInterval,
	}
	if ready != nil {
		ready()
	}
	return runAgentLoop(ctx, runner, *once, *interval)
}

func runAgentLoop(ctx context.Context, runner *agentRunner, once bool, interval time.Duration) error {
	for {
		cycleStarted := runner.currentTime()
		cycleCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		result, err := runner.cycle(cycleCtx)
		cancel()
		if err != nil {
			if once {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s agent cycle failed: %v\n", time.Now().UTC().Format(time.RFC3339), err)
		} else {
			printAgentCycle(result)
		}
		if once {
			return nil
		}
		timer := time.NewTimer(runner.nextDelay(interval, cycleStarted))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func validateAgentTiming(once bool, interval, maxStaleness time.Duration, failOpen bool) error {
	if once {
		return nil
	}
	if interval < minimumAgentInterval {
		return fmt.Errorf("agent interval must be at least %s", minimumAgentInterval)
	}
	if failOpen {
		return nil
	}
	if maxStaleness < 2*minimumAgentInterval {
		return fmt.Errorf("max config staleness must be at least %s", 2*minimumAgentInterval)
	}
	if interval > maxStaleness/2 {
		return fmt.Errorf("agent interval must not exceed half of max config staleness (%s)", maxStaleness/2)
	}
	return nil
}

func configSuccessPersistence(maxStaleness time.Duration) time.Duration {
	interval := time.Minute
	if maxStaleness > 0 && maxStaleness/2 < interval {
		interval = maxStaleness / 2
	}
	if interval <= 0 {
		return time.Second
	}
	return interval
}

// jitteredInterval spreads simultaneous fleet polls while never scheduling a
// node later than its configured base interval.
func jitteredInterval(interval time.Duration) time.Duration {
	spread := interval / 5
	if spread <= 0 {
		return interval
	}
	return interval - spread + time.Duration(rand.Int64N(int64(spread)+1))
}

func (r *agentRunner) currentTime() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

func (r *agentRunner) nextDelay(interval time.Duration, cycleStarted time.Time) time.Duration {
	jitter := r.jitter
	if jitter == nil {
		jitter = jitteredInterval
	}
	delay := jitter(interval) - r.currentTime().Sub(cycleStarted)
	if delay < 0 {
		delay = 0
	}
	if r.failOpen || r.maxConfigStaleness <= 0 || r.quarantined {
		return delay
	}
	state, err := r.store.Load()
	if err != nil || state.LastSuccessfulConfigAt.IsZero() {
		return delay
	}
	untilDeadline := state.LastSuccessfulConfigAt.Add(r.maxConfigStaleness).Sub(r.currentTime())
	if untilDeadline < 0 {
		return 0
	}
	if untilDeadline < delay {
		return untilDeadline
	}
	return delay
}

func (r *agentRunner) cycle(ctx context.Context) (agentCycleResult, error) {
	var result agentCycleResult
	runtimeMutatedAfterNativeDNS := false
	if authorizer, ok := r.runtime.(interface{ AuthorizeCycle(context.Context) error }); ok {
		if err := authorizer.AuthorizeCycle(ctx); err != nil {
			return result, fmt.Errorf("authorize runtime before control-plane poll: %w", err)
		}
	}
	now := r.currentTime()
	state, err := r.store.Load()
	if err != nil {
		return result, err
	}
	if !r.failOpen && (r.startup || r.quarantined || r.configIsStale(state, now)) {
		if err := r.stopRuntime(ctx); err != nil {
			return result, fmt.Errorf("quarantine Nebula runtime before freshness-gated control-plane poll: %w", err)
		}
	}
	// An expired live certificate cannot pass the strict runtime validation in
	// Sync. Recover it first through the nodeagent renewal path, which preserves
	// key identity and authenticates with the independently scoped agent bearer.
	if !state.CertificateExpiresAt.IsZero() && !state.CertificateExpiresAt.After(now) {
		renewed, renewErr := r.agent.RenewCertificate(ctx)
		if renewErr != nil {
			return result, r.handleSyncFailure(ctx, fmt.Errorf("recover expired Nebula certificate before config sync: %w", renewErr))
		}
		result.Renewed = true
		result.Revision = renewed.Revision
		// Renewal activates a complete bundle. If this node was already beyond
		// its freshness deadline, put it back in quarantine until Sync confirms
		// the blocklist/config revision is current.
		if r.quarantined {
			if err := r.stopRuntime(ctx); err != nil {
				return result, fmt.Errorf("restore config-freshness quarantine after renewal: %w", err)
			}
		}
	}
	syncCtx, cancelSync := r.configSyncContext(ctx, state)
	synced, err := r.agent.Sync(syncCtx)
	cancelSync()
	if err != nil {
		var activationError *nodeagent.ConfigActivationError
		if errors.As(err, &activationError) {
			reportConfigApplyFailure(ctx, r.agent, activationError.Revision, activationError.Digest)
		}
		return result, r.handleSyncFailure(ctx, fmt.Errorf("sync signed config: %w", err))
	}
	result.Revision = synced.Revision
	if err := r.ensureRuntimeAfterSync(ctx, synced, result.Renewed); err != nil {
		reportConfigApplyFailure(ctx, r.agent, synced.Revision, synced.Digest)
		return result, err
	}
	if err := r.reconcileNativeDNS(ctx); err != nil {
		reportConfigApplyFailure(ctx, r.agent, synced.Revision, synced.Digest)
		return result, r.quarantine(ctx, fmt.Errorf("apply signed native DNS policy: %w", err))
	}

	state, err = r.store.Load()
	if err != nil {
		return result, err
	}
	if !result.Renewed && certificateRenewalDue(state.CertificateRenewAfter, now) {
		renewed, renewErr := r.agent.RenewCertificate(ctx)
		if renewErr != nil {
			if renewalDeferredByServer(renewErr) {
				result.RenewalDeferred = true
			} else {
				return result, fmt.Errorf("renew Nebula certificate: %w", renewErr)
			}
		} else {
			result.Renewed = true
			result.Revision = renewed.Revision
			runtimeMutatedAfterNativeDNS = true
		}
	}
	state, err = r.store.Load()
	if err != nil {
		return result, err
	}
	if lifecycleDue(state.AgentCredentialExpiresAt, now) {
		if _, err := r.agent.RotateCredential(ctx); err != nil {
			return result, fmt.Errorf("rotate agent credential: %w", err)
		}
		result.CredentialRotated = true
	}

	state, err = r.store.Load()
	if err != nil {
		return result, err
	}
	currentDirectory := filepath.Join(state.OutputDir, "current")
	details, err := r.validator.Validate(ctx, currentDirectory, filepath.Join(currentDirectory, "config.yml"))
	if err != nil {
		return result, fmt.Errorf("validate active Nebula bundle: %w", err)
	}
	versionOutput, err := r.runner.Output(ctx, r.nebulaBinary, "-version")
	if err != nil {
		return result, fmt.Errorf("inspect active Nebula version: %w", err)
	}
	version, err := reportedNebulaVersion(string(versionOutput))
	if err != nil {
		return result, err
	}
	observation, runtimeRecovered, err := observeRuntimeWithRecovery(ctx, r.runtime)
	if err != nil {
		return result, fmt.Errorf("inspect Nebula runtime: %w", err)
	}
	if runtimeMutatedAfterNativeDNS || runtimeRecovered {
		if err := r.reconcileNativeDNS(ctx); err != nil {
			reportConfigApplyFailure(ctx, r.agent, state.AppliedConfigRevision, state.AppliedConfigSHA256)
			return result, r.quarantine(ctx, fmt.Errorf("reapply signed native DNS policy after runtime mutation: %w", err))
		}
	}
	result.CertificateIdentity = details.Fingerprint
	if !observation.HeartbeatAllowed {
		result.HeartbeatSkipped = true
		return result, nil
	}
	sequence, err := r.agent.Heartbeat(ctx, nodeagent.Health{
		NebulaVersion: version, CertificateFingerprint: details.Fingerprint,
		NebulaRunning: observation.NebulaRunning, Status: observation.Status,
		NativeDNSActive: r.nativeDNSActive,
		LastError:       observation.LastError,
	})
	if err != nil {
		return result, fmt.Errorf("post validated heartbeat: %w", err)
	}
	result.HeartbeatSequence = sequence
	result.RuntimeTelemetry = reportRuntimeTelemetry(ctx, r.agent, sequence)
	return result, nil
}

func reportRuntimeTelemetry(ctx context.Context, agent lifecycleAgent, heartbeatSequence int64) string {
	reporter, ok := agent.(runtimeTelemetryReporter)
	if !ok {
		return ""
	}
	switch err := reporter.ReportRuntimeTelemetry(ctx, heartbeatSequence); {
	case err == nil:
		return "reported"
	case errors.Is(err, nodeagent.ErrRuntimeTelemetryUnsupported):
		return "unsupported"
	default:
		// Runtime telemetry is a reconstructible observation plane. A
		// failure here must never retroactively fail or quarantine an
		// already accepted lifecycle heartbeat.
		return "error"
	}
}

func reportConfigApplyFailure(ctx context.Context, agent lifecycleAgent, revision int64, digest string) {
	reporter, ok := agent.(configApplyFailureReporter)
	if !ok || revision < 1 || !configDigestPattern.MatchString(digest) {
		return
	}
	// The local activation error remains the cycle's primary result. Reporting
	// is best effort because an older server, a superseded rollout, or a lost
	// control-plane path must not interfere with local bundle rollback.
	_ = reporter.ReportConfigApplyFailure(ctx, control.ConfigApplyFailureInput{
		AttemptedConfigRevision: revision,
		AttemptedConfigSHA256:   digest,
		FailureCode:             control.ConfigApplyFailureCodeActivation,
	})
}

func (r *agentRunner) configSyncContext(ctx context.Context, state nodeagent.State) (context.Context, context.CancelFunc) {
	if r.failOpen || r.startup || r.maxConfigStaleness <= 0 || state.LastSuccessfulConfigAt.IsZero() {
		return context.WithCancel(ctx)
	}
	deadline := state.LastSuccessfulConfigAt.Add(r.maxConfigStaleness)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	return context.WithDeadline(ctx, deadline)
}

func (r *agentRunner) configIsStale(state nodeagent.State, now time.Time) bool {
	if state.LastSuccessfulConfigAt.IsZero() || now.Before(state.LastSuccessfulConfigAt) {
		return true
	}
	return !now.Before(state.LastSuccessfulConfigAt.Add(r.maxConfigStaleness))
}

func (r *agentRunner) handleSyncFailure(ctx context.Context, cause error) error {
	if r.failOpen {
		return cause
	}
	state, err := r.store.Load()
	if err != nil {
		return errors.Join(cause, fmt.Errorf("load config freshness state: %w", err))
	}
	if !r.startup && !r.configIsStale(state, r.currentTime()) {
		return cause
	}
	if r.quarantined {
		return errors.Join(cause, errors.New("Nebula runtime remains quarantined until signed config freshness recovers"))
	}
	return r.quarantine(ctx, cause)
}

func (r *agentRunner) ensureRuntimeAfterSync(ctx context.Context, synced nodeagent.SyncResult, renewed bool) error {
	if r.quarantined || (r.startup && !synced.Changed && !renewed) {
		if err := r.runtime.Reload(ctx); err != nil {
			activationErr := fmt.Errorf("activate current config after startup or quarantine: %w", err)
			if r.failOpen {
				return activationErr
			}
			return r.quarantine(ctx, activationErr)
		}
	}
	r.startup = false
	r.quarantined = false
	return nil
}

func (r *agentRunner) quarantine(ctx context.Context, cause error) error {
	if err := r.stopRuntime(ctx); err != nil {
		return errors.Join(cause, fmt.Errorf("could not quarantine stale Nebula runtime: %w", err))
	}
	return errors.Join(cause, errors.New("Nebula runtime quarantined until signed config freshness recovers"))
}

func (r *agentRunner) stopRuntime(ctx context.Context) error {
	var resolverErr error
	if r.nativeDNS != nil {
		resolverErr = r.nativeDNS.Disable(ctx)
	}
	r.nativeDNSActive = false
	runtimeErr := r.runtime.Quarantine(ctx)
	if resolverErr != nil || runtimeErr != nil {
		return errors.Join(resolverErr, runtimeErr)
	}
	r.quarantined = true
	return nil
}

func (r *agentRunner) reconcileNativeDNS(ctx context.Context) error {
	if r.nativeDNS == nil {
		return nil
	}
	state, err := r.store.Load()
	if err != nil {
		return err
	}
	path := filepath.Join(state.OutputDir, "current", "config.signed.yml")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > control.MaxManagedConfigBytes {
		return errors.New("current signed configuration is unavailable or exceeds its safety bound")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read current signed configuration")
	}
	if err := r.nativeDNS.Reconcile(ctx, string(raw)); err != nil {
		r.nativeDNSActive = false
		return err
	}
	_, enabled, err := control.ParseNativeDNSPolicy(string(raw))
	if err != nil {
		r.nativeDNSActive = false
		return err
	}
	r.nativeDNSActive = enabled
	return nil
}

func observeRuntimeWithRecovery(ctx context.Context, runtime runtimeController) (runtimeObservation, bool, error) {
	observation, observeErr := runtime.Observe(ctx)
	if observeErr == nil {
		return observation, false, nil
	}
	if reloadErr := runtime.Reload(ctx); reloadErr != nil {
		return runtimeObservation{}, false, errors.Join(observeErr, fmt.Errorf("recover runtime: %w", reloadErr))
	}
	observation, retryErr := runtime.Observe(ctx)
	if retryErr != nil {
		return runtimeObservation{}, false, errors.Join(observeErr, fmt.Errorf("runtime remained unhealthy after recovery: %w", retryErr))
	}
	return observation, true, nil
}

func lifecycleDue(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(now.Add(lifecycleWindow))
}

func certificateRenewalDue(renewAfter, now time.Time) bool {
	return !renewAfter.IsZero() && !now.Before(renewAfter)
}

func renewalDeferredByServer(err error) bool {
	var apiError *nodeagent.APIError
	return errors.As(err, &apiError) && apiError.StatusCode == http.StatusConflict
}

func reportedNebulaVersion(output string) (string, error) {
	if err := nodeagent.EnforceMinimumNebulaVersion(output); err != nil {
		return "", err
	}
	match := reportedVersionPattern.FindStringSubmatch(output)
	if len(match) != 4 {
		return "", errors.New("could not determine active Nebula version")
	}
	return match[2], nil
}

func printAgentCycle(result agentCycleResult) {
	status := fmt.Sprintf("agent cycle ok: revision=%d", result.Revision)
	if result.Renewed {
		status += " certificate=renewed"
	} else if result.RenewalDeferred {
		status += " certificate=server-deferred"
	}
	if result.CredentialRotated {
		status += " credential=rotated"
	}
	if result.HeartbeatSkipped {
		status += " heartbeat=skipped-no-runtime-ack"
	} else {
		status += fmt.Sprintf(" heartbeat_sequence=%d", result.HeartbeatSequence)
	}
	if result.RuntimeTelemetry != "" {
		status += " runtime_telemetry=" + result.RuntimeTelemetry
	}
	if len(result.CertificateIdentity) >= 12 {
		status += " fingerprint=" + result.CertificateIdentity[:12]
	}
	fmt.Println(status)
}

type runtimeOptions struct {
	restartService  string
	reloadService   string
	pidFile         string
	noReload        bool
	superviseNebula bool
	runner          nodeagent.CommandRunner
	configPath      string
	nebulaBinary    string
}

func selectRuntimeController(options runtimeOptions) (runtimeController, error) {
	restartService := strings.TrimSpace(options.restartService)
	reloadService := strings.TrimSpace(options.reloadService)
	pidFile := strings.TrimSpace(options.pidFile)
	selected := 0
	if restartService != "" {
		selected++
	}
	if reloadService != "" {
		selected++
	}
	if pidFile != "" {
		selected++
	}
	if options.noReload {
		selected++
	}
	if options.superviseNebula {
		selected++
	}
	if selected != 1 {
		return nil, errors.New("choose exactly one of --restart-service, --reload-service, --reload-pid-file, --supervise-nebula, or --no-reload")
	}
	if options.superviseNebula {
		return newSupervisedNebulaRuntime(options)
	}
	runner := options.runner
	if runner == nil {
		runner = nodeagent.ExecCommandRunner{}
	}
	service := restartService
	if service == "" {
		service = reloadService
	}
	if service != "" {
		if !serviceNamePattern.MatchString(service) || strings.HasPrefix(service, "-") {
			return nil, errors.New("systemd service name is invalid")
		}
		expectedConfig, err := filepath.Abs(options.configPath)
		if err != nil {
			return nil, fmt.Errorf("resolve managed Nebula config: %w", err)
		}
		nebulaBinary := strings.TrimSpace(options.nebulaBinary)
		if nebulaBinary == "" {
			nebulaBinary = "nebula"
		}
		expectedBinary, err := exec.LookPath(nebulaBinary)
		if err != nil {
			return nil, fmt.Errorf("resolve managed Nebula binary: %w", err)
		}
		expectedBinary, err = filepath.Abs(expectedBinary)
		if err != nil {
			return nil, fmt.Errorf("resolve managed Nebula binary path: %w", err)
		}
		marker, err := packagedRuntimeReadinessMarker(service)
		if err != nil {
			return nil, fmt.Errorf("configure packaged Nebula runtime readiness gate: %w", err)
		}
		return &serviceRuntime{
			service: service, runner: runner, expectedConfig: filepath.Clean(expectedConfig),
			expectedBinary: filepath.Clean(expectedBinary), readinessMarker: marker,
		}, nil
	}
	if pidFile != "" {
		absolute, err := filepath.Abs(pidFile)
		if err != nil {
			return nil, fmt.Errorf("resolve Nebula PID file: %w", err)
		}
		return newPIDRuntime(filepath.Clean(absolute), options.nebulaBinary)
	}
	return noReloadRuntime{}, nil
}

// serviceRuntime intentionally restarts instead of relying on Nebula's SIGHUP
// callback, which cannot acknowledge PKI or blocklist application failures.
type serviceRuntime struct {
	service         string
	runner          nodeagent.CommandRunner
	expectedConfig  string
	expectedBinary  string
	readinessMarker runtimeReadinessMarker
}

type systemdRuntimeState struct {
	activeState string
	subState    string
	mainPID     uint64
}

func (r *serviceRuntime) Reload(ctx context.Context) error {
	if err := r.verifyConfiguration(ctx); err != nil {
		return r.reloadFailure(ctx, err)
	}
	if r.readinessMarker != nil {
		// This publication stays immediately adjacent to the controlled restart:
		// callers validate the signed bundle before invoking Reload, and no other
		// operation may be inserted between authorization and systemd startup.
		if err := r.readinessMarker.Open(); err != nil {
			return r.reloadFailure(ctx, fmt.Errorf("publish Nebula runtime readiness marker: %w", err))
		}
	}
	if err := r.runner.RunQuiet(ctx, "systemctl", "restart", "--", r.service); err != nil {
		return r.reloadFailure(ctx, fmt.Errorf("restart Nebula service: %w", err))
	}
	if err := r.active(ctx); err != nil {
		return r.reloadFailure(ctx, err)
	}
	return nil
}

func (r *serviceRuntime) Observe(ctx context.Context) (runtimeObservation, error) {
	if err := r.verifyConfiguration(ctx); err != nil {
		return runtimeObservation{}, err
	}
	if r.readinessMarker != nil {
		open, err := r.readinessMarker.Inspect()
		if err != nil {
			return runtimeObservation{}, fmt.Errorf("inspect Nebula runtime readiness marker: %w", err)
		}
		if !open {
			return runtimeObservation{}, errors.New("Nebula runtime readiness marker is closed")
		}
	}
	if err := r.active(ctx); err != nil {
		return runtimeObservation{}, err
	}
	return runtimeObservation{HeartbeatAllowed: true, NebulaRunning: true, Status: "healthy"}, nil
}

func (r *serviceRuntime) Quarantine(ctx context.Context) error {
	cleanupCtx, cancel := runtimeCleanupContext(ctx)
	defer cancel()
	return r.closeAndStop(cleanupCtx)
}

// CloseReadinessMarker is deliberately separate from Quarantine so the agent
// can revoke startup authorization before its process exits. BindsTo then stops
// Nebula, and systemd removes RuntimeDirectory as an independent backstop.
func (r *serviceRuntime) CloseReadinessMarker() error {
	if r == nil || r.readinessMarker == nil {
		return nil
	}
	return r.readinessMarker.Close()
}

func (r *serviceRuntime) reloadFailure(ctx context.Context, cause error) error {
	if r.readinessMarker == nil {
		return cause
	}
	cleanupCtx, cancel := runtimeCleanupContext(ctx)
	defer cancel()
	if cleanupErr := r.closeAndStop(cleanupCtx); cleanupErr != nil {
		return errors.Join(cause, fmt.Errorf("fail-closed Nebula cleanup was not proven: %w", cleanupErr))
	}
	return cause
}

func (r *serviceRuntime) closeAndStop(ctx context.Context) error {
	var result error
	if r.readinessMarker != nil {
		if err := r.readinessMarker.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close Nebula runtime readiness marker: %w", err))
		}
	}
	// Stop is attempted even when marker removal reports an error. The ordering
	// is security-sensitive: no stop call may precede the close attempt.
	if err := r.runner.RunQuiet(ctx, "systemctl", "stop", "--", r.service); err != nil {
		result = errors.Join(result, fmt.Errorf("stop Nebula service: %w", err))
	}
	state, err := r.runtimeState(ctx)
	if err != nil {
		return errors.Join(result, fmt.Errorf("confirm Nebula service quarantine: %w", err))
	}
	stoppedState := state.activeState == "inactive" && state.subState == "dead"
	failedButDead := state.activeState == "failed" && state.subState == "dead"
	if state.mainPID != 0 || (!stoppedState && !failedButDead) {
		result = errors.Join(result, fmt.Errorf("Nebula service did not reach a proven stopped state (ActiveState=%q SubState=%q MainPID=%d)", state.activeState, state.subState, state.mainPID))
	}
	return result
}

func runtimeCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), runtimeCleanupTimeout)
}

func (r *serviceRuntime) active(ctx context.Context) error {
	state, err := r.runtimeState(ctx)
	if err != nil {
		return fmt.Errorf("inspect Nebula service runtime: %w", err)
	}
	if state.activeState != "active" || state.subState != "running" || state.mainPID <= 1 {
		return fmt.Errorf("Nebula service is not provably running (ActiveState=%q SubState=%q MainPID=%d)", state.activeState, state.subState, state.mainPID)
	}
	return nil
}

func (r *serviceRuntime) runtimeState(ctx context.Context) (systemdRuntimeState, error) {
	output, err := r.runner.Output(ctx, "systemctl", "show", "--property=ActiveState,SubState,MainPID", "--", r.service)
	if err != nil {
		return systemdRuntimeState{}, err
	}
	return parseSystemdRuntimeState(output)
}

func parseSystemdRuntimeState(output []byte) (systemdRuntimeState, error) {
	var state systemdRuntimeState
	if len(output) == 0 {
		return state, errors.New("systemd returned an empty runtime state")
	}
	if len(output) > maxSystemdStateOutput {
		return state, fmt.Errorf("systemd runtime state exceeds %d bytes", maxSystemdStateOutput)
	}
	raw := string(output)
	if strings.ContainsRune(raw, '\x00') {
		return state, errors.New("systemd runtime state contains a NUL byte")
	}
	raw = strings.TrimSuffix(raw, "\n")
	seen := make(map[string]bool, 3)
	for _, line := range strings.Split(raw, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || value == "" || strings.ContainsRune(value, '=') || !validSystemdPropertyValue(value) {
			return state, fmt.Errorf("malformed systemd runtime property %q", line)
		}
		if seen[key] {
			return state, fmt.Errorf("duplicate systemd runtime property %q", key)
		}
		seen[key] = true
		switch key {
		case "ActiveState":
			state.activeState = value
		case "SubState":
			state.subState = value
		case "MainPID":
			pid, err := strconv.ParseUint(value, 10, 64)
			if err != nil || strconv.FormatUint(pid, 10) != value {
				return state, fmt.Errorf("malformed systemd MainPID %q", value)
			}
			state.mainPID = pid
		default:
			return state, fmt.Errorf("unexpected systemd runtime property %q", key)
		}
	}
	for _, required := range []string{"ActiveState", "SubState", "MainPID"} {
		if !seen[required] {
			return state, fmt.Errorf("missing systemd runtime property %q", required)
		}
	}
	return state, nil
}

func validSystemdPropertyValue(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (r *serviceRuntime) verifyConfiguration(ctx context.Context) error {
	output, err := r.runner.Output(ctx, "systemctl", "show", "--property=ExecStart", "--value", "--", r.service)
	if err != nil {
		return fmt.Errorf("inspect Nebula service command: %w", err)
	}
	if !execStartUsesManagedNebula(string(output), r.expectedBinary, r.expectedConfig) {
		return fmt.Errorf("Nebula service ExecStart must run %s with exactly one managed config %s", r.expectedBinary, r.expectedConfig)
	}
	return nil
}

func execStartUsesManagedNebula(execStart, expectedBinary, expectedConfig string) bool {
	const maxExecStartBytes = 64 << 10
	if len(execStart) == 0 || len(execStart) > maxExecStartBytes || strings.IndexByte(execStart, 0) >= 0 {
		return false
	}
	// `systemctl show --property=ExecStart --value` reports both the executable
	// systemd actually opens (`path=`) and its argument vector (`argv[]=`).
	// Both must name the expected binary: an ExecStart=@/evil /expected ... unit
	// can otherwise spoof argv[0] while systemd executes /evil. Accept exactly
	// one command and exactly one effective managed config flag.
	var executablePath, argvText string
	pathCount, argvCount := 0, 0
	for _, rawPart := range strings.Split(execStart, ";") {
		part := strings.TrimSpace(strings.Trim(strings.TrimSpace(rawPart), "{}"))
		switch {
		case strings.HasPrefix(part, "path="):
			pathCount++
			executablePath = strings.TrimSpace(strings.Trim(strings.TrimPrefix(part, "path="), "'\"{}"))
		case strings.HasPrefix(part, "argv[]="):
			argvCount++
			argvText = strings.TrimSpace(strings.TrimPrefix(part, "argv[]="))
		}
	}
	if pathCount != 1 || argvCount != 1 || executablePath == "" || !filepath.IsAbs(executablePath) || filepath.Clean(executablePath) != filepath.Clean(expectedBinary) {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(argvText))
	if len(fields) < 2 || filepath.Clean(strings.Trim(fields[0], "'\"{}")) != filepath.Clean(expectedBinary) {
		return false
	}
	var configValue string
	switch {
	case len(fields) == 2 && (strings.HasPrefix(strings.Trim(fields[1], "'\"{}"), "-config=") || strings.HasPrefix(strings.Trim(fields[1], "'\"{}"), "--config=")):
		configValue = strings.SplitN(strings.Trim(fields[1], "'\"{}"), "=", 2)[1]
	case len(fields) == 3 && (strings.Trim(fields[1], "'\"{}") == "-config" || strings.Trim(fields[1], "'\"{}") == "--config"):
		configValue = strings.Trim(fields[2], "'\"{}")
	default:
		return false
	}
	return configValue != "" && filepath.Clean(configValue) == filepath.Clean(expectedConfig)
}

type noReloadRuntime struct{}

func (noReloadRuntime) Reload(context.Context) error { return nil }

func (noReloadRuntime) Quarantine(context.Context) error { return errQuarantineUnsupported }

func (noReloadRuntime) Observe(context.Context) (runtimeObservation, error) {
	return runtimeObservation{HeartbeatAllowed: false, Status: "degraded"}, nil
}
