package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mesh/internal/control"
)

var (
	ErrConfigRollback              = errors.New("signed config revision rollback")
	ErrConfigEquivocation          = errors.New("signed config digest changed at the same revision")
	ErrAgentRecoveryPending        = errors.New("agent credential recovery is pending; rerun recover-agent")
	ErrAgentRecoveryResumeRequired = errors.New("pending recovery bearer is already active; rerun recover-agent with --resume")
)

const configSuccessPersistInterval = time.Minute

type SyncResult struct {
	Changed  bool
	Revision int64
	Digest   string
}

// ConfigActivationError carries only signed-artifact identity across the
// local agent boundary. Cause remains local diagnostic text and is never sent
// to the control plane.
type ConfigActivationError struct {
	Revision int64
	Digest   string
	Cause    error
}

func (e *ConfigActivationError) Error() string {
	if e == nil || e.Cause == nil {
		return "activate signed config"
	}
	return e.Cause.Error()
}

func (e *ConfigActivationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type Health struct {
	NebulaVersion          string
	CertificateFingerprint string
	NebulaRunning          bool
	NativeDNSActive        bool
	Status                 string
	LastError              string
}

// Agent coordinates persistence, API operations, signature pinning, bundle
// validation, and rollback. Calls are serialized so state sequences and live
// symlink transitions remain monotonic within the process.
type Agent struct {
	Store        *StateStore
	HTTPClient   *http.Client
	Validator    BundleValidator
	Reloader     Reloader
	AgentVersion string
	// RuntimeObserver is an agent-side test seam for the bounded local
	// observer client. Its result is posted through a separately versioned API;
	// the lifecycle heartbeat schema remains unchanged. A nil value uses
	// runtimeobserver.Client.
	RuntimeObserver RuntimeTelemetryObserver
	// activeProbeExecutor and journal callbacks are private test seams. A nil
	// executor selects the build-tagged platform implementation; nil callbacks
	// use the adjacent crash-durable StateStore journal.
	activeProbeExecutor    activeProbeExecutor
	routeOverlapInspector  routeOverlapInspector
	endpointDNSResolver    endpointDNSResolver
	loadActiveProbeJournal func() (activeProbeJournal, error)
	saveActiveProbeJournal func(activeProbeJournal) error
	// Now exists so freshness persistence can be tested without sleeping. A nil
	// value uses the system clock.
	Now func() time.Time
	// ConfigSuccessPersistInterval coalesces unchanged successful polls. Zero
	// uses the one-minute default; callers with a tighter fail-close policy must
	// set this to no more than half their maximum config staleness.
	ConfigSuccessPersistInterval time.Duration
	mu                           sync.Mutex
	processLock                  *ProcessLock
}

// InstallEnrollment durably saves the locally generated bearer before trying
// the initial activation, then validates the enrollment signature and installs
// a complete first bundle.
func (a *Agent) InstallEnrollment(ctx context.Context, state State, enrollment control.EnrollmentBundle, privateKey, publicKey string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return err
	}
	state.AppliedConfigRevision = 0
	state.AppliedConfigSHA256 = ""
	if err := state.Validate(); err != nil {
		return fmt.Errorf("validate enrollment state: %w", err)
	}
	if err := a.Store.SaveRecoveryKeyPair(privateKey, publicKey); err != nil {
		return fmt.Errorf("persist node recovery keypair: %w", err)
	}
	if err := a.Store.Save(state); err != nil {
		return fmt.Errorf("persist enrollment credential: %w", err)
	}
	desired := control.AgentConfig{
		NodeID:              enrollment.Node.ID,
		NetworkID:           enrollment.Node.NetworkID,
		Revision:            enrollment.ConfigRevision,
		Config:              enrollment.Config,
		IssuedAt:            enrollment.ConfigIssuedAt,
		SHA256:              enrollment.ConfigSHA256,
		Signature:           enrollment.ConfigSignature,
		CACertificateSHA256: enrollment.CACertificateSHA256, PreviousCACertificateSHA256: enrollment.PreviousCACertificateSHA256,
		CARotationRequired:                enrollment.CARotationRequired,
		CertificateProfileRenewalRequired: enrollment.CertificateProfileRenewalRequired,
		CertificateFingerprint:            enrollment.CertificateFingerprint,
		PublicKeyHash:                     enrollment.PublicKeyHash,
		CertificateGeneration:             enrollment.CertificateGeneration,
		CertificateExpiresAt:              enrollment.CertificateExpiresAt,
		CertificateRenewAfter:             enrollment.CertificateRenewAfter,
	}
	if err := VerifySignedConfig(state, desired); err != nil {
		return fmt.Errorf("verify enrollment config: %w", err)
	}
	bundle := Bundle{
		NodeID: desired.NodeID, NetworkID: desired.NetworkID,
		Revision: desired.Revision, IssuedAt: desired.IssuedAt, Digest: desired.SHA256,
		Signature: desired.Signature, SignedConfig: desired.Config,
		CACertificateSHA256: desired.CACertificateSHA256, PreviousCACertificateSHA256: desired.PreviousCACertificateSHA256,
		CARotationRequired: desired.CARotationRequired, CertificateProfileRenewalRequired: desired.CertificateProfileRenewalRequired, CertificateFingerprint: desired.CertificateFingerprint,
		CertificateExpiresAt: desired.CertificateExpiresAt, PublicKeyHash: desired.PublicKeyHash,
		CertificateRenewAfter: desired.CertificateRenewAfter,
		CertificateGeneration: desired.CertificateGeneration,
		CACertificate:         enrollment.CA, Certificate: enrollment.Certificate,
		PrivateKey: privateKey, PublicKey: publicKey,
	}
	activation, err := a.activator(state).Apply(ctx, bundle)
	if err != nil {
		return fmt.Errorf("activate enrollment bundle: %w", err)
	}
	state.AppliedConfigRevision = desired.Revision
	state.AppliedConfigSHA256 = desired.SHA256
	state.CACertificateSHA256 = desired.CACertificateSHA256
	state.CertificateFingerprint = desired.CertificateFingerprint
	state.CertificateGeneration = desired.CertificateGeneration
	state.CertificateExpiresAt = activation.CertificateExpiresAt
	state.CertificateRenewAfter = desired.CertificateRenewAfter
	state.AgentCredentialExpiresAt = enrollment.AgentCredentialExpiresAt
	state.AgentCredentialGeneration = enrollment.AgentCredentialGeneration
	state.LastSuccessfulConfigAt = a.currentTime()
	if err := a.Store.Save(state); err != nil {
		return fmt.Errorf("persist activated enrollment: %w", err)
	}
	if err := a.Store.ClearProvisionalEnrollment(); err != nil {
		return fmt.Errorf("clear completed enrollment journal: %w", err)
	}
	return nil
}

func (a *Agent) Sync(ctx context.Context) (SyncResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return SyncResult{}, err
	}
	state, current, err := a.loadReconciledState(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return SyncResult{}, err
	}
	etag := "\"" + current.Signature + "\""
	response, err := client.GetConfig(ctx, etag)
	if err != nil {
		return SyncResult{}, err
	}
	if response.NotModified {
		if err := a.recordConfigSuccess(&state); err != nil {
			return SyncResult{}, err
		}
		return SyncResult{Revision: state.AppliedConfigRevision, Digest: state.AppliedConfigSHA256}, nil
	}
	desired := response.Config
	if err := VerifySignedConfig(state, desired); err != nil {
		return SyncResult{}, err
	}
	if desired.CACertificateSHA256 != state.CACertificateSHA256 {
		// A signed trust transition authenticates the new digest, but the config
		// endpoint intentionally does not carry CA material. Fetch the complete
		// bootstrap and activate that verified trust bundle before any rotation-
		// required certificate renewal. An agent that missed prepare therefore
		// takes two safe syncs instead of jumping directly from old-only trust to
		// a replacement certificate.
		bootstrap, err := client.Bootstrap(ctx)
		if err != nil {
			return SyncResult{}, fmt.Errorf("fetch signed CA trust transition: %w", err)
		}
		privateKey, publicKey, err := a.Store.LoadRecoveryKeyPair()
		if err != nil {
			return SyncResult{}, err
		}
		state.LastSuccessfulConfigAt = a.currentTime()
		return a.applyBootstrap(ctx, &state, Bundle{PrivateKey: privateKey, PublicKey: publicKey}, bootstrap)
	}
	if desired.CARotationRequired || desired.CertificateProfileRenewalRequired {
		return a.renewCertificateLocked(ctx)
	}
	if desired.CertificateGeneration != current.CertificateGeneration ||
		desired.CertificateFingerprint != current.CertificateFingerprint ||
		!desired.CertificateExpiresAt.Equal(current.CertificateExpiresAt) ||
		!desired.CertificateRenewAfter.Equal(current.CertificateRenewAfter) {
		bootstrap, err := client.Bootstrap(ctx)
		if err != nil {
			return SyncResult{}, fmt.Errorf("recover changed signed certificate artifact: %w", err)
		}
		privateKey, publicKey, err := a.Store.LoadRecoveryKeyPair()
		if err != nil {
			return SyncResult{}, err
		}
		state.LastSuccessfulConfigAt = a.currentTime()
		return a.applyBootstrap(ctx, &state, Bundle{PrivateKey: privateKey, PublicKey: publicKey}, bootstrap)
	}
	if desired.Revision == state.AppliedConfigRevision {
		if !sameSignedArtifact(current, desired) {
			return SyncResult{}, ErrConfigEquivocation
		}
		if err := a.recordConfigSuccess(&state); err != nil {
			return SyncResult{}, err
		}
		return SyncResult{Revision: desired.Revision, Digest: desired.SHA256}, nil
	}
	current.Revision = desired.Revision
	current.IssuedAt = desired.IssuedAt
	current.Digest = desired.SHA256
	current.Signature = desired.Signature
	current.CACertificateSHA256 = desired.CACertificateSHA256
	current.PreviousCACertificateSHA256 = desired.PreviousCACertificateSHA256
	current.CARotationRequired = desired.CARotationRequired
	current.CertificateProfileRenewalRequired = desired.CertificateProfileRenewalRequired
	current.CertificateFingerprint = desired.CertificateFingerprint
	current.CertificateExpiresAt = desired.CertificateExpiresAt
	current.CertificateRenewAfter = desired.CertificateRenewAfter
	current.PublicKeyHash = desired.PublicKeyHash
	current.CertificateGeneration = desired.CertificateGeneration
	current.SignedConfig = desired.Config
	activationState := state
	activationState.CACertificateSHA256 = desired.CACertificateSHA256
	activation, err := a.activator(activationState).Apply(ctx, current)
	if err != nil {
		return SyncResult{}, &ConfigActivationError{
			Revision: desired.Revision, Digest: desired.SHA256,
			Cause: fmt.Errorf("activate signed config: %w", err),
		}
	}
	state.AppliedConfigRevision = desired.Revision
	state.AppliedConfigSHA256 = desired.SHA256
	state.CACertificateSHA256 = desired.CACertificateSHA256
	state.CertificateFingerprint = desired.CertificateFingerprint
	state.CertificateGeneration = desired.CertificateGeneration
	state.CertificateExpiresAt = activation.CertificateExpiresAt
	state.CertificateRenewAfter = desired.CertificateRenewAfter
	state.LastSuccessfulConfigAt = a.currentTime()
	if err := a.Store.Save(state); err != nil {
		return SyncResult{}, fmt.Errorf("persist applied config revision: %w", err)
	}
	return SyncResult{Changed: true, Revision: desired.Revision, Digest: desired.SHA256}, nil
}

func (a *Agent) RenewCertificate(ctx context.Context) (SyncResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return SyncResult{}, err
	}
	return a.renewCertificateLocked(ctx)
}

func (a *Agent) renewCertificateLocked(ctx context.Context) (SyncResult, error) {
	state, err := a.Store.Load()
	if err != nil {
		return SyncResult{}, err
	}
	if err := rejectPendingAgentRecovery(state); err != nil {
		return SyncResult{}, err
	}
	privateKey, publicKey, err := a.Store.LoadRecoveryKeyPair()
	if err != nil {
		return SyncResult{}, fmt.Errorf("load node keypair for renewal: %w", err)
	}
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return SyncResult{}, err
	}
	renewal, err := client.RenewCertificate(ctx, publicKey)
	if err != nil {
		bootstrap, bootstrapErr := client.Bootstrap(ctx)
		if bootstrapErr != nil || bootstrap.CertificateGeneration <= state.CertificateGeneration {
			return SyncResult{}, err
		}
		result, recoveryErr := a.applyBootstrap(ctx, &state, Bundle{PrivateKey: privateKey, PublicKey: publicKey}, bootstrap)
		if recoveryErr != nil {
			return SyncResult{}, errors.Join(err, fmt.Errorf("recover ambiguous certificate renewal: %w", recoveryErr))
		}
		return result, nil
	}
	desired := control.AgentConfig{
		NodeID: renewal.NodeID, NetworkID: renewal.NetworkID,
		Revision: renewal.ConfigRevision, Config: renewal.Config,
		IssuedAt: renewal.ConfigIssuedAt, SHA256: renewal.ConfigSHA256,
		Signature: renewal.ConfigSignature, CertificateExpiresAt: renewal.CertificateExpiresAt,
		CertificateRenewAfter: renewal.CertificateRenewAfter,
		CACertificateSHA256:   renewal.CACertificateSHA256, PreviousCACertificateSHA256: renewal.PreviousCACertificateSHA256,
		CARotationRequired: renewal.CARotationRequired, CertificateProfileRenewalRequired: renewal.CertificateProfileRenewalRequired, CertificateFingerprint: renewal.CertificateFingerprint,
		PublicKeyHash:         renewal.PublicKeyHash,
		CertificateGeneration: renewal.CertificateGeneration,
	}
	if err := VerifySignedConfig(state, desired); err != nil {
		return SyncResult{}, fmt.Errorf("verify renewal config: %w", err)
	}
	// The server deliberately replays the last committed renewal for a short
	// ambiguity window. If the exact signed artifact is already live, avoid
	// creating another immutable version and restarting Nebula on every replay.
	if current, currentErr := a.currentBundle(ctx, state); currentErr == nil && sameSignedArtifact(current, desired) {
		return SyncResult{Revision: desired.Revision, Digest: desired.SHA256}, nil
	}
	current := Bundle{
		NodeID: state.NodeID, NetworkID: state.NetworkID, Revision: desired.Revision,
		IssuedAt: desired.IssuedAt, Digest: desired.SHA256, Signature: desired.Signature,
		CACertificateSHA256: desired.CACertificateSHA256, PreviousCACertificateSHA256: desired.PreviousCACertificateSHA256,
		CARotationRequired: desired.CARotationRequired, CertificateProfileRenewalRequired: desired.CertificateProfileRenewalRequired, CertificateFingerprint: desired.CertificateFingerprint,
		CertificateExpiresAt: desired.CertificateExpiresAt, PublicKeyHash: desired.PublicKeyHash,
		CertificateRenewAfter: desired.CertificateRenewAfter,
		CertificateGeneration: desired.CertificateGeneration,
		SignedConfig:          desired.Config, CACertificate: renewal.CA, Certificate: renewal.Certificate,
		PrivateKey: privateKey, PublicKey: publicKey,
	}
	activationState := state
	activationState.CACertificateSHA256 = desired.CACertificateSHA256
	activation, err := a.activator(activationState).Apply(ctx, current)
	if err != nil {
		return SyncResult{}, fmt.Errorf("activate renewed certificate: %w", err)
	}
	state.AppliedConfigRevision = desired.Revision
	state.AppliedConfigSHA256 = desired.SHA256
	state.CACertificateSHA256 = desired.CACertificateSHA256
	state.CertificateFingerprint = desired.CertificateFingerprint
	state.CertificateGeneration = desired.CertificateGeneration
	state.CertificateExpiresAt = activation.CertificateExpiresAt
	state.CertificateRenewAfter = desired.CertificateRenewAfter
	if err := a.Store.Save(state); err != nil {
		return SyncResult{}, fmt.Errorf("persist certificate renewal: %w", err)
	}
	return SyncResult{Changed: true, Revision: desired.Revision, Digest: desired.SHA256}, nil
}

func sameSignedArtifact(current Bundle, desired control.AgentConfig) bool {
	return current.NodeID == desired.NodeID &&
		current.NetworkID == desired.NetworkID &&
		current.Revision == desired.Revision &&
		current.IssuedAt.Equal(desired.IssuedAt) &&
		current.Digest == desired.SHA256 &&
		current.Signature == desired.Signature &&
		current.CACertificateSHA256 == desired.CACertificateSHA256 &&
		current.PreviousCACertificateSHA256 == desired.PreviousCACertificateSHA256 &&
		current.CARotationRequired == desired.CARotationRequired &&
		current.CertificateProfileRenewalRequired == desired.CertificateProfileRenewalRequired &&
		current.CertificateFingerprint == desired.CertificateFingerprint &&
		current.CertificateExpiresAt.Equal(desired.CertificateExpiresAt) &&
		current.CertificateRenewAfter.Equal(desired.CertificateRenewAfter) &&
		current.CertificateGeneration == desired.CertificateGeneration &&
		current.PublicKeyHash == desired.PublicKeyHash &&
		current.SignedConfig == desired.Config
}

// RotateCredential is crash-recoverable: the new locally generated bearer is
// first persisted as pending, and a retry can finish using either side of the
// server's credential grace window.
func (a *Agent) RotateCredential(ctx context.Context) (control.CredentialRotation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return control.CredentialRotation{}, err
	}
	state, err := a.Store.Load()
	if err != nil {
		return control.CredentialRotation{}, err
	}
	if err := rejectPendingAgentRecovery(state); err != nil {
		return control.CredentialRotation{}, err
	}
	if state.PendingBearer == "" {
		state.PendingBearer, err = GenerateBearer()
		if err != nil {
			return control.CredentialRotation{}, err
		}
		if err := a.Store.Save(state); err != nil {
			return control.CredentialRotation{}, fmt.Errorf("persist pending agent credential: %w", err)
		}
	}
	newHash := control.HashToken(state.PendingBearer)
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return control.CredentialRotation{}, err
	}
	rotation, err := client.RotateCredential(ctx, newHash)
	if err != nil {
		var apiError *APIError
		if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusUnauthorized {
			return control.CredentialRotation{}, err
		}
		pendingClient, clientErr := NewClient(state.ServerURL, state.PendingBearer, a.HTTPClient)
		if clientErr != nil {
			return control.CredentialRotation{}, clientErr
		}
		rotation, err = pendingClient.RotateCredential(ctx, newHash)
		if err != nil {
			return control.CredentialRotation{}, err
		}
	}
	if err := validateCredentialRotation(state, rotation, time.Now().UTC()); err != nil {
		return control.CredentialRotation{}, err
	}
	state.Bearer = state.PendingBearer
	state.PendingBearer = ""
	state.AgentCredentialGeneration = rotation.Generation
	state.AgentCredentialExpiresAt = rotation.ExpiresAt
	if err := a.Store.Save(state); err != nil {
		return control.CredentialRotation{}, fmt.Errorf("commit rotated agent credential: %w", err)
	}
	return rotation, nil
}

// RecoverCredential performs an administrative reset of a lost or expired
// agent bearer without changing the node's Nebula identity. The recovery token
// and proposed bearer are persisted before the first request so every retry is
// byte-for-byte identical after an ambiguous response or process crash.
func (a *Agent) RecoverCredential(ctx context.Context, providedToken string) (SyncResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return SyncResult{}, err
	}
	state, err := a.Store.Load()
	if err != nil {
		return SyncResult{}, err
	}
	privateKey, publicKey, err := a.Store.LoadRecoveryKeyPair()
	if err != nil {
		return SyncResult{}, fmt.Errorf("load immutable node keypair for agent recovery: %w", err)
	}
	if err := validateRecoveryKeyPair(privateKey, publicKey, state.PublicKeyHash); err != nil {
		return SyncResult{}, err
	}

	providedToken = strings.TrimSpace(providedToken)
	if state.PendingRecoveryToken != "" {
		if providedToken != "" && !control.TokenEqual(control.HashToken(state.PendingRecoveryToken), providedToken) {
			if !control.ValidBearerToken(providedToken) {
				return SyncResult{}, errors.New("a canonical replacement agent recovery token is required")
			}
			if err := a.replacePendingRecoveryAfterAuthoritativeRejection(ctx, &state, keysForRecovery(privateKey, publicKey), providedToken); err != nil {
				return SyncResult{}, err
			}
		}
		providedToken = state.PendingRecoveryToken
	} else {
		if !control.ValidBearerToken(providedToken) {
			return SyncResult{}, errors.New("a canonical agent recovery token is required")
		}
		state.PendingRecoveryToken = providedToken
		// PendingBearer without a recovery token belongs to normal credential
		// rotation. It may already be authoritative server-side, in which case
		// recovery correctly rejects its hash as already in use. Administrative
		// recovery supersedes that protocol with a fresh, separately journaled
		// bearer; only recovery retries reuse the exact pair.
		state.PendingBearer = ""
		state.PendingRecoveryAllowsGenerationAdvance = false
	}
	if !control.ValidBearerToken(providedToken) {
		return SyncResult{}, errors.New("pending agent recovery token is invalid")
	}
	if state.PendingBearer == "" {
		state.PendingBearer, err = GenerateBearer()
		if err != nil {
			return SyncResult{}, err
		}
	}
	if control.TokenEqual(control.HashToken(state.Bearer), state.PendingBearer) {
		return SyncResult{}, errors.New("pending recovery bearer must differ from the active bearer")
	}
	// Save is an fsync-backed atomic rename. No recovery request is sent until
	// both secrets needed for an exact retry are durable.
	if err := a.Store.Save(state); err != nil {
		return SyncResult{}, fmt.Errorf("persist pending agent recovery request: %w", err)
	}

	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return SyncResult{}, err
	}
	recovered, err := client.RecoverAgent(ctx, control.RecoverAgentInput{
		RecoveryToken: providedToken, PublicKey: publicKey,
		NewAgentTokenHash: control.HashToken(state.PendingBearer),
	})
	if err != nil {
		return SyncResult{}, err
	}
	keys := keysForRecovery(privateKey, publicKey)
	_, _, err = verifyRecoveredAgentBundle(state, keys, recovered, state.PendingBearer, a.currentTime())
	if err != nil {
		return SyncResult{}, err
	}

	// A valid receipt proves what the server committed. Authentication with the
	// proposed bearer independently proves that the credential is live, and the
	// returned signed artifact must be exactly the one linked by the receipt.
	pendingClient, err := NewClient(state.ServerURL, state.PendingBearer, a.HTTPClient)
	if err != nil {
		return SyncResult{}, err
	}
	confirmed, err := pendingClient.Bootstrap(ctx)
	if err != nil {
		return SyncResult{}, fmt.Errorf("prove recovered agent credential: %w", err)
	}
	_, confirmedBundle, err := verifyBootstrapBundle(state, keys, confirmed)
	if err != nil {
		return SyncResult{}, fmt.Errorf("verify recovered credential bootstrap: %w", err)
	}
	if err := validateRecoveryBootstrapAdvance(recovered.EnrollmentBundle, confirmed, recovered.RecoveryReceipt); err != nil {
		return SyncResult{}, err
	}
	if confirmed.CertificateExpiresAt.After(a.currentTime()) {
		if err := a.validateRecoveryActivationCandidate(ctx, confirmedBundle); err != nil {
			return SyncResult{}, fmt.Errorf("validate recovered Nebula bootstrap before credential commit: %w", err)
		}
	}

	receipt := recovered.RecoveryReceipt
	state.Bearer = state.PendingBearer
	state.PendingBearer = ""
	state.PendingRecoveryToken = ""
	state.PendingRecoveryAllowsGenerationAdvance = false
	state.AgentCredentialGeneration = receipt.AgentCredentialGeneration
	state.AgentCredentialExpiresAt = receipt.AgentCredentialExpiresAt
	state.LastSuccessfulConfigAt = a.currentTime()
	if err := a.Store.Save(state); err != nil {
		return SyncResult{}, fmt.Errorf("commit recovered agent credential: %w", err)
	}

	// An expired certificate is never staged or made live. The now-authenticated
	// bearer can renew the immutable public key; only a strictly newer signed
	// certificate artifact may then be activated.
	if !confirmed.CertificateExpiresAt.After(a.currentTime()) {
		return a.renewRecoveredCertificate(ctx, &state, keys, confirmed.CertificateGeneration)
	}
	return a.applyBootstrap(ctx, &state, keys, confirmed)
}

func keysForRecovery(privateKey, publicKey string) Bundle {
	return Bundle{PrivateKey: privateKey, PublicKey: publicKey}
}

// replacePendingRecoveryAfterAuthoritativeRejection distinguishes an unused
// or expired pending bearer from a committed recovery whose response was lost.
// Only an authenticated endpoint's explicit 401 permits overwriting the crash
// journal. A valid signed bootstrap proves the bearer is active and forces an
// exact resume with the retained token; every other result preserves the old
// token and bearer byte-for-byte.
func (a *Agent) replacePendingRecoveryAfterAuthoritativeRejection(ctx context.Context, state *State, keys Bundle, replacementToken string) error {
	pendingClient, err := NewClient(state.ServerURL, state.PendingBearer, a.HTTPClient)
	if err != nil {
		return err
	}
	bootstrap, err := pendingClient.Bootstrap(ctx)
	if err == nil {
		if _, _, verifyErr := verifyBootstrapBundle(*state, keys, bootstrap); verifyErr != nil {
			return fmt.Errorf("verify pending recovery bearer before token replacement: %w", verifyErr)
		}
		return ErrAgentRecoveryResumeRequired
	}
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("probe pending recovery bearer before token replacement: %w", err)
	}

	freshBearer, err := generateDistinctRecoveryBearer(state.Bearer, state.PendingBearer)
	if err != nil {
		return err
	}
	state.PendingRecoveryToken = replacementToken
	state.PendingBearer = freshBearer
	state.PendingRecoveryAllowsGenerationAdvance = true
	if err := a.Store.Save(*state); err != nil {
		return fmt.Errorf("persist replacement agent recovery request: %w", err)
	}
	return nil
}

func generateDistinctRecoveryBearer(activeBearer, previousPending string) (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		bearer, err := GenerateBearer()
		if err != nil {
			return "", err
		}
		if !control.TokenEqual(control.HashToken(activeBearer), bearer) &&
			!control.TokenEqual(control.HashToken(previousPending), bearer) {
			return bearer, nil
		}
	}
	return "", errors.New("could not generate a distinct replacement recovery bearer")
}

func verifyRecoveredAgentBundle(state State, keys Bundle, recovered control.AgentRecoveryBundle, pendingBearer string, now time.Time) (control.AgentConfig, Bundle, error) {
	receipt := recovered.RecoveryReceipt
	if err := control.VerifyRecoveryReceipt(state.ConfigSigningPublicKey, receipt); err != nil {
		return control.AgentConfig{}, Bundle{}, fmt.Errorf("verify pinned agent recovery receipt: %w", err)
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	validGeneration := state.AgentCredentialGeneration != maxInt64 && receipt.AgentCredentialGeneration == state.AgentCredentialGeneration+1
	if state.PendingRecoveryAllowsGenerationAdvance {
		validGeneration = receipt.AgentCredentialGeneration > state.AgentCredentialGeneration
	}
	if !validGeneration {
		return control.AgentConfig{}, Bundle{}, errors.New("agent recovery returned a non-monotonic credential generation")
	}
	if receipt.NodeID != state.NodeID || receipt.NetworkID != state.NetworkID {
		return control.AgentConfig{}, Bundle{}, errors.New("agent recovery receipt identity does not match the enrolled node")
	}
	if !control.TokenHashEqual(receipt.NewAgentTokenHash, control.HashToken(pendingBearer)) {
		return control.AgentConfig{}, Bundle{}, errors.New("agent recovery receipt does not authorize the pending bearer")
	}
	if receipt.AgentCredentialGeneration != recovered.AgentCredentialGeneration ||
		!receipt.AgentCredentialExpiresAt.Equal(recovered.AgentCredentialExpiresAt) {
		return control.AgentConfig{}, Bundle{}, errors.New("agent recovery receipt credential metadata does not match the bootstrap")
	}
	if !receipt.AgentCredentialExpiresAt.After(now) || receipt.AgentCredentialExpiresAt.After(now.Add(366*24*time.Hour)) {
		return control.AgentConfig{}, Bundle{}, errors.New("agent recovery returned an invalid credential expiry")
	}
	if receipt.ConfigSHA256 != recovered.ConfigSHA256 || receipt.ConfigSignature != recovered.ConfigSignature {
		return control.AgentConfig{}, Bundle{}, errors.New("agent recovery receipt does not match the signed bootstrap artifact")
	}
	desired, bundle, err := verifyBootstrapBundle(state, keys, recovered.EnrollmentBundle)
	if err != nil {
		return control.AgentConfig{}, Bundle{}, fmt.Errorf("verify recovered signed bootstrap: %w", err)
	}
	return desired, bundle, nil
}

func verifyBootstrapBundle(state State, keys Bundle, bootstrap control.EnrollmentBundle) (control.AgentConfig, Bundle, error) {
	if bootstrap.ConfigSigningPublicKey != state.ConfigSigningPublicKey {
		return control.AgentConfig{}, Bundle{}, errors.New("bootstrap config-signing key does not match the enrollment pin")
	}
	if canonicalPublicKeyHash(keys.PublicKey) != state.PublicKeyHash {
		return control.AgentConfig{}, Bundle{}, errors.New("bootstrap keypair does not match the enrolled public-key pin")
	}
	desired := control.AgentConfig{
		NodeID: bootstrap.NodeID, NetworkID: bootstrap.NetworkID,
		Revision: bootstrap.ConfigRevision, Config: bootstrap.Config, IssuedAt: bootstrap.ConfigIssuedAt,
		SHA256: bootstrap.ConfigSHA256, Signature: bootstrap.ConfigSignature,
		CertificateExpiresAt:  bootstrap.CertificateExpiresAt,
		CertificateRenewAfter: bootstrap.CertificateRenewAfter,
		CACertificateSHA256:   bootstrap.CACertificateSHA256, PreviousCACertificateSHA256: bootstrap.PreviousCACertificateSHA256,
		CARotationRequired: bootstrap.CARotationRequired, CertificateProfileRenewalRequired: bootstrap.CertificateProfileRenewalRequired, CertificateFingerprint: bootstrap.CertificateFingerprint,
		PublicKeyHash:         bootstrap.PublicKeyHash,
		CertificateGeneration: bootstrap.CertificateGeneration,
	}
	if err := VerifySignedConfig(state, desired); err != nil {
		return control.AgentConfig{}, Bundle{}, err
	}
	bundle := Bundle{
		NodeID: desired.NodeID, NetworkID: desired.NetworkID, Revision: desired.Revision,
		IssuedAt: desired.IssuedAt, Digest: desired.SHA256, Signature: desired.Signature,
		CACertificateSHA256: desired.CACertificateSHA256, PreviousCACertificateSHA256: desired.PreviousCACertificateSHA256,
		CARotationRequired: desired.CARotationRequired, CertificateProfileRenewalRequired: desired.CertificateProfileRenewalRequired, CertificateFingerprint: desired.CertificateFingerprint,
		CertificateExpiresAt: desired.CertificateExpiresAt, PublicKeyHash: desired.PublicKeyHash,
		CertificateRenewAfter: desired.CertificateRenewAfter,
		CertificateGeneration: desired.CertificateGeneration,
		SignedConfig:          desired.Config, CACertificate: bootstrap.CA, Certificate: bootstrap.Certificate,
		PrivateKey: keys.PrivateKey, PublicKey: keys.PublicKey,
	}
	if err := validateBundle(bundle, state.NodeID, state.NetworkID, state.ConfigSigningPublicKey, desired.CACertificateSHA256, state.PublicKeyHash); err != nil {
		return control.AgentConfig{}, Bundle{}, err
	}
	return desired, bundle, nil
}

func validateRecoveryBootstrapAdvance(recovered, confirmed control.EnrollmentBundle, receipt control.RecoveryReceipt) error {
	if confirmed.NodeID != recovered.NodeID || confirmed.NetworkID != recovered.NetworkID ||
		confirmed.ConfigSigningPublicKey != recovered.ConfigSigningPublicKey ||
		confirmed.CACertificateSHA256 != recovered.CACertificateSHA256 ||
		confirmed.PreviousCACertificateSHA256 != recovered.PreviousCACertificateSHA256 ||
		confirmed.PublicKeyHash != recovered.PublicKeyHash || confirmed.CA != recovered.CA {
		return errors.New("recovered bearer returned bootstrap data for different trust pins or identity")
	}
	if confirmed.AgentCredentialGeneration != receipt.AgentCredentialGeneration ||
		!confirmed.AgentCredentialExpiresAt.Equal(receipt.AgentCredentialExpiresAt) {
		return errors.New("recovered bearer did not confirm the receipt-authorized credential metadata")
	}
	if confirmed.ConfigRevision < recovered.ConfigRevision || confirmed.CertificateGeneration < recovered.CertificateGeneration {
		return ErrConfigRollback
	}
	if confirmed.ConfigRevision == recovered.ConfigRevision &&
		(confirmed.ConfigSHA256 != recovered.ConfigSHA256 || confirmed.Config != recovered.Config) {
		return ErrConfigEquivocation
	}
	if confirmed.CertificateGeneration == recovered.CertificateGeneration &&
		(confirmed.CertificateFingerprint != recovered.CertificateFingerprint ||
			!confirmed.CertificateExpiresAt.Equal(recovered.CertificateExpiresAt) ||
			!confirmed.CertificateRenewAfter.Equal(recovered.CertificateRenewAfter) ||
			confirmed.Certificate != recovered.Certificate) {
		return ErrConfigEquivocation
	}
	if confirmed.ConfigRevision == recovered.ConfigRevision &&
		confirmed.CertificateGeneration == recovered.CertificateGeneration &&
		(!confirmed.ConfigIssuedAt.Equal(recovered.ConfigIssuedAt) || confirmed.ConfigSignature != recovered.ConfigSignature) {
		return ErrConfigEquivocation
	}
	return nil
}

// validateRecoveryActivationCandidate performs the same Nebula certificate and
// configuration checks as activation without touching the live symlink or
// invoking the runtime reloader. Expired artifacts deliberately skip this path:
// they are never activated and must first be replaced through renewal.
func (a *Agent) validateRecoveryActivationCandidate(ctx context.Context, bundle Bundle) error {
	parent := filepath.Dir(a.Store.Path())
	stageDir, err := os.MkdirTemp(parent, ".agent-recovery-verify-")
	if err != nil {
		return fmt.Errorf("create recovery validation directory: %w", err)
	}
	defer os.RemoveAll(stageDir)
	if err := os.Chmod(stageDir, 0o700); err != nil {
		return fmt.Errorf("secure recovery validation directory: %w", err)
	}
	validationConfig, err := rewritePKIPaths(bundle.SignedConfig, stageDir)
	if err != nil {
		return err
	}
	for name, content := range map[string]string{
		"ca.crt": bundle.CACertificate, "host.crt": bundle.Certificate,
		"host.key": bundle.PrivateKey, "host.pub": bundle.PublicKey,
		"config.yml": validationConfig,
	} {
		if err := writeSyncedFile(filepath.Join(stageDir, name), []byte(content)); err != nil {
			return err
		}
	}
	details, err := a.Validator.Validate(ctx, stageDir, filepath.Join(stageDir, "config.yml"))
	if err != nil {
		return err
	}
	if details.Fingerprint != bundle.CertificateFingerprint || !details.ExpiresAt.Equal(bundle.CertificateExpiresAt) {
		return errors.New("verified recovery certificate does not match its signed metadata")
	}
	return nil
}

func (a *Agent) renewRecoveredCertificate(ctx context.Context, state *State, keys Bundle, minimumGeneration int64) (SyncResult, error) {
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return SyncResult{}, err
	}
	renewal, err := client.RenewCertificate(ctx, keys.PublicKey)
	if err != nil {
		return SyncResult{}, fmt.Errorf("renew expired certificate after agent recovery: %w", err)
	}
	desired := control.AgentConfig{
		NodeID: renewal.NodeID, NetworkID: renewal.NetworkID,
		Revision: renewal.ConfigRevision, Config: renewal.Config,
		IssuedAt: renewal.ConfigIssuedAt, SHA256: renewal.ConfigSHA256,
		Signature: renewal.ConfigSignature, CertificateExpiresAt: renewal.CertificateExpiresAt,
		CertificateRenewAfter: renewal.CertificateRenewAfter,
		CACertificateSHA256:   renewal.CACertificateSHA256, PreviousCACertificateSHA256: renewal.PreviousCACertificateSHA256,
		CARotationRequired: renewal.CARotationRequired, CertificateProfileRenewalRequired: renewal.CertificateProfileRenewalRequired, CertificateFingerprint: renewal.CertificateFingerprint,
		PublicKeyHash:         renewal.PublicKeyHash,
		CertificateGeneration: renewal.CertificateGeneration,
	}
	if err := VerifySignedConfig(*state, desired); err != nil {
		return SyncResult{}, fmt.Errorf("verify post-recovery certificate renewal: %w", err)
	}
	if desired.CertificateGeneration <= minimumGeneration || !desired.CertificateExpiresAt.After(a.currentTime()) {
		return SyncResult{}, errors.New("post-recovery certificate renewal did not return a newer valid certificate")
	}
	bundle := Bundle{
		NodeID: state.NodeID, NetworkID: state.NetworkID, Revision: desired.Revision,
		IssuedAt: desired.IssuedAt, Digest: desired.SHA256, Signature: desired.Signature,
		CACertificateSHA256: desired.CACertificateSHA256, PreviousCACertificateSHA256: desired.PreviousCACertificateSHA256,
		CARotationRequired: desired.CARotationRequired, CertificateProfileRenewalRequired: desired.CertificateProfileRenewalRequired, CertificateFingerprint: desired.CertificateFingerprint,
		CertificateExpiresAt: desired.CertificateExpiresAt, PublicKeyHash: desired.PublicKeyHash,
		CertificateRenewAfter: desired.CertificateRenewAfter,
		CertificateGeneration: desired.CertificateGeneration,
		SignedConfig:          desired.Config, CACertificate: renewal.CA, Certificate: renewal.Certificate,
		PrivateKey: keys.PrivateKey, PublicKey: keys.PublicKey,
	}
	activationState := *state
	activationState.CACertificateSHA256 = desired.CACertificateSHA256
	activation, err := a.activator(activationState).Apply(ctx, bundle)
	if err != nil {
		return SyncResult{}, fmt.Errorf("activate post-recovery certificate renewal: %w", err)
	}
	state.AppliedConfigRevision = desired.Revision
	state.AppliedConfigSHA256 = desired.SHA256
	state.CACertificateSHA256 = desired.CACertificateSHA256
	state.CertificateFingerprint = desired.CertificateFingerprint
	state.CertificateGeneration = desired.CertificateGeneration
	state.CertificateExpiresAt = activation.CertificateExpiresAt
	state.CertificateRenewAfter = desired.CertificateRenewAfter
	state.LastSuccessfulConfigAt = a.currentTime()
	if err := a.Store.Save(*state); err != nil {
		return SyncResult{}, fmt.Errorf("persist post-recovery certificate renewal: %w", err)
	}
	return SyncResult{Changed: true, Revision: desired.Revision, Digest: desired.SHA256}, nil
}

func validateCredentialRotation(state State, rotation control.CredentialRotation, now time.Time) error {
	if rotation.Generation != state.AgentCredentialGeneration+1 {
		return errors.New("agent credential rotation returned a non-monotonic generation")
	}
	if !rotation.ExpiresAt.After(now.Add(time.Hour)) || rotation.ExpiresAt.After(now.Add(366*24*time.Hour)) {
		return errors.New("agent credential rotation returned an invalid expiry")
	}
	return nil
}

func rejectPendingAgentRecovery(state State) error {
	if state.PendingRecoveryToken != "" {
		return ErrAgentRecoveryPending
	}
	return nil
}

// Heartbeat consumes and persists a sequence number before transmission. A
// failed request may leave a harmless gap, but can never cause a replay after a
// crash.
func (a *Agent) Heartbeat(ctx context.Context, health Health) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return 0, err
	}
	if err := EnforceMinimumNebulaVersion(health.NebulaVersion); err != nil {
		return 0, err
	}
	state, current, err := a.loadReconciledState(ctx)
	if err != nil {
		return 0, err
	}
	if health.CertificateFingerprint != "" && health.CertificateFingerprint != current.CertificateFingerprint {
		return 0, errors.New("reported certificate fingerprint does not match the verified live bundle")
	}
	if bootID, stable := systemBootID(); stable {
		state.BootID = bootID
	}
	state.HeartbeatSequence++
	if err := a.Store.Save(state); err != nil {
		return 0, fmt.Errorf("persist heartbeat sequence: %w", err)
	}
	status := strings.TrimSpace(health.Status)
	if status == "" {
		status = "healthy"
	}
	input := control.HeartbeatInput{
		AgentVersion: a.AgentVersion, NebulaVersion: health.NebulaVersion,
		AppliedConfigRevision: state.AppliedConfigRevision, AppliedConfigSHA256: state.AppliedConfigSHA256,
		CertificateFingerprint: current.CertificateFingerprint, CertificateGeneration: state.CertificateGeneration,
		NebulaRunning:   health.NebulaRunning,
		NativeDNSActive: health.NativeDNSActive,
		Status:          status, LastError: health.LastError, BootID: state.BootID, Sequence: state.HeartbeatSequence,
	}
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return state.HeartbeatSequence, err
	}
	if err := client.Heartbeat(ctx, input); err != nil {
		return state.HeartbeatSequence, err
	}
	return state.HeartbeatSequence, nil
}

// ReportConfigApplyFailure sends bounded evidence for server-side correlation.
// It does not change local applied state; Activator has already restored the
// previous live bundle before returning a ConfigActivationError.
func (a *Agent) ReportConfigApplyFailure(ctx context.Context, input control.ConfigApplyFailureInput) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ready(); err != nil {
		return err
	}
	state, err := a.Store.Load()
	if err != nil {
		return err
	}
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return err
	}
	return client.ReportConfigApplyFailure(ctx, input)
}

func VerifySignedConfig(state State, desired control.AgentConfig) error {
	if desired.NodeID != state.NodeID || desired.NetworkID != state.NetworkID {
		return errors.New("signed config identity does not match enrolled node")
	}
	if desired.Revision < 1 || !validDigest(desired.SHA256) {
		return errors.New("signed config revision or digest is invalid")
	}
	if desired.PublicKeyHash != state.PublicKeyHash {
		return errors.New("signed config CA or public key does not match the enrollment pin")
	}
	if err := control.VerifyConfig(state.ConfigSigningPublicKey, desired.SignatureMetadata(), desired.Config, desired.SHA256, desired.Signature); err != nil {
		return fmt.Errorf("verify pinned config signature: %w", err)
	}
	if desired.CACertificateSHA256 != state.CACertificateSHA256 && desired.PreviousCACertificateSHA256 != state.CACertificateSHA256 {
		return errors.New("signed config CA or public key transition does not descend from the enrollment pin")
	}
	if desired.Revision < state.AppliedConfigRevision {
		return ErrConfigRollback
	}
	if desired.CertificateGeneration < state.CertificateGeneration {
		return ErrConfigRollback
	}
	if desired.CertificateGeneration == state.CertificateGeneration && state.CertificateFingerprint != "" && (desired.CertificateFingerprint != state.CertificateFingerprint || !desired.CertificateExpiresAt.Equal(state.CertificateExpiresAt) || !desired.CertificateRenewAfter.Equal(state.CertificateRenewAfter)) {
		return ErrConfigEquivocation
	}
	if desired.Revision == state.AppliedConfigRevision && state.AppliedConfigRevision > 0 && desired.SHA256 != state.AppliedConfigSHA256 {
		return ErrConfigEquivocation
	}
	return nil
}

func (a *Agent) ready() error {
	if a.Store == nil {
		return errors.New("agent state store is required")
	}
	if a.Reloader == nil {
		return errors.New("agent Nebula reloader is required")
	}
	if strings.TrimSpace(a.AgentVersion) == "" || len(a.AgentVersion) > 64 {
		return errors.New("agent version is required")
	}
	if a.processLock == nil {
		lock, err := a.Store.AcquireProcessLock()
		if err != nil {
			return err
		}
		a.processLock = lock
	}
	return nil
}

func (a *Agent) currentTime() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// recordConfigSuccess persists proof that the control plane confirmed the
// current signed artifact. It deliberately coalesces unchanged polls so a
// one-minute agent cadence does not force an fsync on every HTTP 304.
func (a *Agent) recordConfigSuccess(state *State) error {
	now := a.currentTime()
	persistInterval := a.ConfigSuccessPersistInterval
	if persistInterval <= 0 {
		persistInterval = configSuccessPersistInterval
	}
	if !state.LastSuccessfulConfigAt.IsZero() &&
		!now.Before(state.LastSuccessfulConfigAt) &&
		now.Sub(state.LastSuccessfulConfigAt) < persistInterval {
		return nil
	}
	state.LastSuccessfulConfigAt = now
	if err := a.Store.Save(*state); err != nil {
		return fmt.Errorf("persist successful config contact: %w", err)
	}
	return nil
}

// Close releases the lifetime process lock. A running service should defer
// Close immediately after constructing its Agent.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.processLock == nil {
		return nil
	}
	err := a.processLock.Close()
	a.processLock = nil
	return err
}

func (a *Agent) activator(state State) *Activator {
	return &Activator{
		OutputDir: state.OutputDir, NodeID: state.NodeID, NetworkID: state.NetworkID,
		ConfigSigningPublicKey: state.ConfigSigningPublicKey,
		CACertificateSHA256:    state.CACertificateSHA256,
		PublicKeyHash:          state.PublicKeyHash,
		Validator:              a.Validator, Reloader: a.Reloader,
	}
}

func (a *Agent) currentBundle(ctx context.Context, state State) (Bundle, error) {
	bundle, err := a.activator(state).CurrentBundle(ctx)
	if err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// loadReconciledState treats the already validated live symlink as the commit
// record. This closes the crash window between a successful reload and the
// subsequent state-file update, including same-revision certificate renewals.
func (a *Agent) loadReconciledState(ctx context.Context) (State, Bundle, error) {
	state, err := a.Store.Load()
	if err != nil {
		return State{}, Bundle{}, err
	}
	if err := rejectPendingAgentRecovery(state); err != nil {
		return State{}, Bundle{}, err
	}
	current, err := a.currentBundle(ctx, state)
	if err != nil {
		client, clientErr := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
		if clientErr != nil {
			return State{}, Bundle{}, errors.Join(err, clientErr)
		}
		bootstrap, bootstrapErr := client.Bootstrap(ctx)
		if bootstrapErr != nil {
			return State{}, Bundle{}, errors.Join(err, bootstrapErr)
		}
		privateKey, publicKey, keyErr := a.Store.LoadRecoveryKeyPair()
		if keyErr != nil {
			return State{}, Bundle{}, errors.Join(err, keyErr)
		}
		recovered := Bundle{PrivateKey: privateKey, PublicKey: publicKey}
		if _, recoveryErr := a.applyBootstrap(ctx, &state, recovered, bootstrap); recoveryErr != nil {
			return State{}, Bundle{}, errors.Join(err, recoveryErr)
		}
		current, err = a.currentBundle(ctx, state)
		if err != nil {
			return State{}, Bundle{}, err
		}
	}
	if current.Revision < state.AppliedConfigRevision || current.CertificateGeneration < state.CertificateGeneration {
		return State{}, Bundle{}, ErrConfigRollback
	}
	if current.Revision == state.AppliedConfigRevision && state.AppliedConfigRevision > 0 && current.Digest != state.AppliedConfigSHA256 {
		return State{}, Bundle{}, ErrConfigEquivocation
	}
	if current.CertificateGeneration == state.CertificateGeneration && (current.CertificateFingerprint != state.CertificateFingerprint || !current.CertificateExpiresAt.Equal(state.CertificateExpiresAt) || !current.CertificateRenewAfter.Equal(state.CertificateRenewAfter)) {
		return State{}, Bundle{}, ErrConfigEquivocation
	}
	changed := current.Revision > state.AppliedConfigRevision || current.CertificateGeneration > state.CertificateGeneration || current.Digest != state.AppliedConfigSHA256 || current.CertificateFingerprint != state.CertificateFingerprint || !current.CertificateExpiresAt.Equal(state.CertificateExpiresAt) || !current.CertificateRenewAfter.Equal(state.CertificateRenewAfter)
	if changed {
		state.AppliedConfigRevision = current.Revision
		state.AppliedConfigSHA256 = current.Digest
		state.CACertificateSHA256 = current.CACertificateSHA256
		state.CertificateFingerprint = current.CertificateFingerprint
		state.CertificateGeneration = current.CertificateGeneration
		state.CertificateExpiresAt = current.CertificateExpiresAt
		state.CertificateRenewAfter = current.CertificateRenewAfter
		if err := a.Store.Save(state); err != nil {
			return State{}, Bundle{}, fmt.Errorf("reconcile live Nebula bundle state: %w", err)
		}
	}
	return state, current, nil
}

func (a *Agent) applyBootstrap(ctx context.Context, state *State, keys Bundle, bootstrap control.EnrollmentBundle) (SyncResult, error) {
	desired, bundle, err := verifyBootstrapBundle(*state, keys, bootstrap)
	if err != nil {
		return SyncResult{}, err
	}
	activationState := *state
	activationState.CACertificateSHA256 = desired.CACertificateSHA256
	activation, err := a.activator(activationState).Apply(ctx, bundle)
	if err != nil {
		return SyncResult{}, err
	}
	state.AppliedConfigRevision = desired.Revision
	state.AppliedConfigSHA256 = desired.SHA256
	state.CACertificateSHA256 = desired.CACertificateSHA256
	state.CertificateFingerprint = desired.CertificateFingerprint
	state.CertificateGeneration = desired.CertificateGeneration
	state.CertificateExpiresAt = activation.CertificateExpiresAt
	state.CertificateRenewAfter = desired.CertificateRenewAfter
	state.AgentCredentialExpiresAt = bootstrap.AgentCredentialExpiresAt
	state.AgentCredentialGeneration = bootstrap.AgentCredentialGeneration
	if err := a.Store.Save(*state); err != nil {
		return SyncResult{}, fmt.Errorf("persist recovered agent bootstrap: %w", err)
	}
	return SyncResult{Changed: true, Revision: desired.Revision, Digest: desired.SHA256}, nil
}
