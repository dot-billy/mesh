package iosmobile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"time"

	"mesh/internal/configsignature"
	"mesh/internal/mobileruntime"
)

const (
	lifecycleRefreshSchema     = "mesh-ios-lifecycle-refresh-v1"
	mobileRuntimeReportSchema  = "mesh-ios-mobile-runtime-report-v1"
	credentialRotationLeadTime = 7 * 24 * time.Hour
)

type lifecycleRefreshStatus string

const (
	lifecycleRefreshReady        lifecycleRefreshStatus = "ready"
	lifecycleRefreshDeferred     lifecycleRefreshStatus = "deferred"
	lifecycleRefreshUnauthorized lifecycleRefreshStatus = "unauthorized"
)

type lifecycleRefreshOutcome struct {
	Schema        string                 `json:"schema"`
	Status        lifecycleRefreshStatus `json:"status"`
	Configuration string                 `json:"configuration,omitempty"`
}

type mobileRuntimeReportStatus string

const (
	mobileRuntimeReportAccepted        mobileRuntimeReportStatus = "accepted"
	mobileRuntimeReportDeferred        mobileRuntimeReportStatus = "deferred"
	mobileRuntimeReportUnauthorized    mobileRuntimeReportStatus = "unauthorized"
	mobileRuntimeReportRefreshRequired mobileRuntimeReportStatus = "refresh-required"
	mobileRuntimeReportUnsupported     mobileRuntimeReportStatus = "unsupported"
)

type mobileRuntimeReportOutcome struct {
	Schema string                    `json:"schema"`
	Status mobileRuntimeReportStatus `json:"status"`
}

// LifecycleSession owns one extension-only, agent-authenticated desired-state
// refresh. It can return a verified replacement configuration, a bounded
// offline deferral, or an authorization rejection. It never returns the
// private key or agent bearer.
type LifecycleSession struct {
	loadPrivateKey                 privateKeyLoader
	loadAgentSecret                enrollmentSecretLoader
	loadPendingAgentSecret         enrollmentSecretLoader
	loadOrCreatePendingAgentSecret enrollmentSecretLoader
	replaceAgentSecret             func([]byte) error
	deletePendingAgentSecret       func() error
	httpClient                     *http.Client
	resolve                        enrollmentResolver
	now                            func() time.Time
}

// NewLifecycleSession binds refresh to existing extension-only credentials.
// Unlike enrollment, refresh never creates a missing identity or agent item.
func NewLifecycleSession(
	accessGroup string,
	identityID string,
) (*LifecycleSession, error) {
	if err := validateIdentityScope(accessGroup, identityID); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	session := newLifecycleSession(
		func() ([]byte, error) {
			return loadPrivateKey(accessGroup, identityID)
		},
		func() ([]byte, error) {
			return loadSecret(
				accessGroup,
				agentCredentialService,
				identityID,
			)
		},
		client,
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		func() time.Time { return time.Now().UTC() },
	)
	session.loadPendingAgentSecret = func() ([]byte, error) {
		return loadSecret(
			accessGroup,
			pendingAgentCredentialService,
			identityID,
		)
	}
	session.loadOrCreatePendingAgentSecret = func() ([]byte, error) {
		return loadOrCreateSecret(
			accessGroup,
			pendingAgentCredentialService,
			identityID,
		)
	}
	session.replaceAgentSecret = func(secret []byte) error {
		return replaceSecret(
			accessGroup,
			agentCredentialService,
			identityID,
			secret,
		)
	}
	session.deletePendingAgentSecret = func() error {
		return deleteSecret(
			accessGroup,
			pendingAgentCredentialService,
			identityID,
		)
	}
	return session, nil
}

func newLifecycleSession(
	privateKeyLoader privateKeyLoader,
	agentSecretLoader enrollmentSecretLoader,
	client *http.Client,
	resolver enrollmentResolver,
	now func() time.Time,
) *LifecycleSession {
	return &LifecycleSession{
		loadPrivateKey:  privateKeyLoader,
		loadAgentSecret: agentSecretLoader,
		httpClient:      client,
		resolve:         resolver,
		now:             now,
	}
}

// Refresh authenticates the exact stored origin against the extension-owned
// agent credential and returns only a verified monotonically newer envelope
// payload. Transport, 429, and 5xx failures defer to the still-valid current
// payload; authorization rejection and malformed authenticated state do not.
func (s *LifecycleSession) Refresh(
	serverURL string,
	currentConfigurationJSON string,
	monotonicCounter int64,
) (string, error) {
	if s == nil ||
		s.loadPrivateKey == nil ||
		s.loadAgentSecret == nil ||
		s.httpClient == nil ||
		s.resolve == nil ||
		s.now == nil {
		return "", errors.New("lifecycle session is unavailable")
	}
	if monotonicCounter < 1 {
		return "", errors.New("lifecycle monotonic counter is invalid")
	}
	origin, err := normalizeEnrollmentOrigin(serverURL)
	if err != nil {
		return "", err
	}
	privateKey, err := s.loadPrivateKey()
	if err != nil {
		return "", errors.New("existing extension identity key is unavailable")
	}
	defer clear(privateKey)
	current, err := decodeEngineConfiguration(currentConfigurationJSON)
	if err != nil || current.ControlPlaneOrigin != origin {
		return "", errors.New("current lifecycle configuration is invalid")
	}
	verifiedCurrent, err := verifyEngineConfiguration(
		currentConfigurationJSON,
		privateKey,
	)
	if err != nil {
		return "", errors.New("current lifecycle configuration is untrusted")
	}
	agentSecret, err := s.loadAgentSecret()
	if err != nil || len(agentSecret) != 32 {
		clear(agentSecret)
		return "", errors.New("existing extension agent credential is unavailable")
	}
	defer clear(agentSecret)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	defer func() { agentBearer = "" }()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	requester := newEnrollmentSession(
		s.loadPrivateKey,
		s.loadAgentSecret,
		s.httpClient,
		s.resolve,
		s.now,
	)
	var bundle enrollmentBundle
	err = requester.requestJSON(
		ctx,
		http.MethodGet,
		origin+"/api/v1/agent/bootstrap",
		agentBearer,
		nil,
		&bundle,
	)
	if err != nil {
		var responseErr *enrollmentHTTPError
		var transportErr *enrollmentTransportError
		switch {
		case errors.As(err, &responseErr) &&
			responseErr.status == http.StatusUnauthorized:
			return marshalLifecycleRefresh(lifecycleRefreshOutcome{
				Schema: lifecycleRefreshSchema,
				Status: lifecycleRefreshUnauthorized,
			})
		case errors.As(err, &transportErr),
			errors.As(err, &responseErr) &&
				(responseErr.status == http.StatusTooManyRequests ||
					responseErr.status >= http.StatusInternalServerError):
			return marshalLifecycleRefresh(lifecycleRefreshOutcome{
				Schema: lifecycleRefreshSchema,
				Status: lifecycleRefreshDeferred,
			})
		default:
			return "", errors.New("authenticated lifecycle refresh failed")
		}
	}
	if bundle.NetworkID != current.NetworkID ||
		bundle.NodeID != current.NodeID ||
		bundle.ConfigRevision < int64(current.ConfigRevision) ||
		bundle.CertificateGeneration < int64(current.CertificateGeneration) ||
		bundle.AgentCredentialGeneration <
			int64(current.AgentCredentialGeneration) ||
		bundle.ConfigSigningPublicKey !=
			current.Nebula.ConfigSigningPublicKey ||
		bundle.ConfigRevision > math.MaxInt64 ||
		bundle.CertificateGeneration > math.MaxInt64 {
		return "", errors.New("lifecycle refresh attempted identity rollback")
	}
	publicKey, err := publicKeyPEM(privateKey)
	if err != nil {
		return "", err
	}
	if enrollmentTokenHash(publicKey) != bundle.PublicKeyHash ||
		configsignature.Digest(bundle.Config) != bundle.ConfigSHA256 ||
		configsignature.Digest(bundle.CA) != bundle.CACertificateSHA256 ||
		configsignature.Verify(
			current.Nebula.ConfigSigningPublicKey,
			bundle.signatureMetadata(),
			bundle.Config,
			bundle.ConfigSHA256,
			bundle.ConfigSignature,
		) != nil {
		return "", errors.New(
			"authenticated lifecycle bootstrap signature is invalid",
		)
	}
	bundle, agentBearer, err = s.rotateAgentCredentialIfNeeded(
		ctx,
		requester,
		origin,
		agentBearer,
		current,
		bundle,
	)
	if err != nil {
		var responseErr *enrollmentHTTPError
		var transportErr *enrollmentTransportError
		switch {
		case errors.As(err, &responseErr) &&
			responseErr.status == http.StatusUnauthorized:
			return marshalLifecycleRefresh(lifecycleRefreshOutcome{
				Schema: lifecycleRefreshSchema,
				Status: lifecycleRefreshUnauthorized,
			})
		case errors.As(err, &transportErr),
			errors.As(err, &responseErr) &&
				(responseErr.status == http.StatusTooManyRequests ||
					responseErr.status >= http.StatusInternalServerError):
			return marshalLifecycleRefresh(lifecycleRefreshOutcome{
				Schema: lifecycleRefreshSchema,
				Status: lifecycleRefreshDeferred,
			})
		default:
			return "", errors.New(
				"authenticated agent credential rotation failed",
			)
		}
	}
	renewalRequired := bundle.CARotationRequired ||
		bundle.CertificateProfileRenewalRequired ||
		!bundle.CertificateRenewAfter.After(s.now().UTC())
	if renewalRequired {
		renewed, renewalErr := s.renewCertificate(
			ctx,
			requester,
			origin,
			agentBearer,
			publicKey,
			bundle,
		)
		if renewalErr != nil {
			var responseErr *enrollmentHTTPError
			var transportErr *enrollmentTransportError
			mandatory := bundle.CARotationRequired ||
				bundle.CertificateProfileRenewalRequired
			switch {
			case errors.As(renewalErr, &responseErr) &&
				responseErr.status == http.StatusUnauthorized:
				return marshalLifecycleRefresh(lifecycleRefreshOutcome{
					Schema: lifecycleRefreshSchema,
					Status: lifecycleRefreshUnauthorized,
				})
			case !mandatory &&
				(errors.As(renewalErr, &transportErr) ||
					errors.As(renewalErr, &responseErr) &&
						(responseErr.status == http.StatusTooManyRequests ||
							responseErr.status >= http.StatusInternalServerError)):
				return marshalLifecycleRefresh(lifecycleRefreshOutcome{
					Schema: lifecycleRefreshSchema,
					Status: lifecycleRefreshDeferred,
				})
			default:
				return "", errors.New(
					"authenticated certificate renewal failed",
				)
			}
		}
		bundle = renewed
	}
	currentNetworks := verifiedCurrent.certificate.Networks()
	if len(currentNetworks) != 1 {
		return "", errors.New("current lifecycle network is invalid")
	}
	refreshPlan := enrollmentPreflight{
		Schema:      enrollmentPreflightV1,
		TargetRole:  "member",
		NetworkCIDR: currentNetworks[0].Masked().String(),
	}
	document, err := requester.configurationDocument(
		ctx,
		bundle,
		privateKey,
		publicKey,
		uint64(monotonicCounter),
		s.now().UTC(),
		origin,
		refreshPlan,
		nil,
	)
	if err != nil {
		return "", err
	}
	return marshalLifecycleRefresh(lifecycleRefreshOutcome{
		Schema:        lifecycleRefreshSchema,
		Status:        lifecycleRefreshReady,
		Configuration: document,
	})
}

func (s *LifecycleSession) rotateAgentCredentialIfNeeded(
	ctx context.Context,
	requester *EnrollmentSession,
	origin string,
	currentBearer string,
	current engineConfiguration,
	bootstrap enrollmentBundle,
) (enrollmentBundle, string, error) {
	now := s.now().UTC()
	recoverPending := bootstrap.AgentCredentialGeneration >
		int64(current.AgentCredentialGeneration)
	rotationDue := !bootstrap.AgentCredentialExpiresAt.After(
		now.Add(credentialRotationLeadTime),
	)
	if !recoverPending && !rotationDue {
		return bootstrap, currentBearer, nil
	}
	if s.loadPendingAgentSecret == nil ||
		s.loadOrCreatePendingAgentSecret == nil ||
		s.replaceAgentSecret == nil ||
		s.deletePendingAgentSecret == nil {
		return enrollmentBundle{}, "", errors.New(
			"agent credential rotation vault is unavailable",
		)
	}
	var pending []byte
	var err error
	if recoverPending {
		pending, err = s.loadPendingAgentSecret()
		if err != nil {
			// A newer authenticated bootstrap with no pending value means the
			// main Keychain item was already committed before the previous
			// configuration envelope. No additional rotation is required.
			return bootstrap, currentBearer, nil
		}
	} else {
		pending, err = s.loadOrCreatePendingAgentSecret()
	}
	if err != nil || len(pending) != 32 {
		clear(pending)
		return enrollmentBundle{}, "", errors.New(
			"pending agent credential is unavailable",
		)
	}
	defer clear(pending)
	pendingBearer := base64.RawURLEncoding.EncodeToString(pending)
	defer func() { pendingBearer = "" }()
	payload := struct {
		NewTokenHash string `json:"new_token_hash"`
	}{NewTokenHash: enrollmentTokenHash(pendingBearer)}

	rotation, err := s.requestCredentialRotation(
		ctx,
		requester,
		origin,
		currentBearer,
		pendingBearer,
		payload,
	)
	if err != nil {
		return enrollmentBundle{}, "", err
	}
	expectedGeneration := bootstrap.AgentCredentialGeneration + 1
	if recoverPending {
		expectedGeneration = bootstrap.AgentCredentialGeneration
	}
	if rotation.Generation != expectedGeneration ||
		!rotation.ExpiresAt.After(now.Add(time.Hour)) ||
		rotation.ExpiresAt.After(now.Add(366*24*time.Hour)) {
		return enrollmentBundle{}, "", errors.New(
			"agent credential rotation metadata is invalid",
		)
	}
	if err := s.replaceAgentSecret(pending); err != nil {
		return enrollmentBundle{}, "", errors.New(
			"commit rotated agent credential",
		)
	}
	if err := s.deletePendingAgentSecret(); err != nil {
		return enrollmentBundle{}, "", errors.New(
			"finalize rotated agent credential",
		)
	}
	bootstrap.AgentCredentialGeneration = rotation.Generation
	bootstrap.AgentCredentialExpiresAt = rotation.ExpiresAt
	bootstrap.Node.AgentCredentialGeneration = rotation.Generation
	bootstrap.Node.AgentCredentialExpiresAt = pointerToLifecycleTime(
		rotation.ExpiresAt,
	)
	return bootstrap, pendingBearer, nil
}

func (s *LifecycleSession) requestCredentialRotation(
	ctx context.Context,
	requester *EnrollmentSession,
	origin string,
	currentBearer string,
	pendingBearer string,
	payload any,
) (credentialRotation, error) {
	var rotation credentialRotation
	firstErr := requester.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/agent/credentials/rotate",
		currentBearer,
		payload,
		&rotation,
	)
	if firstErr == nil {
		return rotation, nil
	}
	var responseErr *enrollmentHTTPError
	var transportErr *enrollmentTransportError
	if !errors.As(firstErr, &transportErr) &&
		(!errors.As(firstErr, &responseErr) ||
			responseErr.status != http.StatusUnauthorized &&
				responseErr.status != http.StatusTooManyRequests &&
				responseErr.status < http.StatusInternalServerError) {
		return credentialRotation{}, firstErr
	}

	// The pending bearer is authoritative after an ambiguous server commit and
	// is also accepted during the server's old-credential grace window.
	var recovered credentialRotation
	recoveryErr := requester.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/agent/credentials/rotate",
		pendingBearer,
		payload,
		&recovered,
	)
	if recoveryErr == nil {
		return recovered, nil
	}
	if lifecycleRenewalTerminal(recoveryErr) {
		return credentialRotation{}, recoveryErr
	}
	return credentialRotation{}, errors.Join(firstErr, recoveryErr)
}

func (s *LifecycleSession) renewCertificate(
	ctx context.Context,
	requester *EnrollmentSession,
	origin string,
	agentBearer string,
	publicKey string,
	bootstrap enrollmentBundle,
) (enrollmentBundle, error) {
	payload := struct {
		PublicKey string `json:"public_key"`
	}{PublicKey: publicKey}
	var first renewalBundle
	firstErr := requester.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/agent/certificate/renew",
		agentBearer,
		payload,
		&first,
	)
	if firstErr == nil {
		return mergeRenewalBundle(bootstrap, first)
	}
	var responseErr *enrollmentHTTPError
	if errors.As(firstErr, &responseErr) &&
		responseErr.status != http.StatusTooManyRequests &&
		responseErr.status < http.StatusInternalServerError {
		return enrollmentBundle{}, firstErr
	}

	// Renewal is idempotently replayed by the control plane. Retry the exact
	// request once, then recover an already committed result from bootstrap.
	var replay renewalBundle
	replayErr := requester.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/agent/certificate/renew",
		agentBearer,
		payload,
		&replay,
	)
	if replayErr == nil {
		return mergeRenewalBundle(bootstrap, replay)
	}
	if lifecycleRenewalTerminal(replayErr) {
		return enrollmentBundle{}, replayErr
	}
	var recovered enrollmentBundle
	recoveryErr := requester.requestJSON(
		ctx,
		http.MethodGet,
		origin+"/api/v1/agent/bootstrap",
		agentBearer,
		nil,
		&recovered,
	)
	if recoveryErr == nil &&
		recovered.NodeID == bootstrap.NodeID &&
		recovered.NetworkID == bootstrap.NetworkID &&
		recovered.CertificateGeneration > bootstrap.CertificateGeneration {
		return recovered, nil
	}
	if lifecycleRenewalTerminal(recoveryErr) {
		return enrollmentBundle{}, recoveryErr
	}
	if recoveryErr == nil {
		recoveryErr = errors.New(
			"recovered bootstrap did not contain a newer certificate",
		)
	}
	return enrollmentBundle{}, errors.Join(
		firstErr,
		fmt.Errorf("identical certificate renewal replay failed: %w", replayErr),
		fmt.Errorf("recover committed certificate renewal: %w", recoveryErr),
	)
}

func lifecycleRenewalTerminal(err error) bool {
	var responseErr *enrollmentHTTPError
	return errors.As(err, &responseErr) &&
		responseErr.status != http.StatusTooManyRequests &&
		responseErr.status < http.StatusInternalServerError
}

func mergeRenewalBundle(
	bootstrap enrollmentBundle,
	renewal renewalBundle,
) (enrollmentBundle, error) {
	if renewal.NodeID != bootstrap.NodeID ||
		renewal.NetworkID != bootstrap.NetworkID ||
		renewal.ConfigRevision < bootstrap.ConfigRevision ||
		renewal.CertificateGeneration <= bootstrap.CertificateGeneration {
		return enrollmentBundle{}, errors.New(
			"certificate renewal attempted identity rollback",
		)
	}
	node := bootstrap.Node
	node.Certificate = renewal.Certificate
	node.CertificateFingerprint = renewal.CertificateFingerprint
	node.CertificateAuthoritySHA256 = renewal.CACertificateSHA256
	node.CertificateExpiresAt = pointerToLifecycleTime(
		renewal.CertificateExpiresAt,
	)
	node.CertificateRenewAfter = pointerToLifecycleTime(
		renewal.CertificateRenewAfter,
	)
	node.CertificateGeneration = renewal.CertificateGeneration
	return enrollmentBundle{
		NodeID:                            renewal.NodeID,
		NetworkID:                         renewal.NetworkID,
		Node:                              node,
		Certificate:                       renewal.Certificate,
		CA:                                renewal.CA,
		Config:                            renewal.Config,
		ConfigRevision:                    renewal.ConfigRevision,
		CertificateExpiresAt:              renewal.CertificateExpiresAt,
		CertificateRenewAfter:             renewal.CertificateRenewAfter,
		AgentCredentialExpiresAt:          bootstrap.AgentCredentialExpiresAt,
		AgentCredentialGeneration:         bootstrap.AgentCredentialGeneration,
		ConfigIssuedAt:                    renewal.ConfigIssuedAt,
		ConfigSHA256:                      renewal.ConfigSHA256,
		CACertificateSHA256:               renewal.CACertificateSHA256,
		PreviousCACertificateSHA256:       renewal.PreviousCACertificateSHA256,
		CARotationRequired:                renewal.CARotationRequired,
		CertificateProfileRenewalRequired: renewal.CertificateProfileRenewalRequired,
		CertificateFingerprint:            renewal.CertificateFingerprint,
		CertificateGeneration:             renewal.CertificateGeneration,
		PublicKeyHash:                     renewal.PublicKeyHash,
		ConfigSignature:                   renewal.ConfigSignature,
		ConfigSigningPublicKey:            bootstrap.ConfigSigningPublicKey,
	}, nil
}

func pointerToLifecycleTime(value time.Time) *time.Time {
	return &value
}

// ReportRuntime publishes one extension-authored mobile lifecycle observation
// bound to the already verified local identity and configuration. It returns a
// bounded status document instead of leaking HTTP or credential detail.
func (s *LifecycleSession) ReportRuntime(
	serverURL string,
	currentConfigurationJSON string,
	instanceGeneration int64,
	sequence int64,
	state string,
	runtimeUptimeMS int64,
	packetsRead int64,
	packetsWritten int64,
	hasPacketCounters bool,
	errorCode string,
) (string, error) {
	if s == nil ||
		s.loadPrivateKey == nil ||
		s.loadAgentSecret == nil ||
		s.httpClient == nil ||
		s.now == nil {
		return "", errors.New("lifecycle session is unavailable")
	}
	if instanceGeneration < 1 ||
		sequence < 1 ||
		runtimeUptimeMS < 0 ||
		packetsRead < 0 ||
		packetsWritten < 0 {
		return "", errors.New("mobile runtime counter is invalid")
	}
	origin, err := normalizeEnrollmentOrigin(serverURL)
	if err != nil {
		return "", err
	}
	privateKey, err := s.loadPrivateKey()
	if err != nil {
		return "", errors.New("existing extension identity key is unavailable")
	}
	defer clear(privateKey)
	current, err := decodeEngineConfiguration(currentConfigurationJSON)
	if err != nil || current.ControlPlaneOrigin != origin {
		return "", errors.New("current mobile runtime configuration is invalid")
	}
	if _, err := verifyEngineConfiguration(
		currentConfigurationJSON,
		privateKey,
	); err != nil {
		return "", errors.New("current mobile runtime configuration is untrusted")
	}
	agentSecret, err := s.loadAgentSecret()
	if err != nil || len(agentSecret) != 32 {
		clear(agentSecret)
		return "", errors.New("existing extension agent credential is unavailable")
	}
	defer clear(agentSecret)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	defer func() { agentBearer = "" }()

	input := mobileruntime.ReportInput{
		Version:                mobileruntime.VersionV1,
		InstanceGeneration:     instanceGeneration,
		Sequence:               sequence,
		State:                  state,
		ConfigRevision:         int64(current.ConfigRevision),
		ConfigSHA256:           current.ConfigDigest,
		CertificateFingerprint: current.CertificateFingerprint,
		CertificateGeneration:  int64(current.CertificateGeneration),
		EngineIdentity:         current.EngineIdentity,
		RuntimeUptimeMS:        uint64(runtimeUptimeMS),
		ErrorCode:              errorCode,
	}
	if hasPacketCounters {
		read, written := uint64(packetsRead), uint64(packetsWritten)
		input.PacketsRead = &read
		input.PacketsWritten = &written
	}
	if err := mobileruntime.Validate(input); err != nil {
		return "", errors.New("mobile runtime evidence is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = s.postMobileRuntime(
		ctx,
		origin+"/api/v1/agent/mobile-runtime",
		agentBearer,
		input,
	)
	if err == nil {
		return marshalMobileRuntimeReport(mobileRuntimeReportAccepted)
	}
	var responseErr *enrollmentHTTPError
	var transportErr *enrollmentTransportError
	switch {
	case errors.As(err, &responseErr) &&
		responseErr.status == http.StatusUnauthorized:
		return marshalMobileRuntimeReport(mobileRuntimeReportUnauthorized)
	case errors.As(err, &responseErr) &&
		responseErr.status == http.StatusConflict:
		return marshalMobileRuntimeReport(mobileRuntimeReportRefreshRequired)
	case errors.As(err, &responseErr) &&
		(responseErr.status == http.StatusNotFound ||
			responseErr.status == http.StatusMethodNotAllowed):
		return marshalMobileRuntimeReport(mobileRuntimeReportUnsupported)
	case errors.As(err, &transportErr),
		errors.As(err, &responseErr) &&
			(responseErr.status == http.StatusTooManyRequests ||
				responseErr.status >= http.StatusInternalServerError):
		return marshalMobileRuntimeReport(mobileRuntimeReportDeferred)
	default:
		return "", errors.New("authenticated mobile runtime report failed")
	}
}

func (s *LifecycleSession) postMobileRuntime(
	ctx context.Context,
	endpoint string,
	bearer string,
	input mobileruntime.ReportInput,
) error {
	raw, err := json.Marshal(input)
	if err != nil ||
		len(raw) == 0 ||
		len(raw) > mobileruntime.MaxReportBytes {
		return errors.New("encode bounded mobile runtime request")
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(raw),
	)
	if err != nil {
		return errors.New("build bounded mobile runtime request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := s.httpClient.Do(request)
	if err != nil {
		return &enrollmentTransportError{}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &enrollmentHTTPError{status: response.StatusCode}
	}
	if !headerHasDirective(response.Header.Values("Cache-Control"), "no-store") {
		return errors.New("mobile runtime response is cacheable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2))
	if err != nil || len(body) != 0 {
		return errors.New("mobile runtime response is invalid")
	}
	return nil
}

func marshalLifecycleRefresh(
	value lifecycleRefreshOutcome,
) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("encode lifecycle refresh outcome")
	}
	return string(raw), nil
}

func marshalMobileRuntimeReport(
	status mobileRuntimeReportStatus,
) (string, error) {
	raw, err := json.Marshal(mobileRuntimeReportOutcome{
		Schema: mobileRuntimeReportSchema,
		Status: status,
	})
	if err != nil {
		return "", errors.New("encode mobile runtime report outcome")
	}
	return string(raw), nil
}
