package iosmobile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"

	"mesh/internal/configsignature"
)

const (
	agentCredentialService        = "io.rw0.mesh.tunnel.mobile.agent.v1"
	pendingAgentCredentialService = "io.rw0.mesh.tunnel.mobile.agent.pending.v1"
	maximumEnrollmentBody         = 8 << 20
	defaultTunnelMTU              = 1300
	enrollmentPreflightV1         = "mesh-enrollment-preflight-v1"
	nativeDNSPolicyV1             = "mesh-native-dns-v1"
	nativeDNSPolicyPrefix         = "# mesh-native-dns-v1 "
)

type enrollmentSecretLoader func() ([]byte, error)
type enrollmentResolver func(context.Context, string) ([]netip.Addr, error)

// EnrollmentSession owns the extension-only identity and node credential used
// by one bounded enrollment exchange. Its gomobile surface returns only an
// authenticated configuration document; it has no private-key, agent-bearer,
// arbitrary-header, or arbitrary-request API.
type EnrollmentSession struct {
	loadPrivateKey  privateKeyLoader
	loadAgentSecret enrollmentSecretLoader
	httpClient      *http.Client
	resolve         enrollmentResolver
	now             func() time.Time
}

// NewEnrollmentSession binds enrollment to the same stable extension-only
// Keychain identity used by EngineSession.
func NewEnrollmentSession(
	accessGroup string,
	identityID string,
) (*EnrollmentSession, error) {
	if err := validateIdentityScope(accessGroup, identityID); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return newEnrollmentSession(
		func() ([]byte, error) {
			return loadOrCreatePrivateKey(accessGroup, identityID)
		},
		func() ([]byte, error) {
			return loadOrCreateSecret(
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
	), nil
}

func newEnrollmentSession(
	privateKeyLoader privateKeyLoader,
	agentSecretLoader enrollmentSecretLoader,
	client *http.Client,
	resolver enrollmentResolver,
	now func() time.Time,
) *EnrollmentSession {
	return &EnrollmentSession{
		loadPrivateKey:  privateKeyLoader,
		loadAgentSecret: agentSecretLoader,
		httpClient:      client,
		resolve:         resolver,
		now:             now,
	}
}

// Enroll validates an HTTPS Mesh origin and one-use enrollment token, performs
// the token-scoped preflight, exchanges the extension-owned public key, and
// returns one fully verified v3 engine configuration. The enrollment token and
// locally generated agent bearer are never returned or persisted outside the
// extension-only Keychain.
func (s *EnrollmentSession) Enroll(
	serverURL string,
	enrollmentToken string,
	monotonicCounter int64,
) (string, error) {
	if s == nil ||
		s.loadPrivateKey == nil ||
		s.loadAgentSecret == nil ||
		s.httpClient == nil ||
		s.resolve == nil ||
		s.now == nil {
		return "", errors.New("enrollment session is unavailable")
	}
	if monotonicCounter < 1 {
		return "", errors.New("enrollment monotonic counter is invalid")
	}
	origin, err := normalizeEnrollmentOrigin(serverURL)
	if err != nil {
		return "", err
	}
	enrollmentToken = strings.TrimSpace(enrollmentToken)
	if !validEnrollmentBearer(enrollmentToken) {
		return "", errors.New("one-time enrollment token is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	preflight, err := s.requestPreflight(ctx, origin, enrollmentToken)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	if preflight.TargetRole != "member" ||
		len(preflight.LighthouseEndpoints) == 0 ||
		!preflight.TokenExpiresAt.After(now) {
		return "", errors.New(
			"iOS tunnel enrollment requires an unexpired member plan with a lighthouse",
		)
	}
	preflightRemotes, err := s.resolvePreflightRemotes(ctx, preflight)
	if err != nil {
		return "", err
	}
	privateKey, err := s.loadPrivateKey()
	if err != nil {
		return "", errors.New("extension identity key is unavailable")
	}
	defer clear(privateKey)
	publicKey, err := publicKeyPEM(privateKey)
	if err != nil {
		return "", err
	}
	agentSecret, err := s.loadAgentSecret()
	if err != nil || len(agentSecret) != 32 {
		clear(agentSecret)
		return "", errors.New("extension agent credential is unavailable")
	}
	defer clear(agentSecret)
	agentBearer := base64.RawURLEncoding.EncodeToString(agentSecret)
	defer func() { agentBearer = "" }()
	payload := enrollmentExchangeRequest{
		Token:          enrollmentToken,
		PublicKey:      publicKey,
		AgentTokenHash: enrollmentTokenHash(agentBearer),
	}
	bundle, err := s.requestEnrollment(
		ctx,
		origin,
		agentBearer,
		payload,
	)
	if err != nil {
		return "", err
	}
	return s.configurationDocument(
		ctx,
		bundle,
		privateKey,
		publicKey,
		uint64(monotonicCounter),
		now,
		origin,
		preflight,
		preflightRemotes,
	)
}

type enrollmentExchangeRequest struct {
	Token          string `json:"token"`
	PublicKey      string `json:"public_key"`
	AgentTokenHash string `json:"agent_token_hash"`
}

type enrollmentPreflight struct {
	Schema              string    `json:"schema"`
	TargetRole          string    `json:"target_role"`
	NetworkCIDR         string    `json:"network_cidr"`
	LighthouseEndpoints []string  `json:"lighthouse_endpoints"`
	TokenExpiresAt      time.Time `json:"token_expires_at"`
}

type enrollmentNode struct {
	ID                             string     `json:"id"`
	NetworkID                      string     `json:"network_id"`
	Name                           string     `json:"name"`
	IP                             string     `json:"ip"`
	RoutedSubnets                  []string   `json:"routed_subnets,omitempty"`
	Site                           string     `json:"site,omitempty"`
	FailureDomain                  string     `json:"failure_domain,omitempty"`
	Groups                         []string   `json:"groups"`
	Role                           string     `json:"role"`
	PublicEndpoint                 string     `json:"public_endpoint,omitempty"`
	Status                         string     `json:"status"`
	Certificate                    string     `json:"certificate,omitempty"`
	CertificateFingerprint         string     `json:"certificate_fingerprint,omitempty"`
	CertificateAuthoritySHA256     string     `json:"certificate_authority_sha256,omitempty"`
	CertificateExpiresAt           *time.Time `json:"certificate_expires_at,omitempty"`
	CertificateRenewAfter          *time.Time `json:"certificate_renew_after,omitempty"`
	CertificateGeneration          int64      `json:"certificate_generation"`
	AppliedConfigRevision          int64      `json:"applied_config_revision"`
	AppliedCertificateGeneration   int64      `json:"applied_certificate_generation"`
	AppliedConfigSHA256            string     `json:"applied_config_sha256,omitempty"`
	ReportedCertificateFingerprint string     `json:"reported_certificate_fingerprint,omitempty"`
	NebulaRunning                  bool       `json:"nebula_running"`
	NativeDNSActive                bool       `json:"native_dns_active,omitempty"`
	AgentVersion                   string     `json:"agent_version,omitempty"`
	NebulaVersion                  string     `json:"nebula_version,omitempty"`
	AgentStatus                    string     `json:"agent_status,omitempty"`
	AgentBootID                    string     `json:"agent_boot_id,omitempty"`
	HeartbeatSequence              int64      `json:"heartbeat_sequence"`
	LastError                      string     `json:"last_error,omitempty"`
	LastSeenAt                     *time.Time `json:"last_seen_at,omitempty"`
	AgentCredentialExpiresAt       *time.Time `json:"agent_credential_expires_at,omitempty"`
	AgentCredentialLastUsedAt      *time.Time `json:"agent_credential_last_used_at,omitempty"`
	AgentCredentialGeneration      int64      `json:"agent_credential_generation"`
	LastRenewedAt                  *time.Time `json:"last_renewed_at,omitempty"`
	CreatedAt                      time.Time  `json:"created_at"`
	EnrolledAt                     *time.Time `json:"enrolled_at,omitempty"`
	RevokedAt                      *time.Time `json:"revoked_at,omitempty"`
}

type enrollmentBundle struct {
	NodeID                            string         `json:"node_id"`
	NetworkID                         string         `json:"network_id"`
	Node                              enrollmentNode `json:"node"`
	Certificate                       string         `json:"certificate"`
	CA                                string         `json:"ca"`
	Config                            string         `json:"config"`
	ConfigRevision                    int64          `json:"config_revision"`
	CertificateExpiresAt              time.Time      `json:"certificate_expires_at"`
	CertificateRenewAfter             time.Time      `json:"certificate_renew_after"`
	AgentCredentialExpiresAt          time.Time      `json:"agent_credential_expires_at"`
	AgentCredentialGeneration         int64          `json:"agent_credential_generation"`
	ConfigIssuedAt                    time.Time      `json:"config_issued_at"`
	ConfigSHA256                      string         `json:"config_sha256"`
	CACertificateSHA256               string         `json:"ca_sha256"`
	PreviousCACertificateSHA256       string         `json:"previous_ca_sha256,omitempty"`
	CARotationRequired                bool           `json:"ca_rotation_required,omitempty"`
	CertificateProfileRenewalRequired bool           `json:"certificate_profile_renewal_required,omitempty"`
	CertificateFingerprint            string         `json:"certificate_fingerprint"`
	CertificateGeneration             int64          `json:"certificate_generation"`
	PublicKeyHash                     string         `json:"public_key_hash"`
	ConfigSignature                   string         `json:"config_signature"`
	ConfigSigningPublicKey            string         `json:"config_signing_public_key"`
}

// renewalBundle is deliberately separate from enrollmentBundle because the
// renewal endpoint does not repeat credential metadata, node metadata, or the
// long-lived config-verification key. Refresh binds those fields to the
// authenticated bootstrap response before constructing a replacement engine
// document.
type renewalBundle struct {
	NodeID                            string    `json:"node_id"`
	NetworkID                         string    `json:"network_id"`
	CA                                string    `json:"ca"`
	Certificate                       string    `json:"certificate"`
	CertificateExpiresAt              time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter             time.Time `json:"certificate_renew_after"`
	Config                            string    `json:"config"`
	ConfigRevision                    int64     `json:"config_revision"`
	ConfigIssuedAt                    time.Time `json:"config_issued_at"`
	ConfigSHA256                      string    `json:"config_sha256"`
	CACertificateSHA256               string    `json:"ca_sha256"`
	PreviousCACertificateSHA256       string    `json:"previous_ca_sha256,omitempty"`
	CARotationRequired                bool      `json:"ca_rotation_required,omitempty"`
	CertificateProfileRenewalRequired bool      `json:"certificate_profile_renewal_required,omitempty"`
	CertificateFingerprint            string    `json:"certificate_fingerprint"`
	CertificateGeneration             int64     `json:"certificate_generation"`
	PublicKeyHash                     string    `json:"public_key_hash"`
	ConfigSignature                   string    `json:"config_signature"`
}

type credentialRotation struct {
	Generation int64     `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (b enrollmentBundle) signatureMetadata() configsignature.Metadata {
	return configsignature.Metadata{
		NodeID:                            b.NodeID,
		NetworkID:                         b.NetworkID,
		Revision:                          b.ConfigRevision,
		IssuedAt:                          b.ConfigIssuedAt,
		CACertificateSHA256:               b.CACertificateSHA256,
		PreviousCACertificateSHA256:       b.PreviousCACertificateSHA256,
		CARotationRequired:                b.CARotationRequired,
		CertificateProfileRenewalRequired: b.CertificateProfileRenewalRequired,
		CertificateFingerprint:            b.CertificateFingerprint,
		CertificateExpiresAt:              b.CertificateExpiresAt,
		CertificateRenewAfter:             b.CertificateRenewAfter,
		CertificateGeneration:             b.CertificateGeneration,
		PublicKeyHash:                     b.PublicKeyHash,
	}
}

type enrollmentHTTPError struct {
	status int
}

func (e *enrollmentHTTPError) Error() string {
	return fmt.Sprintf("Mesh enrollment returned HTTP %d", e.status)
}

type enrollmentTransportError struct{}

func (*enrollmentTransportError) Error() string {
	return "Mesh enrollment transport failed"
}

func (s *EnrollmentSession) requestPreflight(
	ctx context.Context,
	origin string,
	token string,
) (enrollmentPreflight, error) {
	var plan enrollmentPreflight
	if err := s.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/enroll/preflight",
		"",
		struct {
			Token string `json:"token"`
		}{Token: token},
		&plan,
	); err != nil {
		return enrollmentPreflight{}, fmt.Errorf(
			"request enrollment preflight: %w",
			err,
		)
	}
	if err := validateEnrollmentPreflight(plan); err != nil {
		return enrollmentPreflight{}, errors.New(
			"enrollment preflight response is invalid",
		)
	}
	return plan, nil
}

func (s *EnrollmentSession) requestEnrollment(
	ctx context.Context,
	origin string,
	agentBearer string,
	payload enrollmentExchangeRequest,
) (enrollmentBundle, error) {
	var first enrollmentBundle
	firstErr := s.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/enroll",
		"",
		payload,
		&first,
	)
	if firstErr == nil {
		return first, nil
	}
	var responseErr *enrollmentHTTPError
	if errors.As(firstErr, &responseErr) && responseErr.status < 500 {
		return enrollmentBundle{}, fmt.Errorf(
			"enroll iOS tunnel: %w",
			firstErr,
		)
	}

	var replay enrollmentBundle
	replayErr := s.requestJSON(
		ctx,
		http.MethodPost,
		origin+"/api/v1/enroll",
		"",
		payload,
		&replay,
	)
	if replayErr == nil {
		return replay, nil
	}
	var recovered enrollmentBundle
	recoveryErr := s.requestJSON(
		ctx,
		http.MethodGet,
		origin+"/api/v1/agent/bootstrap",
		agentBearer,
		nil,
		&recovered,
	)
	if recoveryErr == nil {
		return recovered, nil
	}
	return enrollmentBundle{}, errors.Join(
		errors.New("initial enrollment result was ambiguous"),
		fmt.Errorf("identical enrollment replay failed: %w", replayErr),
		fmt.Errorf("recover committed enrollment: %w", recoveryErr),
	)
}

func (s *EnrollmentSession) requestJSON(
	ctx context.Context,
	method string,
	endpoint string,
	bearer string,
	input any,
	output any,
) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return errors.New("encode bounded enrollment request")
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("build bounded enrollment request")
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return &enrollmentTransportError{}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &enrollmentHTTPError{status: response.StatusCode}
	}
	if !headerHasDirective(response.Header.Values("Cache-Control"), "no-store") {
		return errors.New("Mesh enrollment response is cacheable")
	}
	raw, err := io.ReadAll(
		io.LimitReader(response.Body, maximumEnrollmentBody+1),
	)
	if err != nil ||
		len(raw) == 0 ||
		len(raw) > maximumEnrollmentBody ||
		!utf8.Valid(raw) {
		return errors.New("Mesh enrollment response is invalid")
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return errors.New("Mesh enrollment response is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("Mesh enrollment response fields are invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("Mesh enrollment response has trailing data")
	}
	return nil
}

func headerHasDirective(values []string, expected string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), expected) {
				return true
			}
		}
	}
	return false
}

func normalizeEnrollmentOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawPath != "" ||
		parsed.ForceQuery {
		return "", errors.New("Mesh enrollment origin must be an exact HTTPS origin")
	}
	host := parsed.Hostname()
	if host == "" ||
		!utf8.ValidString(host) ||
		strings.ContainsAny(host, " \t\r\n") ||
		host != strings.ToLower(host) {
		return "", errors.New("Mesh enrollment origin host is invalid")
	}
	port := parsed.Port()
	if port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return "", errors.New("Mesh enrollment origin port is invalid")
		}
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func (s *EnrollmentSession) configurationDocument(
	ctx context.Context,
	bundle enrollmentBundle,
	privateKey []byte,
	publicKey string,
	monotonicCounter uint64,
	now time.Time,
	controlPlaneOrigin string,
	preflight enrollmentPreflight,
	preflightRemotes map[netip.Addr]struct{},
) (string, error) {
	if bundle.NodeID == "" ||
		bundle.NetworkID == "" ||
		bundle.Node.ID != bundle.NodeID ||
		bundle.Node.NetworkID != bundle.NetworkID ||
		bundle.Node.Status != "active" ||
		bundle.Node.Role != "member" ||
		bundle.ConfigRevision < 1 ||
		bundle.ConfigRevision > math.MaxInt64 ||
		bundle.CertificateGeneration < 1 ||
		bundle.CertificateGeneration > math.MaxInt64 ||
		bundle.AgentCredentialGeneration < 1 ||
		!bundle.AgentCredentialExpiresAt.After(now) ||
		!bundle.CertificateExpiresAt.After(now) ||
		!bundle.CertificateRenewAfter.After(bundle.ConfigIssuedAt) ||
		!bundle.CertificateRenewAfter.Before(bundle.CertificateExpiresAt) ||
		enrollmentTokenHash(publicKey) != bundle.PublicKeyHash ||
		configsignature.Digest(bundle.Config) != bundle.ConfigSHA256 ||
		configsignature.Digest(bundle.CA) != bundle.CACertificateSHA256 {
		return "", errors.New("Mesh enrollment bundle identity is invalid")
	}
	if err := configsignature.Verify(
		bundle.ConfigSigningPublicKey,
		bundle.signatureMetadata(),
		bundle.Config,
		bundle.ConfigSHA256,
		bundle.ConfigSignature,
	); err != nil {
		return "", errors.New("Mesh enrollment bundle signature is invalid")
	}
	certificate, remainder, err := cert.UnmarshalCertificateFromPEM(
		[]byte(bundle.Certificate),
	)
	if err != nil ||
		strings.TrimSpace(string(remainder)) != "" ||
		certificate.IsCA() ||
		certificate.Curve() != cert.Curve_CURVE25519 {
		return "", errors.New("Mesh enrollment certificate is invalid")
	}
	addresses := make([]engineIPPrefix, 0, len(certificate.Networks()))
	included := make([]engineIPPrefix, 0, len(certificate.Networks()))
	preflightNetwork, err := netip.ParsePrefix(preflight.NetworkCIDR)
	if err != nil || len(certificate.Networks()) != 1 {
		return "", errors.New("Mesh enrollment network plan is invalid")
	}
	for _, network := range certificate.Networks() {
		if !network.IsValid() ||
			network.Masked() != preflightNetwork {
			return "", errors.New("Mesh enrollment certificate network is invalid")
		}
		addresses = append(addresses, prefixDocument(network))
		included = append(included, prefixDocument(network.Masked()))
	}
	parsed := config.NewC(nil)
	if err := parsed.LoadString(bundle.Config); err != nil {
		return "", errors.New("Mesh enrollment configuration is invalid")
	}
	routes, err := signedUnsafeRoutes(parsed)
	if err != nil {
		return "", err
	}
	included = append(included, routes...)
	sortPrefixes(addresses)
	sortPrefixes(included)
	dnsServers, err := signedDNSServers(
		bundle.Config,
		certificate.Networks()[0],
	)
	if err != nil {
		return "", err
	}
	remote, err := s.signedTunnelRemote(ctx, parsed, included)
	if err != nil {
		return "", err
	}
	if preflightRemotes != nil {
		if _, ok := preflightRemotes[remote]; !ok {
			return "", errors.New(
				"signed iOS lighthouse remote differs from enrollment preflight",
			)
		}
	}
	document := engineConfiguration{
		Schema:             tunnelConfigurationSchema,
		NetworkID:          bundle.NetworkID,
		NodeID:             bundle.NodeID,
		ControlPlaneOrigin: controlPlaneOrigin,
		AgentCredentialGeneration: uint64(
			bundle.AgentCredentialGeneration,
		),
		AgentCredentialExpiresAt: canonicalTime(
			bundle.AgentCredentialExpiresAt,
		),
		CertificateFingerprint: bundle.CertificateFingerprint,
		CertificateGeneration:  uint64(bundle.CertificateGeneration),
		ConfigRevision:         uint64(bundle.ConfigRevision),
		ConfigDigest:           bundle.ConfigSHA256,
		EngineIdentity:         FrameworkIdentitySHA256(),
		TunnelRemoteAddress:    remote.String(),
		NetworkSettings: engineNetworkSettings{
			Addresses:      addresses,
			IncludedRoutes: included,
			ExcludedRoutes: []engineIPPrefix{},
			DNSServers:     dnsServers,
			MTU:            defaultTunnelMTU,
		},
		MonotonicCounter:     monotonicCounter,
		IssuedAtMilliseconds: uint64(bundle.ConfigIssuedAt.UnixMilli()),
		Nebula: nebulaSignedConfiguration{
			Schema:                            nebulaConfigurationSchema,
			CA:                                bundle.CA,
			Certificate:                       bundle.Certificate,
			Config:                            bundle.Config,
			ConfigIssuedAt:                    canonicalTime(bundle.ConfigIssuedAt),
			CACertificateSHA256:               bundle.CACertificateSHA256,
			PreviousCACertificateSHA256:       bundle.PreviousCACertificateSHA256,
			CARotationRequired:                bundle.CARotationRequired,
			CertificateProfileRenewalRequired: bundle.CertificateProfileRenewalRequired,
			CertificateExpiresAt:              canonicalTime(bundle.CertificateExpiresAt),
			CertificateRenewAfter:             canonicalTime(bundle.CertificateRenewAfter),
			PublicKeyHash:                     bundle.PublicKeyHash,
			ConfigSigningPublicKey:            bundle.ConfigSigningPublicKey,
			ConfigSignature:                   bundle.ConfigSignature,
		},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", errors.New("encode verified enrollment configuration")
	}
	if _, err := verifyEngineConfiguration(string(raw), privateKey); err != nil {
		return "", fmt.Errorf(
			"verify enrolled engine configuration: %w",
			err,
		)
	}
	return string(raw), nil
}

func prefixDocument(prefix netip.Prefix) engineIPPrefix {
	return engineIPPrefix{
		Address:      prefix.Addr().String(),
		PrefixLength: uint8(prefix.Bits()),
	}
}

func sortPrefixes(values []engineIPPrefix) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Address == values[j].Address {
			return values[i].PrefixLength < values[j].PrefixLength
		}
		return values[i].Address < values[j].Address
	})
}

func signedUnsafeRoutes(parsed *config.C) ([]engineIPPrefix, error) {
	value := parsed.Get("tun.unsafe_routes")
	if value == nil {
		return []engineIPPrefix{}, nil
	}
	rawRoutes, ok := value.([]any)
	if !ok || len(rawRoutes) > 128 {
		return nil, errors.New("signed iOS unsafe routes are invalid")
	}
	routes := make([]engineIPPrefix, 0, len(rawRoutes))
	seen := make(map[string]struct{}, len(rawRoutes))
	for _, rawRoute := range rawRoutes {
		fields, ok := rawRoute.(map[string]any)
		routeValue, routeOK := fields["route"].(string)
		route, parseErr := netip.ParsePrefix(routeValue)
		if !ok ||
			!routeOK ||
			parseErr != nil ||
			route.String() != routeValue ||
			route != route.Masked() {
			return nil, errors.New("signed iOS unsafe route is invalid")
		}
		if _, exists := seen[route.String()]; exists {
			return nil, errors.New("signed iOS unsafe route is duplicated")
		}
		seen[route.String()] = struct{}{}
		routes = append(routes, prefixDocument(route))
	}
	sortPrefixes(routes)
	return routes, nil
}

func signedDNSServers(
	rawConfig string,
	certificateNetwork netip.Prefix,
) ([]string, error) {
	policy, enabled, err := parseSignedNativeDNSPolicy(rawConfig)
	if err != nil {
		return nil, errors.New("signed iOS DNS policy is invalid")
	}
	if !enabled {
		return []string{}, nil
	}
	if policy.LocalIP != certificateNetwork.Addr().String() ||
		policy.NetworkCIDR != certificateNetwork.Masked().String() {
		return nil, errors.New(
			"signed iOS DNS policy differs from the enrolled certificate",
		)
	}
	values := make([]string, 0, len(policy.Resolvers))
	seen := make(map[string]struct{}, len(policy.Resolvers))
	for _, resolver := range policy.Resolvers {
		address, parseErr := netip.ParseAddr(resolver.IP)
		if parseErr != nil ||
			address.String() != resolver.IP ||
			!address.IsValid() {
			return nil, errors.New("signed iOS DNS resolver is invalid")
		}
		if _, exists := seen[address.String()]; exists {
			continue
		}
		seen[address.String()] = struct{}{}
		values = append(values, address.String())
	}
	sort.Strings(values)
	return values, nil
}

func (s *EnrollmentSession) signedTunnelRemote(
	ctx context.Context,
	parsed *config.C,
	included []engineIPPrefix,
) (netip.Addr, error) {
	rawMap, ok := parsed.Get("static_host_map").(map[string]any)
	if !ok || len(rawMap) == 0 || len(rawMap) > 64 {
		return netip.Addr{}, errors.New(
			"signed iOS configuration has no bounded lighthouse endpoint",
		)
	}
	endpoints := make([]string, 0, len(rawMap))
	for _, raw := range rawMap {
		values, ok := raw.([]any)
		if !ok || len(values) == 0 || len(values) > 16 {
			return netip.Addr{}, errors.New(
				"signed iOS lighthouse endpoints are invalid",
			)
		}
		for _, value := range values {
			endpoint, ok := value.(string)
			if !ok {
				return netip.Addr{}, errors.New(
					"signed iOS lighthouse endpoint is invalid",
				)
			}
			endpoints = append(endpoints, endpoint)
		}
	}
	sort.Strings(endpoints)
	for _, endpoint := range endpoints {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || host == "" || port == "" {
			continue
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			continue
		}
		candidates := []netip.Addr{}
		if address, err := netip.ParseAddr(host); err == nil {
			candidates = append(candidates, address)
		} else {
			resolved, err := s.resolve(ctx, strings.ToLower(host))
			if err != nil {
				continue
			}
			candidates = append(candidates, resolved...)
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].String() < candidates[j].String()
		})
		for _, candidate := range candidates {
			if candidate.Is4In6() {
				candidate = candidate.Unmap()
			}
			if !isUsableUnicast(candidate) ||
				prefixDocumentsContain(included, candidate) {
				continue
			}
			return candidate, nil
		}
	}
	return netip.Addr{}, errors.New(
		"signed iOS lighthouse remote address is unavailable",
	)
}

func (s *EnrollmentSession) resolvePreflightRemotes(
	ctx context.Context,
	plan enrollmentPreflight,
) (map[netip.Addr]struct{}, error) {
	network, err := netip.ParsePrefix(plan.NetworkCIDR)
	if err != nil {
		return nil, errors.New("enrollment preflight network is invalid")
	}
	remotes := make(map[netip.Addr]struct{})
	for _, endpoint := range plan.LighthouseEndpoints {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, errors.New("enrollment preflight endpoint is invalid")
		}
		var candidates []netip.Addr
		if address, parseErr := netip.ParseAddr(host); parseErr == nil {
			candidates = []netip.Addr{address}
		} else {
			candidates, err = s.resolve(ctx, strings.ToLower(host))
			if err != nil {
				return nil, errors.New(
					"enrollment preflight lighthouse DNS is unavailable",
				)
			}
		}
		usable := false
		for _, candidate := range candidates {
			if candidate.Is4In6() {
				candidate = candidate.Unmap()
			}
			if !isUsableUnicast(candidate) || network.Contains(candidate) {
				continue
			}
			usable = true
			remotes[candidate] = struct{}{}
		}
		if !usable {
			return nil, errors.New(
				"enrollment preflight lighthouse endpoint is unavailable",
			)
		}
	}
	if len(remotes) == 0 {
		return nil, errors.New(
			"enrollment preflight has no usable lighthouse remote",
		)
	}
	return remotes, nil
}

func prefixDocumentsContain(
	prefixes []engineIPPrefix,
	address netip.Addr,
) bool {
	for _, value := range prefixes {
		prefix := netip.PrefixFrom(
			netip.MustParseAddr(value.Address),
			int(value.PrefixLength),
		)
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func canonicalTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func enrollmentTokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validEnrollmentBearer(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validateEnrollmentPreflight(plan enrollmentPreflight) error {
	if plan.Schema != enrollmentPreflightV1 ||
		(plan.TargetRole != "member" && plan.TargetRole != "lighthouse") ||
		len(plan.LighthouseEndpoints) > 64 ||
		plan.TokenExpiresAt.IsZero() ||
		plan.TokenExpiresAt.Location() != time.UTC {
		return errors.New("enrollment preflight metadata is invalid")
	}
	network, err := netip.ParsePrefix(plan.NetworkCIDR)
	if err != nil ||
		!network.Addr().Is4() ||
		network != network.Masked() ||
		network.String() != plan.NetworkCIDR ||
		network.Bits() < 16 ||
		network.Bits() > 28 {
		return errors.New("enrollment preflight network is invalid")
	}
	previous := ""
	for _, endpoint := range plan.LighthouseEndpoints {
		if endpoint == "" || endpoint <= previous {
			return errors.New(
				"enrollment preflight endpoints are not uniquely ordered",
			)
		}
		host, port, splitErr := net.SplitHostPort(endpoint)
		portValue, portErr := strconv.ParseUint(port, 10, 16)
		if splitErr != nil ||
			host == "" ||
			portErr != nil ||
			portValue == 0 ||
			strings.ContainsAny(host, " \t\r\n") {
			return errors.New("enrollment preflight endpoint is invalid")
		}
		previous = endpoint
	}
	return nil
}

type signedNativeDNSResolver struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type signedNativeDNSPolicy struct {
	Schema       string                    `json:"schema"`
	LocalIP      string                    `json:"local_ip"`
	NetworkCIDR  string                    `json:"network_cidr"`
	SearchDomain string                    `json:"search_domain"`
	Resolvers    []signedNativeDNSResolver `json:"resolvers"`
}

func parseSignedNativeDNSPolicy(
	configValue string,
) (signedNativeDNSPolicy, bool, error) {
	encoded := ""
	for _, line := range strings.Split(configValue, "\n") {
		if !strings.HasPrefix(line, nativeDNSPolicyPrefix) {
			continue
		}
		if encoded != "" {
			return signedNativeDNSPolicy{}, false, errors.New(
				"signed config contains duplicate native DNS policies",
			)
		}
		encoded = strings.TrimPrefix(line, nativeDNSPolicyPrefix)
	}
	if encoded == "" {
		return signedNativeDNSPolicy{}, false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy encoding is invalid",
		)
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy is ambiguous",
		)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil ||
		!exactObjectKeys(object, []string{
			"schema",
			"local_ip",
			"network_cidr",
			"search_domain",
			"resolvers",
		}) {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy fields are invalid",
		)
	}
	var resolverObjects []map[string]json.RawMessage
	if err := json.Unmarshal(object["resolvers"], &resolverObjects); err != nil {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS resolvers are invalid",
		)
	}
	for _, resolver := range resolverObjects {
		if !exactObjectKeys(resolver, []string{"ip", "port"}) {
			return signedNativeDNSPolicy{}, false, errors.New(
				"signed config native DNS resolver fields are invalid",
			)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy signedNativeDNSPolicy
	if err := decoder.Decode(&policy); err != nil {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy document is invalid",
		)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy has trailing data",
		)
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, raw) {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy is not canonical",
		)
	}
	if policy.Schema != nativeDNSPolicyV1 ||
		len(policy.Resolvers) == 0 ||
		len(policy.Resolvers) > 8 {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy metadata is invalid",
		)
	}
	local, err := netip.ParseAddr(policy.LocalIP)
	network, networkErr := netip.ParsePrefix(policy.NetworkCIDR)
	if err != nil ||
		!local.Is4() ||
		local.String() != policy.LocalIP ||
		networkErr != nil ||
		!network.Addr().Is4() ||
		network != network.Masked() ||
		network.String() != policy.NetworkCIDR ||
		!network.Contains(local) ||
		!validNativeDNSDomain(policy.SearchDomain) {
		return signedNativeDNSPolicy{}, false, errors.New(
			"signed config native DNS policy identity is invalid",
		)
	}
	previous := ""
	for _, resolver := range policy.Resolvers {
		address, parseErr := netip.ParseAddr(resolver.IP)
		if parseErr != nil ||
			!address.Is4() ||
			address.String() != resolver.IP ||
			!network.Contains(address) ||
			resolver.Port < 1 ||
			resolver.Port > 65535 ||
			resolver.IP <= previous {
			return signedNativeDNSPolicy{}, false, errors.New(
				"signed config native DNS resolver is invalid",
			)
		}
		previous = resolver.IP
	}
	return policy, true, nil
}

func validNativeDNSDomain(value string) bool {
	if value == "" ||
		len(value) > 253 ||
		strings.HasSuffix(value, ".") ||
		value != strings.ToLower(value) ||
		value == "local" ||
		strings.HasSuffix(value, ".local") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for index, character := range []byte(label) {
			alphaNumeric := character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9'
			if !alphaNumeric && character != '-' {
				return false
			}
			if (index == 0 || index == len(label)-1) && !alphaNumeric {
				return false
			}
		}
	}
	return true
}
