package iosmobile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"

	"mesh/internal/configsignature"
)

const (
	tunnelConfigurationSchema  = "mesh-ios-tunnel-configuration-v4"
	nebulaConfigurationSchema  = "mesh-ios-nebula-engine-configuration-v1"
	maximumEngineDocumentBytes = 16 << 20
	maximumTrustBundleBytes    = 256 << 10
	maximumCertificateBytes    = 64 << 10
)

var lowerDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type engineConfiguration struct {
	Schema                    string                    `json:"schema"`
	NetworkID                 string                    `json:"networkID"`
	NodeID                    string                    `json:"nodeID"`
	ControlPlaneOrigin        string                    `json:"controlPlaneOrigin"`
	AgentCredentialGeneration uint64                    `json:"agentCredentialGeneration"`
	AgentCredentialExpiresAt  string                    `json:"agentCredentialExpiresAt"`
	CertificateFingerprint    string                    `json:"certificateFingerprint"`
	CertificateGeneration     uint64                    `json:"certificateGeneration"`
	ConfigRevision            uint64                    `json:"configRevision"`
	ConfigDigest              string                    `json:"configDigest"`
	EngineIdentity            string                    `json:"engineIdentity"`
	TunnelRemoteAddress       string                    `json:"tunnelRemoteAddress"`
	NetworkSettings           engineNetworkSettings     `json:"networkSettings"`
	MonotonicCounter          uint64                    `json:"monotonicCounter"`
	IssuedAtMilliseconds      uint64                    `json:"issuedAtMilliseconds"`
	Nebula                    nebulaSignedConfiguration `json:"nebula"`
}

type nebulaSignedConfiguration struct {
	Schema                            string `json:"schema"`
	CA                                string `json:"ca"`
	Certificate                       string `json:"certificate"`
	Config                            string `json:"config"`
	ConfigIssuedAt                    string `json:"configIssuedAt"`
	CACertificateSHA256               string `json:"caCertificateSHA256"`
	PreviousCACertificateSHA256       string `json:"previousCACertificateSHA256"`
	CARotationRequired                bool   `json:"caRotationRequired"`
	CertificateProfileRenewalRequired bool   `json:"certificateProfileRenewalRequired"`
	CertificateExpiresAt              string `json:"certificateExpiresAt"`
	CertificateRenewAfter             string `json:"certificateRenewAfter"`
	PublicKeyHash                     string `json:"publicKeyHash"`
	ConfigSigningPublicKey            string `json:"configSigningPublicKey"`
	ConfigSignature                   string `json:"configSignature"`
}

type engineNetworkSettings struct {
	Addresses      []engineIPPrefix `json:"addresses"`
	IncludedRoutes []engineIPPrefix `json:"includedRoutes"`
	ExcludedRoutes []engineIPPrefix `json:"excludedRoutes"`
	DNSServers     []string         `json:"dnsServers"`
	MTU            uint16           `json:"mtu"`
}

type engineIPPrefix struct {
	Address      string `json:"address"`
	PrefixLength uint8  `json:"prefixLength"`
}

type verifiedEngineConfiguration struct {
	parsed      *config.C
	certificate cert.Certificate
}

func verifyEngineConfiguration(
	raw string,
	privateKey []byte,
) (*verifiedEngineConfiguration, error) {
	document, err := decodeEngineConfiguration(raw)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != 32 {
		return nil, errors.New("engine identity key is invalid")
	}
	if document.Schema != tunnelConfigurationSchema ||
		document.Nebula.Schema != nebulaConfigurationSchema {
		return nil, errors.New("engine configuration schema is unsupported")
	}
	if document.EngineIdentity != FrameworkIdentitySHA256() {
		return nil, errors.New("engine identity does not match the framework")
	}
	if !identityPattern.MatchString(document.NodeID) ||
		!identityPattern.MatchString(document.NetworkID) ||
		document.AgentCredentialGeneration == 0 ||
		document.AgentCredentialGeneration > math.MaxInt64 ||
		document.CertificateGeneration == 0 ||
		document.CertificateGeneration > math.MaxInt64 ||
		document.ConfigRevision == 0 ||
		document.ConfigRevision > math.MaxInt64 ||
		document.MonotonicCounter == 0 ||
		document.IssuedAtMilliseconds == 0 ||
		!lowerDigestPattern.MatchString(document.CertificateFingerprint) ||
		!lowerDigestPattern.MatchString(document.ConfigDigest) {
		return nil, errors.New("engine configuration identity metadata is invalid")
	}
	if origin, err := normalizeEnrollmentOrigin(
		document.ControlPlaneOrigin,
	); err != nil || origin != document.ControlPlaneOrigin {
		return nil, errors.New("engine control-plane origin is invalid")
	}
	if err := validateEngineNetworkSettings(
		document.NetworkSettings,
		document.TunnelRemoteAddress,
	); err != nil {
		return nil, err
	}

	configIssuedAt, err := parseCanonicalTime(document.Nebula.ConfigIssuedAt)
	if err != nil {
		return nil, errors.New("signed configuration issue time is invalid")
	}
	certificateExpiresAt, err := parseCanonicalTime(
		document.Nebula.CertificateExpiresAt,
	)
	if err != nil {
		return nil, errors.New("signed certificate expiry is invalid")
	}
	certificateRenewAfter, err := parseCanonicalTime(
		document.Nebula.CertificateRenewAfter,
	)
	if err != nil {
		return nil, errors.New("signed certificate renewal time is invalid")
	}
	agentCredentialExpiresAt, err := parseCanonicalTime(
		document.AgentCredentialExpiresAt,
	)
	if err != nil ||
		!agentCredentialExpiresAt.After(configIssuedAt) ||
		!agentCredentialExpiresAt.After(time.Now()) {
		return nil, errors.New("agent credential expiry is invalid")
	}
	if document.IssuedAtMilliseconds != uint64(configIssuedAt.UnixMilli()) {
		return nil, errors.New("engine issue time projection does not match")
	}
	metadata := configsignature.Metadata{
		NodeID:                            document.NodeID,
		NetworkID:                         document.NetworkID,
		Revision:                          int64(document.ConfigRevision),
		IssuedAt:                          configIssuedAt,
		CACertificateSHA256:               document.Nebula.CACertificateSHA256,
		PreviousCACertificateSHA256:       document.Nebula.PreviousCACertificateSHA256,
		CARotationRequired:                document.Nebula.CARotationRequired,
		CertificateProfileRenewalRequired: document.Nebula.CertificateProfileRenewalRequired,
		CertificateFingerprint:            document.CertificateFingerprint,
		CertificateExpiresAt:              certificateExpiresAt,
		CertificateRenewAfter:             certificateRenewAfter,
		CertificateGeneration:             int64(document.CertificateGeneration),
		PublicKeyHash:                     document.Nebula.PublicKeyHash,
	}
	if err := configsignature.Verify(
		document.Nebula.ConfigSigningPublicKey,
		metadata,
		document.Nebula.Config,
		document.ConfigDigest,
		document.Nebula.ConfigSignature,
	); err != nil {
		return nil, errors.New("signed engine configuration verification failed")
	}
	if configsignature.Digest(document.Nebula.CA) !=
		document.Nebula.CACertificateSHA256 {
		return nil, errors.New("engine CA bundle digest does not match signed metadata")
	}
	certificate, err := verifyEngineCertificate(
		document,
		privateKey,
		certificateExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	if err := bindCertificateNetworks(
		certificate,
		document.NetworkSettings,
	); err != nil {
		return nil, err
	}

	parsed := config.NewC(nil)
	if err := parsed.LoadString(document.Nebula.Config); err != nil {
		return nil, errors.New("signed Nebula configuration is invalid")
	}
	if parsed.GetBool("tun.disabled", false) {
		return nil, errors.New("signed Nebula configuration disables the packet device")
	}
	if err := bindSignedRoutes(parsed, document.NetworkSettings); err != nil {
		return nil, err
	}
	pki, ok := parsed.Settings["pki"].(map[string]any)
	if !ok ||
		pki["ca"] != "/etc/nebula/ca.crt" ||
		pki["cert"] != "/etc/nebula/host.crt" ||
		pki["key"] != "/etc/nebula/host.key" {
		return nil, errors.New("signed Nebula configuration has unexpected PKI paths")
	}
	pki["ca"] = document.Nebula.CA
	pki["cert"] = document.Nebula.Certificate
	pki["key"] = string(
		cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey),
	)
	return &verifiedEngineConfiguration{
		parsed:      parsed,
		certificate: certificate,
	}, nil
}

func decodeEngineConfiguration(raw string) (engineConfiguration, error) {
	if raw == "" ||
		len(raw) > maximumEngineDocumentBytes ||
		!utf8.ValidString(raw) ||
		strings.ContainsRune(raw, '\r') {
		return engineConfiguration{}, errors.New(
			"engine configuration document is invalid",
		)
	}
	if err := rejectDuplicateJSONNames([]byte(raw)); err != nil {
		return engineConfiguration{}, errors.New(
			"engine configuration document is ambiguous",
		)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil ||
		!exactObjectKeys(top, []string{
			"schema",
			"networkID",
			"nodeID",
			"controlPlaneOrigin",
			"agentCredentialGeneration",
			"agentCredentialExpiresAt",
			"certificateFingerprint",
			"certificateGeneration",
			"configRevision",
			"configDigest",
			"engineIdentity",
			"tunnelRemoteAddress",
			"networkSettings",
			"monotonicCounter",
			"issuedAtMilliseconds",
			"nebula",
		}) {
		return engineConfiguration{}, errors.New(
			"engine configuration document fields are invalid",
		)
	}
	if err := requireExactNestedObject(
		top["networkSettings"],
		[]string{
			"addresses",
			"includedRoutes",
			"excludedRoutes",
			"dnsServers",
			"mtu",
		},
	); err != nil {
		return engineConfiguration{}, err
	}
	if err := requireExactPrefixArrays(top["networkSettings"]); err != nil {
		return engineConfiguration{}, err
	}
	if err := requireExactNestedObject(
		top["nebula"],
		[]string{
			"schema",
			"ca",
			"certificate",
			"config",
			"configIssuedAt",
			"caCertificateSHA256",
			"previousCACertificateSHA256",
			"caRotationRequired",
			"certificateProfileRenewalRequired",
			"certificateExpiresAt",
			"certificateRenewAfter",
			"publicKeyHash",
			"configSigningPublicKey",
			"configSignature",
		},
	); err != nil {
		return engineConfiguration{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value engineConfiguration
	if err := decoder.Decode(&value); err != nil {
		return engineConfiguration{}, errors.New(
			"engine configuration document types are invalid",
		)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return engineConfiguration{}, errors.New(
			"engine configuration document has trailing data",
		)
	}
	return value, nil
}

func requireExactNestedObject(
	raw json.RawMessage,
	keys []string,
) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil ||
		!exactObjectKeys(object, keys) {
		return errors.New("engine configuration nested fields are invalid")
	}
	return nil
}

func requireExactPrefixArrays(raw json.RawMessage) error {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return errors.New("engine network settings are invalid")
	}
	for _, name := range []string{
		"addresses",
		"includedRoutes",
		"excludedRoutes",
	} {
		var values []map[string]json.RawMessage
		if err := json.Unmarshal(settings[name], &values); err != nil {
			return errors.New("engine network prefix array is invalid")
		}
		for _, value := range values {
			if !exactObjectKeys(
				value,
				[]string{"address", "prefixLength"},
			) {
				return errors.New("engine network prefix fields are invalid")
			}
		}
	}
	return nil
}

func exactObjectKeys(
	object map[string]json.RawMessage,
	keys []string,
) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			names := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("JSON object name is invalid")
				}
				if _, exists := names[name]; exists {
					return fmt.Errorf("duplicate JSON object name %q", name)
				}
				names[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("JSON object is incomplete")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("JSON array is incomplete")
			}
		default:
			return errors.New("JSON delimiter is invalid")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON document has trailing data")
	}
	return nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil ||
		parsed.Location() != time.UTC ||
		parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC")
	}
	return parsed, nil
}

func verifyEngineCertificate(
	document engineConfiguration,
	privateKey []byte,
	certificateExpiresAt time.Time,
) (cert.Certificate, error) {
	if document.Nebula.CA == "" ||
		len(document.Nebula.CA) > maximumTrustBundleBytes ||
		!utf8.ValidString(document.Nebula.CA) ||
		strings.ContainsRune(document.Nebula.CA, '\r') ||
		document.Nebula.Certificate == "" ||
		len(document.Nebula.Certificate) > maximumCertificateBytes ||
		!utf8.ValidString(document.Nebula.Certificate) ||
		strings.ContainsRune(document.Nebula.Certificate, '\r') {
		return nil, errors.New("engine certificate material is invalid")
	}
	certificate, remainder, err := cert.UnmarshalCertificateFromPEM(
		[]byte(document.Nebula.Certificate),
	)
	if err != nil ||
		strings.TrimSpace(string(remainder)) != "" ||
		certificate.IsCA() ||
		certificate.Curve() != cert.Curve_CURVE25519 {
		return nil, errors.New("engine node certificate is invalid")
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil || fingerprint != document.CertificateFingerprint {
		return nil, errors.New("engine certificate fingerprint does not match")
	}
	if !certificate.NotAfter().Equal(certificateExpiresAt) {
		return nil, errors.New("engine certificate expiry does not match")
	}
	if err := certificate.VerifyPrivateKey(
		cert.Curve_CURVE25519,
		privateKey,
	); err != nil {
		return nil, errors.New("engine certificate does not match local identity")
	}
	publicPEM := certificate.MarshalPublicKeyPEM()
	publicHash := sha256.Sum256(publicPEM)
	if base64.RawURLEncoding.EncodeToString(publicHash[:]) !=
		document.Nebula.PublicKeyHash {
		return nil, errors.New("engine certificate public key hash does not match")
	}
	caPool, err := cert.NewCAPoolFromPEM([]byte(document.Nebula.CA))
	if err != nil {
		return nil, errors.New("engine CA trust bundle is invalid")
	}
	if _, err := caPool.VerifyCertificate(time.Now(), certificate); err != nil {
		return nil, errors.New("engine node certificate is not currently trusted")
	}
	return certificate, nil
}

func validateEngineNetworkSettings(
	settings engineNetworkSettings,
	remoteValue string,
) error {
	if len(settings.Addresses) < 1 ||
		len(settings.Addresses) > 8 ||
		len(settings.IncludedRoutes) < 1 ||
		len(settings.IncludedRoutes) > 128 ||
		len(settings.ExcludedRoutes) > 128 ||
		len(settings.DNSServers) > 8 ||
		settings.MTU < 1280 ||
		settings.MTU > 1500 {
		return errors.New("engine network settings bounds are invalid")
	}
	addresses, addressFamilies, err := parseEnginePrefixes(
		settings.Addresses,
		false,
		true,
	)
	if err != nil {
		return err
	}
	included, _, err := parseEnginePrefixes(
		settings.IncludedRoutes,
		true,
		false,
	)
	if err != nil {
		return err
	}
	excluded, _, err := parseEnginePrefixes(
		settings.ExcludedRoutes,
		true,
		false,
	)
	if err != nil {
		return err
	}
	for _, route := range append(
		append([]netip.Prefix(nil), included...),
		excluded...,
	) {
		if _, ok := addressFamilies[route.Addr().BitLen()]; !ok {
			return errors.New("engine network route family is invalid")
		}
	}
	includedKeys := prefixKeys(included)
	for _, route := range excluded {
		if _, ok := includedKeys[route.String()]; ok {
			return errors.New("engine included and excluded routes conflict")
		}
	}
	dnsSeen := make(map[string]struct{})
	for _, value := range settings.DNSServers {
		address, err := parseCanonicalUnicastAddress(value)
		if err != nil {
			return errors.New("engine DNS server is invalid")
		}
		if _, ok := addressFamilies[address.BitLen()]; !ok {
			return errors.New("engine DNS server family is invalid")
		}
		if _, exists := dnsSeen[address.String()]; exists {
			return errors.New("engine DNS server is duplicated")
		}
		dnsSeen[address.String()] = struct{}{}
	}
	remote, err := parseCanonicalUnicastAddress(remoteValue)
	if err != nil {
		return errors.New("engine tunnel remote address is invalid")
	}
	for _, address := range addresses {
		if address.Addr() == remote {
			return errors.New("engine tunnel remote address is an overlay address")
		}
	}
	if prefixesContain(included, remote) &&
		!prefixesContain(excluded, remote) {
		return errors.New("engine tunnel remote address would be captured")
	}
	return nil
}

func parseEnginePrefixes(
	values []engineIPPrefix,
	requireNetwork bool,
	requireUnicast bool,
) ([]netip.Prefix, map[int]struct{}, error) {
	result := make([]netip.Prefix, 0, len(values))
	families := make(map[int]struct{})
	seen := make(map[string]struct{})
	for _, value := range values {
		address, err := netip.ParseAddr(value.Address)
		if err != nil ||
			address.String() != value.Address ||
			address.Is4In6() ||
			int(value.PrefixLength) > address.BitLen() ||
			requireUnicast && !isUsableUnicast(address) {
			return nil, nil, errors.New("engine network prefix is invalid")
		}
		if requireUnicast && value.PrefixLength == 0 {
			return nil, nil, errors.New("engine assigned prefix is invalid")
		}
		prefix := netip.PrefixFrom(address, int(value.PrefixLength))
		if requireNetwork && prefix != prefix.Masked() {
			return nil, nil, errors.New("engine route is not network aligned")
		}
		key := prefix.String()
		if _, exists := seen[key]; exists {
			return nil, nil, errors.New("engine network prefix is duplicated")
		}
		seen[key] = struct{}{}
		families[address.BitLen()] = struct{}{}
		result = append(result, prefix)
	}
	return result, families, nil
}

func parseCanonicalUnicastAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil ||
		address.String() != value ||
		address.Is4In6() ||
		!isUsableUnicast(address) {
		return netip.Addr{}, errors.New("address is invalid")
	}
	return address, nil
}

func isUsableUnicast(address netip.Addr) bool {
	if !address.IsValid() ||
		address.IsUnspecified() ||
		address.IsLoopback() ||
		address.IsMulticast() {
		return false
	}
	if address.Is4() {
		return address.As4()[0] != 0
	}
	return true
}

func prefixKeys(prefixes []netip.Prefix) map[string]struct{} {
	result := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		result[prefix.String()] = struct{}{}
	}
	return result
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() &&
		(left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func bindCertificateNetworks(
	certificate cert.Certificate,
	settings engineNetworkSettings,
) error {
	if len(certificate.UnsafeNetworks()) != 0 {
		return errors.New("iOS engine certificate cannot advertise unsafe routes")
	}
	addresses, _, err := parseEnginePrefixes(
		settings.Addresses,
		false,
		true,
	)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(prefixKeys(addresses), prefixKeys(certificate.Networks())) {
		return errors.New("engine network addresses do not match the certificate")
	}
	included, _, err := parseEnginePrefixes(
		settings.IncludedRoutes,
		true,
		false,
	)
	if err != nil {
		return err
	}
	excluded, _, err := parseEnginePrefixes(
		settings.ExcludedRoutes,
		true,
		false,
	)
	if err != nil {
		return err
	}
	for _, network := range certificate.Networks() {
		network = network.Masked()
		if !routeCovered(included, network) {
			return errors.New("engine certificate network is not routed to the tunnel")
		}
		for _, bypass := range excluded {
			if prefixesOverlap(network, bypass) {
				return errors.New("engine certificate network is excluded from the tunnel")
			}
		}
	}
	return nil
}

func bindSignedRoutes(
	parsed *config.C,
	settings engineNetworkSettings,
) error {
	value := parsed.Get("tun.unsafe_routes")
	if value == nil {
		return nil
	}
	rawRoutes, ok := value.([]any)
	if !ok {
		return errors.New("signed Nebula unsafe routes are invalid")
	}
	included, _, err := parseEnginePrefixes(
		settings.IncludedRoutes,
		true,
		false,
	)
	if err != nil {
		return err
	}
	excluded, _, err := parseEnginePrefixes(
		settings.ExcludedRoutes,
		true,
		false,
	)
	if err != nil {
		return err
	}
	for _, rawRoute := range rawRoutes {
		fields, ok := rawRoute.(map[string]any)
		routeValue, routeOK := fields["route"].(string)
		route, parseErr := netip.ParsePrefix(routeValue)
		if !ok ||
			!routeOK ||
			parseErr != nil ||
			route.String() != routeValue ||
			route != route.Masked() {
			return errors.New("signed Nebula unsafe route is invalid")
		}
		if !routeCovered(included, route) {
			return errors.New("signed Nebula unsafe route is not routed to the tunnel")
		}
		for _, bypass := range excluded {
			if prefixesOverlap(route, bypass) {
				return errors.New("signed Nebula unsafe route is excluded from the tunnel")
			}
		}
	}
	return nil
}

func routeCovered(routes []netip.Prefix, required netip.Prefix) bool {
	for _, route := range routes {
		if route.Addr().BitLen() == required.Addr().BitLen() &&
			route.Bits() <= required.Bits() &&
			route.Contains(required.Addr()) {
			return true
		}
	}
	return false
}
