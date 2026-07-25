package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	// Nebula certificates carry groups in every handshake and use them for
	// firewall evaluation. Sixty-four entries (including the implicit "all")
	// is ample for the product while bounding certificate and policy work.
	maxNodeGroups = 64

	maxPublicEndpointHostBytes = 253
	// Brackets around an IPv6 literal, a colon, and a five-digit port add at
	// most eight bytes to the host.
	maxPublicEndpointBytes = maxPublicEndpointHostBytes + 8

	// These plaintext certificate/key limits are the recovery contract. The
	// graph-level encrypted limits below add AES-GCM's nonce/tag and raw URL
	// base64 expansion, so ordinary reads reject material recovery would reject.
	secretBoxNonceBytes = 12
	secretBoxTagBytes   = 16
	// Raw base64 length is ceil(n*8/6).
	maxEncryptedCAKeyBytes         = ((maxNebulaCAPrivateKeySize+secretBoxNonceBytes+secretBoxTagBytes)*8 + 5) / 6
	configSigningPublicKeyBytes    = (ed25519.PublicKeySize*8 + 5) / 6
	encryptedConfigSigningKeyBytes = ((ed25519.PrivateKeySize+secretBoxNonceBytes+secretBoxTagBytes)*8 + 5) / 6

	maxRevocationReasonBytes           = 256
	maxAuditActionBytes                = 128
	maxAuditResourceBytes              = 64
	maxAuditDetailKeysPerObject        = 32
	maxAuditDetailArrayItems           = 32
	maxAuditDetailDepth                = 4
	maxAuditDetailScalars              = 128
	maxAuditDetailTotalKeys            = 128
	maxAuditDetailStringBytes          = 1024
	maxAuditDetailAggregateStringBytes = 16 << 10
)

var auditLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func validTopologyLabel(value string) bool {
	return topologyLabelPattern.MatchString(value)
}

func validatePersistedNetworkMaterial(network Network) error {
	if !validBoundedUTF8(network.CACertificate, maxNebulaCACertificateSize, false) {
		return errors.New("CA certificate is empty, oversized, or not valid UTF-8")
	}
	if err := validateCanonicalRawURLBase64(network.EncryptedCAKey, maxEncryptedCAKeyBytes, secretBoxNonceBytes+secretBoxTagBytes+1, maxNebulaCAPrivateKeySize+secretBoxNonceBytes+secretBoxTagBytes); err != nil {
		return fmt.Errorf("encrypted CA key: %w", err)
	}

	hasPublic := network.ConfigSigningPublicKey != ""
	hasPrivate := network.EncryptedConfigSigningKey != ""
	// Pair completeness is deliberately left to EnsureManagedNetworks and the
	// recovery validator: that preserves their existing, explicit legacy
	// migration/error path. Any half that is present must still be well formed.
	if hasPublic {
		if !validConfigSigningPublicKey(network.ConfigSigningPublicKey) {
			return errors.New("config signing public key is not canonical")
		}
	}
	if hasPrivate {
		sealedPrivateKey, err := base64.RawURLEncoding.DecodeString(network.EncryptedConfigSigningKey)
		if err != nil || len(network.EncryptedConfigSigningKey) != encryptedConfigSigningKeyBytes || len(sealedPrivateKey) != ed25519.PrivateKeySize+secretBoxNonceBytes+secretBoxTagBytes || base64.RawURLEncoding.EncodeToString(sealedPrivateKey) != network.EncryptedConfigSigningKey {
			return errors.New("encrypted config signing key is not canonical")
		}
	}
	return nil
}

func validConfigSigningPublicKey(value string) bool {
	publicKey, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(value) == configSigningPublicKeyBytes && len(publicKey) == ed25519.PublicKeySize && base64.RawURLEncoding.EncodeToString(publicKey) == value
}

func validatePersistedRecoveryResultMaterial(result *AgentRecoveryBundle, network Network) error {
	if result == nil {
		return errors.New("recovery result is missing")
	}
	if result.Node.NetworkID != network.ID || !validCanonicalNodeGroups(result.Node.Groups) {
		return errors.New("recovery result node identity or groups are not canonical")
	}
	if err := validateCanonicalRoutedSubnets(result.Node.RoutedSubnets); err != nil {
		return fmt.Errorf("recovery result routed subnets are not canonical: %w", err)
	}
	if (result.Node.Site == "") != (result.Node.FailureDomain == "") || result.Node.Site != "" && (!validTopologyLabel(result.Node.Site) || !validTopologyLabel(result.Node.FailureDomain)) {
		return errors.New("recovery result node topology metadata is not canonical")
	}
	if !validPersistedID(result.Node.ID) || !namePattern.MatchString(result.Node.Name) || result.Node.Role != "member" && result.Node.Role != "lighthouse" || result.Node.Status != "active" {
		return errors.New("recovery result node metadata is invalid")
	}
	networkPrefix, networkErr := netip.ParsePrefix(network.CIDR)
	nodeAddress, addressErr := netip.ParseAddr(result.Node.IP)
	if networkErr != nil || addressErr != nil || !nodeAddress.Is4() || nodeAddress.String() != result.Node.IP || !networkPrefix.Contains(nodeAddress) {
		return errors.New("recovery result node address is invalid")
	}
	if result.Node.PublicEndpoint != "" {
		if err := validateEndpoint(result.Node.PublicEndpoint); err != nil {
			return fmt.Errorf("recovery result node endpoint: %w", err)
		}
	}
	if !validBoundedUTF8(result.Node.Certificate, maxNebulaHostCertificateSize, false) || !validBoundedUTF8(result.Certificate, maxNebulaHostCertificateSize, false) || result.Node.Certificate != result.Certificate {
		return errors.New("recovery result certificate is empty, oversized, invalid UTF-8, or inconsistent")
	}
	if !fingerprintPattern.MatchString(result.Node.CertificateFingerprint) || result.Node.CertificateFingerprint != result.CertificateFingerprint || result.Node.CertificateExpiresAt == nil || !result.Node.CertificateExpiresAt.Equal(result.CertificateExpiresAt) || result.Node.CertificateRenewAfter == nil || !result.Node.CertificateRenewAfter.Equal(result.CertificateRenewAfter) || !result.Node.CertificateRenewAfter.Before(*result.Node.CertificateExpiresAt) || result.Node.CertificateGeneration < 1 || result.Node.CertificateGeneration != result.CertificateGeneration {
		return errors.New("recovery result certificate lifecycle is invalid or inconsistent")
	}
	if result.Node.AgentCredentialExpiresAt == nil || !result.Node.AgentCredentialExpiresAt.Equal(result.AgentCredentialExpiresAt) || result.Node.AgentCredentialGeneration < 1 || result.Node.AgentCredentialGeneration != result.AgentCredentialGeneration || result.Node.CreatedAt.IsZero() || result.Node.EnrolledAt == nil || result.Node.EnrolledAt.Before(result.Node.CreatedAt) || result.Node.RevokedAt != nil {
		return errors.New("recovery result node lifecycle is invalid or inconsistent")
	}
	if result.ConfigRevision < 1 || result.ConfigRevision > network.ConfigRevision || result.ConfigIssuedAt.IsZero() {
		return errors.New("recovery result config lifecycle is invalid")
	}
	if err := validatePersistedNodeTelemetry(result.Node, network); err != nil {
		return fmt.Errorf("recovery result node telemetry: %w", err)
	}
	if !validBoundedUTF8(result.CA, maxNebulaCATrustBundleSize, false) || result.CA != networkTrustBundle(network) {
		return errors.New("recovery result CA certificate is empty, oversized, invalid UTF-8, or inconsistent")
	}
	if !validConfigSigningPublicKey(result.ConfigSigningPublicKey) {
		return errors.New("recovery result config signing public key is not canonical")
	}
	if err := validateManagedConfig(result.Config); err != nil {
		return fmt.Errorf("recovery result config: %w", err)
	}
	return nil
}

func validatePersistedEnrollmentClaim(enrollment EnrollmentToken) error {
	hasClaimID := enrollment.ClaimID != ""
	hasClaimedAt := enrollment.ClaimedAt != nil
	hasClaimKey := enrollment.ClaimKeyHash != ""
	if hasClaimID || hasClaimedAt || hasClaimKey {
		if !hasClaimID || !hasClaimedAt || !hasClaimKey || !validPersistedID(enrollment.ClaimID) || !ValidTokenHash(enrollment.ClaimKeyHash) || enrollment.ClaimedAt.IsZero() {
			return errors.New("claim metadata is incomplete or invalid")
		}
	}
	if enrollment.UsedAt != nil && enrollment.UsedAt.IsZero() {
		return errors.New("used-at time is zero")
	}
	return nil
}

func validateGeneratedCA(certificate, privateKey string) error {
	if !validBoundedUTF8(certificate, maxNebulaCACertificateSize, false) {
		return errors.New("generated Nebula CA certificate is empty, oversized, or not valid UTF-8")
	}
	if !validBoundedUTF8(privateKey, maxNebulaCAPrivateKeySize, false) {
		return errors.New("generated Nebula CA private key is empty, oversized, or not valid UTF-8")
	}
	return nil
}

func validateCanonicalRawURLBase64(value string, maxEncoded, minDecoded, maxDecoded int) error {
	if value == "" || len(value) > maxEncoded || !utf8.ValidString(value) {
		return errors.New("value is empty, oversized, or not valid UTF-8")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minDecoded || len(decoded) > maxDecoded || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("value is not canonical raw URL base64 or has an invalid decoded size")
	}
	return nil
}

func validCanonicalNodeGroups(groups []string) bool {
	if len(groups) == 0 || len(groups) > maxNodeGroups {
		return false
	}
	foundAll := false
	previous := ""
	for _, group := range groups {
		if !groupPattern.MatchString(group) || (previous != "" && previous >= group) {
			return false
		}
		foundAll = foundAll || group == "all"
		previous = group
	}
	return foundAll
}

func validBoundedUTF8(value string, maxBytes int, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= maxBytes && utf8.ValidString(value)
}

func validBoundedPlainText(value string, maxBytes int, allowEmpty bool) bool {
	if !validBoundedUTF8(value, maxBytes, allowEmpty) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validAuditLabel(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && auditLabelPattern.MatchString(value)
}

type auditDetailBudget struct {
	keys        int
	scalars     int
	stringBytes int
}

func validateAuditDetails(details map[string]any) error {
	budget := auditDetailBudget{}
	return validateAuditDetailObject(details, 1, &budget)
}

func validateAuditDetailObject(value map[string]any, depth int, budget *auditDetailBudget) error {
	if depth > maxAuditDetailDepth {
		return fmt.Errorf("detail nesting exceeds %d levels", maxAuditDetailDepth)
	}
	if len(value) > maxAuditDetailKeysPerObject {
		return fmt.Errorf("detail object exceeds %d keys", maxAuditDetailKeysPerObject)
	}
	budget.keys += len(value)
	if budget.keys > maxAuditDetailTotalKeys {
		return fmt.Errorf("details exceed %d total keys", maxAuditDetailTotalKeys)
	}
	for key, child := range value {
		if !validAuditLabel(key, maxAuditResourceBytes) {
			return fmt.Errorf("detail key %q is invalid", key)
		}
		if err := validateAuditDetailValue(child, depth+1, budget); err != nil {
			return fmt.Errorf("detail %q: %w", key, err)
		}
	}
	return nil
}

func validateAuditDetailValue(value any, depth int, budget *auditDetailBudget) error {
	if depth > maxAuditDetailDepth {
		return fmt.Errorf("detail nesting exceeds %d levels", maxAuditDetailDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		return validateAuditDetailObject(typed, depth, budget)
	case []any:
		if len(typed) > maxAuditDetailArrayItems {
			return fmt.Errorf("detail array exceeds %d items", maxAuditDetailArrayItems)
		}
		for index, child := range typed {
			if err := validateAuditDetailValue(child, depth+1, budget); err != nil {
				return fmt.Errorf("array item %d: %w", index, err)
			}
		}
		return nil
	case nil, bool:
		return consumeAuditScalar(budget, 0)
	case string:
		if !validBoundedPlainText(typed, maxAuditDetailStringBytes, true) {
			return fmt.Errorf("string is oversized, not valid UTF-8, or contains control characters")
		}
		return consumeAuditScalar(budget, len(typed))
	case time.Time:
		if typed.IsZero() {
			return errors.New("time is zero")
		}
		return consumeAuditScalar(budget, len(typed.UTC().Format(time.RFC3339Nano)))
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return errors.New("number is not finite")
		}
		return consumeAuditScalar(budget, 0)
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return errors.New("number is not finite")
		}
		return consumeAuditScalar(budget, 0)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return consumeAuditScalar(budget, 0)
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return errors.New("JSON number is invalid or not finite")
		}
		return consumeAuditScalar(budget, 0)
	default:
		return fmt.Errorf("unsupported detail type %T", value)
	}
}

func consumeAuditScalar(budget *auditDetailBudget, stringBytes int) error {
	budget.scalars++
	budget.stringBytes += stringBytes
	if budget.scalars > maxAuditDetailScalars {
		return fmt.Errorf("details exceed %d scalar values", maxAuditDetailScalars)
	}
	if budget.stringBytes > maxAuditDetailAggregateStringBytes {
		return fmt.Errorf("detail strings exceed %d aggregate bytes", maxAuditDetailAggregateStringBytes)
	}
	return nil
}

func cloneAuditDetails(details map[string]any) (map[string]any, error) {
	if details == nil {
		return nil, nil
	}
	cloned := make(map[string]any, len(details))
	for key, value := range details {
		copy, err := cloneAuditDetailValue(value)
		if err != nil {
			return nil, fmt.Errorf("clone audit detail %q: %w", key, err)
		}
		cloned[key] = copy
	}
	return cloned, nil
}

func cloneAuditDetailValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		return cloneAuditDetails(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, child := range typed {
			copy, err := cloneAuditDetailValue(child)
			if err != nil {
				return nil, err
			}
			cloned[index] = copy
		}
		return cloned, nil
	case nil, bool, string, time.Time, float32, float64,
		int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return typed, nil
	default:
		return nil, fmt.Errorf("unsupported detail type %T", value)
	}
}
