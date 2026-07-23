package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	nebulacert "github.com/slackhq/nebula/cert"
)

const (
	maxNebulaCAPrivateKeySize    = 4 << 10
	maxNebulaCACertificateSize   = 128 << 10
	maxNebulaCATrustBundleSize   = 2 * maxNebulaCACertificateSize
	maxNebulaHostCertificateSize = 128 << 10
	maxRecoveryJSONDepth         = 64
)

type recoveryIssuanceKey struct {
	nodeID      string
	networkID   string
	fingerprint string
	expiresAt   string
}

type recoveryIssuanceIndex map[recoveryIssuanceKey][]time.Time

// ValidateRecoverySnapshot validates exact persisted control-state bytes for
// offline recovery. It performs the same strict structural and graph checks as
// the live store, then proves that every encrypted private key is recoverable
// with box. The input is never modified.
func ValidateRecoverySnapshot(raw []byte, box *SecretBox) error {
	_, err := validateRecoverySnapshot(raw, box)
	return err
}

// ExportRecoverySnapshot returns an exact, detached copy of the durable
// control-state file. The store's process lock and transaction mutex remain
// held across the stable read, cryptographic validation, and comparison with
// the in-memory state.
func (s *Store) ExportRecoverySnapshot(ctx context.Context, box *SecretBox) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("recovery snapshot context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if box == nil || box.aead == nil {
		return nil, errors.New("recovery snapshot requires a secret box")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil, errors.New("control store is closed")
	}
	if err := s.ensureDurableLocked(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw, err := s.readRecoverySnapshotLocked()
	if err != nil {
		return nil, fmt.Errorf("read recovery snapshot: %w", err)
	}
	persisted, err := validateRecoverySnapshot(raw, box)
	if err != nil {
		return nil, fmt.Errorf("validate recovery snapshot: %w", err)
	}
	inMemory, err := persistenceNormalizedState(s.state)
	if err != nil {
		return nil, fmt.Errorf("normalize in-memory recovery state: %w", err)
	}
	if !reflect.DeepEqual(persisted, inMemory) {
		return nil, errors.New("persisted recovery snapshot does not match in-memory control state")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(raw), nil
}

func validateRecoverySnapshot(raw []byte, box *SecretBox) (State, error) {
	if box == nil || box.aead == nil {
		return State{}, errors.New("recovery snapshot requires a secret box")
	}
	if len(raw) == 0 {
		return State{}, errors.New("recovery snapshot is empty")
	}
	if len(raw) > maxPersistedStateSize {
		return State{}, fmt.Errorf("state exceeds the %d-byte safety limit", maxPersistedStateSize)
	}
	if !utf8.Valid(raw) {
		return State{}, errors.New("recovery snapshot is not valid UTF-8")
	}
	if err := rejectDuplicateRecoveryJSONNames(raw); err != nil {
		return State{}, fmt.Errorf("decode recovery snapshot: %w", err)
	}

	var state State
	if err := decodePersistedState(raw, &state); err != nil {
		return State{}, fmt.Errorf("decode recovery snapshot: %w", err)
	}
	if err := validateStateGraph(state); err != nil {
		return State{}, fmt.Errorf("validate recovery snapshot graph: %w", err)
	}
	networksWithNodes := make(map[string]struct{}, len(state.Nodes))
	for _, node := range state.Nodes {
		networksWithNodes[node.NetworkID] = struct{}{}
	}
	networks := make(map[string]Network, len(state.Networks))
	certificateAuthorities := make(map[string]map[string]nebulacert.Certificate, len(state.Networks))
	issuances := make(recoveryIssuanceIndex, len(state.Issuances))
	for _, issuance := range state.Issuances {
		key := recoveryIssuanceKey{nodeID: issuance.NodeID, networkID: issuance.NetworkID, fingerprint: issuance.Fingerprint, expiresAt: issuance.ExpiresAt.UTC().Format(time.RFC3339Nano)}
		issuances[key] = append(issuances[key], issuance.IssuedAt)
	}
	for _, network := range state.Networks {
		caKey, err := box.Open(network.EncryptedCAKey)
		if err != nil {
			return State{}, fmt.Errorf("network %q CA key: %w", network.ID, err)
		}
		ca, keyErr := validateNebulaCAKeyPair(network, caKey)
		clear(caKey)
		if keyErr != nil {
			return State{}, fmt.Errorf("network %q CA key: %w", network.ID, keyErr)
		}
		networks[network.ID] = network
		certificateAuthorities[network.ID] = map[string]nebulacert.Certificate{ConfigDigest(network.CACertificate): ca}
		if network.CARotation.Phase == CARotationPhasePrepared || network.CARotation.Phase == CARotationPhaseRotating {
			nextKey, err := box.Open(network.CARotation.EncryptedNextCAKey)
			if err != nil {
				return State{}, fmt.Errorf("network %q next CA key: %w", network.ID, err)
			}
			nextNetwork := network
			nextNetwork.CACertificate = network.CARotation.NextCACertificate
			nextCA, nextErr := validateNebulaCAKeyPair(nextNetwork, nextKey)
			clear(nextKey)
			if nextErr != nil {
				return State{}, fmt.Errorf("network %q next CA key: %w", network.ID, nextErr)
			}
			certificateAuthorities[network.ID][ConfigDigest(network.CARotation.NextCACertificate)] = nextCA
		}

		hasPublic := network.ConfigSigningPublicKey != ""
		hasPrivate := network.EncryptedConfigSigningKey != ""
		if hasPublic != hasPrivate {
			return State{}, fmt.Errorf("network %q has an incomplete config signing key pair", network.ID)
		}
		if !hasPrivate {
			if _, inUse := networksWithNodes[network.ID]; inUse {
				return State{}, fmt.Errorf("network %q has nodes but no config signing key pair", network.ID)
			}
			continue
		}
		privateKey, err := box.OpenFor("config-signing-key-v1", network.EncryptedConfigSigningKey)
		if err != nil {
			return State{}, fmt.Errorf("network %q config signing key: %w", network.ID, err)
		}
		pairErr := ValidateConfigSigningKeyPair(network.ConfigSigningPublicKey, privateKey)
		clear(privateKey)
		if pairErr != nil {
			return State{}, fmt.Errorf("network %q config signing key: %w", network.ID, pairErr)
		}
	}
	for _, node := range state.Nodes {
		network, ok := networks[node.NetworkID]
		if !ok {
			return State{}, fmt.Errorf("node %q references a missing network during certificate recovery validation", node.ID)
		}
		authorityDigest := node.CertificateAuthoritySHA256
		if authorityDigest == "" {
			authorityDigest = ConfigDigest(network.CACertificate)
		}
		if err := validateNebulaHostCertificateLifecycle(node, network, certificateAuthorities[node.NetworkID][authorityDigest], issuances); err != nil {
			return State{}, fmt.Errorf("node %q certificate: %w", node.ID, err)
		}
	}
	return state, nil
}

func persistenceNormalizedState(state State) (State, error) {
	raw, err := encodePersistedState(state)
	if err != nil {
		return State{}, err
	}
	var normalized State
	if err := decodePersistedState(raw, &normalized); err != nil {
		return State{}, err
	}
	return normalized, nil
}

func (s *Store) readRecoverySnapshotLocked() ([]byte, error) {
	before, err := os.Lstat(s.path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || !statePathPrivate(before) || before.Size() > maxPersistedStateSize {
		return nil, errors.New("state must be a bounded private regular file")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("state changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPersistedStateSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPersistedStateSize {
		return nil, fmt.Errorf("state exceeds the %d-byte safety limit", maxPersistedStateSize)
	}
	after, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("state changed during recovery snapshot read")
	}
	return raw, nil
}

func validateNebulaCAKeyPair(network Network, privateKeyPEM []byte) (nebulacert.Certificate, error) {
	certificate := network.CACertificate
	if len(certificate) == 0 || len(certificate) > maxNebulaCACertificateSize || !utf8.ValidString(certificate) {
		return nil, errors.New("Nebula CA certificate is empty, oversized, or not valid UTF-8")
	}
	if len(privateKeyPEM) == 0 || len(privateKeyPEM) > maxNebulaCAPrivateKeySize || !utf8.Valid(privateKeyPEM) {
		return nil, errors.New("Nebula CA private key is empty, oversized, or not valid UTF-8")
	}

	certificatePEM := []byte(certificate)
	ca, certificateRemainder, err := nebulacert.UnmarshalCertificateFromPEM(certificatePEM)
	if err != nil {
		return nil, fmt.Errorf("decode Nebula CA certificate: %w", err)
	}
	canonicalCertificate, err := ca.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("canonicalize Nebula CA certificate: %w", err)
	}
	consumedCertificate := len(certificatePEM) - len(certificateRemainder)
	if consumedCertificate < 1 || !bytes.Equal(certificatePEM[:consumedCertificate], canonicalCertificate) || len(bytes.TrimSpace(certificateRemainder)) != 0 {
		return nil, errors.New("Nebula CA certificate is not one canonical PEM block")
	}
	if !ca.IsCA() || ca.Issuer() != "" {
		return nil, errors.New("Nebula CA certificate is not a self-issued CA")
	}
	expectedNetwork, err := netip.ParsePrefix(network.CIDR)
	if err != nil {
		return nil, errors.New("network record has an invalid CA constraint CIDR")
	}
	expectedNetwork = expectedNetwork.Masked()
	certificateNetworks := ca.Networks()
	if ca.Name() != network.Name || len(certificateNetworks) != 1 || certificateNetworks[0] != expectedNetwork {
		return nil, errors.New("Nebula CA identity or network constraint does not match its network record")
	}
	if len(ca.Groups()) != 0 || len(ca.UnsafeNetworks()) != 0 {
		return nil, errors.New("Nebula CA contains group or unsafe-network constraints not represented by its network record")
	}
	if !ca.CheckSignature(ca.PublicKey()) {
		return nil, errors.New("Nebula CA certificate self-signature is invalid")
	}

	privateKey, keyRemainder, curve, err := nebulacert.UnmarshalSigningPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decode Nebula CA private key: %w", err)
	}
	defer clear(privateKey)
	canonicalPrivateKey := nebulacert.MarshalSigningPrivateKeyToPEM(curve, privateKey)
	defer clear(canonicalPrivateKey)
	consumedKey := len(privateKeyPEM) - len(keyRemainder)
	if len(canonicalPrivateKey) == 0 || consumedKey < 1 || !bytes.Equal(privateKeyPEM[:consumedKey], canonicalPrivateKey) || len(bytes.TrimSpace(keyRemainder)) != 0 {
		return nil, errors.New("Nebula CA private key is not one canonical signing-key PEM block")
	}
	if err := ca.VerifyPrivateKey(curve, privateKey); err != nil {
		return nil, fmt.Errorf("Nebula CA public/private key pair does not match: %w", err)
	}
	return ca, nil
}

func validateNebulaHostCertificateLifecycle(node Node, network Network, ca nebulacert.Certificate, issuances recoveryIssuanceIndex) error {
	hasCertificate := node.Certificate != ""
	hasFingerprint := node.CertificateFingerprint != ""
	hasExpiresAt := node.CertificateExpiresAt != nil
	hasRenewAfter := node.CertificateRenewAfter != nil
	hasPublicKeyHash := node.PublicKeyHash != ""
	hasGeneration := node.CertificateGeneration != 0
	hasAnyCertificateMetadata := hasCertificate || hasFingerprint || hasExpiresAt || hasRenewAfter || hasPublicKeyHash || hasGeneration

	switch node.Status {
	case "pending":
		if hasAnyCertificateMetadata {
			return errors.New("pending node retains certificate material")
		}
		return nil
	case "active":
		if !hasCertificate || !hasFingerprint || !hasExpiresAt || !hasRenewAfter || !hasPublicKeyHash || node.CertificateGeneration < 1 {
			return errors.New("active node is missing complete certificate metadata")
		}
	case "revoked":
		if node.EnrolledAt == nil {
			if hasAnyCertificateMetadata {
				return errors.New("never-enrolled revoked node retains certificate material")
			}
			return nil
		}
		if !hasCertificate || !hasFingerprint || !hasExpiresAt || !hasRenewAfter || !hasPublicKeyHash || node.CertificateGeneration < 1 {
			return errors.New("enrolled revoked node is missing complete certificate metadata")
		}
	default:
		return errors.New("node has an unsupported certificate lifecycle")
	}

	if ca == nil {
		return errors.New("network CA is unavailable")
	}
	if len(node.Certificate) > maxNebulaHostCertificateSize || !utf8.ValidString(node.Certificate) {
		return errors.New("Nebula host certificate is oversized or not valid UTF-8")
	}
	certificatePEM := []byte(node.Certificate)
	certificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM(certificatePEM)
	if err != nil {
		return fmt.Errorf("decode Nebula host certificate: %w", err)
	}
	canonicalCertificate, err := certificate.MarshalPEM()
	if err != nil {
		return fmt.Errorf("canonicalize Nebula host certificate: %w", err)
	}
	consumed := len(certificatePEM) - len(remainder)
	if consumed < 1 || !bytes.Equal(certificatePEM[:consumed], canonicalCertificate) || len(bytes.TrimSpace(remainder)) != 0 {
		return errors.New("Nebula host certificate is not one canonical PEM block")
	}
	if certificate.IsCA() {
		return errors.New("Nebula host certificate is a CA")
	}
	if certificate.Version() != ca.Version() || certificate.Curve() != ca.Curve() {
		return errors.New("Nebula host certificate version or curve does not match its network CA")
	}
	caFingerprint, err := ca.Fingerprint()
	if err != nil {
		return fmt.Errorf("fingerprint Nebula network CA: %w", err)
	}
	if certificate.Issuer() != caFingerprint || !certificate.CheckSignature(ca.PublicKey()) {
		return errors.New("Nebula host certificate issuer or signature does not match its network CA")
	}
	if certificate.NotBefore().Before(ca.NotBefore()) || certificate.NotAfter().After(ca.NotAfter()) || !certificate.NotAfter().After(certificate.NotBefore()) {
		return errors.New("Nebula host certificate validity is outside its network CA validity")
	}
	if certificate.Name() != node.Name {
		return errors.New("Nebula host certificate name does not match its node record")
	}

	networkPrefix, err := netip.ParsePrefix(network.CIDR)
	if err != nil {
		return errors.New("network record has an invalid host certificate CIDR")
	}
	nodeAddress, err := netip.ParseAddr(node.IP)
	if err != nil || !nodeAddress.Is4() {
		return errors.New("node record has an invalid host certificate address")
	}
	expectedNetwork := netip.PrefixFrom(nodeAddress, networkPrefix.Bits())
	certificateNetworks := certificate.Networks()
	if len(certificateNetworks) != 1 || certificateNetworks[0] != expectedNetwork {
		return errors.New("Nebula host certificate network does not match its assigned node address")
	}
	if len(certificate.UnsafeNetworks()) != 0 {
		return errors.New("Nebula host certificate contains unsupported unsafe networks")
	}

	if !validRecoveryNodeGroups(node.Groups) {
		return errors.New("node record contains non-canonical certificate groups")
	}
	if !slices.Equal(certificate.Groups(), node.Groups) {
		return errors.New("Nebula host certificate groups do not match its node record")
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		return fmt.Errorf("fingerprint Nebula host certificate: %w", err)
	}
	if fingerprint != node.CertificateFingerprint {
		return errors.New("Nebula host certificate fingerprint does not match its node record")
	}
	if !certificate.NotAfter().Equal(node.CertificateExpiresAt.UTC()) {
		return errors.New("Nebula host certificate expiry does not match its node record")
	}
	expectedRenewAfter := certificate.NotAfter().Add(-renewalWindow(time.Duration(network.CertificateTTL) * time.Hour))
	if !node.CertificateRenewAfter.Equal(expectedRenewAfter) || !node.CertificateRenewAfter.Before(*node.CertificateExpiresAt) {
		return errors.New("Nebula host certificate renewal metadata does not match its node record")
	}
	canonicalPublicKey := certificate.MarshalPublicKeyPEM()
	if len(canonicalPublicKey) == 0 || !TokenHashEqual(node.PublicKeyHash, HashToken(string(canonicalPublicKey))) {
		return errors.New("Nebula host certificate public key does not match its node record")
	}
	matchingIssuance := false
	key := recoveryIssuanceKey{nodeID: node.ID, networkID: node.NetworkID, fingerprint: fingerprint, expiresAt: certificate.NotAfter().UTC().Format(time.RFC3339Nano)}
	for _, issuedAt := range issuances[key] {
		if !issuedAt.Before(certificate.NotBefore()) && issuedAt.Before(certificate.NotAfter()) {
			matchingIssuance = true
			break
		}
	}
	if !matchingIssuance {
		return errors.New("Nebula host certificate has no matching issuance record")
	}
	return nil
}

// CreateNode normalizes operator-provided groups and sorts the implicit "all"
// group with them. The ordinary graph and recovery boundary share this exact
// canonical representation.
func validRecoveryNodeGroups(groups []string) bool {
	return validCanonicalNodeGroups(groups)
}

func rejectDuplicateRecoveryJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	structSchemas := make(map[reflect.Type]recoveryJSONStructSchema)
	var walk func(reflect.Type, int) error
	walk = func(expected reflect.Type, depth int) error {
		if depth > maxRecoveryJSONDepth {
			return errors.New("JSON nesting exceeds its depth limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, structured := token.(json.Delim)
		if !structured {
			return nil
		}
		expected = indirectRecoveryJSONType(expected)
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			var schema recoveryJSONStructSchema
			if expected != nil && expected.Kind() == reflect.Struct && !recoveryJSONCustomUnmarshaler(expected) {
				schema = recoveryJSONSchemaFor(expected, structSchemas)
			}
			var element reflect.Type
			if expected != nil && expected.Kind() == reflect.Map {
				element = expected.Elem()
			}
			seenSchemaNames := make(map[string]string)
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("JSON object name is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return fmt.Errorf("duplicate JSON object name %q", name)
				}
				seen[name] = struct{}{}

				valueType := element
				if schema.fields != nil {
					if fieldType, exact := schema.fields[name]; exact {
						valueType = fieldType
					}
					folded := foldRecoveryJSONName(name)
					if canonical, known := schema.folded[folded]; known {
						if previous, duplicate := seenSchemaNames[folded]; duplicate {
							return fmt.Errorf("duplicate JSON object name %q conflicts with schema field %q", name, previous)
						}
						seenSchemaNames[folded] = canonical
						if name != canonical {
							return fmt.Errorf("JSON object name %q must use exact schema spelling %q", name, canonical)
						}
					}
				}
				if err := walk(valueType, depth+1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("invalid JSON object closing delimiter")
			}
		case '[':
			var element reflect.Type
			if expected != nil && (expected.Kind() == reflect.Array || expected.Kind() == reflect.Slice) {
				element = expected.Elem()
			}
			for decoder.More() {
				if err := walk(element, depth+1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("invalid JSON array closing delimiter")
			}
		default:
			return errors.New("invalid JSON opening delimiter")
		}
		return nil
	}
	if err := walk(reflect.TypeOf(persistedState{}), 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

type recoveryJSONStructSchema struct {
	fields map[string]reflect.Type
	folded map[string]string
}

func recoveryJSONSchemaFor(valueType reflect.Type, cache map[reflect.Type]recoveryJSONStructSchema) recoveryJSONStructSchema {
	if schema, ok := cache[valueType]; ok {
		return schema
	}
	schema := recoveryJSONStructSchema{
		fields: make(map[string]reflect.Type),
		folded: make(map[string]string),
	}
	for _, field := range reflect.VisibleFields(valueType) {
		if field.PkgPath != "" {
			continue
		}
		tagName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if tagName == "-" {
			continue
		}
		if field.Anonymous && tagName == "" {
			embedded := indirectRecoveryJSONType(field.Type)
			if embedded != nil && embedded.Kind() == reflect.Struct {
				continue
			}
		}
		if tagName == "" {
			tagName = field.Name
		}
		schema.fields[tagName] = field.Type
		schema.folded[foldRecoveryJSONName(tagName)] = tagName
	}
	cache[valueType] = schema
	return schema
}

func indirectRecoveryJSONType(valueType reflect.Type) reflect.Type {
	for valueType != nil && valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	return valueType
}

func recoveryJSONCustomUnmarshaler(valueType reflect.Type) bool {
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	return valueType.Implements(unmarshaler) || reflect.PointerTo(valueType).Implements(unmarshaler)
}

// foldRecoveryJSONName mirrors encoding/json's field-name folding. Applying it
// only to typed struct objects prevents case aliases from overwriting fields
// while leaving application-owned map keys, such as AuditEvent.Details, alone.
func foldRecoveryJSONName(name string) string {
	folded := make([]byte, 0, len(name))
	for offset := 0; offset < len(name); {
		if value := name[offset]; value < utf8.RuneSelf {
			if value >= 'a' && value <= 'z' {
				value -= 'a' - 'A'
			}
			folded = append(folded, value)
			offset++
			continue
		}
		value, size := utf8.DecodeRuneInString(name[offset:])
		for {
			next := unicode.SimpleFold(value)
			if next <= value {
				value = next
				break
			}
			value = next
		}
		folded = utf8.AppendRune(folded, value)
		offset += size
	}
	return string(folded)
}
