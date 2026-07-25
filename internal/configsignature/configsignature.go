// Package configsignature owns Mesh's domain-separated desired-configuration
// signature contract. Control-plane signers and every node runtime must use
// this one implementation so platform adapters cannot fork trust semantics.
package configsignature

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaximumManagedConfigBytes = 4 << 20

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Metadata struct {
	NodeID                            string
	NetworkID                         string
	Revision                          int64
	IssuedAt                          time.Time
	CACertificateSHA256               string
	PreviousCACertificateSHA256       string
	CARotationRequired                bool
	CertificateProfileRenewalRequired bool
	CertificateFingerprint            string
	CertificateExpiresAt              time.Time
	CertificateRenewAfter             time.Time
	CertificateGeneration             int64
	PublicKeyHash                     string
}

func Sign(privateKey []byte, metadata Metadata, config string) (string, string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", "", fmt.Errorf("invalid config signing private key")
	}
	if err := ValidateManagedConfig(config); err != nil {
		return "", "", err
	}
	if err := validateMetadata(metadata); err != nil {
		return "", "", err
	}
	digest, canonical := signingPayload(metadata, config)
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), canonical)
	return digest, base64.RawURLEncoding.EncodeToString(signature), nil
}

func Verify(
	publicKeyEncoded string,
	metadata Metadata,
	config string,
	expectedDigest string,
	signatureEncoded string,
) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyEncoded)
	if err != nil ||
		len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != publicKeyEncoded {
		return fmt.Errorf("invalid config signing public key")
	}
	if err := validateMetadata(metadata); err != nil {
		return err
	}
	if err := ValidateManagedConfig(config); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil ||
		len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != signatureEncoded {
		return fmt.Errorf("invalid config signature encoding")
	}
	digest, canonical := signingPayload(metadata, config)
	if subtle.ConstantTimeCompare([]byte(digest), []byte(expectedDigest)) != 1 {
		return fmt.Errorf("config digest mismatch")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return fmt.Errorf("config signature verification failed")
	}
	return nil
}

func Digest(config string) string {
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

// ValidateManagedConfig applies the exact byte-level envelope shared by
// signers and platform runtimes before they parse a desired configuration.
func ValidateManagedConfig(config string) error {
	if config == "" ||
		len(config) > MaximumManagedConfigBytes ||
		!utf8.ValidString(config) ||
		strings.ContainsRune(config, '\r') {
		return fmt.Errorf(
			"managed config must be nonempty valid UTF-8 without carriage returns and no larger than %d bytes",
			MaximumManagedConfigBytes,
		)
	}
	return nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.NodeID == "" ||
		metadata.NetworkID == "" ||
		strings.ContainsAny(metadata.NodeID, "\r\n") ||
		strings.ContainsAny(metadata.NetworkID, "\r\n") {
		return fmt.Errorf("invalid signed config identity")
	}
	if metadata.Revision < 1 ||
		metadata.CertificateGeneration < 1 ||
		metadata.IssuedAt.IsZero() ||
		metadata.CertificateExpiresAt.IsZero() ||
		metadata.CertificateRenewAfter.IsZero() ||
		!metadata.CertificateRenewAfter.Before(metadata.CertificateExpiresAt) {
		return fmt.Errorf("invalid signed config revision or timestamp")
	}
	if !fingerprintPattern.MatchString(metadata.CACertificateSHA256) ||
		!fingerprintPattern.MatchString(metadata.CertificateFingerprint) ||
		!validTokenHash(metadata.PublicKeyHash) {
		return fmt.Errorf("invalid signed config certificate metadata")
	}
	if metadata.PreviousCACertificateSHA256 != "" &&
		(!fingerprintPattern.MatchString(metadata.PreviousCACertificateSHA256) ||
			metadata.PreviousCACertificateSHA256 == metadata.CACertificateSHA256) {
		return fmt.Errorf("invalid signed config CA transition metadata")
	}
	if metadata.CARotationRequired && metadata.PreviousCACertificateSHA256 == "" {
		return fmt.Errorf("CA rotation renewal requires an authenticated trust transition")
	}
	if metadata.CARotationRequired && metadata.CertificateProfileRenewalRequired {
		return fmt.Errorf(
			"CA rotation and certificate profile renewal cannot be required together",
		)
	}
	return nil
}

func signingPayload(metadata Metadata, config string) (string, []byte) {
	digest := Digest(config)
	if metadata.PreviousCACertificateSHA256 == "" &&
		!metadata.CARotationRequired &&
		!metadata.CertificateProfileRenewalRequired {
		canonical := "mesh-desired-artifact-v3\n" +
			"node_id=" + metadata.NodeID + "\n" +
			"network_id=" + metadata.NetworkID + "\n" +
			"revision=" + strconv.FormatInt(metadata.Revision, 10) + "\n" +
			"issued_at=" + metadata.IssuedAt.UTC().Format(time.RFC3339Nano) + "\n" +
			"config_sha256=" + digest + "\n" +
			"ca_sha256=" + metadata.CACertificateSHA256 + "\n" +
			"certificate_fingerprint=" + metadata.CertificateFingerprint + "\n" +
			"certificate_expires_at=" + metadata.CertificateExpiresAt.UTC().Format(time.RFC3339Nano) + "\n" +
			"certificate_renew_after=" + metadata.CertificateRenewAfter.UTC().Format(time.RFC3339Nano) + "\n" +
			"certificate_generation=" + strconv.FormatInt(metadata.CertificateGeneration, 10) + "\n" +
			"public_key_hash=" + metadata.PublicKeyHash + "\n"
		return digest, []byte(canonical)
	}
	if metadata.CertificateProfileRenewalRequired {
		canonical := "mesh-desired-artifact-v5\n" +
			"node_id=" + metadata.NodeID + "\n" +
			"network_id=" + metadata.NetworkID + "\n" +
			"revision=" + strconv.FormatInt(metadata.Revision, 10) + "\n" +
			"issued_at=" + metadata.IssuedAt.UTC().Format(time.RFC3339Nano) + "\n" +
			"config_sha256=" + digest + "\n" +
			"ca_sha256=" + metadata.CACertificateSHA256 + "\n" +
			"certificate_profile_renewal_required=true\n" +
			"certificate_fingerprint=" + metadata.CertificateFingerprint + "\n" +
			"certificate_expires_at=" + metadata.CertificateExpiresAt.UTC().Format(time.RFC3339Nano) + "\n" +
			"certificate_renew_after=" + metadata.CertificateRenewAfter.UTC().Format(time.RFC3339Nano) + "\n" +
			"certificate_generation=" + strconv.FormatInt(metadata.CertificateGeneration, 10) + "\n" +
			"public_key_hash=" + metadata.PublicKeyHash + "\n"
		return digest, []byte(canonical)
	}
	canonical := "mesh-desired-artifact-v4\n" +
		"node_id=" + metadata.NodeID + "\n" +
		"network_id=" + metadata.NetworkID + "\n" +
		"revision=" + strconv.FormatInt(metadata.Revision, 10) + "\n" +
		"issued_at=" + metadata.IssuedAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"config_sha256=" + digest + "\n" +
		"ca_sha256=" + metadata.CACertificateSHA256 + "\n" +
		"previous_ca_sha256=" + metadata.PreviousCACertificateSHA256 + "\n" +
		"ca_rotation_required=" + strconv.FormatBool(metadata.CARotationRequired) + "\n" +
		"certificate_fingerprint=" + metadata.CertificateFingerprint + "\n" +
		"certificate_expires_at=" + metadata.CertificateExpiresAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"certificate_renew_after=" + metadata.CertificateRenewAfter.UTC().Format(time.RFC3339Nano) + "\n" +
		"certificate_generation=" + strconv.FormatInt(metadata.CertificateGeneration, 10) + "\n" +
		"public_key_hash=" + metadata.PublicKeyHash + "\n"
	return digest, []byte(canonical)
}

func validTokenHash(encoded string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil &&
		len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == encoded
}
