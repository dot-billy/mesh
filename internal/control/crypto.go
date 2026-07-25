package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"mesh/internal/configsignature"
)

type SecretBox struct{ aead cipher.AEAD }

const adminCredentialVerifierKeyDomain = "mesh-admin-credential-verifier-key-v1"
const adminCredentialVerifierValueDomain = "mesh-admin-credential-verifier-value-v1\x00"
const masterKeyVerifierDomain = "mesh-master-key-verifier-v1"
const adminCredentialVerifierPrefix = "v1:"

func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

// DeriveAdminCredentialVerifier returns a keyed, domain-separated verifier for
// the administrator bearer. Keying it with the master key avoids placing an
// offline token oracle in state.json while still allowing backup validation to
// prove that both recovered credentials belong to the captured control state.
func DeriveAdminCredentialVerifier(masterKey, adminToken []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", fmt.Errorf("master key must be exactly 32 bytes")
	}
	if err := validateAdminCredential(adminToken); err != nil {
		return "", err
	}
	keyMAC := hmac.New(sha256.New, masterKey)
	_, _ = keyMAC.Write([]byte(adminCredentialVerifierKeyDomain))
	verifierKey := keyMAC.Sum(nil)
	defer clear(verifierKey)

	valueMAC := hmac.New(sha256.New, verifierKey)
	_, _ = valueMAC.Write([]byte(adminCredentialVerifierValueDomain))
	_, _ = valueMAC.Write(adminToken)
	verifier := valueMAC.Sum(nil)
	defer clear(verifier)
	return adminCredentialVerifierPrefix + base64.RawURLEncoding.EncodeToString(verifier), nil
}

// DeriveMasterKeyVerifier creates an independent state anchor for the master
// key. This prevents --rotate-admin-token from authorizing a simultaneous
// master-key replacement when a new or otherwise empty store has no CA
// ciphertext with which to distinguish the two changes.
func DeriveMasterKeyVerifier(masterKey []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", fmt.Errorf("master key must be exactly 32 bytes")
	}
	verifierMAC := hmac.New(sha256.New, masterKey)
	_, _ = verifierMAC.Write([]byte(masterKeyVerifierDomain))
	verifier := verifierMAC.Sum(nil)
	defer clear(verifier)
	return adminCredentialVerifierPrefix + base64.RawURLEncoding.EncodeToString(verifier), nil
}

// ValidAdminCredentialVerifier requires an explicit scheme identifier so a
// future derivation change cannot be mistaken for an administrator-token
// rotation.
func ValidAdminCredentialVerifier(verifier string) bool {
	return strings.HasPrefix(verifier, adminCredentialVerifierPrefix) && ValidTokenHash(strings.TrimPrefix(verifier, adminCredentialVerifierPrefix))
}

func ValidMasterKeyVerifier(verifier string) bool { return ValidAdminCredentialVerifier(verifier) }

func adminCredentialVerifierEqual(expected, actual string) bool {
	if !ValidAdminCredentialVerifier(expected) || !ValidAdminCredentialVerifier(actual) {
		return false
	}
	return TokenHashEqual(strings.TrimPrefix(expected, adminCredentialVerifierPrefix), strings.TrimPrefix(actual, adminCredentialVerifierPrefix))
}

func masterKeyVerifierEqual(expected, actual string) bool {
	return adminCredentialVerifierEqual(expected, actual)
}

func validateAdminCredential(adminToken []byte) error {
	if len(adminToken) < 32 || len(adminToken) > 4096 {
		return errors.New("administrator credential must contain 32-4096 printable ASCII characters")
	}
	for _, character := range adminToken {
		if character < 0x21 || character > 0x7e {
			return errors.New("administrator credential must contain 32-4096 printable ASCII characters")
		}
	}
	return nil
}

func GenerateConfigSigningKey() (string, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(publicKey), []byte(privateKey), nil
}

func ValidateConfigSigningKeyPair(publicKeyEncoded string, privateKey []byte) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyEncoded)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != publicKeyEncoded {
		return fmt.Errorf("invalid config signing public key")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid config signing private key")
	}
	derived := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(publicKey, derived) != 1 {
		return fmt.Errorf("config signing key pair does not match")
	}
	return nil
}

func SignConfig(privateKey []byte, metadata ConfigSignatureMetadata, config string) (string, string, error) {
	return configsignature.Sign(privateKey, metadata, config)
}

func VerifyConfig(publicKeyEncoded string, metadata ConfigSignatureMetadata, config, expectedDigest, signatureEncoded string) error {
	return configsignature.Verify(
		publicKeyEncoded,
		metadata,
		config,
		expectedDigest,
		signatureEncoded,
	)
}

func validateManagedConfig(config string) error {
	return configsignature.ValidateManagedConfig(config)
}

// SignRecoveryReceipt signs the credential-reset facts with the same network
// key agents already pin for desired configuration. A distinct domain prefix
// prevents a valid receipt from being interpreted as any config-signing
// payload (or vice versa).
func SignRecoveryReceipt(privateKey []byte, receipt RecoveryReceipt) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid config signing private key")
	}
	canonical, err := recoveryReceiptPayload(receipt)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), canonical)
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

// VerifyRecoveryReceipt verifies the domain-separated credential-reset
// receipt against a network config-signing public key already trusted by the
// caller. Trust-on-first-use decisions belong to the node agent, not here.
func VerifyRecoveryReceipt(publicKeyEncoded string, receipt RecoveryReceipt) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyEncoded)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != publicKeyEncoded {
		return fmt.Errorf("invalid config signing public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid recovery receipt signature encoding")
	}
	canonical, err := recoveryReceiptPayload(receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return fmt.Errorf("recovery receipt signature verification failed")
	}
	return nil
}

func recoveryReceiptPayload(receipt RecoveryReceipt) ([]byte, error) {
	if !validPersistedID(receipt.NodeID) || !validPersistedID(receipt.NetworkID) {
		return nil, fmt.Errorf("invalid recovery receipt identity")
	}
	if !ValidTokenHash(receipt.NewAgentTokenHash) || receipt.AgentCredentialGeneration < 1 || receipt.AgentCredentialExpiresAt.IsZero() {
		return nil, fmt.Errorf("invalid recovery receipt credential metadata")
	}
	if !fingerprintPattern.MatchString(receipt.ConfigSHA256) {
		return nil, fmt.Errorf("invalid recovery receipt config digest")
	}
	configSignature, err := base64.RawURLEncoding.DecodeString(receipt.ConfigSignature)
	if err != nil || len(configSignature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(configSignature) != receipt.ConfigSignature {
		return nil, fmt.Errorf("invalid recovery receipt config signature")
	}
	canonical := "mesh-agent-recovery-receipt-v1\n" +
		"node_id=" + receipt.NodeID + "\n" +
		"network_id=" + receipt.NetworkID + "\n" +
		"new_agent_token_hash=" + receipt.NewAgentTokenHash + "\n" +
		"agent_credential_generation=" + strconv.FormatInt(receipt.AgentCredentialGeneration, 10) + "\n" +
		"agent_credential_expires_at=" + receipt.AgentCredentialExpiresAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"config_sha256=" + receipt.ConfigSHA256 + "\n" +
		"config_signature=" + receipt.ConfigSignature + "\n"
	return []byte(canonical), nil
}

func ConfigDigest(config string) string {
	return configsignature.Digest(config)
}

func (s *SecretBox) Seal(plain []byte) (string, error) {
	return s.SealFor("ca-key-v1", plain)
}

func (s *SecretBox) SealFor(purpose string, plain []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte("mesh-"+purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *SecretBox) Open(encoded string) ([]byte, error) {
	return s.OpenFor("ca-key-v1", encoded)
}

func (s *SecretBox) OpenFor(purpose, encoded string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}
	if len(sealed) < s.aead.NonceSize() {
		return nil, fmt.Errorf("encrypted key is truncated")
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, []byte("mesh-"+purpose))
	if err != nil {
		return nil, fmt.Errorf("decrypt CA key: %w", err)
	}
	return plain, nil
}

func RandomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ValidTokenHash(encoded string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func ValidBearerToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func TokenHashEqual(expected, actual string) bool {
	a, errA := base64.RawURLEncoding.DecodeString(expected)
	b, errB := base64.RawURLEncoding.DecodeString(actual)
	return errA == nil && errB == nil && len(a) == sha256.Size && len(b) == sha256.Size && subtle.ConstantTimeCompare(a, b) == 1
}

func TokenEqual(expectedHash, token string) bool {
	a, errA := base64.RawURLEncoding.DecodeString(expectedHash)
	bSum := sha256.Sum256([]byte(token))
	if errA != nil || len(a) != len(bSum) {
		return false
	}
	return subtle.ConstantTimeCompare(a, bSum[:]) == 1
}
