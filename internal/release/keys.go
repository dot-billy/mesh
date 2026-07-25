package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

var keyIDPattern = regexp.MustCompile(`^ed25519-sha256:[0-9a-f]{64}$`)

type TrustedKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

func KeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	digest := sha256.Sum256(publicKey)
	return "ed25519-sha256:" + hex.EncodeToString(digest[:]), nil
}

func GeneratePrivateKeyFile() (PrivateKeyFile, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKeyFile{}, nil, err
	}
	keyID, err := KeyID(publicKey)
	if err != nil {
		clear(privateKey)
		return PrivateKeyFile{}, nil, err
	}
	seed := privateKey.Seed()
	file := PrivateKeyFile{
		Schema:     PrivateKeySchema,
		KeyID:      keyID,
		PrivateKey: base64.RawURLEncoding.EncodeToString(seed),
	}
	clear(seed)
	return file, privateKey, nil
}

func MarshalPrivateKeyFile(file PrivateKeyFile) ([]byte, error) {
	privateKey, err := ParsePrivateKeyFileValue(file)
	if err != nil {
		return nil, err
	}
	clear(privateKey)
	encoded, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func ParsePrivateKeyFile(raw []byte) (PrivateKeyFile, ed25519.PrivateKey, error) {
	if len(raw) == 0 || len(raw) > MaxKeyFileSize {
		return PrivateKeyFile{}, nil, fmt.Errorf("private key file size must be between 1 and %d bytes", MaxKeyFileSize)
	}
	object, err := exactObject(raw, "schema", "key_id", "private_key")
	if err != nil {
		return PrivateKeyFile{}, nil, err
	}
	if err := requireFields(object, "schema", "key_id", "private_key"); err != nil {
		return PrivateKeyFile{}, nil, err
	}
	var file PrivateKeyFile
	if err := decodeStrict(raw, &file); err != nil {
		return PrivateKeyFile{}, nil, err
	}
	privateKey, err := ParsePrivateKeyFileValue(file)
	if err != nil {
		return PrivateKeyFile{}, nil, err
	}
	return file, privateKey, nil
}

func ParsePrivateKeyFileValue(file PrivateKeyFile) (ed25519.PrivateKey, error) {
	if file.Schema != PrivateKeySchema {
		return nil, fmt.Errorf("unsupported private key schema %q", file.Schema)
	}
	if !keyIDPattern.MatchString(file.KeyID) {
		return nil, fmt.Errorf("private key id is not canonical")
	}
	seed, err := decodeCanonicalBase64(file.PrivateKey, ed25519.SeedSize, "private key")
	if err != nil {
		return nil, err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	derived, err := KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil || derived != file.KeyID {
		clear(privateKey)
		return nil, fmt.Errorf("private key id does not match key material")
	}
	return privateKey, nil
}

func PublicKeyFileFromPrivate(privateKey ed25519.PrivateKey) (PublicKeyFile, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return PublicKeyFile{}, fmt.Errorf("Ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := KeyID(publicKey)
	if err != nil {
		return PublicKeyFile{}, err
	}
	return PublicKeyFile{
		Schema:    PublicKeySchema,
		KeyID:     keyID,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}, nil
}

func MarshalPublicKeyFile(file PublicKeyFile) ([]byte, error) {
	if _, err := trustedKeyFromValue(file); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func ParseTrustedPublicKey(raw []byte) (TrustedKey, error) {
	if len(raw) == 0 || len(raw) > MaxKeyFileSize {
		return TrustedKey{}, fmt.Errorf("public key file size must be between 1 and %d bytes", MaxKeyFileSize)
	}
	object, err := exactObject(raw, "schema", "key_id", "public_key")
	if err != nil {
		return TrustedKey{}, err
	}
	if err := requireFields(object, "schema", "key_id", "public_key"); err != nil {
		return TrustedKey{}, err
	}
	var file PublicKeyFile
	if err := decodeStrict(raw, &file); err != nil {
		return TrustedKey{}, err
	}
	return trustedKeyFromValue(file)
}

func trustedKeyFromValue(file PublicKeyFile) (TrustedKey, error) {
	if file.Schema != PublicKeySchema {
		return TrustedKey{}, fmt.Errorf("unsupported public key schema %q", file.Schema)
	}
	if !keyIDPattern.MatchString(file.KeyID) {
		return TrustedKey{}, fmt.Errorf("public key id is not canonical")
	}
	decoded, err := decodeCanonicalBase64(file.PublicKey, ed25519.PublicKeySize, "public key")
	if err != nil {
		return TrustedKey{}, err
	}
	publicKey := ed25519.PublicKey(decoded)
	derived, err := KeyID(publicKey)
	if err != nil || derived != file.KeyID {
		return TrustedKey{}, fmt.Errorf("public key id does not match key material")
	}
	return TrustedKey{KeyID: file.KeyID, PublicKey: publicKey}, nil
}

func decodeCanonicalBase64(value string, expectedSize int, label string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != expectedSize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url encoding of %d bytes", label, expectedSize)
	}
	return decoded, nil
}
