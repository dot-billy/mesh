package nodeagent

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	nebulaX25519PrivateHeader = "-----BEGIN NEBULA X25519 PRIVATE KEY-----" // gitleaks:allow -- public format sentinel, not key material
	nebulaX25519PrivateFooter = "-----END NEBULA X25519 PRIVATE KEY-----"
	nebulaX25519PublicHeader  = "-----BEGIN NEBULA X25519 PUBLIC KEY-----"
	nebulaX25519PublicFooter  = "-----END NEBULA X25519 PUBLIC KEY-----"
)

// validateRecoveryKeyPair proves that the immutable host key files are a
// canonical X25519 pair and that their public half is the one pinned during
// enrollment. The public key is identity binding, not proof that the caller of
// the remote recovery endpoint possesses this private key.
func validateRecoveryKeyPair(privateKey, publicKey, expectedPublicKeyHash string) error {
	if canonicalPublicKeyHash(publicKey) != expectedPublicKeyHash {
		return errors.New("immutable node public key does not match the enrolled public-key pin")
	}
	privateBytes, err := decodeCanonicalNebulaX25519Key(privateKey, nebulaX25519PrivateHeader, nebulaX25519PrivateFooter)
	if err != nil {
		return fmt.Errorf("invalid immutable node private key: %w", err)
	}
	publicBytes, err := decodeCanonicalNebulaX25519Key(publicKey, nebulaX25519PublicHeader, nebulaX25519PublicFooter)
	if err != nil {
		return fmt.Errorf("invalid immutable node public key: %w", err)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return errors.New("invalid immutable node X25519 private key")
	}
	if subtle.ConstantTimeCompare(private.PublicKey().Bytes(), publicBytes) != 1 {
		return errors.New("immutable node recovery keypair does not match")
	}
	return nil
}

func decodeCanonicalNebulaX25519Key(value, header, footer string) ([]byte, error) {
	lines := strings.Split(value, "\n")
	if len(lines) != 4 || lines[0] != header || lines[2] != footer || lines[3] != "" {
		return nil, errors.New("key is not in canonical Nebula X25519 form")
	}
	decoded, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != lines[1] {
		return nil, errors.New("key payload is not canonical 32-byte base64")
	}
	return decoded, nil
}
