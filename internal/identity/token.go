package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
)

const OpaqueTokenBytes = 32

func NewOpaqueToken() (string, error) {
	raw := make([]byte, OpaqueTokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func ValidOpaqueToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == OpaqueTokenBytes && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func HashOpaqueToken(token string) (string, error) {
	if !ValidOpaqueToken(token) {
		return "", fmt.Errorf("opaque token must be canonical unpadded base64url containing %d random bytes", OpaqueTokenBytes)
	}
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func ValidCredentialHash(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func CredentialHashEqual(left, right string) bool {
	if !ValidCredentialHash(left) || !ValidCredentialHash(right) {
		return false
	}
	a, errA := base64.RawURLEncoding.DecodeString(left)
	b, errB := base64.RawURLEncoding.DecodeString(right)
	return errA == nil && errB == nil && len(a) == sha256.Size && len(b) == sha256.Size && subtle.ConstantTimeCompare(a, b) == 1
}

func CredentialMatches(hash, token string) bool {
	if !ValidCredentialHash(hash) || !ValidOpaqueToken(token) {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(hash)
	actual := sha256.Sum256([]byte(token))
	return err == nil && len(expected) == sha256.Size && subtle.ConstantTimeCompare(expected, actual[:]) == 1
}
