// Package iosmobile is the narrow Go boundary for the iOS Packet Tunnel.
//
// Its exported API deliberately has no private-key getter or raw configuration
// execution entrypoint. The first feasibility slice proves only pinned engine
// identity and extension-owned key generation.
package iosmobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

const (
	frameworkSchema       = "mesh-ios-mobile-framework-v5"
	nebulaVersion         = "1.10.3"
	identityGroupSuffix   = "io.rw0.mesh.tunnel.mobile.identity"
	identityService       = "io.rw0.mesh.tunnel.mobile.identity.v1"
	maximumAccessGroupLen = 256
)

var identityPattern = regexp.MustCompile(`\A[a-zA-Z0-9._:-]{1,128}\z`)

// FrameworkIdentity returns non-secret build identity for receipt binding.
func FrameworkIdentity() string {
	value, _ := json.Marshal(map[string]string{
		"schema":         frameworkSchema,
		"nebula_version": nebulaVersion,
		"capability": "extension-enrollment-lifecycle-renewal-credential-rotation-" +
			"mobile-evidence-identity-removal-signed-config-packet-session",
	})
	return string(value)
}

// FrameworkIdentitySHA256 returns the exact engine identity carried by the
// authenticated app-to-extension configuration.
func FrameworkIdentitySHA256() string {
	sum := sha256.Sum256([]byte(FrameworkIdentity()))
	return hex.EncodeToString(sum[:])
}

// EnsureIdentity creates or reads one X25519 identity in the extension-only,
// device-only Keychain group and returns only its public key.
func EnsureIdentity(accessGroup, identityID string) (string, error) {
	if err := validateIdentityScope(accessGroup, identityID); err != nil {
		return "", err
	}
	privateKey, err := loadOrCreatePrivateKey(accessGroup, identityID)
	if err != nil {
		return "", fmt.Errorf("identity key custody failed: %w", err)
	}
	defer clear(privateKey)
	return publicKeyPEM(privateKey)
}

func validateIdentityScope(accessGroup, identityID string) error {
	if len(accessGroup) == 0 ||
		len(accessGroup) > maximumAccessGroupLen ||
		len(accessGroup) <= len(identityGroupSuffix)+1 ||
		accessGroup[len(accessGroup)-len(identityGroupSuffix):] != identityGroupSuffix ||
		accessGroup[len(accessGroup)-len(identityGroupSuffix)-1] != '.' {
		return errors.New("identity access group is invalid")
	}
	if !identityPattern.MatchString(identityID) {
		return errors.New("identity identifier is invalid")
	}
	return nil
}

func publicKeyPEM(privateKey []byte) (string, error) {
	if len(privateKey) != curve25519.ScalarSize {
		return "", errors.New("identity private key is invalid")
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", errors.New("derive identity public key")
	}
	return string(
		cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, publicKey),
	), nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
