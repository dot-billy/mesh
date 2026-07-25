package configsignature

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerifyPreserveEveryDesiredArtifactDomain(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	now := time.Date(2026, time.July, 24, 12, 0, 0, 123, time.UTC)
	base := Metadata{
		NodeID:                 "node_1",
		NetworkID:              "network_1",
		Revision:               7,
		IssuedAt:               now,
		CACertificateSHA256:    strings.Repeat("a", 64),
		CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt:   now.Add(24 * time.Hour),
		CertificateRenewAfter:  now.Add(12 * time.Hour),
		CertificateGeneration:  3,
		PublicKeyHash: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x33}, sha256.Size),
		),
	}
	cases := map[string]Metadata{
		"v3": base,
		"v4": func() Metadata {
			value := base
			value.PreviousCACertificateSHA256 = strings.Repeat("c", 64)
			value.CARotationRequired = true
			return value
		}(),
		"v5": func() Metadata {
			value := base
			value.CertificateProfileRenewalRequired = true
			return value
		}(),
	}
	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			digest, signature, err := Sign(privateKey, metadata, "listen:\n  port: 4242\n")
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(
				publicKey,
				metadata,
				"listen:\n  port: 4242\n",
				digest,
				signature,
			); err != nil {
				t.Fatal(err)
			}
			if err := Verify(
				publicKey,
				metadata,
				"listen:\n  port: 4243\n",
				digest,
				signature,
			); err == nil {
				t.Fatal("changed configuration verified")
			}
		})
	}
}

func TestSigningPayloadPreservesStableV3AndAuthenticatesCARotationWithV4(t *testing.T) {
	issuedAt := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	metadata := Metadata{
		NodeID: "node-1", NetworkID: "network-1", Revision: 1, IssuedAt: issuedAt,
		CACertificateSHA256: strings.Repeat("a", 64), CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt: issuedAt.Add(24 * time.Hour), CertificateRenewAfter: issuedAt.Add(16 * time.Hour),
		CertificateGeneration: 1,
		PublicKeyHash: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x33}, sha256.Size),
		),
	}
	_, stablePayload := signingPayload(metadata, "config: valid\n")
	if !bytes.HasPrefix(stablePayload, []byte("mesh-desired-artifact-v3\n")) ||
		bytes.Contains(stablePayload, []byte("previous_ca_sha256=")) {
		t.Fatal("stable desired artifact did not preserve the exact legacy v3 envelope")
	}
	metadata.PreviousCACertificateSHA256 = strings.Repeat("c", 64)
	_, preparedPayload := signingPayload(metadata, "config: valid\n")
	if !bytes.HasPrefix(preparedPayload, []byte("mesh-desired-artifact-v4\n")) ||
		!bytes.Contains(
			preparedPayload,
			[]byte("previous_ca_sha256="+strings.Repeat("c", 64)+"\n"),
		) ||
		!bytes.Contains(preparedPayload, []byte("ca_rotation_required=false\n")) {
		t.Fatal("prepared CA transition did not use the authenticated v4 envelope")
	}
	metadata.CARotationRequired = true
	_, rotatingPayload := signingPayload(metadata, "config: valid\n")
	if !bytes.Contains(rotatingPayload, []byte("ca_rotation_required=true\n")) {
		t.Fatal("rotating desired artifact did not authenticate mandatory renewal")
	}
}

func TestVerifyRejectsNonCanonicalInputsAndInvalidTransitions(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	metadata := Metadata{
		NodeID:                 "node_1",
		NetworkID:              "network_1",
		Revision:               1,
		IssuedAt:               now,
		CACertificateSHA256:    strings.Repeat("a", 64),
		CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt:   now.Add(24 * time.Hour),
		CertificateRenewAfter:  now.Add(12 * time.Hour),
		CertificateGeneration:  1,
		PublicKeyHash: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x55}, sha256.Size),
		),
	}
	digest, signature, err := Sign(privateKey, metadata, "listen:\n  port: 4242\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey+"=", metadata, "listen:\n  port: 4242\n", digest, signature); err == nil {
		t.Fatal("padded public key verified")
	}
	if err := Verify(publicKey, metadata, "listen:\r\n  port: 4242\r\n", digest, signature); err == nil {
		t.Fatal("carriage-return configuration verified")
	}
	invalidTransition := metadata
	invalidTransition.CARotationRequired = true
	if err := Verify(publicKey, invalidTransition, "listen:\n  port: 4242\n", digest, signature); err == nil {
		t.Fatal("rotation without previous CA digest verified")
	}
}
