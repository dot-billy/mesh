package control

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestConfigSigningPayloadPreservesStableV3AndAuthenticatesCARotationWithV4(t *testing.T) {
	issuedAt := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	metadata := ConfigSignatureMetadata{
		NodeID: "node-1", NetworkID: "network-1", Revision: 1, IssuedAt: issuedAt,
		CACertificateSHA256: strings.Repeat("a", 64), CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt: issuedAt.Add(24 * time.Hour), CertificateRenewAfter: issuedAt.Add(16 * time.Hour),
		CertificateGeneration: 1, PublicKeyHash: HashToken("node-public-key"),
	}
	_, stablePayload := configSigningPayload(metadata, "config: valid\n")
	if !bytes.HasPrefix(stablePayload, []byte("mesh-desired-artifact-v3\n")) || bytes.Contains(stablePayload, []byte("previous_ca_sha256=")) {
		t.Fatal("stable desired artifact did not preserve the exact legacy v3 envelope")
	}
	metadata.PreviousCACertificateSHA256 = strings.Repeat("c", 64)
	_, preparedPayload := configSigningPayload(metadata, "config: valid\n")
	if !bytes.HasPrefix(preparedPayload, []byte("mesh-desired-artifact-v4\n")) || !bytes.Contains(preparedPayload, []byte("previous_ca_sha256="+strings.Repeat("c", 64)+"\n")) || !bytes.Contains(preparedPayload, []byte("ca_rotation_required=false\n")) {
		t.Fatal("prepared CA transition did not use the authenticated v4 envelope")
	}
	metadata.CARotationRequired = true
	_, rotatingPayload := configSigningPayload(metadata, "config: valid\n")
	if !bytes.Contains(rotatingPayload, []byte("ca_rotation_required=true\n")) {
		t.Fatal("rotating desired artifact did not authenticate mandatory renewal")
	}
}

func TestSignedConfigRejectsIdentityContentCAAndCertificateMetadataTampering(t *testing.T) {
	publicKey, privateKey, err := GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	metadata := ConfigSignatureMetadata{
		NodeID:                 "node-1",
		NetworkID:              "network-1",
		Revision:               7,
		IssuedAt:               issuedAt,
		CACertificateSHA256:    strings.Repeat("a", 64),
		CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt:   issuedAt.Add(24 * time.Hour),
		CertificateRenewAfter:  issuedAt.Add(16 * time.Hour),
		CertificateGeneration:  3,
		PublicKeyHash:          HashToken("node-public-key"),
	}
	digest, signature, err := SignConfig(privateKey, metadata, "config: valid\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConfig(publicKey, metadata, "config: valid\n", digest, signature); err != nil {
		t.Fatal(err)
	}
	withMetadata := func(change func(*ConfigSignatureMetadata)) func() error {
		return func() error {
			changed := metadata
			change(&changed)
			return VerifyConfig(publicKey, changed, "config: valid\n", digest, signature)
		}
	}
	for name, verify := range map[string]func() error{
		"node":               withMetadata(func(value *ConfigSignatureMetadata) { value.NodeID = "node-2" }),
		"network":            withMetadata(func(value *ConfigSignatureMetadata) { value.NetworkID = "network-2" }),
		"revision":           withMetadata(func(value *ConfigSignatureMetadata) { value.Revision++ }),
		"issued at":          withMetadata(func(value *ConfigSignatureMetadata) { value.IssuedAt = value.IssuedAt.Add(time.Second) }),
		"CA digest":          withMetadata(func(value *ConfigSignatureMetadata) { value.CACertificateSHA256 = strings.Repeat("c", 64) }),
		"previous CA digest": withMetadata(func(value *ConfigSignatureMetadata) { value.PreviousCACertificateSHA256 = strings.Repeat("c", 64) }),
		"CA rotation required": withMetadata(func(value *ConfigSignatureMetadata) {
			value.CARotationRequired = true
			value.PreviousCACertificateSHA256 = strings.Repeat("c", 64)
		}),
		"certificate fingerprint": withMetadata(func(value *ConfigSignatureMetadata) { value.CertificateFingerprint = strings.Repeat("d", 64) }),
		"certificate expiry": withMetadata(func(value *ConfigSignatureMetadata) {
			value.CertificateExpiresAt = value.CertificateExpiresAt.Add(time.Second)
		}),
		"certificate renew after": withMetadata(func(value *ConfigSignatureMetadata) {
			value.CertificateRenewAfter = value.CertificateRenewAfter.Add(time.Second)
		}),
		"certificate generation": withMetadata(func(value *ConfigSignatureMetadata) { value.CertificateGeneration++ }),
		"public key hash":        withMetadata(func(value *ConfigSignatureMetadata) { value.PublicKeyHash = HashToken("hostile-public-key") }),
		"content": func() error {
			return VerifyConfig(publicKey, metadata, "config: changed\n", digest, signature)
		},
		"claimed config digest": func() error {
			return VerifyConfig(publicKey, metadata, "config: valid\n", strings.Repeat("e", 64), signature)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verify(); err == nil {
				t.Fatal("tampered signed config was accepted")
			}
		})
	}
	invalidRenewalTime := metadata
	invalidRenewalTime.CertificateRenewAfter = invalidRenewalTime.CertificateExpiresAt
	if _, _, err := SignConfig(privateKey, invalidRenewalTime, "config: valid\n"); err == nil {
		t.Fatal("signed a certificate renewal time that was not before expiry")
	}
}

func TestManagedConfigGenerationAndVerificationShareExactByteEnvelope(t *testing.T) {
	publicKey, privateKey, err := GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 7, 20, 5, 0, 0, 0, time.UTC)
	metadata := ConfigSignatureMetadata{
		NodeID: "node-1", NetworkID: "network-1", Revision: 1, IssuedAt: issuedAt,
		CACertificateSHA256: strings.Repeat("a", 64), CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt: issuedAt.Add(24 * time.Hour), CertificateRenewAfter: issuedAt.Add(16 * time.Hour),
		CertificateGeneration: 1, PublicKeyHash: HashToken("node-public-key"),
	}
	boundary := strings.Repeat("x", MaxManagedConfigBytes-1) + "\n"
	digest, signature, err := SignConfig(privateKey, metadata, boundary)
	if err != nil {
		t.Fatalf("sign boundary config: %v", err)
	}
	if err := VerifyConfig(publicKey, metadata, boundary, digest, signature); err != nil {
		t.Fatalf("verify boundary config: %v", err)
	}

	invalid := map[string]string{
		"empty":           "",
		"oversized":       boundary + "x",
		"carriage return": "config: valid\r\n",
		"invalid UTF-8":   string([]byte{'x', 0xff}),
	}
	for name, config := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, _, err := SignConfig(privateKey, metadata, config); err == nil {
				t.Fatal("invalid managed config was signed")
			}
			if err := VerifyConfig(publicKey, metadata, config, digest, signature); err == nil {
				t.Fatal("invalid managed config was verified")
			}
		})
	}
}

func TestSecretBoxSeparatesKeyPurposes(t *testing.T) {
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealFor("config-signing-key-v1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.Open(sealed); err == nil {
		t.Fatal("config signing key decrypted under CA key purpose")
	}
	plain, err := box.OpenFor("config-signing-key-v1", sealed)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("purpose-bound decrypt failed: %q %v", plain, err)
	}
}

func TestRecoveryReceiptRejectsCredentialAndBootstrapTampering(t *testing.T) {
	publicKey, privateKey, err := GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 7, 19, 23, 0, 0, 0, time.UTC)
	metadata := ConfigSignatureMetadata{
		NodeID: "node-1", NetworkID: "network-1", Revision: 1, IssuedAt: issuedAt,
		CACertificateSHA256: strings.Repeat("a", 64), CertificateFingerprint: strings.Repeat("b", 64),
		CertificateExpiresAt: issuedAt.Add(24 * time.Hour), CertificateRenewAfter: issuedAt.Add(16 * time.Hour),
		CertificateGeneration: 1, PublicKeyHash: HashToken("node-public-key"),
	}
	digest, configSignature, err := SignConfig(privateKey, metadata, "config: valid\n")
	if err != nil {
		t.Fatal(err)
	}
	receipt := RecoveryReceipt{
		NodeID: "node-1", NetworkID: "network-1", NewAgentTokenHash: HashToken("new-agent-token"),
		AgentCredentialGeneration: 2, AgentCredentialExpiresAt: issuedAt.Add(90 * 24 * time.Hour),
		ConfigSHA256: digest, ConfigSignature: configSignature,
	}
	receipt.Signature, err = SignRecoveryReceipt(privateKey, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecoveryReceipt(publicKey, receipt); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*RecoveryReceipt){
		"node":           func(value *RecoveryReceipt) { value.NodeID = "node-2" },
		"network":        func(value *RecoveryReceipt) { value.NetworkID = "network-2" },
		"new token hash": func(value *RecoveryReceipt) { value.NewAgentTokenHash = HashToken("other-token") },
		"generation":     func(value *RecoveryReceipt) { value.AgentCredentialGeneration++ },
		"expiry": func(value *RecoveryReceipt) {
			value.AgentCredentialExpiresAt = value.AgentCredentialExpiresAt.Add(time.Second)
		},
		"config digest":    func(value *RecoveryReceipt) { value.ConfigSHA256 = strings.Repeat("c", 64) },
		"config signature": func(value *RecoveryReceipt) { value.ConfigSignature = receipt.Signature },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			change(&changed)
			if err := VerifyRecoveryReceipt(publicKey, changed); err == nil {
				t.Fatal("tampered recovery receipt was accepted")
			}
		})
	}
}

func TestBearerTokensRequireCanonicalThirtyTwoByteEncoding(t *testing.T) {
	valid := strings.Repeat("a", 42) + "A"
	if !ValidBearerToken(valid) {
		t.Fatal("canonical 32-byte bearer token was rejected")
	}
	for name, token := range map[string]string{
		"prefixed":     "meshv1." + valid,
		"too short":    valid[:42],
		"noncanonical": strings.Repeat("a", 43),
		"padded":       valid + "=",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidBearerToken(token) {
				t.Fatal("malformed bearer token was accepted")
			}
		})
	}
	hash := HashToken(valid)
	if !TokenHashEqual(hash, hash) || TokenHashEqual(hash, HashToken(strings.Repeat("b", 42)+"A")) {
		t.Fatal("constant-time token hash comparison returned the wrong result")
	}
}
