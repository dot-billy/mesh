package nodeagent

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestValidateRecoveryKeyPairRequiresCanonicalMatchingX25519Keys(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := nebulaX25519PrivateHeader + "\n" + base64.StdEncoding.EncodeToString(private.Bytes()) + "\n" + nebulaX25519PrivateFooter + "\n"
	publicPEM := nebulaX25519PublicHeader + "\n" + base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) + "\n" + nebulaX25519PublicFooter + "\n"
	otherPublicPEM := nebulaX25519PublicHeader + "\n" + base64.StdEncoding.EncodeToString(other.PublicKey().Bytes()) + "\n" + nebulaX25519PublicFooter + "\n"
	if err := validateRecoveryKeyPair(privatePEM, publicPEM, canonicalPublicKeyHash(publicPEM)); err != nil {
		t.Fatalf("valid recovery keypair: %v", err)
	}
	if err := validateRecoveryKeyPair(privatePEM, otherPublicPEM, canonicalPublicKeyHash(otherPublicPEM)); err == nil {
		t.Fatal("mismatched recovery keypair was accepted")
	}
	if err := validateRecoveryKeyPair(privatePEM, publicPEM+"\n", canonicalPublicKeyHash(publicPEM+"\n")); err == nil {
		t.Fatal("non-canonical recovery public key was accepted")
	}
}
