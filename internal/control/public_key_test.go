package control

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalNebulaPublicKeyPEMRejectsRemainderAndNormalizesOuterWhitespace(t *testing.T) {
	canonical := testNebulaPublicKey(0x42)
	for _, input := range []string{canonical, strings.TrimSuffix(canonical, "\n"), " \n" + canonical + "\t"} {
		got, err := canonicalNebulaPublicKeyPEM(input)
		if err != nil || got != canonical {
			t.Fatalf("canonicalize public key: got=%q err=%v", got, err)
		}
	}
	for name, input := range map[string]string{
		"comment remainder": canonical + "# ignored by nebula-cert\n",
		"second PEM":        canonical + testNebulaPublicKey(0x43),
		"invalid payload":   "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nAAAA\n-----END NEBULA X25519 PUBLIC KEY-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalNebulaPublicKeyPEM(input); err == nil {
				t.Fatal("noncanonical public-key input was accepted")
			}
		})
	}
}

func TestEnrollmentRenewalAndRecoveryRejectPublicKeyRemainders(t *testing.T) {
	issuer := &countingIssuer{}
	service := testServiceWithIssuer(t, issuer)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "key-ingress", CIDR: "10.121.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "key-node"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey(0x44)
	withRemainder := publicKey + "ignored-remainder\n"
	agentToken := strings.Repeat("a", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, withRemainder, HashToken(agentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("enrollment accepted a public-key remainder: %v", err)
	}
	if issuer.signCalls.Load() != 0 {
		t.Fatal("malformed enrollment reached the certificate issuer")
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken)); err != nil {
		t.Fatalf("canonical enrollment failed: %v", err)
	}
	if _, err := service.Renew(context.Background(), agentToken, withRemainder); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("renewal accepted a public-key remainder: %v", err)
	}
	recovery, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	newAgentToken := strings.Repeat("b", 42) + "A"
	if _, err := service.RecoverAgent(recovery.RecoveryToken, withRemainder, HashToken(newAgentToken)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("agent recovery accepted a public-key remainder: %v", err)
	}
}
