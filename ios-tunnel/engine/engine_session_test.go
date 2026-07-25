package iosmobile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"go.yaml.in/yaml/v3"

	"mesh/internal/configsignature"
)

type engineTestAuthority struct {
	ca                  cert.Certificate
	caKey               []byte
	caPEM               string
	configSigningKey    ed25519.PrivateKey
	configSigningPublic string
}

type engineTestFixture struct {
	document    engineConfiguration
	raw         string
	privateKey  []byte
	certificate cert.Certificate
	authority   engineTestAuthority
}

func newEngineTestAuthority(
	t *testing.T,
	now time.Time,
) engineTestAuthority {
	t.Helper()
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(
		cert.Version2,
		cert.Curve_CURVE25519,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		nil,
		nil,
		nil,
	)
	configSigningKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x61}, ed25519.SeedSize),
	)
	return engineTestAuthority{
		ca:               ca,
		caKey:            caKey,
		caPEM:            string(caPEM),
		configSigningKey: configSigningKey,
		configSigningPublic: base64.RawURLEncoding.EncodeToString(
			configSigningKey.Public().(ed25519.PublicKey),
		),
	}
}

func newEngineTestFixture(
	t *testing.T,
	authority engineTestAuthority,
	now time.Time,
	nodeID string,
	vpnAddress netip.Addr,
	udpPort int,
	amLighthouse bool,
	lighthouseRemote netip.AddrPort,
) engineTestFixture {
	t.Helper()
	certificate, _, privateKeyPEM, certificatePEM := cert_test.NewTestCert(
		cert.Version2,
		cert.Curve_CURVE25519,
		authority.ca,
		authority.caKey,
		nodeID,
		now.Add(-time.Minute),
		now.Add(30*time.Minute),
		[]netip.Prefix{netip.PrefixFrom(vpnAddress, 24)},
		nil,
		nil,
	)
	privateKey, remainder, curve, err := cert.UnmarshalPrivateKeyFromPEM(
		privateKeyPEM,
	)
	if err != nil ||
		len(remainder) != 0 ||
		curve != cert.Curve_CURVE25519 {
		t.Fatal("parse generated test private key")
	}
	lighthouse := map[string]any{
		"am_lighthouse": amLighthouse,
		"interval":      1,
	}
	staticHosts := map[string]any{}
	if !amLighthouse {
		lighthouse["hosts"] = []string{"10.88.0.1"}
		staticHosts["10.88.0.1"] = []string{lighthouseRemote.String()}
	} else {
		lighthouse["hosts"] = []string{}
	}
	settings := map[string]any{
		"pki": map[string]any{
			"ca":   "/etc/nebula/ca.crt",
			"cert": "/etc/nebula/host.crt",
			"key":  "/etc/nebula/host.key",
		},
		"listen": map[string]any{
			"host": "127.0.0.1",
			"port": udpPort,
		},
		"lighthouse":      lighthouse,
		"static_host_map": staticHosts,
		"routines":        1,
		"firewall": map[string]any{
			"outbound": []map[string]any{{
				"host":  "any",
				"port":  "any",
				"proto": "any",
			}},
			"inbound": []map[string]any{{
				"host":  "any",
				"port":  "any",
				"proto": "any",
			}},
		},
		"logging": map[string]any{
			"level":  "error",
			"format": "text",
		},
	}
	rawConfig, err := yaml.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	publicHash := sha256.Sum256(certificate.MarshalPublicKeyPEM())
	caDigest := configsignature.Digest(authority.caPEM)
	metadata := configsignature.Metadata{
		NodeID:                 nodeID,
		NetworkID:              "network_1",
		Revision:               7,
		IssuedAt:               now,
		CACertificateSHA256:    caDigest,
		CertificateFingerprint: fingerprint,
		CertificateExpiresAt:   certificate.NotAfter(),
		CertificateRenewAfter:  certificate.NotAfter().Add(-10 * time.Minute),
		CertificateGeneration:  2,
		PublicKeyHash: base64.RawURLEncoding.EncodeToString(
			publicHash[:],
		),
	}
	digest, signature, err := configsignature.Sign(
		authority.configSigningKey,
		metadata,
		string(rawConfig),
	)
	if err != nil {
		t.Fatal(err)
	}
	network := netip.PrefixFrom(vpnAddress, 24)
	document := engineConfiguration{
		Schema:                    tunnelConfigurationSchema,
		NetworkID:                 metadata.NetworkID,
		NodeID:                    nodeID,
		ControlPlaneOrigin:        "https://mesh.example",
		AgentCredentialGeneration: 1,
		AgentCredentialExpiresAt: now.Add(30 * time.Minute).Format(
			time.RFC3339Nano,
		),
		CertificateFingerprint: fingerprint,
		CertificateGeneration:  uint64(metadata.CertificateGeneration),
		ConfigRevision:         uint64(metadata.Revision),
		ConfigDigest:           digest,
		EngineIdentity:         FrameworkIdentitySHA256(),
		TunnelRemoteAddress:    "192.0.2.9",
		NetworkSettings: engineNetworkSettings{
			Addresses: []engineIPPrefix{{
				Address:      vpnAddress.String(),
				PrefixLength: 24,
			}},
			IncludedRoutes: []engineIPPrefix{{
				Address:      network.Masked().Addr().String(),
				PrefixLength: 24,
			}},
			ExcludedRoutes: []engineIPPrefix{},
			DNSServers:     []string{},
			MTU:            1300,
		},
		MonotonicCounter:     9,
		IssuedAtMilliseconds: uint64(now.UnixMilli()),
		Nebula: nebulaSignedConfiguration{
			Schema:                            nebulaConfigurationSchema,
			CA:                                authority.caPEM,
			Certificate:                       string(certificatePEM),
			Config:                            string(rawConfig),
			ConfigIssuedAt:                    now.Format(time.RFC3339Nano),
			CACertificateSHA256:               caDigest,
			PreviousCACertificateSHA256:       "",
			CARotationRequired:                false,
			CertificateProfileRenewalRequired: false,
			CertificateExpiresAt: certificate.NotAfter().UTC().Format(
				time.RFC3339Nano,
			),
			CertificateRenewAfter: metadata.CertificateRenewAfter.UTC().Format(
				time.RFC3339Nano,
			),
			PublicKeyHash:          metadata.PublicKeyHash,
			ConfigSigningPublicKey: authority.configSigningPublic,
			ConfigSignature:        signature,
		},
	}
	return engineTestFixture{
		document:    document,
		raw:         marshalEngineTestDocument(t, document),
		privateKey:  append([]byte(nil), privateKey...),
		certificate: certificate,
		authority:   authority,
	}
}

func marshalEngineTestDocument(
	t *testing.T,
	document engineConfiguration,
) string {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func resignEngineTestDocument(
	t *testing.T,
	fixture engineTestFixture,
	document *engineConfiguration,
) {
	t.Helper()
	metadata := configsignature.Metadata{
		NodeID:                            document.NodeID,
		NetworkID:                         document.NetworkID,
		Revision:                          int64(document.ConfigRevision),
		IssuedAt:                          mustParseEngineTestTime(t, document.Nebula.ConfigIssuedAt),
		CACertificateSHA256:               document.Nebula.CACertificateSHA256,
		PreviousCACertificateSHA256:       document.Nebula.PreviousCACertificateSHA256,
		CARotationRequired:                document.Nebula.CARotationRequired,
		CertificateProfileRenewalRequired: document.Nebula.CertificateProfileRenewalRequired,
		CertificateFingerprint:            document.CertificateFingerprint,
		CertificateExpiresAt:              mustParseEngineTestTime(t, document.Nebula.CertificateExpiresAt),
		CertificateRenewAfter:             mustParseEngineTestTime(t, document.Nebula.CertificateRenewAfter),
		CertificateGeneration:             int64(document.CertificateGeneration),
		PublicKeyHash:                     document.Nebula.PublicKeyHash,
	}
	digest, signature, err := configsignature.Sign(
		fixture.authority.configSigningKey,
		metadata,
		document.Nebula.Config,
	)
	if err != nil {
		t.Fatal(err)
	}
	document.ConfigDigest = digest
	document.Nebula.ConfigSignature = signature
}

func mustParseEngineTestTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func newEngineTestSession(privateKey []byte) *EngineSession {
	return newEngineSession(func() ([]byte, error) {
		return append([]byte(nil), privateKey...), nil
	})
}

func TestEngineSessionVerifiesSignedConfigurationAndIsNonRestartable(
	t *testing.T,
) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_1",
		netip.MustParseAddr("10.88.0.1"),
		reserveUDPPort(t),
		true,
		netip.AddrPort{},
	)
	session := newEngineTestSession(fixture.privateKey)
	if session.FrameworkIdentity() != FrameworkIdentitySHA256() {
		t.Fatal("session reported the wrong framework identity")
	}
	if err := session.Prepare(fixture.raw); err != nil {
		t.Fatal(err)
	}
	if err := session.Prepare(fixture.raw); err == nil {
		t.Fatal("prepared one engine session twice")
	}
	if err := session.Start(); err != nil {
		t.Fatal(err)
	}
	session.Stop()
	session.Stop()
	if err := session.Start(); err == nil {
		t.Fatal("restarted a stopped engine session")
	}
}

func TestEngineSessionRejectsTamperingBeforeEngineConstruction(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_1",
		netip.MustParseAddr("10.88.0.1"),
		reserveUDPPort(t),
		true,
		netip.AddrPort{},
	)
	tests := map[string]func() (string, []byte){
		"framework identity": func() (string, []byte) {
			document := fixture.document
			document.EngineIdentity = strings.Repeat("0", 64)
			return marshalEngineTestDocument(t, document), fixture.privateKey
		},
		"signed config": func() (string, []byte) {
			document := fixture.document
			document.Nebula.Config += "\n"
			return marshalEngineTestDocument(t, document), fixture.privateKey
		},
		"local identity": func() (string, []byte) {
			return fixture.raw, bytes.Repeat([]byte{0x55}, 32)
		},
		"certificate network": func() (string, []byte) {
			document := fixture.document
			document.NetworkSettings.Addresses[0].Address = "10.88.0.2"
			return marshalEngineTestDocument(t, document), fixture.privateKey
		},
		"PKI path": func() (string, []byte) {
			document := fixture.document
			document.Nebula.Config = strings.Replace(
				document.Nebula.Config,
				"/etc/nebula/host.key",
				"/tmp/host.key",
				1,
			)
			resignEngineTestDocument(t, fixture, &document)
			return marshalEngineTestDocument(t, document), fixture.privateKey
		},
		"duplicate field": func() (string, []byte) {
			return strings.Replace(
				fixture.raw,
				`"schema":`,
				`"schema":"mesh-ios-tunnel-configuration-v4","schema":`,
				1,
			), fixture.privateKey
		},
		"unknown field": func() (string, []byte) {
			return strings.Replace(
				fixture.raw,
				`{"schema":`,
				`{"unexpected":true,"schema":`,
				1,
			), fixture.privateKey
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			raw, privateKey := mutate()
			session := newEngineTestSession(privateKey)
			if err := session.Prepare(raw); err == nil {
				session.Stop()
				t.Fatal("tampered engine configuration prepared")
			}
		})
	}
}

func TestEngineSessionStopUnblocksReceive(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_1",
		netip.MustParseAddr("10.88.0.1"),
		reserveUDPPort(t),
		true,
		netip.AddrPort{},
	)
	session := newEngineTestSession(fixture.privateKey)
	if err := session.Prepare(fixture.raw); err != nil {
		t.Fatal(err)
	}
	if err := session.Start(); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		_, err := session.Receive()
		completed <- err
	}()
	session.Stop()
	select {
	case err := <-completed:
		if err == nil || !errors.Is(err, io.EOF) {
			t.Fatalf("blocked receive returned %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not unblock receive")
	}
}

func TestEngineSessionCanStopAfterPrepareWithoutStarting(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	fixture := newEngineTestFixture(
		t,
		newEngineTestAuthority(t, now),
		now,
		"node_1",
		netip.MustParseAddr("10.88.0.1"),
		reserveUDPPort(t),
		true,
		netip.AddrPort{},
	)
	session := newEngineTestSession(fixture.privateKey)
	if err := session.Prepare(fixture.raw); err != nil {
		t.Fatal(err)
	}
	session.Stop()
	if err := session.Send(ipv4Packet(nil)); err == nil {
		t.Fatal("prepared-and-stopped engine accepted a packet")
	}
}
