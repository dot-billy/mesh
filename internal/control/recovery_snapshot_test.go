package control

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
)

const testNebulaCACertificate = "-----BEGIN NEBULA CERTIFICATE V2-----\n" +
	"MIGIoCKACHNuYXBzaG90oQcEBQpvAAAYhAH/hQRqXXB4hgR9KXN4giAaTNi9ydaO\n" +
	"7PcGCH8fyXv/jFKg1IplR2x6T9St4oMeeoNA1Tn8WCeDc8yx6Q0jeILisIajc5Gs\n" +
	"SXJbdflSsQrCQuIjJ1Jv98c/QBQIVqYJh0cmFbOIANDvbBnmw1c2zcLuDQ==\n" +
	"-----END NEBULA CERTIFICATE V2-----\n"

const testNebulaCAPrivateKey = "-----BEGIN NEBULA ED25519 PRIVATE KEY-----\n" + // gitleaks:allow -- deterministic non-production test fixture
	"abqCamuiCP/Q7dcQeWit3vrdv6z6gTUxhMg60mUqkEwaTNi9ydaO7PcGCH8fyXv/\n" +
	"jFKg1IplR2x6T9St4oMeeg==\n" +
	"-----END NEBULA ED25519 PRIVATE KEY-----\n"

const transplantedNebulaCACertificate = "-----BEGIN NEBULA CERTIFICATE V2-----\n" +
	"MIGIoCKACHNuYXBzaG90oQcEBQpwAAAYhAH/hQRqXXCFhgR9KXOFgiDux58wdV2w\n" +
	"McTR7OUqq3LttKlzBZbyJ28alCsc24FrdYNAMsjmFFRMr8YgYckrLFOMgDjjlAwJ\n" +
	"sIZh/Fc87Ygq//7O7XPVsfsHUgTqz2oAfUPHTlBGmKajDRRXJfvnn79fBw==\n" +
	"-----END NEBULA CERTIFICATE V2-----\n"

const transplantedNebulaCAPrivateKey = "-----BEGIN NEBULA ED25519 PRIVATE KEY-----\n" + // gitleaks:allow -- deterministic non-production test fixture
	"lZ1bEBgckcVGoTsiwblCdP6NKSjjwkQKNwdbmvSG3hzux58wdV2wMcTR7OUqq3Lt\n" +
	"tKlzBZbyJ28alCsc24FrdQ==\n" +
	"-----END NEBULA ED25519 PRIVATE KEY-----\n"

const mismatchedNebulaCAPrivateKey = "-----BEGIN NEBULA ED25519 PRIVATE KEY-----\n" + // gitleaks:allow -- deterministic non-production test fixture
	"AcePXP8CGpPG9sNJ2Csyg9OL29Fuis4hUQ8x5jMoWPXQhIZM35L8kvGK9iZJnA0D\n" +
	"ef3EoIo4EkKVc+65q6+Bgw==\n" +
	"-----END NEBULA ED25519 PRIVATE KEY-----\n"

type recoverySnapshotIssuer struct{}

var recoverySnapshotNow = time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)

func (recoverySnapshotIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	return testNebulaCACertificate, testNebulaCAPrivateKey, nil
}

func (recoverySnapshotIssuer) SignPublicKey(_ context.Context, caCertificate, caPrivateKey, publicKey, name, network, groups, unsafeNetworks string, ttl time.Duration) (string, string, time.Time, error) {
	ca, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(caCertificate))
	if err != nil {
		return "", "", time.Time{}, err
	}
	privateKey, _, privateCurve, err := nebulacert.UnmarshalSigningPrivateKeyFromPEM([]byte(caPrivateKey))
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer clear(privateKey)
	publicKeyBytes, remainder, publicCurve, err := nebulacert.UnmarshalPublicKeyFromPEM([]byte(publicKey))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		return "", "", time.Time{}, errors.New("invalid test host public key")
	}
	if privateCurve != ca.Curve() || publicCurve != ca.Curve() {
		return "", "", time.Time{}, errors.New("test host key curve does not match CA")
	}
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return "", "", time.Time{}, err
	}
	var certificateGroups []string
	if groups != "" {
		certificateGroups = strings.Split(groups, ",")
	}
	var certificateUnsafeNetworks []netip.Prefix
	if unsafeNetworks != "" {
		for _, value := range strings.Split(unsafeNetworks, ",") {
			prefix, parseErr := netip.ParsePrefix(value)
			if parseErr != nil {
				return "", "", time.Time{}, parseErr
			}
			certificateUnsafeNetworks = append(certificateUnsafeNetworks, prefix)
		}
	}
	certificate, err := (&nebulacert.TBSCertificate{
		Version:        ca.Version(),
		Name:           name,
		Networks:       []netip.Prefix{prefix},
		UnsafeNetworks: certificateUnsafeNetworks,
		Groups:         certificateGroups,
		NotBefore:      recoverySnapshotNow,
		NotAfter:       recoverySnapshotNow.Add(ttl),
		PublicKey:      publicKeyBytes,
		Curve:          publicCurve,
	}).Sign(ca, privateCurve, privateKey)
	if err != nil {
		return "", "", time.Time{}, err
	}
	certificatePEM, err := certificate.MarshalPEM()
	if err != nil {
		return "", "", time.Time{}, err
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(certificatePEM), fingerprint, certificate.NotAfter().UTC(), nil
}

func TestValidateRecoverySnapshotCryptographicMaterial(t *testing.T) {
	store, box, path := newControlRecoverySnapshotHarness(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	if err := ValidateRecoverySnapshot(raw, box); err != nil {
		t.Fatalf("validate recovery snapshot: %v", err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("validation modified its input")
	}

	wrongBox, err := NewSecretBox(bytes.Repeat([]byte{0x7f}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(raw, wrongBox); err == nil || !strings.Contains(err.Error(), "CA key") {
		t.Fatalf("wrong master key was accepted: %v", err)
	}
	if err := ValidateRecoverySnapshot(raw, nil); err == nil {
		t.Fatal("nil secret box was accepted")
	}

	var state State
	if err := decodePersistedState(raw, &state); err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	mismatched, err := box.SealFor("config-signing-key-v1", wrongPrivate)
	clear(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	state.Networks[0].EncryptedConfigSigningKey = mismatched
	mismatchedRaw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(mismatchedRaw, box); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched config signing key was accepted: %v", err)
	}

	state = State{}
	if err := decodePersistedState(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Networks[0].EncryptedConfigSigningKey = base64LikeTamperForControl(state.Networks[0].EncryptedConfigSigningKey)
	corruptRaw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(corruptRaw, box); err == nil || !strings.Contains(err.Error(), "config signing key") {
		t.Fatalf("corrupt config signing key was accepted: %v", err)
	}

	state = State{}
	if err := decodePersistedState(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Networks[0].EncryptedCAKey, err = box.Seal([]byte("not-a-nebula-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	invalidCARaw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(invalidCARaw, box); err == nil || !strings.Contains(err.Error(), "decode Nebula CA private key") {
		t.Fatalf("noncanonical CA key was accepted: %v", err)
	}

	state = State{}
	if err := decodePersistedState(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Networks[0].EncryptedCAKey, err = box.Seal([]byte(mismatchedNebulaCAPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	mismatchedCARaw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(mismatchedCARaw, box); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched Nebula CA key was accepted: %v", err)
	}

	state = State{}
	if err := decodePersistedState(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Networks[0].CACertificate = transplantedNebulaCACertificate
	state.Networks[0].EncryptedCAKey, err = box.Seal([]byte(transplantedNebulaCAPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	transplantedRaw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(transplantedRaw, box); err == nil || !strings.Contains(err.Error(), "network constraint does not match") {
		t.Fatalf("valid CA pair transplanted from another network was accepted: %v", err)
	}

	if err := store.View(func(current State) error {
		if len(current.Networks) != 1 {
			t.Fatalf("offline validation mutated live state: %#v", current.Networks)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRecoverySnapshotBindsNebulaHostCertificates(t *testing.T) {
	fixture := newActiveControlRecoveryFixture(t, 2)
	if err := ValidateRecoverySnapshot(fixture.raw, fixture.box); err != nil {
		t.Fatalf("valid active-node recovery snapshot: %v", err)
	}
	withTrailingWhitespace := cloneRecoveryState(t, fixture.state)
	withTrailingWhitespace.Nodes[0].Certificate += " \n\t\n"
	withTrailingWhitespaceRaw, err := encodePersistedState(withTrailingWhitespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(withTrailingWhitespaceRaw, fixture.box); err != nil {
		t.Fatalf("canonical certificate with whitespace-only remainder: %v", err)
	}

	mutations := map[string]struct {
		mutate  func(*State)
		message string
	}{
		"malformed certificate": {
			mutate:  func(state *State) { state.Nodes[0].Certificate = "not a certificate" },
			message: "decode Nebula host certificate",
		},
		"multiple certificates": {
			mutate:  func(state *State) { state.Nodes[0].Certificate += state.Nodes[0].Certificate },
			message: "one canonical PEM block",
		},
		"noncanonical certificate": {
			mutate:  func(state *State) { state.Nodes[0].Certificate = strings.TrimSuffix(state.Nodes[0].Certificate, "\n") },
			message: "one canonical PEM block",
		},
		"swapped complete host identity": {
			mutate: func(state *State) {
				first := certificateRecord(state.Nodes[0])
				second := certificateRecord(state.Nodes[1])
				applyCertificateRecord(&state.Nodes[0], second)
				applyCertificateRecord(&state.Nodes[1], first)
			},
			message: "does not match its node record",
		},
		"wrong CA": {
			mutate: func(state *State) {
				wrongCA, wrongKey := newRecoveryTestCA(t, state.Networks[0].Name, state.Networks[0].CIDR)
				certificate, fingerprint, expiresAt := signRecoveryHostCertificate(t, wrongCA, wrongKey, fixture.publicKeys[0], state.Nodes[0].Name, []netip.Prefix{mustRecoveryPrefix(t, state.Nodes[0].IP+"/24")}, nil, state.Nodes[0].Groups)
				setRecoveryNodeCertificate(&state.Nodes[0], state.Networks[0], certificate, fingerprint, expiresAt)
			},
			message: "issuer or signature",
		},
		"wrong name": {
			mutate: func(state *State) {
				certificate, fingerprint, expiresAt := signRecoveryHostCertificate(t, state.Networks[0].CACertificate, testNebulaCAPrivateKey, fixture.publicKeys[0], "other-node", []netip.Prefix{mustRecoveryPrefix(t, state.Nodes[0].IP+"/24")}, nil, state.Nodes[0].Groups)
				setRecoveryNodeCertificate(&state.Nodes[0], state.Networks[0], certificate, fingerprint, expiresAt)
			},
			message: "name does not match",
		},
		"wrong assigned IP": {
			mutate: func(state *State) {
				certificate, fingerprint, expiresAt := signRecoveryHostCertificate(t, state.Networks[0].CACertificate, testNebulaCAPrivateKey, fixture.publicKeys[0], state.Nodes[0].Name, []netip.Prefix{mustRecoveryPrefix(t, "10.111.0.200/24")}, nil, state.Nodes[0].Groups)
				setRecoveryNodeCertificate(&state.Nodes[0], state.Networks[0], certificate, fingerprint, expiresAt)
			},
			message: "assigned node address",
		},
		"multiple assigned networks": {
			mutate: func(state *State) {
				certificate, fingerprint, expiresAt := signRecoveryHostCertificate(t, state.Networks[0].CACertificate, testNebulaCAPrivateKey, fixture.publicKeys[0], state.Nodes[0].Name, []netip.Prefix{mustRecoveryPrefix(t, state.Nodes[0].IP+"/24"), mustRecoveryPrefix(t, "10.111.0.200/24")}, nil, state.Nodes[0].Groups)
				setRecoveryNodeCertificate(&state.Nodes[0], state.Networks[0], certificate, fingerprint, expiresAt)
			},
			message: "assigned node address",
		},
		"wrong groups": {
			mutate: func(state *State) {
				certificate, fingerprint, expiresAt := signRecoveryHostCertificate(t, state.Networks[0].CACertificate, testNebulaCAPrivateKey, fixture.publicKeys[0], state.Nodes[0].Name, []netip.Prefix{mustRecoveryPrefix(t, state.Nodes[0].IP+"/24")}, nil, []string{"other-group"})
				setRecoveryNodeCertificate(&state.Nodes[0], state.Networks[0], certificate, fingerprint, expiresAt)
			},
			message: "groups do not match",
		},
		"noncanonical node groups": {
			mutate: func(state *State) {
				state.Nodes[0].Groups[0], state.Nodes[0].Groups[1] = state.Nodes[0].Groups[1], state.Nodes[0].Groups[0]
			},
			message: "non-canonical certificate groups",
		},
		"wrong public key hash": {
			mutate:  func(state *State) { state.Nodes[0].PublicKeyHash = HashToken(fixture.publicKeys[1]) },
			message: "public key does not match",
		},
		"different signed public key": {
			mutate: func(state *State) {
				certificate, fingerprint, expiresAt := signRecoveryHostCertificate(t, state.Networks[0].CACertificate, testNebulaCAPrivateKey, fixture.publicKeys[1], state.Nodes[0].Name, []netip.Prefix{mustRecoveryPrefix(t, state.Nodes[0].IP+"/24")}, nil, state.Nodes[0].Groups)
				setRecoveryNodeCertificate(&state.Nodes[0], state.Networks[0], certificate, fingerprint, expiresAt)
			},
			message: "public key does not match",
		},
		"wrong fingerprint": {
			mutate:  func(state *State) { state.Nodes[0].CertificateFingerprint = strings.Repeat("0", 64) },
			message: "fingerprint does not match",
		},
		"wrong expiry": {
			mutate: func(state *State) {
				expiresAt := state.Nodes[0].CertificateExpiresAt.Add(time.Second)
				state.Nodes[0].CertificateExpiresAt = &expiresAt
			},
			message: "expiry does not match",
		},
		"detached issuance record": {
			mutate: func(state *State) {
				kept := state.Issuances[:0]
				for _, issuance := range state.Issuances {
					if issuance.NodeID != state.Nodes[0].ID || issuance.Fingerprint != state.Nodes[0].CertificateFingerprint {
						kept = append(kept, issuance)
					}
				}
				state.Issuances = kept
			},
			message: "no matching issuance record",
		},
		"subsecond issuance expiry mismatch": {
			mutate: func(state *State) {
				for index := range state.Issuances {
					if state.Issuances[index].NodeID == state.Nodes[0].ID && state.Issuances[index].Fingerprint == state.Nodes[0].CertificateFingerprint {
						state.Issuances[index].ExpiresAt = state.Issuances[index].ExpiresAt.Add(time.Nanosecond)
					}
				}
			},
			message: "no matching issuance record",
		},
	}

	for name, test := range mutations {
		t.Run(name, func(t *testing.T) {
			state := cloneRecoveryState(t, fixture.state)
			test.mutate(&state)
			raw, err := encodePersistedState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRecoverySnapshot(raw, fixture.box); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("mutated host certificate was accepted or returned the wrong error: %v", err)
			}
		})
	}
}

func TestValidateRecoverySnapshotHostCertificateLifecycle(t *testing.T) {
	store, box, path := newControlRecoverySnapshotHarness(t)
	service := NewService(store, box, recoverySnapshotIssuer{})
	service.now = func() time.Time { return recoverySnapshotNow }
	var network Network
	if err := store.View(func(state State) error {
		network = state.Networks[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, CreateNodeInput{Name: "pending-node", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	assertControlRecoveryFileValid(t, path, box)
	pendingState := fixtureStateFromPath(t, path)
	if _, err := service.RevokeNode(pending.Node.ID); err != nil {
		t.Fatal(err)
	}
	assertControlRecoveryFileValid(t, path, box)
	neverEnrolledRevokedState := fixtureStateFromPath(t, path)

	active := newActiveControlRecoveryFixture(t, 1)
	if _, err := active.service.RevokeNode(active.state.Nodes[0].ID); err != nil {
		t.Fatal(err)
	}
	assertControlRecoveryFileValid(t, active.path, active.box)
	enrolledRevokedState := fixtureStateFromPath(t, active.path)

	for name, mutate := range map[string]func(*State){
		"active missing certificate": func(state *State) { state.Nodes[0].Certificate = "" },
		"active missing fingerprint": func(state *State) { state.Nodes[0].CertificateFingerprint = "" },
		"active missing expiry":      func(state *State) { state.Nodes[0].CertificateExpiresAt = nil },
		"active missing renewal":     func(state *State) { state.Nodes[0].CertificateRenewAfter = nil },
		"active missing public key":  func(state *State) { state.Nodes[0].PublicKeyHash = "" },
		"active missing generation":  func(state *State) { state.Nodes[0].CertificateGeneration = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			state := cloneRecoveryState(t, active.state)
			mutate(&state)
			raw, err := encodePersistedState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRecoverySnapshot(raw, active.box); err == nil {
				t.Fatal("incomplete active certificate lifecycle was accepted")
			}
		})
	}

	record := certificateRecord(active.state.Nodes[0])
	for name, test := range map[string]struct {
		state   State
		box     *SecretBox
		mutate  func(*State)
		message string
	}{
		"pending with certificate material": {
			state: pendingState, box: box,
			mutate: func(state *State) {
				applyCertificateRecord(&state.Nodes[0], record)
				state.Nodes[0].PublicKeyHash = ""
			},
			message: "pending node retains certificate material",
		},
		"never-enrolled revoked with certificate material": {
			state: neverEnrolledRevokedState, box: box,
			mutate:  func(state *State) { applyCertificateRecord(&state.Nodes[0], record) },
			message: "never-enrolled revoked node retains certificate material",
		},
		"enrolled revoked missing certificate": {
			state: enrolledRevokedState, box: active.box,
			mutate:  func(state *State) { state.Nodes[0].Certificate = "" },
			message: "enrolled revoked node is missing complete certificate metadata",
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := cloneRecoveryState(t, test.state)
			test.mutate(&state)
			raw, err := encodePersistedState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRecoverySnapshot(raw, test.box); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid certificate lifecycle was accepted or returned the wrong error: %v", err)
			}
		})
	}
}

func TestValidateRecoverySnapshotAcceptsProductionNebulaCertificates(t *testing.T) {
	nebulaBinary, err := exec.LookPath("nebula-cert")
	if err != nil {
		t.Skip("nebula-cert is not installed")
	}

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box := mustControlRecoveryBox(t)
	service := NewService(store, box, NebulaIssuer{Binary: nebulaBinary})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "production-recovery", CIDR: "10.119.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "production-node", Role: "member", Groups: []string{"production"}})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := newRecoveryHostPublicKey(t)
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken("production-agent-token")); err != nil {
		t.Fatal(err)
	}
	assertControlRecoveryFileValid(t, path, box)
}

func TestStoreExportRecoverySnapshotExactDetachedAndDurable(t *testing.T) {
	t.Run("exact bytes detached and read-only", func(t *testing.T) {
		store, box, path := newControlRecoverySnapshotHarness(t)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		exact := append([]byte(" \n"), raw...)
		exact = append(exact, '\n', '\t')
		if err := os.WriteFile(path, exact, 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.ExportRecoverySnapshot(context.Background(), box)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(snapshot, exact) {
			t.Fatal("export canonicalized persisted bytes")
		}
		snapshot[0] ^= 0xff
		second, err := store.ExportRecoverySnapshot(context.Background(), box)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(second, exact) {
			t.Fatal("returned snapshot was not detached")
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
			t.Fatal("snapshot export rewrote the source file")
		}

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := store.ExportRecoverySnapshot(cancelled, box); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled export = %v, want context cancellation", err)
		}
	})

	t.Run("pending durability barrier", func(t *testing.T) {
		store, box, _ := newControlRecoverySnapshotHarness(t)
		var syncCalls int
		store.syncDirectory = func(directory string) error {
			syncCalls++
			if syncCalls == 1 {
				return errors.New("injected directory sync failure")
			}
			return syncStateDirectory(directory)
		}
		now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
		if err := store.Update(func(state *State) error {
			state.Audit = append(state.Audit, newAudit(now, "recovery.snapshot_test", "store", "snapshot", nil))
			return nil
		}); !errors.Is(err, ErrUncertainCommit) {
			t.Fatalf("update = %v, want uncertain commit", err)
		}
		if _, err := store.ExportRecoverySnapshot(context.Background(), box); err != nil {
			t.Fatalf("export did not resolve durability barrier: %v", err)
		}
		if syncCalls != 2 || store.durabilityPending {
			t.Fatalf("sync calls=%d pending=%v, want resolved barrier", syncCalls, store.durabilityPending)
		}
	})

	t.Run("disk and memory mismatch", func(t *testing.T) {
		store, box, path := newControlRecoverySnapshotHarness(t)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var changed State
		if err := decodePersistedState(raw, &changed); err != nil {
			t.Fatal(err)
		}
		changed.Audit = append(changed.Audit, newAudit(time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC), "external.change", "store", "snapshot", nil))
		changedRaw, err := encodePersistedState(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, changedRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportRecoverySnapshot(context.Background(), box); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("disk/memory mismatch was accepted: %v", err)
		}
	})
}

func TestControlStateDecodeRejectsAmbiguousNamesAndInvalidUTF8(t *testing.T) {
	invalidNames := map[string]struct {
		raw  []byte
		want string
	}{
		"root duplicate": {
			raw:  []byte(`{"version":1,"version":1,"networks":[],"nodes":[],"enrollments":[],"audit":[]}`),
			want: "duplicate JSON object name",
		},
		"root case-folded duplicate": {
			raw:  []byte(`{"version":1,"admin_credential_verifier":"","ADMIN_CREDENTIAL_VERIFIER":"attacker-controlled","networks":[],"nodes":[],"enrollments":[],"audit":[]}`),
			want: "duplicate JSON object name",
		},
		"root case-folded alias": {
			raw:  []byte(`{"VERSION":1,"networks":[],"nodes":[],"enrollments":[],"audit":[]}`),
			want: "exact schema spelling",
		},
		"nested duplicate": {
			raw:  []byte(`{"version":1,"networks":[{"id":"network_1","id":"network_2"}],"nodes":[],"enrollments":[],"audit":[]}`),
			want: "duplicate JSON object name",
		},
		"nested case-folded duplicate": {
			raw:  []byte(`{"version":1,"networks":[{"id":"network_1","ID":"network_2"}],"nodes":[],"enrollments":[],"audit":[]}`),
			want: "duplicate JSON object name",
		},
		"deep embedded case-folded duplicate": {
			raw:  []byte(`{"version":1,"networks":[],"nodes":[],"enrollments":[],"agent_recoveries":[{"result":{"node_id":"node_1","NODE_ID":"node_2"}}],"audit":[]}`),
			want: "duplicate JSON object name",
		},
	}
	for name, test := range invalidNames {
		t.Run(name, func(t *testing.T) {
			var state State
			if err := decodePersistedState(test.raw, &state); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decode error = %v, want %q", err, test.want)
			}
			if err := ValidateRecoverySnapshot(test.raw, mustControlRecoveryBox(t)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("recovery validation error = %v, want %q", err, test.want)
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("OpenStore error = %v, want %q", err, test.want)
			}
		})
	}

	invalidUTF8 := append([]byte(`{"version":1,"networks":[],"nodes":[],"enrollments":[],"audit":[],"x":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
	if err := ValidateRecoverySnapshot(invalidUTF8, mustControlRecoveryBox(t)); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 validation = %v", err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, invalidUTF8, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil {
		t.Fatal("OpenStore accepted invalid UTF-8 state")
	}
}

func TestControlStateDecodePreservesCaseDistinctAuditDetailNames(t *testing.T) {
	raw := []byte(`{"version":1,"networks":[],"nodes":[],"enrollments":[],"audit":[{"id":"audit_1","action":"store.checked","resource":"store","resource_id":"state","at":"2026-07-19T20:00:00Z","details":{"TraceID":"upper","traceid":"lower","nested":{"Field":1,"field":2}}}]}`)
	var state State
	if err := decodePersistedState(raw, &state); err != nil {
		t.Fatalf("decode case-distinct audit details: %v", err)
	}
	if len(state.Audit) != 1 || state.Audit[0].Details["TraceID"] != "upper" || state.Audit[0].Details["traceid"] != "lower" {
		t.Fatalf("case-distinct audit details were not preserved: %#v", state.Audit)
	}
	nested, ok := state.Audit[0].Details["nested"].(map[string]any)
	if !ok || nested["Field"] != float64(1) || nested["field"] != float64(2) {
		t.Fatalf("nested case-distinct audit details were not preserved: %#v", state.Audit[0].Details["nested"])
	}
	if err := ValidateRecoverySnapshot(raw, mustControlRecoveryBox(t)); err != nil {
		t.Fatalf("validate case-distinct audit details: %v", err)
	}
}

type activeControlRecoveryFixture struct {
	service    *Service
	box        *SecretBox
	path       string
	raw        []byte
	state      State
	publicKeys []string
}

type recoveryCertificateRecord struct {
	certificate string
	fingerprint string
	expiresAt   time.Time
	renewAfter  time.Time
	generation  int64
	publicHash  string
}

func newActiveControlRecoveryFixture(t *testing.T, count int) activeControlRecoveryFixture {
	t.Helper()
	store, box, path := newControlRecoverySnapshotHarness(t)
	service := NewService(store, box, recoverySnapshotIssuer{})
	service.now = func() time.Time { return recoverySnapshotNow }
	var network Network
	if err := store.View(func(state State) error {
		network = state.Networks[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture := activeControlRecoveryFixture{service: service, box: box, path: path}
	for index := 0; index < count; index++ {
		groups := []string{"infra", "ops"}
		if index > 0 {
			groups = []string{"members"}
		}
		created, err := service.CreateNode(network.ID, CreateNodeInput{
			Name:   fmt.Sprintf("recovery-node-%d", index+1),
			Role:   "member",
			Groups: groups,
		})
		if err != nil {
			t.Fatal(err)
		}
		publicKey := newRecoveryHostPublicKey(t)
		if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(fmt.Sprintf("agent-token-%d", index+1))); err != nil {
			t.Fatal(err)
		}
		fixture.publicKeys = append(fixture.publicKeys, publicKey)
	}
	fixture.raw = mustReadRecoveryFile(t, path)
	if err := decodePersistedState(fixture.raw, &fixture.state); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func newRecoveryHostPublicKey(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := nebulacert.MarshalPublicKeyToPEM(nebulacert.Curve_CURVE25519, privateKey.PublicKey().Bytes())
	if len(publicKey) == 0 {
		t.Fatal("marshal test host public key")
	}
	return string(publicKey)
}

func newRecoveryTestCA(t *testing.T, name, cidr string) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	network := mustRecoveryPrefix(t, cidr).Masked()
	certificate, err := (&nebulacert.TBSCertificate{
		Version:   nebulacert.Version2,
		Name:      name,
		Networks:  []netip.Prefix{network},
		IsCA:      true,
		NotBefore: recoverySnapshotNow.Add(-time.Hour),
		NotAfter:  recoverySnapshotNow.Add(10 * 365 * 24 * time.Hour),
		PublicKey: publicKey,
		Curve:     nebulacert.Curve_CURVE25519,
	}).Sign(nil, nebulacert.Curve_CURVE25519, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := certificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := nebulacert.MarshalSigningPrivateKeyToPEM(nebulacert.Curve_CURVE25519, privateKey)
	if len(privateKeyPEM) == 0 {
		t.Fatal("marshal test CA private key")
	}
	defer clear(privateKeyPEM)
	return string(certificatePEM), string(privateKeyPEM)
}

func signRecoveryHostCertificate(t *testing.T, caCertificate, caPrivateKey, publicKey, name string, networks, unsafeNetworks []netip.Prefix, groups []string) (string, string, time.Time) {
	t.Helper()
	ca, remainder, err := nebulacert.UnmarshalCertificateFromPEM([]byte(caCertificate))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatalf("decode test CA: %v", err)
	}
	privateKey, remainder, privateCurve, err := nebulacert.UnmarshalSigningPrivateKeyFromPEM([]byte(caPrivateKey))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatalf("decode test CA private key: %v", err)
	}
	defer clear(privateKey)
	publicKeyBytes, remainder, publicCurve, err := nebulacert.UnmarshalPublicKeyFromPEM([]byte(publicKey))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatalf("decode test host public key: %v", err)
	}
	certificate, err := (&nebulacert.TBSCertificate{
		Version:        ca.Version(),
		Name:           name,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		NotBefore:      recoverySnapshotNow,
		NotAfter:       recoverySnapshotNow.Add(24 * time.Hour),
		PublicKey:      publicKeyBytes,
		Curve:          publicCurve,
	}).Sign(ca, privateCurve, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := certificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return string(certificatePEM), fingerprint, certificate.NotAfter().UTC()
}

func setRecoveryNodeCertificate(node *Node, network Network, certificate, fingerprint string, expiresAt time.Time) {
	renewAfter := expiresAt.Add(-renewalWindow(time.Duration(network.CertificateTTL) * time.Hour))
	node.Certificate = certificate
	node.CertificateFingerprint = fingerprint
	node.CertificateExpiresAt = &expiresAt
	node.CertificateRenewAfter = &renewAfter
}

func certificateRecord(node Node) recoveryCertificateRecord {
	return recoveryCertificateRecord{
		certificate: node.Certificate,
		fingerprint: node.CertificateFingerprint,
		expiresAt:   node.CertificateExpiresAt.UTC(),
		renewAfter:  node.CertificateRenewAfter.UTC(),
		generation:  node.CertificateGeneration,
		publicHash:  node.PublicKeyHash,
	}
}

func applyCertificateRecord(node *Node, record recoveryCertificateRecord) {
	expiresAt := record.expiresAt
	renewAfter := record.renewAfter
	node.Certificate = record.certificate
	node.CertificateFingerprint = record.fingerprint
	node.CertificateExpiresAt = &expiresAt
	node.CertificateRenewAfter = &renewAfter
	node.CertificateGeneration = record.generation
	node.PublicKeyHash = record.publicHash
}

func cloneRecoveryState(t *testing.T, state State) State {
	t.Helper()
	raw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}
	var cloned State
	if err := decodePersistedState(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func fixtureStateFromPath(t *testing.T, path string) State {
	t.Helper()
	var state State
	if err := decodePersistedState(mustReadRecoveryFile(t, path), &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func mustReadRecoveryFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertControlRecoveryFileValid(t *testing.T, path string, box *SecretBox) {
	t.Helper()
	if err := ValidateRecoverySnapshot(mustReadRecoveryFile(t, path), box); err != nil {
		t.Fatalf("validate control recovery file: %v", err)
	}
}

func mustRecoveryPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func newControlRecoverySnapshotHarness(t *testing.T) (*Store, *SecretBox, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box := mustControlRecoveryBox(t)
	service := NewService(store, box, recoverySnapshotIssuer{})
	service.now = func() time.Time { return recoverySnapshotNow }
	if _, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "snapshot", CIDR: "10.111.0.0/24", CertificateTTL: 24}); err != nil {
		t.Fatal(err)
	}
	return store, box, path
}

func mustControlRecoveryBox(t *testing.T) *SecretBox {
	t.Helper()
	box, err := NewSecretBox(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func base64LikeTamperForControl(value string) string {
	if value == "" {
		return "A"
	}
	replacement := byte('A')
	if value[0] == replacement {
		replacement = 'B'
	}
	return string(replacement) + value[1:]
}
