package kubeinit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunMaterializesProjectedSecretsAndIsRetrySafe(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials")
	tlsSource := filepath.Join(root, "tls")
	identity := filepath.Join(root, "identity")
	postgres := filepath.Join(root, "postgres")
	output := filepath.Join(root, "output")
	data := filepath.Join(root, "data")
	for _, path := range []string{output, data} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	certificate, key, ca := testTLSIdentity(t, "mesh.example.test")
	project(t, credentials, map[string][]byte{
		"admin.token": []byte(strings.Repeat("a", 43) + "\n"),
		"master.key":  []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "\n"),
	})
	project(t, tlsSource, map[string][]byte{
		"tls.crt": certificate,
		"tls.key": key,
		"ca.crt":  ca,
	})
	project(t, identity, map[string][]byte{
		"identity.json":      []byte("{\"schema\":\"mesh-identity-v2\"}\n"),
		"oidc-client.secret": []byte("private-client-secret\n"),
	})
	project(t, postgres, map[string][]byte{
		"postgres.dsn": []byte("postgres://mesh@example.test/mesh?sslmode=verify-full\n"),
	})
	options := Options{
		CredentialsSourceDir: credentials,
		TLSSourceDir:         tlsSource,
		IdentitySourceDir:    identity,
		PostgresSourceDir:    postgres,
		OutputRoot:           output,
		DataDir:              data,
		TLSServerName:        "mesh.example.test",
		RuntimeUID:           os.Geteuid(),
		RuntimeGID:           os.Getegid(),
	}
	if err := Run(options); err != nil {
		t.Fatal(err)
	}
	if err := Run(options); err != nil {
		t.Fatalf("byte-identical retry failed: %v", err)
	}
	private := filepath.Join(output, finalDirectoryName)
	entries, err := os.ReadDir(private)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
		info, statErr := os.Lstat(filepath.Join(private, entry.Name()))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("materialized %s is not a regular file: info=%v err=%v", entry.Name(), info, statErr)
		}
	}
	if want := Inventory(true, true); !reflect.DeepEqual(names, want) {
		t.Fatalf("inventory = %v, want %v", names, want)
	}
	dataInfo, err := os.Lstat(data)
	if err != nil || dataInfo.Mode().Perm() != 0o700 {
		t.Fatalf("data directory mode = %v, err=%v", dataInfo.Mode(), err)
	}
}

func TestRunTLSMaterializesOnlyValidatedTLSAndIsRetrySafe(t *testing.T) {
	root := t.TempDir()
	tlsSource := filepath.Join(root, "tls")
	output := filepath.Join(root, "output")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	certificate, key, ca := testTLSIdentity(t, "releases.example.test")
	project(t, tlsSource, map[string][]byte{
		"tls.crt": certificate,
		"tls.key": key,
		"ca.crt":  ca,
	})
	options := TLSOptions{
		TLSSourceDir: tlsSource, OutputRoot: output,
		TLSServerName: "releases.example.test",
		RuntimeUID:    os.Geteuid(), RuntimeGID: os.Getegid(),
	}
	if err := RunTLS(options); err != nil {
		t.Fatal(err)
	}
	if err := RunTLS(options); err != nil {
		t.Fatalf("byte-identical TLS retry failed: %v", err)
	}
	private := filepath.Join(output, finalDirectoryName)
	entries, err := os.ReadDir(private)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ca.crt", "server.crt", "server.key"}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
		info, statErr := os.Lstat(filepath.Join(private, entry.Name()))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("materialized %s is not a regular file: info=%v err=%v", entry.Name(), info, statErr)
		}
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("TLS inventory = %v, want %v", names, want)
	}
	if info, err := os.Lstat(filepath.Join(private, "server.key")); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("private-key mode = %v, err=%v", info.Mode(), err)
	}
}

func TestRunRejectsEscapingProjection(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0o755); err != nil {
		t.Fatal(err)
	}
	escaped := filepath.Join(root, "admin.token")
	if err := os.WriteFile(escaped, []byte(strings.Repeat("a", 43)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(escaped, filepath.Join(credentials, "admin.token")); err != nil {
		t.Fatal(err)
	}
	_, err := readProjectedFile(credentials, "admin.token", maximumCredentialBytes)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("escaping projection returned %v", err)
	}
}

func TestRunRejectsChangedPublishedOutput(t *testing.T) {
	root := t.TempDir()
	certificate, key, ca := testTLSIdentity(t, "mesh.example.test")
	credentials := filepath.Join(root, "credentials")
	tlsSource := filepath.Join(root, "tls")
	output := filepath.Join(root, "output")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	project(t, credentials, map[string][]byte{
		"admin.token": []byte(strings.Repeat("a", 43)),
		"master.key":  []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))),
	})
	project(t, tlsSource, map[string][]byte{"tls.crt": certificate, "tls.key": key, "ca.crt": ca})
	options := Options{
		CredentialsSourceDir: credentials, TLSSourceDir: tlsSource,
		OutputRoot: output, TLSServerName: "mesh.example.test",
		RuntimeUID: os.Geteuid(), RuntimeGID: os.Getegid(),
	}
	if err := Run(options); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(output, finalDirectoryName, "admin.token")
	if err := os.Chmod(adminPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminPath, []byte(strings.Repeat("b", 43)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(adminPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := Run(options); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed publication returned %v", err)
	}
}

func TestValidateMasterKeyRejectsNonCanonicalEncoding(t *testing.T) {
	if err := validateMasterKey([]byte(base64.StdEncoding.EncodeToString(make([]byte, 32)))); err == nil {
		t.Fatal("padded standard base64 master key was accepted")
	}
}

func project(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	revisionName := "..2026_07_21_00_00_00.000000000"
	revision := filepath.Join(root, revisionName)
	if err := os.Mkdir(revision, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(revision, name), raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(revisionName, filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func testTLSIdentity(t *testing.T, serverName string) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Now()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mesh test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	_, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serverName},
		DNSNames: []string{serverName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
