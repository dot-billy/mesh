package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateDevelopmentSecretIsPrivateAndStable(t *testing.T) {
	directory := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, "admin.token")
	first, err := loadOrCreate(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreate(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 43 {
		t.Fatalf("development secret was not a stable 256-bit token: %q %q", first, second)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("secret mode = %04o, want 0600", info.Mode().Perm())
		}
	}
}

func TestProductionSecretsLoadPrivateFilesWithoutEnvironmentValues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native private-file DACL proof is not implemented on Windows")
	}
	t.Setenv("MESH_ADMIN_TOKEN", "")
	t.Setenv("MESH_MASTER_KEY", "")
	root := t.TempDir()
	adminPath := filepath.Join(root, "admin.token")
	masterPath := filepath.Join(root, "master.key")
	admin := strings.Repeat("a", 43)
	masterBytes := []byte("0123456789abcdef0123456789abcdef")
	master := base64.RawURLEncoding.EncodeToString(masterBytes)
	for path, value := range map[string]string{adminPath: admin, masterPath: master} {
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gotAdmin, gotMaster, err := secrets("", false, adminPath, masterPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotAdmin != admin || string(gotMaster) != string(masterBytes) {
		t.Fatal("loaded credentials differ from private files")
	}
	clear(gotMaster)

	t.Setenv("MESH_ADMIN_TOKEN", strings.Repeat("b", 43))
	if _, _, err := secrets("", false, adminPath, masterPath); err == nil || !strings.Contains(err.Error(), "cannot both be set") {
		t.Fatalf("file/environment ambiguity returned %v", err)
	}
}

func TestPrivateCredentialFileRejectsUnsafeOrNoncanonicalInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native private-file DACL proof is not implemented on Windows")
	}
	root := t.TempDir()
	valid := filepath.Join(root, "valid")
	if err := os.WriteFile(valid, []byte(strings.Repeat("x", 43)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCredentialFile("--test", valid); err != nil {
		t.Fatalf("private canonical credential rejected: %v", err)
	}

	worldReadable := filepath.Join(root, "world")
	if err := os.WriteFile(worldReadable, []byte(strings.Repeat("x", 43)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldReadable, 0o644); err != nil {
		t.Fatal(err)
	}
	hardLink := filepath.Join(root, "hard-link")
	if err := os.Link(valid, hardLink); err != nil {
		t.Fatal(err)
	}
	badNewline := filepath.Join(root, "bad-newline")
	if err := os.WriteFile(badNewline, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{worldReadable, valid, hardLink, badNewline, symlink} {
		if _, err := readPrivateCredentialFile("--test", path); err == nil {
			t.Fatalf("unsafe credential path accepted: %s", path)
		}
	}
}

func TestLoadOrCreateRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("do-not-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "admin.token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreate(link, 32); err == nil {
		t.Fatal("symlink secret path was accepted")
	}
}

func TestLoadOrCreateRejectsWeakExistingSecret(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "admin.token")
	if err := os.WriteFile(path, []byte("weak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreate(path, 32); err == nil {
		t.Fatal("weak existing development secret was accepted")
	}
}

func TestLoopbackListen(t *testing.T) {
	for address, want := range map[string]bool{
		"127.0.0.1:8080": true,
		"[::1]:8080":     true,
		"localhost:8080": false,
		"0.0.0.0:8080":   false,
		":8080":          false,
		"not-an-address": false,
	} {
		if got := loopbackListen(address); got != want {
			t.Errorf("loopbackListen(%q) = %v, want %v", address, got, want)
		}
	}
}

func TestProxyTLSUsesCleartextBackendListener(t *testing.T) {
	// --behind-tls-proxy affects Secure cookies and HSTS, not the protocol on
	// the private backend listener. Only an actual local keypair enables TLS.
	if nativeTLSEnabled("", "") {
		t.Fatal("proxy-terminated listener incorrectly selected native TLS")
	}
	if !nativeTLSEnabled("server.crt", "server.key") {
		t.Fatal("native TLS keypair did not select TLS listener")
	}
}

func TestResolvePublicURLDerivationAndRefusal(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		listen     string
		nativeTLS  bool
		proxyTLS   bool
		wantURL    string
		wantSecure bool
		wantError  bool
	}{
		{name: "default loopback development", listen: "127.0.0.1:8080", wantURL: "http://127.0.0.1:8080"},
		{name: "explicit IPv6 loopback TLS", listen: "[::1]:8443", nativeTLS: true, wantURL: "https://[::1]:8443", wantSecure: true},
		{name: "hostname listener is ambiguous", listen: "localhost:8080", wantError: true},
		{name: "wildcard listener cannot derive", listen: "0.0.0.0:8443", nativeTLS: true, wantError: true},
		{name: "ephemeral port cannot derive", listen: "127.0.0.1:0", wantError: true},
		{name: "proxy external origin required", listen: "127.0.0.1:8080", proxyTLS: true, wantError: true},
		{name: "explicit proxy origin", configured: "https://mesh.example.test", listen: "127.0.0.1:8080", proxyTLS: true, wantURL: "https://mesh.example.test", wantSecure: true},
		{name: "explicit native TLS origin", configured: "https://mesh.example.test", listen: "0.0.0.0:8443", nativeTLS: true, wantURL: "https://mesh.example.test", wantSecure: true},
		{name: "proxy rejects http origin", configured: "http://127.0.0.1:8080", listen: "127.0.0.1:8080", proxyTLS: true, wantError: true},
		{name: "https origin requires TLS", configured: "https://mesh.example.test", listen: "127.0.0.1:8080", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, secure, err := resolvePublicURL(test.configured, test.listen, test.nativeTLS, test.proxyTLS)
			if (err != nil) != test.wantError || resolved != test.wantURL || secure != test.wantSecure {
				t.Fatalf("resolvePublicURL() = (%q, %v, %v), want (%q, %v, error=%v)", resolved, secure, err, test.wantURL, test.wantSecure, test.wantError)
			}
		})
	}
}

func TestValidateTransportRequiresPrivateProxyBackend(t *testing.T) {
	if err := validateTransport("127.0.0.1:8080", "", "", false, true, false); err != nil {
		t.Fatalf("loopback proxy backend rejected: %v", err)
	}
	if err := validateTransport("0.0.0.0:8080", "", "", false, true, false); err == nil {
		t.Fatal("wildcard proxy backend was accepted")
	}
	if err := validateTransport("10.0.0.5:8080", "", "", false, true, false); err == nil {
		t.Fatal("network-reachable proxy backend was accepted")
	}
}

func TestValidateTransportExposureModes(t *testing.T) {
	tests := []struct {
		name          string
		listen        string
		tlsCert       string
		tlsKey        string
		dev           bool
		allowInsecure bool
		wantError     bool
	}{
		{name: "native TLS", listen: "0.0.0.0:8443", tlsCert: "server.crt", tlsKey: "server.key"},
		{name: "partial keypair", listen: "127.0.0.1:8443", tlsCert: "server.crt", wantError: true},
		{name: "production cleartext", listen: "0.0.0.0:8080", wantError: true},
		{name: "removed non-loopback development override", listen: "0.0.0.0:8080", dev: true, allowInsecure: true, wantError: true},
		{name: "override outside development", listen: "0.0.0.0:8080", allowInsecure: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateTransport(test.listen, test.tlsCert, test.tlsKey, test.dev, false, test.allowInsecure)
			if (err != nil) != test.wantError {
				t.Fatalf("validateTransport() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
