package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseOriginConfigRequiresCanonicalNativeHTTPSBoundary(t *testing.T) {
	root := t.TempDir()
	arguments := []string{
		"--listen=0.0.0.0:8444",
		"--public-url=https://origin.example:8444",
		"--tls-cert=" + filepath.Join(root, "server.crt"),
		"--tls-key=" + filepath.Join(root, "server.key"),
		"--root=" + filepath.Join(root, "repository"),
		"--index=" + filepath.Join(root, "origin-index.json"),
	}
	config, err := parseOriginConfig(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if config.listen != "0.0.0.0:8444" || config.publicURL != "https://origin.example:8444" {
		t.Fatalf("unexpected parsed config: %+v", config)
	}
	for _, replacement := range []struct {
		index int
		value string
	}{
		{0, "--listen=origin.example:8444"},
		{0, "--listen=0.0.0.0:0"},
		{1, "--public-url=http://origin.example:8444"},
		{1, "--public-url=https://origin.example:443"},
		{1, "--public-url=https://origin.example:8444/path"},
		{2, "--tls-cert=server.crt"},
		{4, "--root=/"},
	} {
		candidate := append([]string(nil), arguments...)
		candidate[replacement.index] = replacement.value
		if _, err := parseOriginConfig(candidate); err == nil {
			t.Fatalf("invalid origin config accepted: %q", replacement.value)
		}
	}
}

func TestOriginTLSPrivateKeyRequiresOwnerOnlySingleLinkFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows TLS DACL proof is not implemented")
	}
	root := t.TempDir()
	path := filepath.Join(root, "server.key")
	if err := os.WriteFile(path, []byte("private-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableTLSFile("TLS private key", path, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableTLSFile("TLS private key", path, true); err == nil {
		t.Fatal("permissive TLS private key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "key-link")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableTLSFile("TLS private key", path, true); err == nil {
		t.Fatal("hard-linked TLS private key accepted")
	}
}
