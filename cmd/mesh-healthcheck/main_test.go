package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthcheckRequiresTrustedExactReadyResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ready\"}\n"))
	}))
	defer server.Close()
	caPath := writeTestCA(t, server.Certificate())
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		"MESH_HEALTHCHECK_URL":         server.URL + "/readyz",
		"MESH_HEALTHCHECK_CA_FILE":     caPath,
		"MESH_HEALTHCHECK_SERVER_NAME": parsed.Hostname(),
	}
	if err := run(nil, func(name string) string { return environment[name] }); err != nil {
		t.Fatalf("valid readiness rejected: %v", err)
	}

	environment["MESH_HEALTHCHECK_SERVER_NAME"] = "wrong.example"
	if err := run(nil, func(name string) string { return environment[name] }); err == nil {
		t.Fatal("wrong TLS identity accepted")
	}
}

func TestHealthcheckRejectsNonReadyAndInexactResponses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "unavailable", status: http.StatusServiceUnavailable, contentType: "application/json", body: `{"status":"unavailable"}`},
		{name: "wrong content type", status: http.StatusOK, contentType: "text/plain", body: `{"status":"ready"}`},
		{name: "unknown field", status: http.StatusOK, contentType: "application/json", body: `{"status":"ready","extra":true}`},
		{name: "trailing JSON", status: http.StatusOK, contentType: "application/json", body: `{"status":"ready"}{}`},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: `{"status":"ready"}` + strings.Repeat(" ", maximumReadyBody)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			parsed, _ := url.Parse(server.URL)
			environment := map[string]string{
				"MESH_HEALTHCHECK_URL":         server.URL + "/readyz",
				"MESH_HEALTHCHECK_CA_FILE":     writeTestCA(t, server.Certificate()),
				"MESH_HEALTHCHECK_SERVER_NAME": parsed.Hostname(),
			}
			if err := run(nil, func(name string) string { return environment[name] }); err == nil {
				t.Fatal("inexact readiness response accepted")
			}
		})
	}
}

func TestParseHealthcheckConfigRejectsUnsafeBoundary(t *testing.T) {
	base := map[string]string{
		"MESH_HEALTHCHECK_URL":         "https://127.0.0.1:8443/readyz",
		"MESH_HEALTHCHECK_CA_FILE":     "/run/tls/ca.crt",
		"MESH_HEALTHCHECK_SERVER_NAME": "mesh.example.com",
	}
	for name, value := range map[string]string{
		"missing URL":       "",
		"cleartext":         "http://127.0.0.1:8443/readyz",
		"remote target":     "https://192.0.2.1:8443/readyz",
		"query":             "https://127.0.0.1:8443/readyz?x=1",
		"wrong path":        "https://127.0.0.1:8443/healthz",
		"implicit port":     "https://127.0.0.1/readyz",
		"embedded identity": "https://user@127.0.0.1:8443/readyz",
	} {
		t.Run(name, func(t *testing.T) {
			environment := map[string]string{}
			for key, item := range base {
				environment[key] = item
			}
			environment["MESH_HEALTHCHECK_URL"] = value
			if _, err := parseHealthcheckConfig(nil, func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("unsafe URL accepted: %q", value)
			}
		})
	}
	if _, err := parseHealthcheckConfig([]string{"--timeout=11s"}, func(name string) string { return base[name] }); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("invalid timeout returned %v", err)
	}
}

func writeTestCA(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if raw == nil {
		t.Fatal("encode test CA")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHealthcheckErrorMessagesDoNotIncludeCABytes(t *testing.T) {
	secret := "private-ca-marker"
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		"MESH_HEALTHCHECK_URL":         "https://127.0.0.1:8443/readyz",
		"MESH_HEALTHCHECK_CA_FILE":     path,
		"MESH_HEALTHCHECK_SERVER_NAME": "127.0.0.1",
	}
	err := run(nil, func(name string) string { return environment[name] })
	if err == nil || strings.Contains(fmt.Sprint(err), secret) {
		t.Fatalf("invalid CA returned %v", err)
	}
}
