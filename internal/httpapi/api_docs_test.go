package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAPIReferenceIsEmbeddedUnauthenticatedAndSelfContained(t *testing.T) {
	server := testServer(t, strings.Repeat("r", 43))
	defer server.Close()

	for _, asset := range []struct {
		path        string
		contentType string
		required    []string
	}{
		{
			path:        "/api-docs.html",
			contentType: "text/html; charset=utf-8",
			required: []string{
				"Mesh control-plane API",
				"Browser sessions",
				"CSRF is added automatically",
				"Agent and recovery calls stay disabled",
				`href="/openapi.json"`,
				`src="/api-docs.js"`,
				`href="/api-docs.css"`,
			},
		},
		{
			path:        "/api-docs.css",
			contentType: "text/css; charset=utf-8",
			required:    []string{".api-workspace", ".operation-summary", ".try-panel", "prefers-reduced-motion"},
		},
		{
			path:        "/api-docs.js",
			contentType: "text/javascript; charset=utf-8",
			required: []string{
				`fetch("/openapi.json"`,
				`credentials: "same-origin"`,
				`headers.set("X-Mesh-CSRF", csrf)`,
				"I understand this sends a real state-changing request",
			},
		},
	} {
		response, err := server.Client().Get(server.URL + asset.path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", asset.path, response.StatusCode, body)
		}
		if response.Header.Get("Content-Type") != asset.contentType {
			t.Fatalf("%s content type=%q", asset.path, response.Header.Get("Content-Type"))
		}
		if response.Header.Get("Content-Security-Policy") == "" ||
			response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s is missing application security headers", asset.path)
		}
		for _, required := range asset.required {
			if !bytes.Contains(body, []byte(required)) {
				t.Fatalf("%s is missing %q", asset.path, required)
			}
		}
		for _, forbidden := range []string{
			"https://cdn.",
			"unpkg.com",
			"localStorage",
			"sessionStorage",
			"innerHTML",
			`set("Authorization"`,
		} {
			if bytes.Contains(body, []byte(forbidden)) {
				t.Fatalf("%s contains forbidden browser behavior %q", asset.path, forbidden)
			}
		}
	}
}

func TestAPIReferenceLinksCanonicalContractFromPublicGuide(t *testing.T) {
	publicGuide, err := webFiles.ReadFile("web/docs.html")
	if err != nil {
		t.Fatal(err)
	}
	apiReference, err := webFiles.ReadFile("web/api-docs.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(publicGuide, []byte(`href="/api-docs.html"`)) {
		t.Fatal("public guide does not link the API reference")
	}
	for _, required := range []string{
		`href="/docs.html"`,
		`href="/openapi.json"`,
		`href="/"`,
	} {
		if !bytes.Contains(apiReference, []byte(required)) {
			t.Fatalf("API reference is missing navigation %q", required)
		}
	}
}
