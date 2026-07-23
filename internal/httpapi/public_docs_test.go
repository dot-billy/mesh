package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPublicDocumentationIsEmbeddedAndUnauthenticated(t *testing.T) {
	server := testServer(t, strings.Repeat("d", 43))
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/docs.html")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public documentation status=%d body=%s", response.StatusCode, body)
	}
	if response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("public documentation content type=%q", response.Header.Get("Content-Type"))
	}
	if response.Header.Get("Content-Security-Policy") == "" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("public documentation is missing application security headers")
	}
	for _, required := range []string{
		"Public documentation",
		"Build a healthy network",
		"Firewall rules and groups",
		"Nebula relays",
		"Revoke a node",
		"Verify revocation",
		"Revocation cannot be undone",
		"Identity and security operations",
		"Use the API reference",
		`href="/api-docs.html"`,
		"Backup and restore",
		"Troubleshooting checklist",
		`href="/"`,
		`href="/docs.css"`,
	} {
		if !bytes.Contains(body, []byte(required)) {
			t.Fatalf("public documentation is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"enrollment_token",
		"recovery_token",
		"admin.token",
		"master.key",
		"BEGIN PRIVATE KEY",
	} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("public documentation exposes forbidden value %q", forbidden)
		}
	}

	response, err = server.Client().Get(server.URL + "/docs.css")
	if err != nil {
		t.Fatal(err)
	}
	css, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != "text/css; charset=utf-8" ||
		!bytes.Contains(css, []byte(".docs-topic-grid")) {
		t.Fatalf("public documentation stylesheet status=%d type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}

func TestDashboardLinksPublicDocumentationBeforeAndAfterLogin(t *testing.T) {
	index, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(index, []byte(`href="/docs.html"`)); count != 2 {
		t.Fatalf("dashboard has %d documentation links, want login and authenticated navigation", count)
	}
	if count := bytes.Count(index, []byte(`href="/api-docs.html"`)); count != 2 {
		t.Fatalf("dashboard has %d API reference links, want login and authenticated navigation", count)
	}
	for _, required := range []string{
		"Read the public documentation",
		`class="nav-item docs-nav"`,
		"Documentation",
		"API reference",
	} {
		if !bytes.Contains(index, []byte(required)) {
			t.Fatalf("dashboard documentation navigation is missing %q", required)
		}
	}
}
