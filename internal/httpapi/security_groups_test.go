package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/control"
)

func ensureSecurityGroupSchemaForHTTPTest(t *testing.T, service *control.Service, adminToken string) {
	t.Helper()
	master := make([]byte, 32)
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, []byte(adminToken))
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema, service.EnsureRouteProfileEditSchema, service.EnsureRoutePolicySchema,
		service.EnsureNativeDNSSchema, service.EnsureFirewallScopeSchema, service.EnsureSecurityGroupSchema,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecurityGroupAPIAuthenticationCSRFLifecycleAndDeleteGuards(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	adminToken := strings.Repeat("G", 43)
	ensureSecurityGroupSchemaForHTTPTest(t, service, adminToken)
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "groups-api", CIDR: "10.128.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/groups"

	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated group GET returned %d", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var initial control.NetworkSecurityGroupsDocument
	if err := json.NewDecoder(response.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" ||
		initial.NetworkID != network.ID || len(initial.Groups) != 1 || initial.Groups[0].Name != "all" || !initial.Groups[0].Builtin {
		t.Fatalf("initial group catalog status=%d cache=%q document=%#v", response.StatusCode, response.Header.Get("Cache-Control"), initial)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"token": adminToken})
	response, err = postTestLogin(client, server.URL, loginBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	parsedEndpoint, _ := url.Parse(endpoint)
	var csrf string
	for _, cookie := range jar.Cookies(parsedEndpoint) {
		if cookie.Name == "mesh_csrf" {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("login did not issue a CSRF token")
	}

	createBody := []byte(`{"name":"database","description":"Production databases"}`)
	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(createBody))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie group create without CSRF returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(createBody))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var created control.NetworkSecurityGroupsDocument
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" ||
		len(created.Groups) != 2 || created.Groups[1].Name != "database" || created.Groups[1].Description != "Production databases" {
		t.Fatalf("created group status=%d document=%#v", response.StatusCode, created)
	}

	groupEndpoint := endpoint + "/database"
	request, _ = http.NewRequest(http.MethodPut, groupEndpoint, strings.NewReader(`{"description":"Primary data tier"}`))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var updated control.NetworkSecurityGroupsDocument
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || updated.Groups[1].Description != "Primary data tier" {
		t.Fatalf("updated group status=%d document=%#v", response.StatusCode, updated)
	}

	if _, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "database-01", Groups: []string{"database"}}); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodDelete, groupEndpoint, strings.NewReader(`{"confirmation_name":"database"}`))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var conflict map[string]string
	_ = json.NewDecoder(response.Body).Decode(&conflict)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict || !strings.Contains(conflict["error"], "membership") {
		t.Fatalf("member group delete status=%d error=%q", response.StatusCode, conflict["error"])
	}

	request, _ = http.NewRequest(http.MethodGet, endpoint+"?unexpected=1", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("group query rejection status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}
