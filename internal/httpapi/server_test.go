package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/runtimetelemetry"
)

func TestAdminAuthenticationAndCSRFGates(t *testing.T) {
	token := strings.Repeat("a", 43)
	server := testServer(t, token)
	defer server.Close()

	response, err := http.Get(server.URL + "/api/v1/networks")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request returned %d", response.StatusCode)
	}
	response.Body.Close()

	body := `{"name":"production","cidr":"10.42.0.0/24"}`
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/networks", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("bearer request returned %d", response.StatusCode)
	}
	var network map[string]any
	if err := json.NewDecoder(response.Body).Decode(&network); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if _, leaked := network["encrypted_ca_key"]; leaked {
		t.Fatal("encrypted CA key leaked through API")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"token": token})
	response, err = postTestLogin(client, server.URL, loginBody)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/networks", strings.NewReader(`{"name":"staging","cidr":"10.43.0.0/24"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie mutation without CSRF returned %d", response.StatusCode)
	}
	var csrf string
	for _, cookie := range jar.Cookies(request.URL) {
		if cookie.Name == "mesh_csrf" {
			csrf = cookie.Value
		}
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/networks", strings.NewReader(`{"name":"staging","cidr":"10.43.0.0/24"}`))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("cookie mutation with CSRF returned %d", response.StatusCode)
	}
}

func TestNewRejectsInvalidLinuxInstallBundleURL(t *testing.T) {
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
	token := strings.Repeat("u", 43)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, apiServer, identityStore := newTestHTTPServer(t, service, token, false, logger, nil)
	defer server.Close()
	config := apiServer.identityConfig
	validation := identity.ValidationOptions{AllowInsecureLoopback: true}
	fingerprint, err := config.PolicyFingerprint(validation)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := DeriveLegacyCredentialBinding(make([]byte, 32), token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(service, Options{
		IdentityConfig: config, ValidationOptions: validation,
		PolicyFingerprint: fingerprint, LegacyCredentialBinding: binding,
		SessionStore: identityStore, AdminToken: token, Logger: logger,
		LinuxInstallBundleURL: "https://RELEASES.example/channels/stable/bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "Linux install bundle URL") {
		t.Fatalf("noncanonical Linux install bundle URL returned %v", err)
	}
	_, err = New(service, Options{
		IdentityConfig: config, ValidationOptions: validation,
		PolicyFingerprint: fingerprint, LegacyCredentialBinding: binding,
		SessionStore: identityStore, AdminToken: token, Logger: logger,
		LinuxBootstrapHandoffURL: "https://RELEASES.example/bootstrap/stable/bootstrap-handoff.json",
	})
	if err == nil || !strings.Contains(err.Error(), "Linux bootstrap handoff URL") {
		t.Fatalf("noncanonical Linux bootstrap handoff URL returned %v", err)
	}
}

func TestFleetHealthEndpointIsAuthenticatedReadOnlyAndSecretFree(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "health-api", CIDR: "10.93.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	beforeAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("h", 43)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _, _ := newTestHTTPServer(t, service, token, false, logger, nil)

	response, err := server.Client().Get(server.URL + "/api/v1/networks/" + network.ID + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated fleet health status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/networks/"+network.ID+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("fleet health status=%d cache=%q type=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("Content-Type"), body)
	}
	var report control.FleetHealthReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Network.ID != network.ID || report.Summary.Overall != control.FleetHealthCritical || len(report.Alerts) != 1 || report.Alerts[0].Code != "lighthouse_unavailable" {
		t.Fatalf("unexpected fleet health response: %#v", report)
	}
	for _, forbidden := range []string{"ca_certificate", "encrypted_ca_key", "certificate_fingerprint", "sha256", "last_error"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("fleet health response exposed forbidden field %q: %s", forbidden, body)
		}
	}
	afterAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterAudit, beforeAudit) {
		t.Fatalf("fleet health read changed audit history: before=%#v after=%#v", beforeAudit, afterAudit)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/networks/"+network.ID+"/health?window=1h", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported fleet health query returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/networks/missing-network/health", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown fleet health network returned %d", response.StatusCode)
	}
}

func TestCreateNodeEndpointPersistsTopologyApartFromSecurityGroups(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := make([]byte, 32)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'P'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "placed-api", CIDR: "10.96.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("p", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	body := `{"name":"lh-placed","site":" AWS-USE1 ","failure_domain":" AZ-A ","groups":["infra"],"routed_subnets":["192.168.96.0/24"],"role":"lighthouse","public_endpoint":"198.51.100.96:4242"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/networks/"+network.ID+"/nodes", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var created control.CreatedNode
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || created.Node.Site != "aws-use1" || created.Node.FailureDomain != "az-a" || !reflect.DeepEqual(created.Node.Groups, []string{"all", "infra"}) || !reflect.DeepEqual(created.Node.RoutedSubnets, []string{"192.168.96.0/24"}) {
		t.Fatalf("unexpected topology node response status=%d node=%#v", response.StatusCode, created.Node)
	}
	_ = response.Body.Close()
	request, err = http.NewRequest(http.MethodPut, server.URL+"/api/v1/nodes/"+created.Node.ID+"/topology", strings.NewReader(`{"site":"gcp-use1","failure_domain":"gcp-use1-b"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var moved control.Node
	if err := json.NewDecoder(response.Body).Decode(&moved); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || moved.Site != "gcp-use1" || moved.FailureDomain != "gcp-use1-b" {
		t.Fatalf("unexpected topology update status=%d cache=%q node=%#v", response.StatusCode, response.Header.Get("Cache-Control"), moved)
	}
}

func TestNetworkDNSEndpointsRequireExactVersionedLifecycle(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x45}, 32)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'D'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureCARotationSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "dns-api", CIDR: "10.97.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("d", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	request := func(method, suffix, body string) *http.Response {
		t.Helper()
		req, requestErr := http.NewRequest(method, server.URL+"/api/v1/networks/"+network.ID+"/dns"+suffix, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}

	response := request(http.MethodGet, "", "")
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("initial DNS GET status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	var initial control.NetworkDNSDocument
	if err := json.NewDecoder(response.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if initial.Schema != control.NetworkDNSDocumentSchema || initial.Enabled || initial.ListenPort != control.DefaultNetworkDNSPort || initial.NativeResolver || initial.SearchDomain != "" || initial.ConfigRevision != network.ConfigRevision || !initial.FirewallReady || initial.Resolvers == nil {
		t.Fatalf("unexpected initial DNS document: %#v", initial)
	}

	body := fmt.Sprintf(`{"expected_config_revision":%d,"enabled":true,"listen_port":5353,"native_resolver":true,"search_domain":"corp.mesh"}`, initial.ConfigRevision)
	response = request(http.MethodPut, "", body)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		payload, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("DNS PUT status=%d cache=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), payload)
	}
	var enabled control.NetworkDNSDocument
	if err := json.NewDecoder(response.Body).Decode(&enabled); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !enabled.Enabled || enabled.ListenPort != 5353 || !enabled.NativeResolver || enabled.SearchDomain != "corp.mesh" || enabled.ConfigRevision != initial.ConfigRevision+1 || !enabled.FirewallReady || enabled.Resolvers == nil {
		t.Fatalf("unexpected enabled DNS document: %#v", enabled)
	}

	response = request(http.MethodPut, "", strings.TrimSuffix(body, "}")+`,"unexpected":true}`)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("DNS endpoint accepted an unknown field: %d", response.StatusCode)
	}
	response = request(http.MethodGet, "?unexpected=1", "")
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("DNS endpoint accepted a query string: %d", response.StatusCode)
	}
}

func TestNetworkRelayEndpointsRequireExactVersionedLifecycle(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x46}, 32)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'E'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "relay-api", CIDR: "10.98.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "relay-api-node"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("e", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	request := func(method, suffix, body string) *http.Response {
		t.Helper()
		req, requestErr := http.NewRequest(method, server.URL+"/api/v1/networks/"+network.ID+"/relays"+suffix, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}

	response := request(http.MethodGet, "", "")
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("initial relays GET status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	var initial control.NetworkRelaysDocument
	if err := json.NewDecoder(response.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if initial.Schema != control.NetworkRelaysDocumentSchema || initial.Enabled || initial.RelayNodeIDs == nil || initial.ActiveRelays == nil || initial.MaxRelayNodes != control.MaxNetworkRelayNodes || initial.ConfigRevision != network.ConfigRevision {
		t.Fatalf("unexpected initial relays document: %#v", initial)
	}

	body := fmt.Sprintf(`{"expected_config_revision":%d,"enabled":true,"relay_node_ids":[%q]}`, initial.ConfigRevision, relay.Node.ID)
	response = request(http.MethodPut, "", body)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		payload, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("relays PUT status=%d cache=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), payload)
	}
	var enabled control.NetworkRelaysDocument
	if err := json.NewDecoder(response.Body).Decode(&enabled); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !enabled.Enabled || !slices.Equal(enabled.RelayNodeIDs, []string{relay.Node.ID}) || len(enabled.ActiveRelays) != 0 || enabled.ConfigRevision != initial.ConfigRevision+1 {
		t.Fatalf("unexpected enabled relays document: %#v", enabled)
	}

	response = request(http.MethodPut, "", strings.TrimSuffix(body, "}")+`,"unexpected":true}`)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("relays endpoint accepted an unknown field: %d", response.StatusCode)
	}
	response = request(http.MethodPut, "", fmt.Sprintf(`{"expected_config_revision":%d,"enabled":false}`, enabled.ConfigRevision))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("relays endpoint accepted a missing relay_node_ids array: %d", response.StatusCode)
	}
	response = request(http.MethodGet, "?unexpected=1", "")
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("relays endpoint accepted a query string: %d", response.StatusCode)
	}
}

func TestNetworkReadinessEndpointIsAuthenticatedReadOnlyAndEvidenceScoped(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "readiness-api", CIDR: "10.92.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "public-lighthouse", Role: "lighthouse", PublicEndpoint: "198.51.100.40:4242"})
	if err != nil {
		t.Fatal(err)
	}
	beforeAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("r", 43)
	server, apiServer, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if capacity := cap(apiServer.networkReadinessSlots); capacity != maxConcurrentNetworkReadinessRequests {
		t.Fatalf("network readiness capacity=%d, want %d", capacity, maxConcurrentNetworkReadinessRequests)
	}

	path := "/api/v1/networks/" + network.ID + "/readiness"
	response, err := server.Client().Get(server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated readiness status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("readiness status=%d cache=%q type=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("Content-Type"), body)
	}
	var report control.NetworkReadinessReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != control.NetworkReadinessSchemaV6 || report.Network.ID != network.ID || report.Overall != control.NetworkReadinessOverallBlocked || report.Checks.LighthouseRedundancy.Status != control.NetworkReadinessBlocked || report.Checks.ManagedRouteOverlap.Status != control.NetworkReadinessPass || report.Checks.ClientRouteOverlap.Status != control.NetworkReadinessUnknown || report.Checks.MemberDNSResolution.Status != control.NetworkReadinessUnknown || report.Checks.PublicUDPReachability.Status != control.NetworkReadinessUnknown {
		t.Fatalf("unexpected readiness response: %#v", report)
	}
	if len(report.Lighthouses) != 1 || report.Lighthouses[0].ID != created.Node.ID || report.Lighthouses[0].PublicEndpoint != "198.51.100.40:4242" || report.Lighthouses[0].DNSResolution != "not_applicable" {
		t.Fatalf("unexpected readiness lighthouse evidence: %#v", report.Lighthouses)
	}
	for _, forbidden := range []string{"ca_certificate", "encrypted_ca_key", "certificate_fingerprint", "agent_token", "enrollment_token", "last_error"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("readiness response exposed forbidden field %q: %s", forbidden, body)
		}
	}
	afterAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterAudit, beforeAudit) {
		t.Fatalf("readiness read changed audit history: before=%#v after=%#v", beforeAudit, afterAudit)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+path+"?probe=udp", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("readiness query status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/networks/missing/readiness", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown readiness network returned %d", response.StatusCode)
	}
}

func TestNetworkReadinessCorrelatesRuntimeProbeAndDegradesOnReplayOrStoreFailure(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "readiness-runtime", CIDR: "10.90.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	lighthouse, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "public-lighthouse", Role: "lighthouse", PublicEndpoint: "198.51.100.90:4242"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "external-member", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	lighthouseToken := strings.Repeat("l", 42) + "A"
	lighthouseBundle, err := service.Enroll(context.Background(), lighthouse.EnrollmentToken, testNebulaPublicKey('L'), control.HashToken(lighthouseToken))
	if err != nil {
		t.Fatal(err)
	}
	memberToken := strings.Repeat("m", 42) + "A"
	bundle, err := service.Enroll(context.Background(), member.EnrollmentToken, testNebulaPublicKey('M'), control.HashToken(memberToken))
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := control.HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3",
		AppliedConfigRevision: bundle.ConfigRevision, AppliedConfigSHA256: bundle.ConfigSHA256,
		CertificateFingerprint: bundle.CertificateFingerprint, CertificateGeneration: bundle.CertificateGeneration,
		NebulaRunning: true, Status: "healthy", BootID: "boot-readiness", Sequence: 1,
	}
	if _, err := service.Heartbeat(memberToken, heartbeat); err != nil {
		t.Fatalf("accept member heartbeat: %v", err)
	}
	lighthouseHeartbeat := heartbeat
	lighthouseHeartbeat.AppliedConfigRevision = lighthouseBundle.ConfigRevision
	lighthouseHeartbeat.AppliedConfigSHA256 = lighthouseBundle.ConfigSHA256
	lighthouseHeartbeat.CertificateFingerprint = lighthouseBundle.CertificateFingerprint
	lighthouseHeartbeat.CertificateGeneration = lighthouseBundle.CertificateGeneration
	lighthouseHeartbeat.BootID = "boot-readiness-lighthouse"
	if _, err := service.Heartbeat(lighthouseToken, lighthouseHeartbeat); err != nil {
		t.Fatalf("accept lighthouse heartbeat: %v", err)
	}

	receivedAt := time.Now().UTC()
	telemetryStore := runtimetelemetry.NewMemoryStore()
	adminToken := strings.Repeat("a", 43)
	server, _, _ := newTestHTTPServerWithRuntimeTelemetry(
		t, service, adminToken, false, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() time.Time { return receivedAt }, telemetryStore,
	)
	zero := uint64(0)
	probe := runtimetelemetry.ActiveProbeResult{
		Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
		SampleAgeMS: &zero, Attempted: 1, Replied: 1, DurationMS: 25,
	}
	input := runtimetelemetry.ReportInput{
		HeartbeatSequence: 1,
		Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV2, State: runtimetelemetry.StateUnknown},
		ActiveProbe:       &probe,
		RouteOverlap: func() *runtimetelemetry.RouteOverlapResult {
			value := runtimetelemetry.ObservedRouteOverlap(false)
			return &value
		}(),
		EndpointDNS: func() *runtimetelemetry.EndpointDNSResult {
			value := runtimetelemetry.ObservedEndpointDNS(0, 0)
			return &value
		}(),
	}
	response := postRuntimeTelemetry(t, server, memberToken, input)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("runtime probe report returned %d", response.StatusCode)
	}
	lighthouseInput := runtimetelemetry.ReportInput{
		HeartbeatSequence: 1,
		Observation:       runtimetelemetry.Observation{Version: runtimetelemetry.VersionV2, State: runtimetelemetry.StateUnknown},
		RouteOverlap: func() *runtimetelemetry.RouteOverlapResult {
			value := runtimetelemetry.ObservedRouteOverlap(false)
			return &value
		}(),
	}
	response = postRuntimeTelemetry(t, server, lighthouseToken, lighthouseInput)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("lighthouse route report returned %d", response.StatusCode)
	}

	read := func() control.NetworkReadinessReport {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodGet, server.URL+"/api/v1/networks/"+network.ID+"/readiness", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+adminToken)
		readResponse, requestErr := server.Client().Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		body, readErr := io.ReadAll(readResponse.Body)
		_ = readResponse.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if readResponse.StatusCode != http.StatusOK {
			t.Fatalf("readiness returned %d: %s", readResponse.StatusCode, body)
		}
		var report control.NetworkReadinessReport
		if err := json.Unmarshal(body, &report); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"target_ip", "local_ip", "plan_sha256", "nonce", "packet", "socket_error", "interface_name", "route_prefix", "gateway", "route_table"} {
			if bytes.Contains(body, []byte(`"`+forbidden+`"`)) {
				t.Fatalf("readiness response exposed forbidden probe field %q: %s", forbidden, body)
			}
		}
		return report
	}

	report := read()
	udp := report.Checks.PublicUDPReachability
	if udp.Status != control.NetworkReadinessPass || udp.EvidenceSource != "authenticated_member_active_probe" || udp.ObservedMembers != 1 || udp.RequiredMembers != 1 || udp.VerifiedLighthouses != 1 || udp.RequiredLighthouses != 1 || udp.EvidenceAt == nil {
		t.Fatalf("fresh runtime evidence did not pass: %#v", udp)
	}
	routes := report.Checks.ClientRouteOverlap
	if routes.Status != control.NetworkReadinessPass || routes.EvidenceSource != "authenticated_node_route_inventory" || routes.ObservedNodes != 2 || routes.RequiredNodes != 2 || routes.OverlappingNodes != 0 || routes.EvidenceAt == nil {
		t.Fatalf("fresh route evidence did not pass: %#v", routes)
	}
	memberDNS := report.Checks.MemberDNSResolution
	if memberDNS.Status != control.NetworkReadinessPass || memberDNS.EvidenceSource != "authenticated_member_dns_resolution" || memberDNS.ObservedMembers != 1 || memberDNS.RequiredMembers != 1 || memberDNS.FailingMembers != 0 || memberDNS.DNSNames != 0 || memberDNS.EvidenceAt == nil {
		t.Fatalf("fresh member DNS evidence did not pass: %#v", memberDNS)
	}

	// Advance the authoritative lifecycle sequence without replacing runtime
	// evidence. This models the state immediately after a newer heartbeat and
	// before its corresponding runtime report, while avoiding a wall-clock wait
	// for the independent heartbeat rate-limit test.
	if err := store.Update(func(state *control.State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID == bundle.Node.ID {
				state.Nodes[index].HeartbeatSequence = 2
				return nil
			}
		}
		return errors.New("test member disappeared")
	}); err != nil {
		t.Fatal(err)
	}
	report = read()
	if udp = report.Checks.PublicUDPReachability; udp.Status != control.NetworkReadinessUnknown || udp.EvidenceSource != "not_observed" || udp.ObservedMembers != 0 || udp.VerifiedLighthouses != 0 || udp.EvidenceAt != nil {
		t.Fatalf("older-sequence evidence survived a heartbeat: %#v", udp)
	}
	if routes = report.Checks.ClientRouteOverlap; routes.Status != control.NetworkReadinessUnknown || routes.EvidenceSource != "not_observed" || routes.ObservedNodes != 0 || routes.OverlappingNodes != 0 || routes.EvidenceAt != nil {
		t.Fatalf("older-sequence route evidence survived a heartbeat: %#v", routes)
	}
	if memberDNS = report.Checks.MemberDNSResolution; memberDNS.Status != control.NetworkReadinessUnknown || memberDNS.EvidenceSource != "not_observed" || memberDNS.ObservedMembers != 0 || memberDNS.FailingMembers != 0 || memberDNS.EvidenceAt != nil {
		t.Fatalf("older-sequence member DNS evidence survived a heartbeat: %#v", memberDNS)
	}

	receivedAt = time.Now().UTC()
	input.HeartbeatSequence = 2
	response = postRuntimeTelemetry(t, server, memberToken, input)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("replacement runtime probe report returned %d", response.StatusCode)
	}
	report = read()
	if udp = report.Checks.PublicUDPReachability; udp.Status != control.NetworkReadinessPass || udp.ObservedMembers != 1 || udp.VerifiedLighthouses != 1 {
		t.Fatalf("new current evidence did not recover readiness: %#v", udp)
	}
	if routes = report.Checks.ClientRouteOverlap; routes.Status != control.NetworkReadinessPass || routes.ObservedNodes != 2 || routes.OverlappingNodes != 0 {
		t.Fatalf("new current route evidence did not recover readiness: %#v", routes)
	}
	if memberDNS = report.Checks.MemberDNSResolution; memberDNS.Status != control.NetworkReadinessPass || memberDNS.ObservedMembers != 1 || memberDNS.FailingMembers != 0 {
		t.Fatalf("new current member DNS evidence did not recover readiness: %#v", memberDNS)
	}

	// Runtime storage is supporting evidence, not authoritative control state.
	// Losing it must preserve an authenticated readiness response but return
	// UDP to unknown instead of serving a stale success or failing the report.
	if err := telemetryStore.Close(); err != nil {
		t.Fatal(err)
	}
	report = read()
	if udp = report.Checks.PublicUDPReachability; udp.Status != control.NetworkReadinessUnknown || udp.EvidenceSource != "not_observed" || udp.EvidenceAt != nil {
		t.Fatalf("closed runtime store retained UDP evidence: %#v", udp)
	}
	if routes = report.Checks.ClientRouteOverlap; routes.Status != control.NetworkReadinessUnknown || routes.EvidenceSource != "not_observed" || routes.EvidenceAt != nil {
		t.Fatalf("closed runtime store retained route evidence: %#v", routes)
	}
	if memberDNS = report.Checks.MemberDNSResolution; memberDNS.Status != control.NetworkReadinessUnknown || memberDNS.EvidenceSource != "not_observed" || memberDNS.EvidenceAt != nil {
		t.Fatalf("closed runtime store retained member DNS evidence: %#v", memberDNS)
	}
}

func TestFleetHealthCollectionEndpointIsOneContractAuthenticatedAndReadOnly(t *testing.T) {
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
	for _, input := range []control.CreateNetworkInput{
		{Name: "zeta-health", CIDR: "10.95.0.0/24"},
		{Name: "alpha-health", CIDR: "10.94.0.0/24"},
	} {
		if _, err := service.CreateNetwork(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	beforeAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("f", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	response, err := server.Client().Get(server.URL + "/api/v1/fleet/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated collection status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("collection status=%d cache=%q type=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("Content-Type"), body)
	}
	var collection control.FleetHealthCollection
	if err := json.Unmarshal(body, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Networks) != 2 || collection.Networks[0].Network.Name != "alpha-health" || collection.Networks[1].Network.Name != "zeta-health" || collection.Networks[0].Network.CIDR != "10.94.0.0/24" || collection.Networks[0].Network.ListenPort != 4242 || collection.Summary.TotalNetworks != 2 || collection.Summary.CriticalNetworks != 2 || collection.Rollout.Percent != 100 {
		t.Fatalf("unexpected fleet collection: %#v", collection)
	}
	if bytes.Count(body, []byte(`"generated_at"`)) != 1 || bytes.Count(body, []byte(`"policy"`)) != 1 {
		t.Fatalf("collection repeated generated_at or policy: %s", body)
	}
	for _, forbidden := range []string{`"ca_certificate"`, `"encrypted_ca_key"`, `"certificate_fingerprint"`, `"sha256"`, `"last_error"`, `"certificate"`, `"firewall_policy"`, `"groups"`, `"public_endpoint"`, `"agent_version"`, `"nebula_version"`} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("fleet collection exposed forbidden field %q: %s", forbidden, body)
		}
	}
	afterAudit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterAudit, beforeAudit) {
		t.Fatalf("fleet collection changed audit history: before=%#v after=%#v", beforeAudit, afterAudit)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/health?window=5m", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("collection query status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}

func TestFleetHealthCollectionEndpointSanitizesAgentControlledStrings(t *testing.T) {
	now := time.Now().UTC()
	enrolledAt := now.Add(-time.Hour)
	lastSeenAt := now.Add(-time.Minute)
	certificateExpiresAt := now.Add(90 * 24 * time.Hour)
	certificateRenewAfter := now.Add(30 * 24 * time.Hour)
	credentialExpiresAt := now.Add(60 * 24 * time.Hour)
	network := control.Network{
		ID: "network-agent-strings", Name: "agent-strings", CIDR: "10.96.0.0/24", ListenPort: 4242,
		ConfigRevision: 2, ConfigUpdatedAt: now.Add(-time.Hour),
	}
	fingerprint := strings.Repeat("a", 64)
	backend := &httpHealthStateStore{state: control.State{
		Networks: []control.Network{network},
		Nodes: []control.Node{{
			ID: "node-agent-strings", NetworkID: network.ID, Name: "agent-strings", IP: "10.96.0.10", Role: "member", Status: "active",
			EnrolledAt: &enrolledAt, LastSeenAt: &lastSeenAt, NebulaRunning: true,
			AgentVersion: "HTTP-RAW-AGENT-VERSION-MUST-NOT-LEAK", NebulaVersion: "HTTP-RAW-NEBULA-VERSION-MUST-NOT-LEAK",
			AgentStatus: "HTTP-RAW-STATUS-MUST-NOT-LEAK", LastError: "HTTP-RAW-ERROR-MUST-NOT-LEAK",
			AppliedConfigRevision: network.ConfigRevision, AppliedConfigSHA256: "HTTP-RAW-DIGEST-MUST-NOT-LEAK",
			CertificateGeneration: 1, AppliedCertificateGeneration: 1,
			CertificateFingerprint: fingerprint, ReportedCertificateFingerprint: fingerprint,
			CertificateExpiresAt: &certificateExpiresAt, CertificateRenewAfter: &certificateRenewAfter,
			AgentCredentialExpiresAt: &credentialExpiresAt,
		}},
	}}
	service, err := control.NewServiceWithStateStore(backend, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("v", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || backend.viewCalls != 1 || backend.updateCalls != 0 {
		t.Fatalf("agent-string collection status=%d views=%d updates=%d body=%s", response.StatusCode, backend.viewCalls, backend.updateCalls, body)
	}
	for _, forbidden := range []string{
		`"agent_version"`, `"nebula_version"`,
		"HTTP-RAW-AGENT-VERSION-MUST-NOT-LEAK", "HTTP-RAW-NEBULA-VERSION-MUST-NOT-LEAK",
		"HTTP-RAW-STATUS-MUST-NOT-LEAK", "HTTP-RAW-ERROR-MUST-NOT-LEAK", "HTTP-RAW-DIGEST-MUST-NOT-LEAK",
	} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("fleet collection exposed agent-controlled value %q: %s", forbidden, body)
		}
	}
	var collection control.FleetHealthCollection
	if err := json.Unmarshal(body, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Networks) != 1 || len(collection.Networks[0].Nodes) != 1 {
		t.Fatalf("unexpected agent-string collection: %#v", collection)
	}
	projected := collection.Networks[0].Nodes[0]
	if projected.AgentStatus != "" || projected.Operational || projected.Severity != control.FleetHealthCritical {
		t.Fatalf("unknown agent status did not fail closed: %#v", projected)
	}
	foundTelemetryInvalid := false
	for _, alert := range projected.Alerts {
		if alert.Code == "telemetry_invalid" && alert.Severity == control.FleetHealthCritical && alert.Scope == "node" {
			foundTelemetryInvalid = true
		}
	}
	if !foundTelemetryInvalid {
		t.Fatalf("unknown agent status lacks generic telemetry alert: %#v", projected.Alerts)
	}
}

func TestFleetHealthConcurrencyLimitIsSharedAndReleases(t *testing.T) {
	now := time.Now().UTC()
	network := control.Network{
		ID: "network-health-limit", Name: "health-limit", CIDR: "10.97.0.0/24", ListenPort: 4242,
		ConfigRevision: 1, ConfigUpdatedAt: now.Add(-time.Hour),
	}
	const privateFailure = "private fleet projection failure"
	tests := []struct {
		name         string
		holderPath   string
		blockedPath  string
		firstErr     error
		holderStatus int
	}{
		{
			name: "collection failure releases for per-network route", holderPath: "/api/v1/fleet/health",
			blockedPath: "/api/v1/networks/" + network.ID + "/health", firstErr: errors.New(privateFailure), holderStatus: http.StatusInternalServerError,
		},
		{
			name: "per-network success releases for collection route", holderPath: "/api/v1/networks/" + network.ID + "/health",
			blockedPath: "/api/v1/fleet/health", holderStatus: http.StatusOK,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newBlockingHTTPHealthStateStore(control.State{Networks: []control.Network{network}}, test.firstErr)
			t.Cleanup(backend.releaseFirst)
			service, err := control.NewServiceWithStateStore(backend, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("q", 43)
			server, apiServer, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			if capacity := cap(apiServer.fleetHealthSlots); capacity != maxConcurrentFleetHealthRequests {
				t.Fatalf("fleet health capacity=%d, want %d", capacity, maxConcurrentFleetHealthRequests)
			}
			// One slot makes both directions deterministic while exercising the exact
			// shared gate installed on the production routes.
			apiServer.fleetHealthSlots = make(chan struct{}, 1)

			type result struct {
				status int
				header http.Header
				body   []byte
				err    error
			}
			do := func(path string) result {
				request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
				if err != nil {
					return result{err: err}
				}
				request.Header.Set("Authorization", "Bearer "+token)
				response, err := server.Client().Do(request)
				if err != nil {
					return result{err: err}
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				return result{status: response.StatusCode, header: response.Header, body: body, err: readErr}
			}

			holder := make(chan result, 1)
			go func() { holder <- do(test.holderPath) }()
			select {
			case <-backend.started:
			case <-time.After(5 * time.Second):
				t.Fatal("first fleet health request did not enter the projection")
			}

			blocked := do(test.blockedPath)
			if blocked.err != nil {
				t.Fatal(blocked.err)
			}
			if blocked.status != http.StatusServiceUnavailable || blocked.header.Get("Retry-After") != "1" || blocked.header.Get("Cache-Control") != "no-store" || string(blocked.body) != "{\"error\":\"fleet health is temporarily unavailable\"}\n" {
				t.Fatalf("saturated shared gate status=%d retry=%q cache=%q body=%q", blocked.status, blocked.header.Get("Retry-After"), blocked.header.Get("Cache-Control"), blocked.body)
			}
			if bytes.Contains(blocked.body, []byte(privateFailure)) || backend.viewCalls.Load() != 1 {
				t.Fatalf("saturated request leaked or entered projection: views=%d body=%q", backend.viewCalls.Load(), blocked.body)
			}

			backend.releaseFirst()
			var held result
			select {
			case held = <-holder:
			case <-time.After(5 * time.Second):
				t.Fatal("first fleet health request did not finish after release")
			}
			if held.err != nil || held.status != test.holderStatus || bytes.Contains(held.body, []byte(privateFailure)) {
				t.Fatalf("holder status=%d err=%v body=%q", held.status, held.err, held.body)
			}
			if occupied := len(apiServer.fleetHealthSlots); occupied != 0 {
				t.Fatalf("fleet health slot remained occupied after handler return: %d", occupied)
			}

			afterRelease := do(test.blockedPath)
			if afterRelease.err != nil || afterRelease.status != http.StatusOK {
				t.Fatalf("released route status=%d err=%v body=%q", afterRelease.status, afterRelease.err, afterRelease.body)
			}
		})
	}
}

type blockingHTTPHealthStateStore struct {
	state       control.State
	firstErr    error
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
	viewCalls   atomic.Int32
}

func newBlockingHTTPHealthStateStore(state control.State, firstErr error) *blockingHTTPHealthStateStore {
	return &blockingHTTPHealthStateStore{state: state, firstErr: firstErr, started: make(chan struct{}), release: make(chan struct{})}
}

func (s *blockingHTTPHealthStateStore) releaseFirst() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *blockingHTTPHealthStateStore) View(fn func(control.State) error) error {
	call := s.viewCalls.Add(1)
	if call == 1 {
		s.startedOnce.Do(func() { close(s.started) })
		<-s.release
		if s.firstErr != nil {
			return s.firstErr
		}
	}
	return fn(s.state)
}

func (s *blockingHTTPHealthStateStore) Update(fn func(*control.State) error) error {
	return fn(&s.state)
}

type httpHealthStateStore struct {
	state       control.State
	viewCalls   int
	updateCalls int
}

func (s *httpHealthStateStore) View(fn func(control.State) error) error {
	s.viewCalls++
	return fn(s.state)
}

func (s *httpHealthStateStore) Update(fn func(*control.State) error) error {
	s.updateCalls++
	return fn(&s.state)
}

func TestSecurityHeadersAndHealth(t *testing.T) {
	server := testServer(t, strings.Repeat("b", 43))
	defer server.Close()
	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("unexpected health response: status=%d headers=%v", response.StatusCode, response.Header)
	}
}

func TestReadinessEndpointIsDependencyBackedGenericAndNotCached(t *testing.T) {
	secret := "private storage diagnostic"
	tests := []struct {
		name       string
		check      func(context.Context) error
		wantStatus int
		wantBody   string
	}{
		{name: "ready", check: func(context.Context) error { return nil }, wantStatus: http.StatusOK, wantBody: "{\"status\":\"ready\"}\n"},
		{name: "failed", check: func(context.Context) error { return errors.New(secret) }, wantStatus: http.StatusServiceUnavailable, wantBody: "{\"status\":\"unavailable\"}\n"},
		{name: "missing", check: nil, wantStatus: http.StatusServiceUnavailable, wantBody: "{\"status\":\"unavailable\"}\n"},
		{name: "panic", check: func(context.Context) error { panic(secret) }, wantStatus: http.StatusServiceUnavailable, wantBody: "{\"status\":\"unavailable\"}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			box, err := control.NewSecretBox(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			service := control.NewService(store, box, control.NebulaIssuer{})
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, _, _ := newTestHTTPServerWithReadiness(t, service, strings.Repeat("r", 43), false, logger, nil, test.check)

			response, err := server.Client().Get(server.URL + "/readyz")
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != test.wantStatus || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" || string(body) != test.wantBody {
				t.Fatalf("GET readiness status=%d cache=%q type=%q body=%q", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("Content-Type"), body)
			}
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("readiness response leaked an internal diagnostic")
			}

			request, err := http.NewRequest(http.MethodHead, server.URL+"/readyz", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err = server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr = io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != test.wantStatus || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" || len(body) != 0 {
				t.Fatalf("HEAD readiness status=%d cache=%q type=%q body=%q", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("Content-Type"), body)
			}

			response, err = server.Client().Get(server.URL + "/healthz")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("dependency failure changed liveness status to %d", response.StatusCode)
			}
		})
	}
}

func TestDashboardIsEmbedded(t *testing.T) {
	server := testServer(t, strings.Repeat("c", 43))
	defer server.Close()
	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(body.String(), "Nebula control plane") {
		t.Fatalf("dashboard was not served: status=%d", response.StatusCode)
	}
}

func TestPendingEnrollmentReissueRequiresAdminCSRFAndIsNotCached(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "reissue", CIDR: "10.89.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "pending-01"})
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("w", 43)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/nodes/" + created.Node.ID + "/enrollment/reissue"

	request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated reissue returned %d", response.StatusCode)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"token": adminToken})
	response, err = postTestLogin(client, server.URL, loginBody)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie reissue without CSRF returned %d", response.StatusCode)
	}
	var csrf string
	for _, cookie := range jar.Cookies(request.URL) {
		if cookie.Name == "mesh_csrf" {
			csrf = cookie.Value
		}
	}
	request, _ = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var reissued control.ReissuedEnrollment
	if err := json.NewDecoder(response.Body).Decode(&reissued); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("CSRF-authenticated reissue status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	if reissued.Node.ID != created.Node.ID || reissued.EnrollmentToken == "" || reissued.EnrollmentToken == created.EnrollmentToken {
		t.Fatalf("unexpected reissue response: %#v", reissued)
	}

	// CLI-style admin bearer authentication does not use a browser CSRF
	// cookie, but it still passes through the same admin middleware.
	request, _ = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin bearer reissue returned %d", response.StatusCode)
	}
}

func TestPendingEnrollmentCancellationIsStrictAttributedAndNotCached(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "cancel-api", CIDR: "10.88.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "pending-api", RoutedSubnets: []string{"192.168.88.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "active-api"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, testNebulaPublicKey('X'), control.HashToken(strings.Repeat("x", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("q", 43)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/nodes/" + pending.Node.ID + "/enrollment/cancel"
	body, _ := json.Marshal(control.CancelPendingNodeInput{ConfirmationName: pending.Node.Name})

	request, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated cancellation returned %d", response.StatusCode)
	}

	for _, rejected := range []struct {
		path string
		body string
		want int
	}{
		{path: endpoint + "?confirm=true", body: string(body), want: http.StatusBadRequest},
		{path: endpoint, body: `{"confirmation_name":"Pending-API"}`, want: http.StatusConflict},
		{path: endpoint, body: `{"confirmation_name":"pending-api","extra":true}`, want: http.StatusBadRequest},
	} {
		request, _ = http.NewRequest(http.MethodPost, rejected.path, strings.NewReader(rejected.body))
		request.Header.Set("Authorization", "Bearer "+adminToken)
		request.Header.Set("Content-Type", "application/json")
		response, err = http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != rejected.want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("rejected cancellation status=%d cache=%q, want %d", response.StatusCode, response.Header.Get("Cache-Control"), rejected.want)
		}
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("rejected cancellation changed inventory: nodes=%#v err=%v", nodes, err)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var receipt control.CancelledPendingNode
	if err := json.NewDecoder(response.Body).Decode(&receipt); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cancellation status=%d cache=%q receipt=%#v", response.StatusCode, response.Header.Get("Cache-Control"), receipt)
	}
	if receipt.NodeID != pending.Node.ID || receipt.NetworkID != network.ID || receipt.Name != pending.Node.Name || receipt.IP != pending.Node.IP || receipt.Role != pending.Node.Role || receipt.EnrollmentRecordsInvalidated != 1 || receipt.RelayAssignmentRemoved || receipt.RoutedSubnetReservationsReleased != 1 || receipt.ConfigRevision != network.ConfigRevision {
		t.Fatalf("unexpected cancellation receipt: %#v", receipt)
	}
	if _, err := service.PreflightEnrollment(pending.EnrollmentToken); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("cancelled API credential remained usable: %v", err)
	}
	nodes, err = service.Nodes(network.ID)
	if err != nil || len(nodes) != 1 || nodes[0].ID != active.Node.ID || nodes[0].Status != "active" {
		t.Fatalf("cancellation changed the wrong inventory: nodes=%#v err=%v", nodes, err)
	}
	events, err := service.Audit(10)
	if err != nil {
		t.Fatal(err)
	}
	var last control.AuditEvent
	for _, event := range events {
		if event.Action == "node.pending_cancelled" && event.ResourceID == pending.Node.ID {
			last = event
			break
		}
	}
	legacy := control.LegacyAdminActor()
	if last.Action != "node.pending_cancelled" || last.ResourceID != pending.Node.ID || last.Details["actor_id"] != legacy.ID || last.Details["actor_kind"] != legacy.Kind {
		t.Fatalf("cancellation audit is missing attribution: %#v", last)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("repeated cancellation status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	activeEndpoint := server.URL + "/api/v1/nodes/" + active.Node.ID + "/enrollment/cancel"
	activeBody, _ := json.Marshal(control.CancelPendingNodeInput{ConfirmationName: active.Node.Name})
	request, _ = http.NewRequest(http.MethodPost, activeEndpoint, bytes.NewReader(activeBody))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("active-node cancellation status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}

func TestAgentRecoveryAdminIssueAndUnauthenticatedSignedExchange(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "agent-recovery", CIDR: "10.87.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "recoverable-01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('X')
	oldAgentToken := strings.Repeat("4", 42) + "A"
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, control.HashToken(oldAgentToken)); err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("5", 42) + "A"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	issueEndpoint := server.URL + "/api/v1/nodes/" + created.Node.ID + "/agent-recovery"

	request, _ := http.NewRequest(http.MethodPost, issueEndpoint, strings.NewReader(`{}`))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated recovery issue returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, issueEndpoint, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var issued control.IssuedAgentRecovery
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" || !control.ValidBearerToken(issued.RecoveryToken) {
		t.Fatalf("agent recovery issue status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), issued)
	}

	newAgentToken := strings.Repeat("6", 42) + "A"
	recoverBody, _ := json.Marshal(control.RecoverAgentInput{
		RecoveryToken: issued.RecoveryToken, PublicKey: publicKey, NewAgentTokenHash: control.HashToken(newAgentToken),
	})
	response, err = http.Post(server.URL+"/api/v1/agent/recover", "application/json", bytes.NewReader(recoverBody))
	if err != nil {
		t.Fatal(err)
	}
	var recovered control.AgentRecoveryBundle
	if err := json.NewDecoder(response.Body).Decode(&recovered); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("agent recovery status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	if recovered.RecoveryReceipt.NewAgentTokenHash != control.HashToken(newAgentToken) || recovered.RecoveryReceipt.ConfigSHA256 != recovered.ConfigSHA256 || recovered.RecoveryReceipt.ConfigSignature != recovered.ConfigSignature {
		t.Fatalf("HTTP recovery receipt is not linked to bootstrap: %#v", recovered)
	}
	if err := control.VerifyConfig(recovered.ConfigSigningPublicKey, recovered.SignatureMetadata(), recovered.Config, recovered.ConfigSHA256, recovered.ConfigSignature); err != nil {
		t.Fatalf("verify HTTP recovery bootstrap: %v", err)
	}
	if err := control.VerifyRecoveryReceipt(recovered.ConfigSigningPublicKey, recovered.RecoveryReceipt); err != nil {
		t.Fatalf("verify HTTP recovery receipt: %v", err)
	}

	// The agent endpoint is authorized by the recovery token in the JSON body,
	// not by an existing (lost) Authorization bearer.
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/recover", bytes.NewReader([]byte(`{"recovery_token":"bad","public_key":"bad","new_agent_token_hash":"bad"}`)))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid recovery request returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}

func TestNodeIdentityReplacementRequiresAdminAndStrictRevisionedJSON(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "identity-replacement", CIDR: "10.88.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "lost-key-node", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	oldAgentToken := strings.Repeat("7", 42) + "A"
	enrolled, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('L'), control.HashToken(oldAgentToken))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("8", 42) + "A"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/nodes/" + created.Node.ID + "/replace"

	request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"expected_config_revision":1}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated identity replacement returned %d", response.StatusCode)
	}

	for name, test := range map[string]struct {
		endpoint string
		body     string
	}{
		"query":         {endpoint: endpoint + "?confirm=true", body: `{"expected_config_revision":1}`},
		"unknown field": {endpoint: endpoint, body: `{"expected_config_revision":1,"replacement_name":"other"}`},
		"multiple JSON": {endpoint: endpoint, body: `{"expected_config_revision":1}{}`},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, test.endpoint, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+adminToken)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("strict identity replacement returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
		})
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"expected_config_revision":999}`))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stale identity replacement returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 1 || nodes[0].Status != "active" {
		t.Fatalf("rejected identity replacements changed the active node: nodes=%#v err=%v", nodes, err)
	}

	body, _ := json.Marshal(control.ReplaceNodeInput{ExpectedConfigRevision: enrolled.ConfigRevision})
	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var replacement control.ReplacedNode
	if err := json.NewDecoder(response.Body).Decode(&replacement); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" || replacement.RevokedNodeID != created.Node.ID || replacement.Node.ID == created.Node.ID || replacement.Node.Status != "pending" || !control.ValidBearerToken(replacement.EnrollmentToken) || replacement.ConfigRevision != enrolled.ConfigRevision+1 {
		t.Fatalf("identity replacement status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), replacement)
	}
	if _, err := service.AgentConfig(oldAgentToken); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("replaced node's old agent token returned %v", err)
	}
	events, err := service.Audit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[0].Action != "node.identity_replacement_created" || events[1].Action != "node.revoked" {
		t.Fatalf("replacement audit events are missing: %#v", events)
	}
	legacy := control.LegacyAdminActor()
	for _, event := range events[:2] {
		if event.Details["actor_id"] != legacy.ID || event.Details["actor_kind"] != legacy.Kind {
			t.Fatalf("replacement audit actor is missing: %#v", event)
		}
	}
}

func TestRevokedNodeArchivalRequiresExactConfirmationAndCleansRuntimeTelemetry(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "archive-http", CIDR: "10.85.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "abandoned-node", RoutedSubnets: []string{"192.168.85.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	stillPending, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "still-pending"})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "active-node"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, testNebulaPublicKey('A'), control.HashToken(strings.Repeat("a", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeNode(target.Node.ID); err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("load archive revision: networks=%#v err=%v", networks, err)
	}
	expectedRevision := networks[0].ConfigRevision

	telemetry := runtimetelemetry.NewMemoryStore()
	if _, changed, err := telemetry.Put(target.Node.ID, 1, time.Now().UTC(), validRuntimeTelemetryObservation(), runtimetelemetry.UnsupportedActiveProbe()); err != nil || !changed {
		t.Fatalf("seed archived-node runtime telemetry: changed=%t err=%v", changed, err)
	}
	adminToken := strings.Repeat("p", 42) + "A"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServerWithRuntimeTelemetry(t, service, adminToken, false, logger, nil, telemetry)
	defer server.Close()
	endpoint := server.URL + "/api/v1/nodes/" + target.Node.ID + "/archive"
	body, _ := json.Marshal(control.ArchiveNodeInput{ExpectedConfigRevision: expectedRevision, ConfirmationName: target.Node.Name})

	request, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated archival returned %d", response.StatusCode)
	}

	for name, test := range map[string]struct {
		endpoint string
		body     string
		status   int
	}{
		"query":          {endpoint: endpoint + "?force=true", body: string(body), status: http.StatusBadRequest},
		"unknown field":  {endpoint: endpoint, body: fmt.Sprintf(`{"expected_config_revision":%d,"confirmation_name":"abandoned-node","force":true}`, expectedRevision), status: http.StatusBadRequest},
		"stale revision": {endpoint: endpoint, body: `{"expected_config_revision":1,"confirmation_name":"abandoned-node"}`, status: http.StatusConflict},
		"wrong name":     {endpoint: endpoint, body: fmt.Sprintf(`{"expected_config_revision":%d,"confirmation_name":"Abandoned-node"}`, expectedRevision), status: http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, test.endpoint, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+adminToken)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("rejected archival returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
		})
	}
	if nodes, err := service.Nodes(network.ID); err != nil || len(nodes) != 3 {
		t.Fatalf("rejected archival changed inventory: nodes=%#v err=%v", nodes, err)
	}
	if _, found, err := telemetry.Get(target.Node.ID); err != nil || !found {
		t.Fatalf("rejected archival changed runtime telemetry: found=%t err=%v", found, err)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var archived archivedNodeResponse
	if err := json.Unmarshal(responseBody, &archived); err != nil {
		t.Fatal(err)
	}
	var archivedFields map[string]json.RawMessage
	if err := json.Unmarshal(responseBody, &archivedFields); err != nil {
		t.Fatal(err)
	}
	expectedFields := []string{
		"node_id", "network_id", "name", "ip", "role", "revoked_at", "archived_at",
		"enrollment_records_removed", "agent_recovery_records_removed", "certificate_issuances_removed",
		"revocations_removed", "blocklist_entries_removed", "routed_subnet_reservations_released", "config_revision",
		"runtime_telemetry_record_removed", "runtime_telemetry_cleanup_complete",
	}
	if len(archivedFields) != len(expectedFields) {
		t.Fatalf("archival response schema=%s", responseBody)
	}
	for _, field := range expectedFields {
		if _, ok := archivedFields[field]; !ok {
			t.Fatalf("archival response omitted %q: %s", field, responseBody)
		}
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || archived.NodeID != target.Node.ID || archived.NetworkID != network.ID || archived.Name != target.Node.Name || archived.IP != target.Node.IP || archived.Role != target.Node.Role || archived.LastCertificateExpiredAt != nil || archived.EnrollmentRecordsRemoved != 1 || archived.AgentRecoveryRecordsRemoved != 0 || archived.CertificateIssuancesRemoved != 0 || archived.RevocationsRemoved != 0 || archived.BlocklistEntriesRemoved != 0 || archived.RoutedSubnetReservationsReleased != 1 || archived.ConfigRevision != expectedRevision || !archived.RuntimeTelemetryRecordRemoved || !archived.RuntimeTelemetryCleanupComplete {
		t.Fatalf("archival status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), archived)
	}
	if _, found, err := telemetry.Get(target.Node.ID); err != nil || found {
		t.Fatalf("archived-node runtime telemetry remains: found=%t err=%v", found, err)
	}
	if _, err := service.PreflightEnrollment(target.EnrollmentToken); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("archived node's enrollment token returned %v", err)
	}
	nodes, err := service.Nodes(network.ID)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("archival changed the wrong inventory: nodes=%#v err=%v", nodes, err)
	}
	for _, node := range nodes {
		if node.ID == target.Node.ID {
			t.Fatalf("archived node remains in inventory: %#v", node)
		}
	}
	events, err := service.Audit(10)
	if err != nil {
		t.Fatal(err)
	}
	legacy := control.LegacyAdminActor()
	var archivedEvent control.AuditEvent
	for _, event := range events {
		if event.Action == "node.archived" && event.ResourceID == target.Node.ID {
			archivedEvent = event
			break
		}
	}
	if archivedEvent.Action == "" || archivedEvent.Details["actor_id"] != legacy.ID || archivedEvent.Details["actor_kind"] != legacy.Kind {
		t.Fatalf("archival audit is missing attribution: %#v", archivedEvent)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("repeated archival status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	for _, node := range []control.Node{stillPending.Node, active.Node} {
		conflictEndpoint := server.URL + "/api/v1/nodes/" + node.ID + "/archive"
		conflictBody, _ := json.Marshal(control.ArchiveNodeInput{ExpectedConfigRevision: expectedRevision, ConfirmationName: node.Name})
		request, _ = http.NewRequest(http.MethodPost, conflictEndpoint, bytes.NewReader(conflictBody))
		request.Header.Set("Authorization", "Bearer "+adminToken)
		request.Header.Set("Content-Type", "application/json")
		response, err = http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusConflict || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s-node archival status=%d cache=%q", node.Status, response.StatusCode, response.Header.Get("Cache-Control"))
		}
	}
}

func TestImmediateCertificateRotationRequiresExactIdempotentAdminRequest(t *testing.T) {
	nebulaCert, err := exec.LookPath("nebula-cert")
	if err != nil {
		t.Skip("nebula-cert is required for the real certificate rotation HTTP test")
	}
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, control.NebulaIssuer{Binary: nebulaCert})
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "rotate-http", CIDR: "10.84.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "certificate-node", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	targetToken := strings.Repeat("c", 42) + "A"
	first, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('C'), control.HashToken(targetToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueAgentRecovery(target.Node.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "pending-certificate"})
	if err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("load certificate rotation revision: networks=%#v err=%v", networks, err)
	}
	expectedRevision := networks[0].ConfigRevision
	adminToken := strings.Repeat("r", 42) + "A"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/nodes/" + target.Node.ID + "/certificate/rotate"
	input := control.RotateNodeCertificateInput{ExpectedConfigRevision: expectedRevision, ConfirmationName: target.Node.Name, RequestID: "http-certificate-rotation-0001"}
	body, _ := json.Marshal(input)

	request, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated certificate rotation returned %d", response.StatusCode)
	}

	for name, test := range map[string]struct {
		endpoint string
		body     string
		status   int
	}{
		"query":         {endpoint: endpoint + "?force=true", body: string(body), status: http.StatusBadRequest},
		"unknown field": {endpoint: endpoint, body: fmt.Sprintf(`{"expected_config_revision":%d,"confirmation_name":"certificate-node","request_id":"http-certificate-rotation-unknown","force":true}`, expectedRevision), status: http.StatusBadRequest},
		"stale revision": {
			endpoint: endpoint,
			body:     `{"expected_config_revision":999,"confirmation_name":"certificate-node","request_id":"http-certificate-rotation-stale"}`,
			status:   http.StatusConflict,
		},
		"wrong name": {
			endpoint: endpoint,
			body:     fmt.Sprintf(`{"expected_config_revision":%d,"confirmation_name":"Certificate-node","request_id":"http-certificate-rotation-name"}`, expectedRevision),
			status:   http.StatusConflict,
		},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, test.endpoint, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+adminToken)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("rejected certificate rotation status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
		})
	}
	pendingEndpoint := server.URL + "/api/v1/nodes/" + pending.Node.ID + "/certificate/rotate"
	pendingBody, _ := json.Marshal(control.RotateNodeCertificateInput{ExpectedConfigRevision: expectedRevision, ConfirmationName: pending.Node.Name, RequestID: "http-certificate-rotation-pending"})
	request, _ = http.NewRequest(http.MethodPost, pendingEndpoint, bytes.NewReader(pendingBody))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("pending-node certificate rotation status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var receipt control.RotatedNodeCertificate
	if err := json.Unmarshal(responseBody, &receipt); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(responseBody, &fields); err != nil {
		t.Fatal(err)
	}
	expectedFields := []string{
		"request_id", "node_id", "network_id", "name", "ip", "role", "rotated_at", "previous_certificate_expires_at",
		"certificate_expires_at", "certificate_renew_after", "previous_certificate_generation", "certificate_generation",
		"agent_recovery_records_invalidated", "certificate_issuances_added", "blocklist_entries_added",
		"previous_certificate_blocklisted", "config_revision",
	}
	if len(fields) != len(expectedFields) {
		t.Fatalf("certificate rotation response schema=%s", responseBody)
	}
	for _, field := range expectedFields {
		if _, ok := fields[field]; !ok {
			t.Fatalf("certificate rotation response omitted %q: %s", field, responseBody)
		}
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || receipt.RequestID != input.RequestID || receipt.NodeID != target.Node.ID || receipt.NetworkID != network.ID || receipt.Name != target.Node.Name || receipt.IP != target.Node.IP || receipt.Role != target.Node.Role || receipt.PreviousCertificateGeneration != first.CertificateGeneration || receipt.CertificateGeneration != first.CertificateGeneration+1 || receipt.AgentRecoveryRecordsInvalidated != 1 || receipt.CertificateIssuancesAdded != 1 || receipt.BlocklistEntriesAdded != 1 || !receipt.PreviousCertificateBlocklisted || receipt.ConfigRevision != expectedRevision+1 {
		t.Fatalf("certificate rotation status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), receipt)
	}
	managed, err := service.AgentConfig(targetToken)
	if err != nil || managed.CertificateGeneration != receipt.CertificateGeneration || managed.CertificateFingerprint == first.CertificateFingerprint || managed.Revision != receipt.ConfigRevision || !strings.Contains(managed.Config, first.CertificateFingerprint) {
		t.Fatalf("rotated agent config=%#v err=%v", managed, err)
	}
	events, err := service.Audit(10)
	if err != nil {
		t.Fatal(err)
	}
	legacy := control.LegacyAdminActor()
	var rotationEvent control.AuditEvent
	for _, event := range events {
		if event.Action == "node.certificate_rotated" && event.ResourceID == target.Node.ID {
			rotationEvent = event
			break
		}
	}
	if rotationEvent.Action == "" || rotationEvent.Details["actor_id"] != legacy.ID || rotationEvent.Details["actor_kind"] != legacy.Kind {
		t.Fatalf("certificate rotation audit attribution is missing: %#v", rotationEvent)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var replayed control.RotatedNodeCertificate
	if err := json.NewDecoder(response.Body).Decode(&replayed); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || replayed != receipt {
		t.Fatalf("certificate rotation replay status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), replayed)
	}
}

func TestNodeRevocationRequiresExactIdempotentAdminRequest(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, err := control.OpenStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "revoke-http", CIDR: "10.85.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "revocation-node", Groups: []string{"operators"}, RoutedSubnets: []string{"192.168.85.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	targetToken := strings.Repeat("j", 42) + "A"
	if _, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('J'), control.HashToken(targetToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueAgentRecovery(target.Node.ID); err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("load revocation revision: networks=%#v err=%v", networks, err)
	}
	expectedRevision := networks[0].ConfigRevision
	adminToken := strings.Repeat("q", 42) + "A"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/nodes/" + target.Node.ID + "/revocation"
	input := control.RevokeNodeInput{ExpectedConfigRevision: expectedRevision, ConfirmationName: target.Node.Name, RequestID: "http-node-revocation-0001"}
	body, _ := json.Marshal(input)

	request, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revocation returned %d", response.StatusCode)
	}

	beforeRejected, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		endpoint string
		body     string
		status   int
	}{
		"query":          {endpoint: endpoint + "?force=true", body: string(body), status: http.StatusBadRequest},
		"unknown field":  {endpoint: endpoint, body: fmt.Sprintf(`{"expected_config_revision":%d,"confirmation_name":"revocation-node","request_id":"http-node-revocation-unknown","force":true}`, expectedRevision), status: http.StatusBadRequest},
		"stale revision": {endpoint: endpoint, body: `{"expected_config_revision":999,"confirmation_name":"revocation-node","request_id":"http-node-revocation-stale"}`, status: http.StatusConflict},
		"wrong name":     {endpoint: endpoint, body: fmt.Sprintf(`{"expected_config_revision":%d,"confirmation_name":"Revocation-node","request_id":"http-node-revocation-name"}`, expectedRevision), status: http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, test.endpoint, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+adminToken)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("rejected revocation status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
		})
	}
	if afterRejected, err := os.ReadFile(statePath); err != nil || !bytes.Equal(beforeRejected, afterRejected) {
		t.Fatalf("rejected HTTP revocation changed state: equal=%t err=%v", bytes.Equal(beforeRejected, afterRejected), err)
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var receipt control.RevokedNodeReceipt
	if err := json.Unmarshal(responseBody, &receipt); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(responseBody, &fields); err != nil {
		t.Fatal(err)
	}
	expectedFields := []string{
		"request_id", "node_id", "network_id", "name", "ip", "role", "revoked_at", "was_enrolled",
		"enrollment_records_invalidated", "agent_recovery_records_invalidated", "blocklist_entries_added",
		"relay_assignment_removed", "firewall_canary_removed", "firewall_rollout_auto_rolled_back",
		"credentials_invalidated", "routed_subnet_reservations_released", "config_revision",
	}
	if len(fields) != len(expectedFields) {
		t.Fatalf("revocation response schema=%s", responseBody)
	}
	for _, field := range expectedFields {
		if _, ok := fields[field]; !ok {
			t.Fatalf("revocation response omitted %q: %s", field, responseBody)
		}
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || receipt.RequestID != input.RequestID || receipt.NodeID != target.Node.ID || receipt.NetworkID != network.ID || receipt.Name != target.Node.Name || receipt.IP != target.Node.IP || receipt.Role != target.Node.Role || !receipt.WasEnrolled || receipt.EnrollmentRecordsInvalidated != 1 || receipt.AgentRecoveryRecordsInvalidated != 1 || receipt.BlocklistEntriesAdded != 1 || !receipt.CredentialsInvalidated || receipt.RoutedSubnetReservationsReleased != 1 || receipt.ConfigRevision != expectedRevision+1 {
		t.Fatalf("revocation status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), receipt)
	}
	if _, err := service.AgentConfig(targetToken); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("revoked HTTP agent credential returned %v", err)
	}
	committedBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	committedInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	replayBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	replayedBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	replayedInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(responseBody, replayBody) || !bytes.Equal(committedBytes, replayedBytes) || !os.SameFile(committedInfo, replayedInfo) || !committedInfo.ModTime().Equal(replayedInfo.ModTime()) {
		t.Fatal("exact HTTP revocation replay changed its receipt or control state")
	}
}

func TestNetworkRetirementRequiresExactConfirmationAndCleansRuntimeTelemetry(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "retire-http", CIDR: "10.86.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "active-node"})
	if err != nil {
		t.Fatal(err)
	}
	activeToken := strings.Repeat("9", 42) + "A"
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, testNebulaPublicKey('T'), control.HashToken(activeToken)); err != nil {
		t.Fatal(err)
	}
	pending, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "pending-node"})
	if err != nil {
		t.Fatal(err)
	}
	telemetry := runtimetelemetry.NewMemoryStore()
	for _, nodeID := range []string{active.Node.ID, pending.Node.ID} {
		if _, changed, err := telemetry.Put(nodeID, 1, time.Now().UTC(), validRuntimeTelemetryObservation(), runtimetelemetry.UnsupportedActiveProbe()); err != nil || !changed {
			t.Fatalf("seed runtime telemetry for %s: changed=%t err=%v", nodeID, changed, err)
		}
	}
	adminToken := strings.Repeat("q", 42) + "A"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServerWithRuntimeTelemetry(t, service, adminToken, false, logger, nil, telemetry)
	defer server.Close()
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/retire"

	request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"expected_config_revision":1,"confirmation_name":"retire-http"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated retirement returned %d", response.StatusCode)
	}

	for name, test := range map[string]struct {
		endpoint string
		body     string
		status   int
	}{
		"query":          {endpoint: endpoint + "?force=true", body: `{"expected_config_revision":1,"confirmation_name":"retire-http"}`, status: http.StatusBadRequest},
		"unknown field":  {endpoint: endpoint, body: `{"expected_config_revision":1,"confirmation_name":"retire-http","force":true}`, status: http.StatusBadRequest},
		"stale revision": {endpoint: endpoint, body: `{"expected_config_revision":999,"confirmation_name":"retire-http"}`, status: http.StatusConflict},
		"wrong name":     {endpoint: endpoint, body: `{"expected_config_revision":1,"confirmation_name":"Retire-http"}`, status: http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, test.endpoint, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+adminToken)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("rejected retirement returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
		})
	}
	if networks, err := service.Networks(); err != nil || len(networks) != 1 {
		t.Fatalf("rejected retirement changed network inventory: networks=%#v err=%v", networks, err)
	}

	body, _ := json.Marshal(control.RetireNetworkInput{ExpectedConfigRevision: network.ConfigRevision, ConfirmationName: network.Name})
	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var retired retiredNetworkResponse
	if err := json.NewDecoder(response.Body).Decode(&retired); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || retired.NetworkID != network.ID || retired.Name != network.Name || retired.NodeCount != 2 || retired.ActiveNodes != 1 || retired.PendingNodes != 1 || retired.RuntimeTelemetryRecordsRemoved != 2 || !retired.RuntimeTelemetryCleanupComplete {
		t.Fatalf("retirement status=%d cache=%q body=%#v", response.StatusCode, response.Header.Get("Cache-Control"), retired)
	}
	for _, nodeID := range []string{active.Node.ID, pending.Node.ID} {
		if _, found, err := telemetry.Get(nodeID); err != nil || found {
			t.Fatalf("runtime telemetry for retired node %s remains: found=%t err=%v", nodeID, found, err)
		}
	}
	if _, err := service.AgentConfig(activeToken); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("retired agent credential returned %v", err)
	}
	events, err := service.Audit(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].Action != "network.retired" {
		t.Fatalf("retirement audit event is missing: %#v", events)
	}
	legacy := control.LegacyAdminActor()
	if events[0].Details["actor_id"] != legacy.ID || events[0].Details["actor_kind"] != legacy.Kind {
		t.Fatalf("retirement audit actor is missing: %#v", events[0])
	}

	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("repeated retirement returned status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}

func TestDashboardExposesSafePendingReissueAndCertificateConvergence(t *testing.T) {
	server := testServer(t, strings.Repeat("v", 43))
	defer server.Close()
	response, err := http.Get(server.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	script := body.String()
	if response.StatusCode != http.StatusOK || !strings.Contains(script, "Reissue enrollment") || !strings.Contains(script, "/enrollment/reissue") {
		t.Fatalf("dashboard does not expose pending enrollment recovery: status=%d", response.StatusCode)
	}
	healthScript, err := webFiles.ReadFile("web/health.js")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(healthScript, []byte("certificate_generation_drift")) {
		t.Fatal("dashboard can report Online before the renewed certificate is applied")
	}
	for _, required := range []string{
		"Recover agent", "/agent-recovery", "read -rsp 'Agent recovery token: '",
		"MESH_AGENT_RECOVERY_TOKEN", "systemctl stop mesh-agent.service",
		"--token-file -", "--quarantine-service mesh-nebula.service", "systemctl start mesh-agent.service",
		"does not invalidate the current agent credential",
		"Rotate certificate", "/certificate/rotate", "request_id: expected.requestID",
		"This does not replace the private key", "Verify rotation", "replay the exact request safely",
		"Verify revocation", "/revocation", "rememberNodeRevocationRequest",
		"This trust cutoff cannot be undone", "revocation outcome is still unknown",
		"Replace identity", "/replace", "expected_config_revision: network.config_revision",
		"Use this only when its Nebula private key is lost", "connectivity will stop until the replacement enrolls",
		"Use Reissue enrollment on its pending identity",
		"Cancel enrollment", "/enrollment/cancel", "confirmation_name: node.name",
		"Archive record", "/archive", "NODE_ARCHIVE_CERTIFICATE_SAFETY_MARGIN_MS",
		"expired certificate history", "runtime telemetry cleanup could not be verified",
		"Retire network", "/retire", "confirmation_name: expected.networkName",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("dashboard recovery flow omitted %q", required)
		}
	}
	if strings.Contains(script, "recover-agent --token ") {
		t.Fatal("dashboard exposes an agent recovery token through argv")
	}
	if strings.Contains(script, "sudo env MESH_AGENT_RECOVERY_TOKEN") {
		t.Fatal("dashboard passes the recovery token through a privileged process environment instead of stdin")
	}

	htmlResponse, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer htmlResponse.Body.Close()
	html, err := io.ReadAll(htmlResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte(`id="recovery-dialog"`)) || !bytes.Contains(html, []byte("displayed once and expires in 30 minutes")) {
		t.Fatal("dashboard does not provide a one-time recovery-token dialog")
	}
	for _, required := range []string{
		"--resume", "private state journal", "transient or ambiguous",
		"authenticated pending-bearer conflict", "replacement token", "rejected or expired",
		"safely probes the old pending bearer", "durably committed",
		"maximum config-staleness deadline", "Stop fail-open or unmanaged Nebula manually",
		"name and overlapping CIDR remain permanently reserved", "Retire permanently",
	} {
		if !bytes.Contains(html, []byte(required)) {
			t.Fatalf("dashboard recovery guidance omitted %q", required)
		}
	}
}

func TestManagedNodeEndpointsAreScopedAndSigned(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, _ := control.NewSecretBox(make([]byte, 32))
	service := control.NewService(store, box, &httpTestIssuer{})
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "managed", CIDR: "10.90.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "node-01"})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("h", 42) + "A"
	publicKey := testNebulaPublicKey('C')
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, control.HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	peerCreated, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "node-02"})
	if err != nil {
		t.Fatal(err)
	}
	peerToken := strings.Repeat("i", 42) + "A"
	peerPublicKey := testNebulaPublicKey('D')
	peerBundle, err := service.Enroll(context.Background(), peerCreated.EnrollmentToken, peerPublicKey, control.HashToken(peerToken))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, strings.Repeat("z", 43), false, logger, nil)
	defer server.Close()

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	request.Header.Set("Authorization", "Bearer "+agentToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var desired control.AgentConfig
	if err := json.NewDecoder(response.Body).Decode(&desired); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") == "" {
		t.Fatalf("managed config status=%d etag=%q", response.StatusCode, response.Header.Get("ETag"))
	}
	agentETag := response.Header.Get("ETag")
	if agentETag != `"`+desired.Signature+`"` {
		t.Fatalf("ETag does not identify the full signed artifact: etag=%q signature=%q", agentETag, desired.Signature)
	}
	if err := control.VerifyConfig(bundle.ConfigSigningPublicKey, desired.SignatureMetadata(), desired.Config, desired.SHA256, desired.Signature); err != nil {
		t.Fatalf("managed config signature: %v", err)
	}
	if desired.CACertificateSHA256 != control.ConfigDigest(bundle.CA) || desired.CertificateFingerprint != bundle.CertificateFingerprint || desired.CertificateGeneration != 1 || desired.PublicKeyHash != bundle.PublicKeyHash {
		t.Fatalf("managed config omitted signed metadata: %#v", desired)
	}
	if !desired.CertificateRenewAfter.Equal(bundle.CertificateRenewAfter) || !desired.CertificateRenewAfter.Before(desired.CertificateExpiresAt) {
		t.Fatalf("managed config omitted signed renewal time: %#v", desired)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/bootstrap", nil)
	request.Header.Set("Authorization", "Bearer "+agentToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var recovered control.EnrollmentBundle
	if err := json.NewDecoder(response.Body).Decode(&recovered); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || recovered.Certificate != bundle.Certificate || recovered.ConfigSignature != bundle.ConfigSignature {
		t.Fatal("authenticated bootstrap did not recover the committed enrollment bundle")
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	request.Header.Set("Authorization", "Bearer "+peerToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var peerDesired control.AgentConfig
	if err := json.NewDecoder(response.Body).Decode(&peerDesired); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	peerETag := response.Header.Get("ETag")
	if response.StatusCode != http.StatusOK || peerETag == "" || peerDesired.CertificateFingerprint != peerBundle.CertificateFingerprint {
		t.Fatalf("peer managed config status=%d etag=%q", response.StatusCode, peerETag)
	}

	eligible := time.Now().UTC().Add(-time.Second)
	if err := store.Update(func(state *control.State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID == bundle.Node.ID {
				state.Nodes[index].CertificateRenewAfter = &eligible
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	renewBody, _ := json.Marshal(map[string]string{"public_key": publicKey})
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/certificate/renew", bytes.NewReader(renewBody))
	request.Header.Set("Authorization", "Bearer "+agentToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var renewal control.RenewalBundle
	if err := json.NewDecoder(response.Body).Decode(&renewal); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || renewal.ConfigRevision != desired.Revision || renewal.CertificateGeneration != desired.CertificateGeneration+1 {
		t.Fatalf("node-local renewal changed network revision or failed to advance generation: status=%d renewal=%#v", response.StatusCode, renewal)
	}
	if want := renewal.CertificateExpiresAt.Add(-8 * time.Hour); !renewal.CertificateRenewAfter.Equal(want) || !renewal.CertificateRenewAfter.After(desired.CertificateRenewAfter) {
		t.Fatalf("renewal returned wrong server renewal time: got=%s want=%s previous=%s", renewal.CertificateRenewAfter, want, desired.CertificateRenewAfter)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	request.Header.Set("Authorization", "Bearer "+agentToken)
	request.Header.Set("If-None-Match", agentETag)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") == agentETag {
		t.Fatalf("renewed node retained stale desired-artifact ETag: status=%d old=%q new=%q", response.StatusCode, agentETag, response.Header.Get("ETag"))
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	request.Header.Set("Authorization", "Bearer "+peerToken)
	request.Header.Set("If-None-Match", peerETag)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotModified {
		t.Fatalf("one member renewal changed a peer's desired artifact: status=%d old_etag=%q new_etag=%q", response.StatusCode, peerETag, response.Header.Get("ETag"))
	}

	heartbeat := control.HeartbeatInput{AgentVersion: "0.1.0", NebulaVersion: "1.10.3", AppliedConfigRevision: desired.Revision, CertificateGeneration: renewal.CertificateGeneration, AppliedConfigSHA256: desired.SHA256, CertificateFingerprint: renewal.CertificateFingerprint, NebulaRunning: true, Status: "healthy", BootID: "boot-http", Sequence: 1}
	postHeartbeat := func(body []byte) int {
		t.Helper()
		heartbeatRequest, requestErr := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/heartbeat", bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		heartbeatRequest.Header.Set("Authorization", "Bearer "+agentToken)
		heartbeatRequest.Header.Set("Content-Type", "application/json")
		heartbeatResponse, requestErr := http.DefaultClient.Do(heartbeatRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer heartbeatResponse.Body.Close()
		return heartbeatResponse.StatusCode
	}
	invalidHeartbeats := map[string]control.HeartbeatInput{
		"future revision": func() control.HeartbeatInput {
			value := heartbeat
			value.AppliedConfigRevision++
			return value
		}(),
		"future certificate generation": func() control.HeartbeatInput {
			value := heartbeat
			value.CertificateGeneration++
			return value
		}(),
		"negative certificate generation": func() control.HeartbeatInput {
			value := heartbeat
			value.CertificateGeneration = -1
			return value
		}(),
		"sequence poisoning": func() control.HeartbeatInput {
			value := heartbeat
			value.Sequence = int64(1<<63 - 1)
			return value
		}(),
	}
	for name, invalidHeartbeat := range invalidHeartbeats {
		t.Run("heartbeat rejects "+name, func(t *testing.T) {
			body, marshalErr := json.Marshal(invalidHeartbeat)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if status := postHeartbeat(body); status != http.StatusBadRequest {
				t.Fatalf("invalid heartbeat returned %d", status)
			}
		})
	}
	overflowHeartbeat := []byte(`{"agent_version":"0.1.0","nebula_version":"1.10.3","applied_config_revision":9223372036854775808,"certificate_generation":1,"sequence":1,"boot_id":"boot-http"}`)
	if status := postHeartbeat(overflowHeartbeat); status != http.StatusBadRequest {
		t.Fatalf("overflow heartbeat returned %d", status)
	}
	body, _ := json.Marshal(heartbeat)
	if status := postHeartbeat(body); status != http.StatusNoContent {
		t.Fatalf("heartbeat returned %d", status)
	}

	// A node may not rotate onto another node's current credential hash. That
	// would make the bearer resolve to more than one identity.
	rotationBody, _ := json.Marshal(map[string]string{"new_token_hash": control.HashToken(peerToken)})
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/credentials/rotate", bytes.NewReader(rotationBody))
	request.Header.Set("Authorization", "Bearer "+agentToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("credential-colliding rotation returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 43))
	response, _ = http.DefaultClient.Do(request)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unscoped credential returned %d", response.StatusCode)
	}
}

func TestRuntimeTelemetryEndpointIsOptionalAndBoundToAcceptedHeartbeat(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "runtime-telemetry", CIDR: "10.91.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "runtime-node"})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("t", 42) + "A"
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('R'), control.HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	legacyServer, _, _ := newTestHTTPServer(t, service, strings.Repeat("z", 43), false, logger, nil)
	legacyResponse := postRuntimeTelemetry(t, legacyServer, agentToken, runtimetelemetry.ReportInput{
		HeartbeatSequence: 1,
		Observation:       validRuntimeTelemetryObservation(),
	})
	_ = legacyResponse.Body.Close()
	if legacyResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("server without telemetry store returned %d, want 405", legacyResponse.StatusCode)
	}
	legacyRead, err := http.NewRequest(http.MethodGet, legacyServer.URL+"/api/v1/fleet/runtime-telemetry", nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyRead.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 43))
	legacyResponse, err = legacyServer.Client().Do(legacyRead)
	if err != nil {
		t.Fatal(err)
	}
	_ = legacyResponse.Body.Close()
	if legacyResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("server without telemetry store exposed administrator read route with status %d", legacyResponse.StatusCode)
	}

	receivedAt := time.Date(2026, 7, 20, 15, 4, 5, 0, time.UTC)
	telemetryStore := runtimetelemetry.NewMemoryStore()
	t.Cleanup(func() { _ = telemetryStore.Close() })
	server, _, _ := newTestHTTPServerWithRuntimeTelemetry(t, service, strings.Repeat("z", 43), false, logger, func() time.Time { return receivedAt }, telemetryStore)

	routeOverlap := runtimetelemetry.ObservedRouteOverlap(false)
	input := runtimetelemetry.ReportInput{HeartbeatSequence: 1, Observation: validRuntimeTelemetryObservation(), RouteOverlap: &routeOverlap}
	response := postRuntimeTelemetry(t, server, agentToken, input)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("pre-heartbeat telemetry status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}

	heartbeat := control.HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3",
		AppliedConfigRevision: bundle.ConfigRevision, AppliedConfigSHA256: bundle.ConfigSHA256,
		CertificateFingerprint: bundle.CertificateFingerprint, CertificateGeneration: bundle.CertificateGeneration,
		NebulaRunning: true, Status: "healthy", BootID: "boot-runtime", Sequence: 1,
	}
	if _, err := service.Heartbeat(agentToken, heartbeat); err != nil {
		t.Fatalf("accept lifecycle heartbeat: %v", err)
	}
	controlBefore := readControlState(t, store)
	auditBefore, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}

	response = postRuntimeTelemetry(t, server, agentToken, input)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("accepted telemetry status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	record, found, err := telemetryStore.Get(bundle.Node.ID)
	if err != nil || !found {
		t.Fatalf("stored telemetry found=%v err=%v", found, err)
	}
	if record.NodeID != bundle.Node.ID || record.HeartbeatSequence != 1 || !record.ReceivedAt.Equal(receivedAt) ||
		record.ProcessContinuity != runtimetelemetry.ContinuityUnclassified || !reflect.DeepEqual(record.Observation, input.Observation) ||
		record.ActiveProbe != runtimetelemetry.UnsupportedActiveProbe() || record.AppliedConfigSHA256 != bundle.ConfigSHA256 || record.ProbeTransition != runtimetelemetry.ProbeTransitionUnavailable || record.RouteOverlap.State != runtimetelemetry.RouteOverlapObserved || record.RouteOverlap.Overlap || record.EndpointDNS != runtimetelemetry.UnsupportedEndpointDNS() {
		t.Fatalf("stored telemetry = %#v", record)
	}

	unauthenticatedRead, err := server.Client().Get(server.URL + "/api/v1/fleet/runtime-telemetry")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthenticatedRead.Body.Close()
	if unauthenticatedRead.StatusCode != http.StatusUnauthorized || unauthenticatedRead.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated runtime telemetry read status=%d cache=%q", unauthenticatedRead.StatusCode, unauthenticatedRead.Header.Get("Cache-Control"))
	}
	readRequest, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/runtime-telemetry", nil)
	if err != nil {
		t.Fatal(err)
	}
	readRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 43))
	readResponse, err := server.Client().Do(readRequest)
	if err != nil {
		t.Fatal(err)
	}
	readBody, readErr := io.ReadAll(readResponse.Body)
	_ = readResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if readResponse.StatusCode != http.StatusOK || readResponse.Header.Get("Cache-Control") != "no-store" || readResponse.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("runtime telemetry read status=%d cache=%q type=%q body=%s", readResponse.StatusCode, readResponse.Header.Get("Cache-Control"), readResponse.Header.Get("Content-Type"), readBody)
	}
	var projection runtimetelemetry.FleetProjection
	if err := json.Unmarshal(readBody, &projection); err != nil {
		t.Fatal(err)
	}
	if projection.Schema != runtimetelemetry.FleetProjectionSchema || !projection.GeneratedAt.Equal(receivedAt) ||
		len(projection.Records) != 1 || projection.Records[0].NodeID != bundle.Node.ID ||
		projection.Records[0].HeartbeatSequence != heartbeat.Sequence || projection.Records[0].ObservationVersion != runtimetelemetry.VersionV2 ||
		projection.Records[0].ProcessContinuity != runtimetelemetry.ContinuityUnclassified ||
		projection.Records[0].ActiveProbe != runtimetelemetry.UnsupportedActiveProbe() ||
		projection.Records[0].ProbeTransition != runtimetelemetry.ProbeTransitionUnavailable ||
		projection.Records[0].Snapshot == nil || projection.Records[0].Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS == nil ||
		!projection.Policy.AggregateOnly || projection.Policy.EndToEndReachabilityProven {
		t.Fatalf("unexpected runtime telemetry projection: %#v", projection)
	}
	for _, forbidden := range []string{"process_instance_id", "0123456789abcdef0123456789abcdef", "last_error", "certificate_fingerprint", "agent_token", "target_ip", "local_ip", "plan_sha256", "applied_config_sha256", bundle.ConfigSHA256, "nonce", "packet", "socket_error", "route_overlap", "endpoint_dns"} {
		if bytes.Contains(readBody, []byte(forbidden)) {
			t.Fatalf("runtime telemetry read exposed forbidden field %q: %s", forbidden, readBody)
		}
	}
	healthRequest, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	healthRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 43))
	healthResponse, err := server.Client().Do(healthRequest)
	if err != nil {
		t.Fatal(err)
	}
	var health control.FleetHealthCollection
	if err := json.NewDecoder(healthResponse.Body).Decode(&health); err != nil {
		_ = healthResponse.Body.Close()
		t.Fatal(err)
	}
	_ = healthResponse.Body.Close()
	if healthResponse.StatusCode != http.StatusOK || len(health.Networks) != 1 || len(health.Networks[0].Nodes) != 1 || health.Networks[0].Nodes[0].HeartbeatSequence != heartbeat.Sequence {
		t.Fatalf("health projection does not expose exact telemetry binding: status=%d health=%#v", healthResponse.StatusCode, health)
	}
	readRequest, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/runtime-telemetry?window=5m", nil)
	readRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 43))
	readResponse, err = server.Client().Do(readRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusBadRequest || readResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("runtime telemetry query status=%d cache=%q", readResponse.StatusCode, readResponse.Header.Get("Cache-Control"))
	}

	// An exact retry is idempotent and retains the original server receive time.
	receivedAt = receivedAt.Add(time.Minute)
	response = postRuntimeTelemetry(t, server, agentToken, input)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("idempotent telemetry retry returned %d", response.StatusCode)
	}
	retried, _, err := telemetryStore.Get(bundle.Node.ID)
	if err != nil || !retried.ReceivedAt.Equal(record.ReceivedAt) {
		t.Fatalf("idempotent retry changed receive time: before=%s after=%s err=%v", record.ReceivedAt, retried.ReceivedAt, err)
	}

	probeEquivocation := input
	probe := runtimetelemetry.NotEligibleActiveProbe()
	probeEquivocation.ActiveProbe = &probe
	response = postRuntimeTelemetry(t, server, agentToken, probeEquivocation)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("same-sequence probe equivocation returned %d", response.StatusCode)
	}
	retained, found, err := telemetryStore.Get(bundle.Node.ID)
	if err != nil || !found || retained.ActiveProbe != runtimetelemetry.UnsupportedActiveProbe() {
		t.Fatalf("probe equivocation replaced accepted record: %#v found=%t err=%v", retained, found, err)
	}
	routeEquivocation := input
	conflictingRoute := runtimetelemetry.ObservedRouteOverlap(true)
	routeEquivocation.RouteOverlap = &conflictingRoute
	response = postRuntimeTelemetry(t, server, agentToken, routeEquivocation)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("same-sequence route equivocation returned %d", response.StatusCode)
	}
	dnsEquivocation := input
	conflictingDNS := runtimetelemetry.ObservedEndpointDNS(1, 0)
	dnsEquivocation.EndpointDNS = &conflictingDNS
	response = postRuntimeTelemetry(t, server, agentToken, dnsEquivocation)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("same-sequence endpoint DNS equivocation returned %d", response.StatusCode)
	}

	equivocation := input
	equivocation.Observation = runtimetelemetry.Observation{Version: runtimetelemetry.VersionV1, State: runtimetelemetry.StateUnknown}
	response = postRuntimeTelemetry(t, server, agentToken, equivocation)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("same-sequence equivocation returned %d", response.StatusCode)
	}

	response = postRuntimeTelemetry(t, server, strings.Repeat("x", 42)+"A", input)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong bearer returned %d", response.StatusCode)
	}
	malformedRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/runtime-telemetry", strings.NewReader(`{"heartbeat_sequence":1,"observation":{"version":1,"state":"unknown"},"extra":true}`))
	malformedRequest.Header.Set("Authorization", "Bearer "+agentToken)
	malformedRequest.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(malformedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown JSON field returned %d", response.StatusCode)
	}
	invalidProbeRequest, _ := http.NewRequest(
		http.MethodPost,
		server.URL+"/api/v1/agent/runtime-telemetry",
		strings.NewReader(`{"heartbeat_sequence":1,"observation":{"version":2,"state":"unknown"},"active_probe":{"version":1,"state":"attempted","sample_age_ms":null,"attempted":1,"replied":0,"duration_ms":1}}`),
	)
	invalidProbeRequest.Header.Set("Authorization", "Bearer "+agentToken)
	invalidProbeRequest.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(invalidProbeRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid active probe returned %d", response.StatusCode)
	}
	invalidRouteRequest, _ := http.NewRequest(
		http.MethodPost,
		server.URL+"/api/v1/agent/runtime-telemetry",
		strings.NewReader(`{"heartbeat_sequence":1,"observation":{"version":2,"state":"unknown"},"route_overlap":{"version":1,"state":"observed","sample_age_ms":null,"overlap":false}}`),
	)
	invalidRouteRequest.Header.Set("Authorization", "Bearer "+agentToken)
	invalidRouteRequest.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(invalidRouteRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid route overlap returned %d", response.StatusCode)
	}
	invalidDNSRequest, _ := http.NewRequest(
		http.MethodPost,
		server.URL+"/api/v1/agent/runtime-telemetry",
		strings.NewReader(`{"heartbeat_sequence":1,"observation":{"version":2,"state":"unknown"},"endpoint_dns":{"version":1,"state":"observed","sample_age_ms":0,"dns_names":1,"resolved_names":2}}`),
	)
	invalidDNSRequest.Header.Set("Authorization", "Bearer "+agentToken)
	invalidDNSRequest.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(invalidDNSRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid endpoint DNS returned %d", response.StatusCode)
	}
	retained, found, err = telemetryStore.Get(bundle.Node.ID)
	if err != nil || !found || retained.HeartbeatSequence != 1 || retained.ActiveProbe != runtimetelemetry.UnsupportedActiveProbe() {
		t.Fatalf("invalid telemetry request changed accepted record: %#v found=%t err=%v", retained, found, err)
	}

	if err := telemetryStore.Close(); err != nil {
		t.Fatal(err)
	}
	readRequest, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/runtime-telemetry", nil)
	readRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 43))
	readResponse, err = server.Client().Do(readRequest)
	if err != nil {
		t.Fatal(err)
	}
	closedBody, readErr := io.ReadAll(readResponse.Body)
	_ = readResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if readResponse.StatusCode != http.StatusInternalServerError || !bytes.Contains(closedBody, []byte(`"error":"internal server error"`)) || bytes.Contains(closedBody, []byte("closed")) {
		t.Fatalf("closed runtime telemetry store did not fail closed: status=%d body=%s", readResponse.StatusCode, closedBody)
	}

	controlAfter := readControlState(t, store)
	auditAfter, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(controlAfter, controlBefore) || !reflect.DeepEqual(auditAfter, auditBefore) {
		t.Fatal("runtime telemetry mutated authoritative control state or audit history")
	}
}

func TestRuntimeTelemetryEndpointRejectsRollbackAndProjectsConfigBoundRecovery(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "runtime-rollback", CIDR: "10.92.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "runtime-node"})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("r", 42) + "A"
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('S'), control.HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := control.HeartbeatInput{
		AgentVersion: "0.1.0", NebulaVersion: "1.10.3",
		AppliedConfigRevision: bundle.ConfigRevision, AppliedConfigSHA256: bundle.ConfigSHA256,
		CertificateFingerprint: bundle.CertificateFingerprint, CertificateGeneration: bundle.CertificateGeneration,
		NebulaRunning: true, Status: "healthy", BootID: "boot-runtime-rollback", Sequence: 1,
	}
	if _, err := service.Heartbeat(agentToken, heartbeat); err != nil {
		t.Fatal(err)
	}
	receivedAt := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	telemetryStore := runtimetelemetry.NewMemoryStore()
	t.Cleanup(func() { _ = telemetryStore.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _, _ := newTestHTTPServerWithRuntimeTelemetry(t, service, strings.Repeat("z", 43), false, logger, func() time.Time { return receivedAt }, telemetryStore)
	probeAge := uint64(0)
	probe := runtimetelemetry.ActiveProbeResult{
		Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
		SampleAgeMS: &probeAge, Attempted: 1, Replied: 0, DurationMS: 3,
	}
	first := runtimetelemetry.ReportInput{HeartbeatSequence: 1, Observation: validRuntimeTelemetryObservation(), ActiveProbe: &probe}
	response := postRuntimeTelemetry(t, server, agentToken, first)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("initial telemetry returned %d", response.StatusCode)
	}
	eligibleHeartbeat := time.Now().UTC().Add(-10 * time.Second)
	if err := store.Update(func(state *control.State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID == bundle.Node.ID {
				enrolledAt := eligibleHeartbeat.Add(-time.Minute)
				state.Nodes[index].CreatedAt = enrolledAt
				state.Nodes[index].EnrolledAt = &enrolledAt
				state.Nodes[index].LastSeenAt = &eligibleHeartbeat
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	heartbeat.Sequence = 2
	if _, err := service.Heartbeat(agentToken, heartbeat); err != nil {
		t.Fatal(err)
	}
	rollback := validRuntimeTelemetryObservation()
	rollback.Snapshot.SampleSequence++
	rollback.Snapshot.ProcessUptimeMS--
	receivedAt = receivedAt.Add(time.Minute)
	response = postRuntimeTelemetry(t, server, agentToken, runtimetelemetry.ReportInput{HeartbeatSequence: 2, Observation: rollback})
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("same-process rollback status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	accepted, found, err := telemetryStore.Get(bundle.Node.ID)
	if err != nil || !found || accepted.HeartbeatSequence != 1 ||
		accepted.ProcessContinuity != runtimetelemetry.ContinuityUnclassified ||
		accepted.Observation.Snapshot.SampleSequence != first.Observation.Snapshot.SampleSequence ||
		accepted.ActiveProbe.State != runtimetelemetry.ProbeAttempted || accepted.ActiveProbe.Replied != 0 {
		t.Fatalf("rejected rollback changed accepted record: %+v found=%t err=%v", accepted, found, err)
	}

	next := validRuntimeTelemetryObservation()
	next.Snapshot.SampleSequence++
	next.Snapshot.ProcessUptimeMS++
	completeProbe := runtimetelemetry.CloneActiveProbe(probe)
	completeProbe.Replied = 1
	response = postRuntimeTelemetry(t, server, agentToken, runtimetelemetry.ReportInput{
		HeartbeatSequence: 2, Observation: next, ActiveProbe: &completeProbe,
	})
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("valid recovery telemetry returned %d", response.StatusCode)
	}
	recovered, found, err := telemetryStore.Get(bundle.Node.ID)
	if err != nil || !found || recovered.HeartbeatSequence != 2 ||
		recovered.AppliedConfigSHA256 != bundle.ConfigSHA256 ||
		recovered.ProbeTransition != runtimetelemetry.ProbeTransitionRecovered {
		t.Fatalf("recovery telemetry=%#v found=%t err=%v", recovered, found, err)
	}

	readRequest, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/fleet/runtime-telemetry", nil)
	if err != nil {
		t.Fatal(err)
	}
	readRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 43))
	readResponse, err := server.Client().Do(readRequest)
	if err != nil {
		t.Fatal(err)
	}
	readBody, err := io.ReadAll(readResponse.Body)
	_ = readResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var projection runtimetelemetry.FleetProjection
	if err := json.Unmarshal(readBody, &projection); err != nil {
		t.Fatal(err)
	}
	if readResponse.StatusCode != http.StatusOK || projection.Schema != runtimetelemetry.FleetProjectionSchemaV5 ||
		len(projection.Records) != 1 || projection.Records[0].ProbeTransition != runtimetelemetry.ProbeTransitionRecovered ||
		bytes.Contains(readBody, []byte("applied_config_sha256")) || bytes.Contains(readBody, []byte(bundle.ConfigSHA256)) {
		t.Fatalf("recovery fleet projection status=%d body=%s", readResponse.StatusCode, readBody)
	}
}

func postRuntimeTelemetry(t *testing.T, server *httptest.Server, bearer string, input runtimetelemetry.ReportInput) *http.Response {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent/runtime-telemetry", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func validRuntimeTelemetryObservation() runtimetelemetry.Observation {
	handshakeAge, receiveAge, lighthouseReceiveAge := uint64(100), uint64(200), uint64(150)
	return runtimetelemetry.Observation{
		Version: runtimetelemetry.VersionV2,
		State:   runtimetelemetry.StateObserved,
		Snapshot: &runtimetelemetry.Snapshot{
			ProcessInstanceID: strings.Repeat("a", 32), SampleSequence: 2, ProcessUptimeMS: 1_000,
			Handshakes: runtimetelemetry.HandshakeAggregate{CompletedTotal: 1, MostRecentCompletionAgeMS: &handshakeAge},
			Peers:      runtimetelemetry.PeerAggregate{Established: 1, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 1, OldestAuthenticatedRXAgeMS: &receiveAge},
			Lighthouses: runtimetelemetry.LighthouseAggregate{
				Configured: 1, Established: 1, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 1,
				MostRecentAuthenticatedRXAgeMS: &lighthouseReceiveAge,
			},
		},
	}
}

func readControlState(t *testing.T, store *control.Store) control.State {
	t.Helper()
	var state control.State
	if err := store.View(func(current control.State) error {
		state = current
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAgentEndpointsBoundPreAuthenticationWork(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, &httpTestIssuer{})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, apiServer, _ := newTestHTTPServer(t, service, strings.Repeat("z", 43), false, logger, nil)
	apiServer.agentRate = newTokenBucket(0, 2)
	defer server.Close()

	for index, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 42)+"A")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("request %d status = %d, want %d", index+1, response.StatusCode, want)
		}
		if want == http.StatusTooManyRequests && response.Header.Get("Retry-After") == "" {
			t.Fatal("rate-limited response omitted Retry-After")
		}
	}
}

type httpTestIssuer struct{ calls int }

func TestRouteTransferEndpointsRequireAuthStrictJSONAndReturnAuthoritativeReceipt(t *testing.T) {
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
	master := make([]byte, 32)
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'R'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema, service.EnsureRouteProfileEditSchema, service.EnsureRoutePolicySchema,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "route-api", CIDR: "10.126.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "route-api-source", RoutedSubnets: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "route-api-target"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), source.EnrollmentToken, testNebulaPublicKey('U'), control.HashToken(strings.Repeat("u", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), target.EnrollmentToken, testNebulaPublicKey('V'), control.HashToken(strings.Repeat("v", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("networks=%#v err=%v", networks, err)
	}
	adminToken := strings.Repeat("r", 43)
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/route-transfer"
	response, err := server.Client().Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status=%d", response.StatusCode)
	}

	body := fmt.Sprintf(`{"source_node_id":%q,"target_node_id":%q,"routed_subnets":["203.0.113.0/24"],"expected_config_revision":%d,"request_id":"route-transfer-api-0001","extra":true}`, source.Node.ID, target.Node.ID, networks[0].ConfigRevision)
	request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-field POST status=%d", response.StatusCode)
	}

	body = fmt.Sprintf(`{"source_node_id":%q,"target_node_id":%q,"routed_subnets":["203.0.113.0/24"],"expected_config_revision":%d,"request_id":"route-transfer-api-0001"}`, source.Node.ID, target.Node.ID, networks[0].ConfigRevision)
	request, _ = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("start status=%d body=%s", response.StatusCode, payload)
	}
	var document control.NetworkRouteTransferDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != control.NetworkRouteTransferDocumentSchema || document.Phase != control.RouteTransferPhasePreparingTarget || document.RequestID != "route-transfer-api-0001" || document.Target == nil || document.Target.DesiredCertificateGeneration < 2 {
		t.Fatalf("unexpected route transfer document: %#v", document)
	}
}

func TestRouteProfileEndpointsRequireAuthStrictJSONAndReturnAuthoritativeReceipt(t *testing.T) {
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
	master := make([]byte, 32)
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'P'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema, service.EnsureRouteProfileEditSchema, service.EnsureRoutePolicySchema,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "profile-api", CIDR: "10.136.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{Name: "profile-api-owner", RoutedSubnets: []string{"192.168.136.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('W'), control.HashToken(strings.Repeat("w", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 {
		t.Fatalf("networks=%#v err=%v", networks, err)
	}
	adminToken := strings.Repeat("q", 43)
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	endpoint := server.URL + "/api/v1/nodes/" + created.Node.ID + "/route-profile"
	response, err := server.Client().Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status=%d", response.StatusCode)
	}

	body := fmt.Sprintf(`{"routed_subnets":["192.168.137.0/24"],"expected_config_revision":%d,"request_id":"route-profile-api-0001","extra":true}`, networks[0].ConfigRevision)
	request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-field POST status=%d", response.StatusCode)
	}

	body = fmt.Sprintf(`{"routed_subnets":["192.168.137.0/24"],"expected_config_revision":%d,"request_id":"route-profile-api-0001"}`, networks[0].ConfigRevision)
	request, _ = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("start status=%d body=%s", response.StatusCode, payload)
	}
	var document control.NodeRouteProfileEditDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != control.NodeRouteProfileEditDocumentSchema || document.Phase != control.RouteProfileEditPhasePreparingOwner || document.RequestID != "route-profile-api-0001" || document.NodeID != created.Node.ID || document.Owner == nil || document.Owner.DesiredCertificateGeneration < 2 || !slices.Equal(document.Additions, []string{"192.168.137.0/24"}) || !slices.Equal(document.Removals, []string{"192.168.136.0/24"}) {
		t.Fatalf("unexpected route profile document: %#v", document)
	}
}

func TestRoutePolicyEndpointsRequireAuthStrictJSONAndBindAuthoritativeOwners(t *testing.T) {
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
	master := make([]byte, 32)
	masterVerifier, _ := control.DeriveMasterKeyVerifier(master)
	adminVerifier, _ := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'E'}, 43))
	for _, step := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema,
		service.EnsureCARotationSchema, service.EnsureFirewallRolloutSchema, service.EnsureFirewallPauseSchema,
		service.EnsureRouteTransferSchema, service.EnsureRouteProfileEditSchema, service.EnsureRoutePolicySchema,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "route-policy-api", CIDR: "10.142.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "192.168.142.0/24"
	first, _ := service.CreateNode(network.ID, control.CreateNodeInput{Name: "route-policy-api-a", RoutedSubnets: []string{prefix}})
	second, _ := service.CreateNode(network.ID, control.CreateNodeInput{Name: "route-policy-api-b"})
	if _, err := service.Enroll(context.Background(), first.EnrollmentToken, testNebulaPublicKey('E'), control.HashToken(strings.Repeat("e", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), second.EnrollmentToken, testNebulaPublicKey('F'), control.HashToken(strings.Repeat("f", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(state *control.State) error {
		for index := range state.Nodes {
			if state.Nodes[index].ID == second.Node.ID {
				state.Nodes[index].RoutedSubnets = []string{prefix}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("e", 43)
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/route-policies"
	response, err := server.Client().Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status=%d", response.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodGet, endpoint+"?prefix="+prefix, nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("query GET status=%d", response.StatusCode)
	}
	request, _ = http.NewRequest(http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var current control.NetworkRoutePoliciesDocument
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("GET status=%d body=%s", response.StatusCode, payload)
	}
	if err := json.NewDecoder(response.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if current.Schema != control.NetworkRoutePoliciesDocumentSchema || len(current.Policies) != 1 || len(current.Policies[0].Gateways) != 2 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("route-policy document=%#v", current)
	}
	gateways := make([]control.NetworkRoutePolicyGateway, len(current.Policies[0].Gateways))
	for index, gateway := range current.Policies[0].Gateways {
		gateways[index] = control.NetworkRoutePolicyGateway{NodeID: gateway.NodeID, Weight: index + 1}
	}
	body, _ := json.Marshal(map[string]any{
		"prefix": prefix, "gateways": gateways, "mtu": 1400, "metric": 7,
		"expected_config_revision": current.ConfigRevision, "request_id": "route-policy-api-request-0001", "extra": true,
	})
	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-field POST status=%d", response.StatusCode)
	}
	body, _ = json.Marshal(control.UpdateNetworkRoutePolicyInput{
		Prefix: prefix, Gateways: gateways, MTU: 1400, Metric: 7,
		ExpectedConfigRevision: current.ConfigRevision, RequestID: "route-policy-api-request-0001",
	})
	request, _ = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("update status=%d body=%s", response.StatusCode, payload)
	}
	var updated control.NetworkRoutePoliciesDocument
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.ConfigRevision != current.ConfigRevision+1 || len(updated.Policies) != 1 || updated.Policies[0].MTU != 1400 || updated.Policies[0].Metric != 7 || updated.Policies[0].LastRequestID != "route-policy-api-request-0001" {
		t.Fatalf("updated route-policy document=%#v", updated)
	}
}

func (i *httpTestIssuer) CreateCA(context.Context, string, string) (string, string, error) {
	return "test-ca", "test-private-ca", nil
}

func (i *httpTestIssuer) SignPublicKey(_ context.Context, _, _, _, _, _, _, _ string, ttl time.Duration) (string, string, time.Time, error) {
	i.calls++
	return fmt.Sprintf("test-cert-%d", i.calls), fmt.Sprintf("%064x", i.calls), time.Now().UTC().Add(ttl), nil
}

func testServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, control.NebulaIssuer{})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, token, false, logger, nil)
	return server
}

func newTestHTTPServer(t *testing.T, service *control.Service, token string, secure bool, logger *slog.Logger, now func() time.Time) (*httptest.Server, *Server, *identity.FileStore) {
	return newTestHTTPServerWithReadiness(t, service, token, secure, logger, now, nil)
}

func newTestHTTPServerWithReadiness(t *testing.T, service *control.Service, token string, secure bool, logger *slog.Logger, now func() time.Time, readinessCheck func(context.Context) error) (*httptest.Server, *Server, *identity.FileStore) {
	return newTestHTTPServerWithOptions(t, service, token, secure, logger, now, readinessCheck, nil)
}

func newTestHTTPServerWithRuntimeTelemetry(t *testing.T, service *control.Service, token string, secure bool, logger *slog.Logger, now func() time.Time, telemetryStore runtimetelemetry.Store) (*httptest.Server, *Server, *identity.FileStore) {
	return newTestHTTPServerWithOptions(t, service, token, secure, logger, now, nil, telemetryStore)
}

func newTestHTTPServerWithOptions(t *testing.T, service *control.Service, token string, secure bool, logger *slog.Logger, now func() time.Time, readinessCheck func(context.Context) error, telemetryStore runtimetelemetry.Store) (*httptest.Server, *Server, *identity.FileStore) {
	t.Helper()
	testServer := httptest.NewUnstartedServer(nil)
	scheme := "http"
	if secure {
		scheme = "https"
	}
	config, err := (identity.IdentityConfig{
		Mode: identity.ModeLegacyToken, PublicURL: scheme + "://" + testServer.Listener.Addr().String(),
		LegacyBrowserLogin: true, LegacyBearer: true,
	}).Normalized(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		testServer.Close()
		t.Fatal(err)
	}
	fingerprint, err := config.PolicyFingerprint(identity.ValidationOptions{AllowInsecureLoopback: true})
	if err != nil {
		testServer.Close()
		t.Fatal(err)
	}
	box, err := control.NewSecretBox(make([]byte, 32))
	if err != nil {
		testServer.Close()
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(t.TempDir(), "identity-state.json"), box)
	if err != nil {
		testServer.Close()
		t.Fatal(err)
	}
	credentialBinding, err := DeriveLegacyCredentialBinding(make([]byte, 32), token)
	if err != nil {
		_ = identityStore.Close()
		testServer.Close()
		t.Fatal(err)
	}
	apiServer, err := New(service, Options{
		IdentityConfig: config, ValidationOptions: identity.ValidationOptions{AllowInsecureLoopback: !secure},
		PolicyFingerprint: fingerprint, LegacyCredentialBinding: credentialBinding, SessionStore: identityStore,
		AdminToken: token, SecureCookies: secure, Logger: logger, ReadinessCheck: readinessCheck, Now: now,
		RuntimeTelemetryStore: telemetryStore,
	})
	if err != nil {
		_ = identityStore.Close()
		testServer.Close()
		t.Fatal(err)
	}
	testServer.Config.Handler = apiServer.Handler()
	if secure {
		testServer.StartTLS()
	} else {
		testServer.Start()
	}
	t.Cleanup(func() {
		testServer.Close()
		_ = identityStore.Close()
	})
	return testServer, apiServer, identityStore
}

func addCookieCSRF(request *http.Request, origin, csrf string) {
	request.Header.Set("X-Mesh-CSRF", csrf)
	request.Header.Set("Origin", origin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
}

func postTestLogin(client *http.Client, origin string, body []byte) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodPost, origin+"/api/v1/session", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return client.Do(request)
}
