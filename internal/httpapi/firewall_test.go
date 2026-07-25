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

func TestFirewallPolicyAPIAuthenticationCSRFPreviewUpdateAndValidation(t *testing.T) {
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "firewall-api", CIDR: "10.90.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("f", 43)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/firewall"

	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated firewall GET returned %d", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var initial control.FirewallPolicyDocument
	if err := json.NewDecoder(response.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || initial.NetworkID != network.ID || initial.ConfigRevision != 1 || initial.Mode != control.FirewallPolicyModeManaged || initial.RendererVersion != control.FirewallRendererVersionV2 || len(initial.Inbound) != 1 || len(initial.Outbound) != 1 {
		t.Fatalf("unexpected authenticated GET: status=%d cache=%q document=%#v", response.StatusCode, response.Header.Get("Cache-Control"), initial)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"token": adminToken})
	response, err = postTestLogin(client, server.URL, loginBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d", response.StatusCode)
	}
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

	desired := control.FirewallPolicyInput{
		Inbound:  []control.FirewallRule{{Proto: "tcp", Port: "443", Group: "operators"}},
		Outbound: []control.FirewallRule{},
	}
	previewRaw, _ := json.Marshal(desired)
	request, _ = http.NewRequest(http.MethodPut, endpoint+"/preview", bytes.NewReader(previewRaw))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie preview without CSRF returned %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPut, endpoint+"/preview", bytes.NewReader(previewRaw))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var preview control.FirewallPolicyPreview
	if err := json.NewDecoder(response.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || !preview.WouldChange || preview.ConfigRevision != 1 || preview.ProposedConfigRevision != 2 || preview.RendererVersion != control.FirewallRendererVersionV2 || !strings.Contains(preview.RenderedFirewall, "group: \"operators\"") {
		t.Fatalf("unexpected preview: status=%d cache=%q preview=%#v", response.StatusCode, response.Header.Get("Cache-Control"), preview)
	}

	update := control.UpdateFirewallPolicyInput{ExpectedConfigRevision: preview.ConfigRevision, Inbound: desired.Inbound, Outbound: desired.Outbound}
	updateRaw, _ := json.Marshal(update)
	request, _ = http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(updateRaw))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var updated control.FirewallPolicyDocument
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || updated.ConfigRevision != 2 || updated.Mode != control.FirewallPolicyModeManaged {
		t.Fatalf("unexpected update: status=%d cache=%q document=%#v", response.StatusCode, response.Header.Get("Cache-Control"), updated)
	}

	// A lost-response retry of the same canonical policy succeeds even though
	// its optimistic revision is stale.
	request, _ = http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(updateRaw))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var retried control.FirewallPolicyDocument
	if err := json.NewDecoder(response.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || retried.ConfigRevision != 2 || !retried.ConfigUpdatedAt.Equal(updated.ConfigUpdatedAt) {
		t.Fatalf("same-payload retry status=%d document=%#v", response.StatusCode, retried)
	}

	stale := control.UpdateFirewallPolicyInput{
		ExpectedConfigRevision: 1,
		Inbound:                []control.FirewallRule{{Proto: "udp", Port: "53", Host: "10.90.0.53"}}, Outbound: []control.FirewallRule{},
	}
	status, message := firewallAPIError(t, client, http.MethodPut, endpoint, stale, csrf)
	if status != http.StatusConflict || !strings.Contains(message, "current revision 2") {
		t.Fatalf("stale overwrite status=%d error=%q", status, message)
	}

	duplicate := control.UpdateFirewallPolicyInput{
		ExpectedConfigRevision: 2,
		Inbound: []control.FirewallRule{
			{Proto: "tcp", Port: "80", Host: "10.90.0.10"},
			{Proto: "tcp", Port: "80", Host: "10.90.0.10/32"},
		},
		Outbound: []control.FirewallRule{},
	}
	status, message = firewallAPIError(t, client, http.MethodPut, endpoint, duplicate, csrf)
	if status != http.StatusBadRequest || !strings.Contains(message, "duplicates an equivalent rule") {
		t.Fatalf("duplicate policy status=%d error=%q", status, message)
	}

	request, _ = http.NewRequest(http.MethodPut, endpoint+"/preview", strings.NewReader(`{"inbound":[],"outbound":[],"padding":"`+strings.Repeat("x", 65<<10)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	addCookieCSRF(request, server.URL, csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var errorBody map[string]string
	_ = json.NewDecoder(response.Body).Decode(&errorBody)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Cache-Control") != "no-store" || !strings.Contains(errorBody["error"], "malformed JSON") {
		t.Fatalf("oversize preview status=%d cache=%q error=%q", response.StatusCode, response.Header.Get("Cache-Control"), errorBody["error"])
	}

	request, _ = http.NewRequest(http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var final control.FirewallPolicyDocument
	if err := json.NewDecoder(response.Body).Decode(&final); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if final.ConfigRevision != 2 || len(final.Inbound) != 1 || final.Inbound[0].Group != "operators" {
		t.Fatalf("rejected API mutations changed policy: %#v", final)
	}
}

func firewallAPIError(t *testing.T, client *http.Client, method, endpoint string, body any, csrf string) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	addCookieCSRF(request, parsed.Scheme+"://"+parsed.Host, csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload map[string]string
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, payload["error"]
}
