package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mesh/internal/control"
)

func TestHTTPAdminMutationsDistinguishCookieSessionFromLegacyBearer(t *testing.T) {
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
	adminToken := strings.Repeat("l", 43)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server, _, _ := newTestHTTPServer(t, service, adminToken, false, logger, nil)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cookieClient := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"token": adminToken})
	response, err := postTestLogin(cookieClient, server.URL, loginBody)
	if err != nil {
		t.Fatal(err)
	}
	var loggedIn sessionResponse
	if err := json.NewDecoder(response.Body).Decode(&loggedIn); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || loggedIn.SessionID == "" {
		t.Fatalf("login returned %d with session %#v", response.StatusCode, loggedIn)
	}
	baseURL, _ := url.Parse(server.URL)
	csrf := ""
	for _, cookie := range jar.Cookies(baseURL) {
		if cookie.Name == "mesh_csrf" {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("login omitted CSRF cookie")
	}

	cookie := actorHTTPAuth{client: cookieClient, csrf: csrf, origin: server.URL}
	bearer := actorHTTPAuth{client: server.Client(), bearer: adminToken}
	cookieResult := runAttributedHTTPWorkflow(t, server.URL, service, cookie, "cookie", "10.96.0.0/24", "10.96.0.10", "A")
	bearerResult := runAttributedHTTPWorkflow(t, server.URL, service, bearer, "bearer", "10.97.0.0/24", "10.97.0.10", "B")

	events, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	wantPerActor := map[string]int{
		"network.created":                 1,
		"node.created":                    2,
		"node.enrollment_reissued":        1,
		"node.agent_recovery_issued":      1,
		"network.firewall_policy_updated": 1,
		"node.revoked":                    1,
	}
	cookieCounts := map[string]int{}
	bearerCounts := map[string]int{}
	actorlessEnrollments := 0
	for _, event := range events {
		if event.Action == "node.enrolled" {
			actorlessEnrollments++
			if _, attributed := event.Details["actor_id"]; attributed {
				t.Fatalf("agent enrollment unexpectedly received administrator attribution: %#v", event)
			}
			continue
		}
		if _, wanted := wantPerActor[event.Action]; !wanted {
			continue
		}
		legacyActor := control.LegacyAdminActor()
		if event.Details["actor_id"] != legacyActor.ID || event.Details["actor_kind"] != legacyActor.Kind {
			t.Fatalf("HTTP mutation %q has inconsistent legacy actor identity: %#v", event.Action, event.Details)
		}
		switch event.Details["actor_session_id"] {
		case loggedIn.SessionID:
			cookieCounts[event.Action]++
		case "":
			bearerCounts[event.Action]++
		default:
			t.Fatalf("HTTP mutation %q has an unexpected session attribution: %#v", event.Action, event.Details)
		}
	}
	if !reflect.DeepEqual(cookieCounts, wantPerActor) || !reflect.DeepEqual(bearerCounts, wantPerActor) || actorlessEnrollments != 2 {
		t.Fatalf("HTTP cookie counts=%v bearer counts=%v enrollments=%d, want %v each and 2", cookieCounts, bearerCounts, actorlessEnrollments, wantPerActor)
	}

	beforeFailures := len(events)
	// Same effective policy is a successful lost-response retry even after
	// revocation advanced the network revision, and must not add attribution.
	actorAdminJSON(t, bearer, http.MethodPut, server.URL+"/api/v1/networks/"+bearerResult.network.ID+"/firewall", control.UpdateFirewallPolicyInput{
		ExpectedConfigRevision: bearerResult.firewallRevision,
		Inbound:                bearerResult.inbound,
		Outbound:               []control.FirewallRule{},
	}, http.StatusOK, nil)
	actorAdminJSON(t, cookie, http.MethodPost, server.URL+"/api/v1/networks/"+cookieResult.network.ID+"/nodes", control.CreateNodeInput{Name: cookieResult.pendingName}, http.StatusConflict, nil)
	afterFailures, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterFailures) != beforeFailures {
		t.Fatalf("failed/no-op HTTP mutations appended %d audit events", len(afterFailures)-beforeFailures)
	}
}

type actorHTTPAuth struct {
	client *http.Client
	bearer string
	csrf   string
	origin string
}

type attributedHTTPWorkflow struct {
	network          control.Network
	pendingName      string
	firewallRevision int64
	inbound          []control.FirewallRule
}

func runAttributedHTTPWorkflow(t *testing.T, serverURL string, service *control.Service, auth actorHTTPAuth, label, cidr, host, keyCharacter string) attributedHTTPWorkflow {
	t.Helper()
	var network control.Network
	actorAdminJSON(t, auth, http.MethodPost, serverURL+"/api/v1/networks", control.CreateNetworkInput{Name: label + "-network", CIDR: cidr, CertificateTTL: 24}, http.StatusCreated, &network)

	pendingName := label + "-pending"
	var pending control.CreatedNode
	actorAdminJSON(t, auth, http.MethodPost, serverURL+"/api/v1/networks/"+network.ID+"/nodes", control.CreateNodeInput{Name: pendingName}, http.StatusCreated, &pending)
	actorAdminJSON(t, auth, http.MethodPost, serverURL+"/api/v1/nodes/"+pending.Node.ID+"/enrollment/reissue", nil, http.StatusOK, nil)

	var active control.CreatedNode
	actorAdminJSON(t, auth, http.MethodPost, serverURL+"/api/v1/networks/"+network.ID+"/nodes", control.CreateNodeInput{Name: label + "-active"}, http.StatusCreated, &active)
	publicKey := testNebulaPublicKey(keyCharacter[0])
	agentToken := strings.Repeat(strings.ToLower(keyCharacter), 42) + "A"
	if _, err := service.Enroll(context.Background(), active.EnrollmentToken, publicKey, control.HashToken(agentToken)); err != nil {
		t.Fatalf("enroll %s active node: %v", label, err)
	}
	actorAdminJSON(t, auth, http.MethodPost, serverURL+"/api/v1/nodes/"+active.Node.ID+"/agent-recovery", nil, http.StatusCreated, nil)

	current, err := service.GetFirewallPolicy(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	inbound := []control.FirewallRule{{Proto: "tcp", Port: "443", Host: host}}
	actorAdminJSON(t, auth, http.MethodPut, serverURL+"/api/v1/networks/"+network.ID+"/firewall", control.UpdateFirewallPolicyInput{
		ExpectedConfigRevision: current.ConfigRevision,
		Inbound:                inbound,
		Outbound:               []control.FirewallRule{},
	}, http.StatusOK, nil)
	actorAdminJSON(t, auth, http.MethodPost, serverURL+"/api/v1/nodes/"+active.Node.ID+"/revoke", nil, http.StatusOK, nil)
	return attributedHTTPWorkflow{network: network, pendingName: pendingName, firewallRevision: current.ConfigRevision, inbound: inbound}
}

func actorAdminJSON(t *testing.T, auth actorHTTPAuth, method, endpoint string, body any, wantStatus int, destination any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if auth.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+auth.bearer)
	} else {
		addCookieCSRF(request, auth.origin, auth.csrf)
	}
	response, err := auth.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s returned %d, want %d: %s", method, endpoint, response.StatusCode, wantStatus, raw)
	}
	if destination != nil {
		if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
			t.Fatal(err)
		}
	}
}
