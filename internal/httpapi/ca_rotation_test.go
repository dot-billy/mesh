package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/control"
)

func TestNetworkCARotationEndpointsRequireExactAuthenticatedLifecycle(t *testing.T) {
	if _, err := exec.LookPath("nebula-cert"); err != nil {
		t.Skip("nebula-cert is not installed")
	}
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	master := bytes.Repeat([]byte{0x71}, 32)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	service := control.NewService(store, box, control.NebulaIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'A'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, migrate := range []func() error{
		func() error { return service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false) },
		service.EnsureTopologySchema, service.EnsureNetworkDNSSchema, service.EnsureNetworkRelaySchema, service.EnsureCARotationSchema,
	} {
		if err := migrate(); err != nil {
			t.Fatal(err)
		}
	}
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "ca-api", CIDR: "10.99.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 43)
	server, _, _ := newTestHTTPServer(t, service, token, false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	endpoint := server.URL + "/api/v1/networks/" + network.ID + "/ca-rotation"
	request := func(method, suffix, body, authorization string) *http.Response {
		t.Helper()
		req, requestErr := http.NewRequest(method, endpoint+suffix, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if authorization != "" {
			req.Header.Set("Authorization", "Bearer "+authorization)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}

	unauthorized := request(http.MethodGet, "", "", "")
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated CA rotation GET returned %d", unauthorized.StatusCode)
	}
	response := request(http.MethodGet, "", "", token)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stable CA rotation GET status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	var stable control.NetworkCARotationDocument
	if err := json.NewDecoder(response.Body).Decode(&stable); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if stable.Schema != control.NetworkCARotationDocumentSchema || stable.Phase != "stable" || stable.ConfigRevision != network.ConfigRevision || len(stable.AvailableActions) != 1 || stable.AvailableActions[0] != "prepare" {
		t.Fatalf("unexpected stable CA rotation document: %+v", stable)
	}

	body := `{"action":"prepare","expected_config_revision":1}`
	response = request(http.MethodPost, "", body, token)
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("prepare CA rotation status=%d body=%s", response.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte("next_ca_certificate")) || bytes.Contains(raw, []byte("encrypted")) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatalf("CA rotation API leaked private/internal material: %s", raw)
	}
	var prepared control.NetworkCARotationDocument
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Phase != control.CARotationPhasePrepared || prepared.ConfigRevision != 2 || prepared.TargetCACertificateSHA256 == "" || prepared.CurrentTrustBundleSHA256 == prepared.ActiveCACertificateSHA256 {
		t.Fatalf("unexpected prepared CA rotation: %+v", prepared)
	}

	response = request(http.MethodPost, "", strings.TrimSuffix(body, "}")+`,"unexpected":true}`, token)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("CA rotation endpoint accepted an unknown field: %d", response.StatusCode)
	}
	response = request(http.MethodGet, "?unexpected=1", "", token)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("CA rotation endpoint accepted a query string: %d", response.StatusCode)
	}
	response = request(http.MethodPost, "", `{"action":"activate","expected_config_revision":1}`, token)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("CA rotation endpoint accepted a stale action: %d", response.StatusCode)
	}
}
