package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
)

func TestReissueEnrollmentCommandUsesAdminAPIAndPrintsSecretOnce(t *testing.T) {
	adminToken := strings.Repeat("a", 43)
	replacement := strings.Repeat("b", 42) + "A"
	expiresAt := time.Date(2026, 7, 19, 20, 30, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/nodes/node-01/enrollment/reissue" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+adminToken {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(response).Encode(control.ReissuedEnrollment{
			Node:            control.Node{ID: "node-01", Name: "pending-01", IP: "10.42.0.2", Status: "pending"},
			EnrollmentToken: replacement,
			ExpiresAt:       expiresAt,
		})
	}))
	defer server.Close()

	var output bytes.Buffer
	err := reissueEnrollmentTo([]string{"--server", server.URL, "--admin-token", adminToken, "--node", "node-01"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), replacement) != 1 || !strings.Contains(output.String(), "pending-01") || !strings.Contains(output.String(), expiresAt.Format(time.RFC3339)) {
		t.Fatalf("unexpected command output: %q", output.String())
	}
}

func TestReissueEnrollmentCommandRequiresNode(t *testing.T) {
	if err := reissueEnrollmentTo(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--node is required") {
		t.Fatalf("missing --node returned %v", err)
	}
}

func TestIssueAgentRecoveryUsesScopedAdminEndpointAndExplainsActivation(t *testing.T) {
	const adminToken = "admin-token-value"
	recoveryToken := strings.Repeat("r", 42) + "A"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/nodes/node-01/agent-recovery" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+adminToken {
			t.Fatalf("unexpected authorization header %q", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(control.IssuedAgentRecovery{
			Node:          control.Node{ID: "node-01", Name: "active-01", IP: "10.42.0.2", Status: "active"},
			RecoveryToken: recoveryToken,
			ExpiresAt:     time.Date(2030, 1, 1, 0, 30, 0, 0, time.UTC),
		})
	}))
	defer server.Close()

	var output bytes.Buffer
	err := issueAgentRecoveryTo([]string{"--server", server.URL, "--admin-token", adminToken, "--node", "node-01"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	printed := output.String()
	if strings.Count(printed, recoveryToken) != 1 || !strings.Contains(printed, "shown once") || !strings.Contains(printed, "does not invalidate") || !strings.Contains(printed, "successful node recovery replaces it atomically") {
		t.Fatalf("unsafe or incomplete recovery output: %q", printed)
	}
}

func TestIssueAgentRecoveryRequiresNode(t *testing.T) {
	if err := issueAgentRecoveryTo(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--node is required") {
		t.Fatalf("missing --node returned %v", err)
	}
}
