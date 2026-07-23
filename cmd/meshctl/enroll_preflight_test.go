package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/nodeagent"
)

func TestRequestEnrollmentPreflightIsStrictAndTokenScoped(t *testing.T) {
	token := strings.Repeat("t", 42) + "A"
	plan := control.EnrollmentPreflight{
		Schema: control.EnrollmentPreflightSchemaV1, TargetRole: "member", NetworkCIDR: "10.235.0.0/24",
		LighthouseEndpoints: []string{"198.51.100.9:4242"}, TokenExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll/preflight" || r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected preflight request path=%q authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || len(input) != 1 || input["token"] != token {
			t.Fatalf("preflight input=%#v err=%v", input, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plan)
	}))
	defer server.Close()
	got, err := requestEnrollmentPreflight(context.Background(), server.Client(), server.URL, token)
	if err != nil || got.NetworkCIDR != plan.NetworkCIDR {
		t.Fatalf("preflight=%#v err=%v", got, err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema":"mesh-enrollment-preflight-v1","target_role":"member","network_cidr":"10.235.0.0/24","lighthouse_endpoints":[],"token_expires_at":"2026-07-21T06:00:00Z","extra":true}`))
	}))
	defer bad.Close()
	if _, err := requestEnrollmentPreflight(context.Background(), bad.Client(), bad.URL, token); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown response field returned %v", err)
	}
}

func TestEnrollmentPreflightRejectsUnsafeOutputBeforeHTTP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner and mode preflight")
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	private := t.TempDir()
	fakeNebula := filepath.Join(private, "nebula")
	if err := os.WriteFile(fakeNebula, []byte("#!/bin/sh\necho 'Version: 1.10.3'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(private, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	err := enroll([]string{
		"--server", server.URL,
		"--token", strings.Repeat("e", 42) + "A",
		"--state", filepath.Join(private, "state", "agent.json"),
		"--output", filepath.Join(shared, "nebula"),
		"--nebula", fakeNebula,
		"--nebula-cert", filepath.Join(private, "unused-nebula-cert"),
	})
	if err == nil || !strings.Contains(err.Error(), "preflight managed Nebula output") {
		t.Fatalf("unsafe output error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("unsafe output consumed enrollment over %d HTTP requests", requests.Load())
	}
}

func TestEnrollmentResumeRechecksUnsafeOutputBeforeHTTP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner and mode preflight")
	}
	t.Setenv("MESH_ENROLL_TOKEN", "")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	private := t.TempDir()
	fakeNebula := filepath.Join(private, "nebula")
	if err := os.WriteFile(fakeNebula, []byte("#!/bin/sh\necho 'Version: 1.10.3'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	outputParent := filepath.Join(private, "output-parent")
	if err := os.Mkdir(outputParent, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputParent, "nebula")
	statePath := filepath.Join(private, "state", "agent.json")
	store, err := nodeagent.NewStateStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := nodeagent.NewProvisionalEnrollment(
		server.URL, strings.Repeat("e", 42)+"A", output,
		"private-key", "public-key",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveProvisionalEnrollment(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outputParent, 0o777); err != nil {
		t.Fatal(err)
	}

	err = enroll([]string{
		"--server", server.URL,
		"--state", statePath,
		"--output", output,
		"--nebula", fakeNebula,
		"--nebula-cert", filepath.Join(private, "unused-nebula-cert"),
	})
	if err == nil || !strings.Contains(err.Error(), "preflight pending managed Nebula output") {
		t.Fatalf("unsafe resume error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("unsafe resume made %d HTTP requests", requests.Load())
	}
}
