package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mesh/internal/control"
)

func TestEnrollmentPreflightEndpointIsTokenScopedStrictAndReadOnly(t *testing.T) {
	admin := strings.Repeat("a", 43)
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
	network, err := service.CreateNetwork(context.Background(), control.CreateNetworkInput{Name: "preflight-api", CIDR: "10.233.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, control.CreateNodeInput{
		Name: "future-lighthouse", Role: "lighthouse", PublicEndpoint: "future.example:4242",
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _, _ := newTestHTTPServer(t, service, admin, false, logger, nil)
	defer server.Close()

	auditBefore, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"token": created.EnrollmentToken})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/enroll/preflight", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("preflight status=%d cache=%q type=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("Content-Type"), responseBody)
	}
	var plan control.EnrollmentPreflight
	if err := json.Unmarshal(responseBody, &plan); err != nil {
		t.Fatal(err)
	}
	if err := control.ValidateEnrollmentPreflight(plan); err != nil || plan.NetworkCIDR != network.CIDR || plan.TargetRole != "lighthouse" || !reflect.DeepEqual(plan.LighthouseEndpoints, []string{"future.example:4242"}) {
		t.Fatalf("invalid endpoint plan=%#v err=%v", plan, err)
	}
	auditAfter, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(auditAfter, auditBefore) {
		t.Fatal("preflight endpoint mutated audit history")
	}

	for _, candidate := range []struct {
		path string
		body string
		want int
	}{
		{path: "/api/v1/enroll/preflight", body: `{"token":"` + strings.Repeat("x", 43) + `"}`, want: http.StatusUnauthorized},
		{path: "/api/v1/enroll/preflight?site=future", body: string(body), want: http.StatusBadRequest},
		{path: "/api/v1/enroll/preflight", body: `{"token":"` + created.EnrollmentToken + `","extra":true}`, want: http.StatusBadRequest},
	} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+candidate.path, strings.NewReader(candidate.body))
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != candidate.want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("strict preflight path=%q status=%d cache=%q", candidate.path, response.StatusCode, response.Header.Get("Cache-Control"))
		}
	}
}
