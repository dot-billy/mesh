package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

func TestInstallGuideIsAuthenticatedExactAndReadOnly(t *testing.T) {
	configuredURL := "https://releases.example/channels/stable/bundle.json"
	handoffURL := "https://releases.example/bootstrap/stable/bootstrap-handoff.json"
	tests := []struct {
		name       string
		bundleURL  string
		handoffURL string
		want       map[string]any
	}{
		{
			name: "configured", bundleURL: configuredURL, handoffURL: handoffURL,
			want: map[string]any{
				"schema": "mesh-install-guide-v2",
				"linux": map[string]any{
					"online_available": true, "bundle_url": configuredURL,
					"bootstrap_handoff_url": handoffURL,
				},
			},
		},
		{
			name: "handoff only", handoffURL: handoffURL,
			want: map[string]any{
				"schema": "mesh-install-guide-v2",
				"linux":  map[string]any{"online_available": false, "bootstrap_handoff_url": handoffURL},
			},
		},
		{
			name: "unset",
			want: map[string]any{
				"schema": "mesh-install-guide-v2",
				"linux":  map[string]any{"online_available": false},
			},
		},
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
			service := control.NewService(store, box, &httpTestIssuer{})
			token := strings.Repeat("g", 43)
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, _, _ := newTestHTTPServerWithInstallURL(t, service, token, false, logger, nil, test.bundleURL, test.handoffURL)
			defer server.Close()

			before, err := service.Audit(100)
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.Get(server.URL + "/api/v1/install-guide")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("unauthenticated response = %d, cache %q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
			request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/install-guide", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			response, err = server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("authenticated status = %d", response.StatusCode)
			}
			if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("Content-Type = %q", contentType)
			}
			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header.Get("Cache-Control"))
			}
			var got map[string]any
			if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("install guide = %#v, want %#v", got, test.want)
			}
			after, err := service.Audit(100)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("read-only install guide mutated control audit: before=%#v after=%#v", before, after)
			}
		})
	}
}

func newTestHTTPServerWithInstallURL(t *testing.T, service *control.Service, token string, secure bool, logger *slog.Logger, now func() time.Time, bundleURL, handoffURL string) (*httptest.Server, *Server, *identity.FileStore) {
	t.Helper()
	testServer := httptest.NewUnstartedServer(nil)
	scheme := "http"
	if secure {
		scheme = "https"
	}
	validation := identity.ValidationOptions{AllowInsecureLoopback: true}
	config, err := (identity.IdentityConfig{
		Mode: identity.ModeLegacyToken, PublicURL: scheme + "://" + testServer.Listener.Addr().String(),
		LegacyBrowserLogin: true, LegacyBearer: true,
	}).Normalized(validation)
	if err != nil {
		testServer.Close()
		t.Fatal(err)
	}
	fingerprint, err := config.PolicyFingerprint(validation)
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
		IdentityConfig: config, ValidationOptions: validation,
		PolicyFingerprint: fingerprint, LegacyCredentialBinding: credentialBinding,
		SessionStore: identityStore, AdminToken: token, SecureCookies: secure, Logger: logger, Now: now,
		LinuxInstallBundleURL: bundleURL, LinuxBootstrapHandoffURL: handoffURL,
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

func TestInstallGuideHelperUsesNoEnvironmentFallback(t *testing.T) {
	t.Setenv("MESH_LINUX_INSTALL_BUNDLE_URL", "https://environment.example/bundle.json")
	t.Setenv("MESH_LINUX_BOOTSTRAP_HANDOFF_URL", "https://environment.example/bootstrap-handoff.json")
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
	server, api, _ := newTestHTTPServerWithInstallURL(t, service, strings.Repeat("e", 43), false, slog.New(slog.NewTextHandler(os.Stderr, nil)), nil, "", "")
	defer server.Close()
	if api.linuxInstallBundleURL != "" || api.linuxBootstrapHandoffURL != "" {
		t.Fatalf("environment configured install URLs %q, %q", api.linuxInstallBundleURL, api.linuxBootstrapHandoffURL)
	}
}
