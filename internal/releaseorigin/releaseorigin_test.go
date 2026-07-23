package releaseorigin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"mesh/internal/onlinerelease"
)

func TestBuildOpenAndServeExplicitReleaseObjects(t *testing.T) {
	root, channel, artifact := writeOriginFixture(t)
	index, err := BuildIndex(root, []string{artifact, channel})
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Objects) != 2 || index.Objects[0].Path != channel || index.Objects[0].Cache != CacheChannel || index.Objects[1].Path != artifact || index.Objects[1].Cache != CacheImmutable {
		t.Fatalf("unexpected canonical index: %+v", index)
	}
	raw, err := Encode(index)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, mustEncodeIndex(t, parsed)) {
		t.Fatal("index readback changed canonical bytes")
	}
	store, err := Open(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CheckReadiness(); err != nil {
		t.Fatal(err)
	}

	channelRaw, err := os.ReadFile(objectFilesystemPath(root, channel))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://origin.example"+channel, nil)
	response := httptest.NewRecorder()
	store.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), channelRaw) {
		t.Fatalf("channel GET = %d %q", response.Code, response.Body.Bytes())
	}
	if response.Header().Get("Content-Type") != ContentTypeJSON || response.Header().Get("Cache-Control") != channelCacheControl || response.Header().Get("ETag") == "" || response.Header().Get("Content-Encoding") != "" {
		t.Fatalf("unexpected channel headers: %v", response.Header())
	}
	if response.Header().Get("Strict-Transport-Security") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", response.Header())
	}

	head := httptest.NewRecorder()
	store.Handler().ServeHTTP(head, httptest.NewRequest(http.MethodHead, "https://origin.example"+artifact, nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Cache-Control") != immutableCacheControl || head.Header().Get("Content-Type") != ContentTypeOctet {
		t.Fatalf("artifact HEAD = %d %q %v", head.Code, head.Body.Bytes(), head.Header())
	}
	notModifiedRequest := httptest.NewRequest(http.MethodGet, "https://origin.example"+artifact, nil)
	notModifiedRequest.Header.Set("If-None-Match", head.Header().Get("ETag"))
	notModified := httptest.NewRecorder()
	store.Handler().ServeHTTP(notModified, notModifiedRequest)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("conditional GET = %d %q", notModified.Code, notModified.Body.Bytes())
	}

	for name, request := range map[string]*http.Request{
		"unlisted": httptest.NewRequest(http.MethodGet, "https://origin.example/private.key", nil),
		"query":    httptest.NewRequest(http.MethodGet, "https://origin.example"+channel+"?x=1", nil),
		"encoded":  httptest.NewRequest(http.MethodGet, "https://origin.example/channels/%73table/bundle.json", nil),
		"write":    httptest.NewRequest(http.MethodPost, "https://origin.example"+channel, strings.NewReader("x")),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			store.Handler().ServeHTTP(response, request)
			if name == "write" {
				if response.Code != http.StatusMethodNotAllowed {
					t.Fatalf("write status = %d", response.Code)
				}
				return
			}
			if response.Code != http.StatusNotFound {
				t.Fatalf("unpublished request status = %d", response.Code)
			}
		})
	}
}

func TestOriginFailsClosedForTamperingAndUnsafeFilesystemGraph(t *testing.T) {
	root, channel, artifact := writeOriginFixture(t)
	index, err := BuildIndex(root, []string{channel, artifact})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustEncodeIndex(t, index)
	index.Objects[1].SHA256 = strings.Repeat("0", 64)
	wrongDigest := mustEncodeIndex(t, index)
	if store, err := Open(root, wrongDigest); err == nil {
		_ = store.Close()
		t.Fatal("wrong indexed digest accepted")
	}

	store, err := Open(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	artifactPath := objectFilesystemPath(root, artifact)
	if err := os.WriteFile(artifactPath, []byte("changed-artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(artifactPath, future, future); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReadiness(); err == nil {
		t.Fatal("in-place object mutation left readiness passing")
	}
	response := httptest.NewRecorder()
	store.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example"+artifact, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("mutated object status = %d", response.Code)
	}

	if runtime.GOOS != "windows" {
		root, _, artifact = writeOriginFixture(t)
		if err := os.Link(objectFilesystemPath(root, artifact), filepath.Join(root, "artifact-hardlink")); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildIndex(root, []string{artifact}); err == nil {
			t.Fatal("hard-linked release object accepted")
		}
	}
}

func TestIndexStrictCanonicalValidation(t *testing.T) {
	root, channel, artifact := writeOriginFixture(t)
	index, err := BuildIndex(root, []string{channel, artifact})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustEncodeIndex(t, index)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["unknown"] = true
	unknown, _ := json.Marshal(generic)
	unknown = append(unknown, '\n')
	pretty, _ := json.MarshalIndent(index, "", "  ")
	pretty = append(pretty, '\n')
	for name, candidate := range map[string][]byte{
		"unknown":    unknown,
		"pretty":     pretty,
		"missing LF": bytes.TrimSuffix(raw, []byte("\n")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(candidate); err == nil {
				t.Fatal("inexact index accepted")
			}
		})
	}
	for _, path := range []string{"relative", "/../secret", "/a//b", "/a/%62", "/a/", "/channels/stable/bundle.tar"} {
		if _, err := BuildIndex(root, []string{path}); err == nil {
			t.Fatalf("unsafe object path accepted: %q", path)
		}
	}
}

func writeOriginFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	channel := "/channels/stable/bundle.json"
	artifact := "/releases/1.2.3/mesh-linux-bundle.tar"
	for _, path := range []string{channel, artifact} {
		if err := os.MkdirAll(filepath.Dir(objectFilesystemPath(root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundle, err := onlinerelease.Encode(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   []byte("channel-manifest\n"),
		ChannelSignatures: [][]byte{[]byte("channel-signature")},
		ReleaseManifest:   []byte("release-manifest\n"),
		ReleaseSignatures: [][]byte{[]byte("release-signature")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectFilesystemPath(root, channel), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectFilesystemPath(root, artifact), []byte("signed-artifact-bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, channel, artifact
}

func mustEncodeIndex(t *testing.T, index Index) []byte {
	t.Helper()
	raw, err := Encode(index)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
