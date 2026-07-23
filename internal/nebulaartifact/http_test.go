package nebulaartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestDownloadAuthenticatedManualRedirectAndExactBody(t *testing.T) {
	body := []byte("authenticated archive bytes")
	digest := sha256.Sum256(body)
	artifact := ArtifactLock{URL: "https://github.test/release", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
	policy := networkPolicy{initialURL: artifact.URL, initialHost: "github.test", finalHost: "assets.test"}
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("unsafe request headers: %v", request.Header)
		}
		if calls == 1 {
			return response(request, http.StatusFound, nil, map[string]string{"Location": "https://assets.test/object?token=opaque"}), nil
		}
		return response(request, http.StatusOK, body, nil), nil
	}), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	destination, err := os.CreateTemp(t.TempDir(), "archive-")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if err := downloadAuthenticated(context.Background(), client, policy, artifact, destination); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("got %d requests, want 2", calls)
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(destination)
	if !bytes.Equal(got, body) {
		t.Fatalf("staged body %q, want %q", got, body)
	}
}

func TestDownloadAuthenticatedRejectsNetworkAndBodyVariants(t *testing.T) {
	body := []byte("body")
	digest := sha256.Sum256(body)
	baseArtifact := ArtifactLock{URL: "https://github.test/release", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
	basePolicy := networkPolicy{initialURL: baseArtifact.URL, initialHost: "github.test", finalHost: "assets.test"}
	tests := []struct {
		name     string
		location string
		status   int
		body     []byte
		headers  map[string]string
	}{
		{"wrong-host", "https://evil.test/object", http.StatusOK, body, nil},
		{"userinfo", "https://user@assets.test/object", http.StatusOK, body, nil},
		{"plain-http", "http://assets.test/object", http.StatusOK, body, nil},
		{"nonstandard-port", "https://assets.test:8443/object", http.StatusOK, body, nil},
		{"second-redirect", "https://assets.test/object", http.StatusFound, nil, map[string]string{"Location": "https://assets.test/other"}},
		{"compressed", "https://assets.test/object", http.StatusOK, body, map[string]string{"Content-Encoding": "gzip"}},
		{"short", "https://assets.test/object", http.StatusOK, body[:3], nil},
		{"long", "https://assets.test/object", http.StatusOK, append(append([]byte(nil), body...), '!'), nil},
		{"wrong-hash", "https://assets.test/object", http.StatusOK, []byte("boDy"), nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return response(request, http.StatusFound, nil, map[string]string{"Location": test.location}), nil
				}
				return response(request, test.status, test.body, test.headers), nil
			}), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
			destination, err := os.CreateTemp(t.TempDir(), "archive-")
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			if err := downloadAuthenticated(context.Background(), client, basePolicy, baseArtifact, destination); err == nil {
				t.Fatal("adversarial response accepted")
			}
			if calls > 2 {
				t.Fatalf("made %d requests; retries or extra redirects occurred", calls)
			}
		})
	}
}

func response(request *http.Request, status int, body []byte, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	length := int64(len(body))
	if body == nil {
		length = 0
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: header, Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: length, Request: request}
}
