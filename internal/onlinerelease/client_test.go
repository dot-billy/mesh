package onlinerelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	releasetrust "mesh/internal/release"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClientFetchesExactBundleAndArtifact(t *testing.T) {
	bundleRaw, err := Encode(testBundle())
	if err != nil {
		t.Fatal(err)
	}
	artifactRaw := []byte("authenticated artifact")
	digest := sha256.Sum256(artifactRaw)
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodGet || request.Body != nil {
			t.Fatalf("unsafe request shape: %s, %v", request.Method, request.Body)
		}
		if request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatalf("unsafe headers: %v", request.Header)
		}
		if request.Header.Get("Cache-Control") != "no-cache" || request.Header.Get("User-Agent") != "mesh-install/online-release-v1" {
			t.Fatalf("missing policy headers: %v", request.Header)
		}
		body := bundleRaw
		wantAccept := "application/json"
		if requests == 2 {
			body = artifactRaw
			wantAccept = "application/octet-stream"
		}
		if request.Header.Get("Accept") != wantAccept {
			t.Fatalf("Accept = %q, want %q", request.Header.Get("Accept"), wantAccept)
		}
		return onlineResponse(request, http.StatusOK, body, int64(len(body)), ""), nil
	})
	client := newClientUsing(transport, time.Second)
	bundle, err := client.FetchBundle(context.Background(), "https://releases.example/channels/stable/bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.ChannelManifest, testBundle().ChannelManifest) {
		t.Fatal("bundle bytes changed")
	}
	file, err := os.CreateTemp(t.TempDir(), "artifact-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("existing-prefix:"); err != nil {
		t.Fatal(err)
	}
	want := releasetrust.Artifact{
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		URL: "https://releases.example/artifact.tar", Size: int64(len(artifactRaw)), SHA256: hex.EncodeToString(digest[:]),
	}
	if err := client.FetchArtifact(context.Background(), want, file); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if wantBytes := append([]byte("existing-prefix:"), artifactRaw...); !bytes.Equal(got, wantBytes) {
		t.Fatalf("destination bytes = %q, want %q; client may have sought or truncated", got, wantBytes)
	}
}

func TestClientRejectsBundleResponseVariants(t *testing.T) {
	valid, err := Encode(testBundle())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		status        int
		body          io.ReadCloser
		contentLength int64
		encoding      string
		location      string
		match         string
	}{
		{name: "status", status: http.StatusInternalServerError, body: bodyFor(valid), contentLength: int64(len(valid)), match: "status"},
		{name: "redirect", status: http.StatusFound, body: bodyFor(nil), contentLength: 0, location: "https://evil.example/bundle.json", match: "status"},
		{name: "nil body", status: http.StatusOK, contentLength: int64(len(valid)), match: "nil Body"},
		{name: "compressed", status: http.StatusOK, body: bodyFor(valid), contentLength: int64(len(valid)), encoding: "gzip", match: "Content-Encoding"},
		{name: "declared oversize", status: http.StatusOK, body: bodyFor(valid), contentLength: MaxEncodedBundleSize + 1, match: "Content-Length"},
		{name: "actual oversize", status: http.StatusOK, body: bodyFor(bytes.Repeat([]byte{'x'}, MaxEncodedBundleSize+1)), contentLength: -1, match: "size"},
		{name: "truncated document", status: http.StatusOK, body: bodyFor(valid[:len(valid)-1]), contentLength: int64(len(valid) - 1), match: "bundle"},
		{name: "read error", status: http.StatusOK, body: &errorBody{err: errors.New("read failure")}, contentLength: -1, match: "read"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := newClientUsing(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				response := onlineResponseWithBody(request, test.status, test.body, test.contentLength, test.encoding)
				if test.location != "" {
					response.Header.Set("Location", test.location)
				}
				return response, nil
			}), time.Second)
			if _, err := client.FetchBundle(context.Background(), "https://releases.example/channels/stable/bundle.json"); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("FetchBundle error = %v, want %q", err, test.match)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}

	for name, length := range map[string]int64{"unknown": -1, "dishonest smaller": 1} {
		t.Run(name+" Content-Length accepted within bound", func(t *testing.T) {
			client := newClientUsing(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return onlineResponse(request, http.StatusOK, valid, length, ""), nil
			}), time.Second)
			if _, err := client.FetchBundle(context.Background(), "https://releases.example/channels/stable/bundle.json"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientRejectsArtifactResponseVariants(t *testing.T) {
	valid := []byte("artifact body")
	digest := sha256.Sum256(valid)
	artifact := releasetrust.Artifact{
		OS: "linux", Arch: "amd64", URL: "https://releases.example/artifact.tar",
		Size: int64(len(valid)), SHA256: hex.EncodeToString(digest[:]),
	}
	tests := []struct {
		name          string
		status        int
		body          io.ReadCloser
		contentLength int64
		encoding      string
		location      string
		match         string
	}{
		{name: "status", status: http.StatusNotFound, body: bodyFor(valid), contentLength: int64(len(valid)), match: "status"},
		{name: "redirect", status: http.StatusFound, body: bodyFor(nil), contentLength: 0, location: "https://evil.example/artifact", match: "status"},
		{name: "nil body", status: http.StatusOK, contentLength: int64(len(valid)), match: "nil Body"},
		{name: "compressed", status: http.StatusOK, body: bodyFor(valid), contentLength: int64(len(valid)), encoding: "br", match: "Content-Encoding"},
		{name: "missing length", status: http.StatusOK, body: bodyFor(valid), contentLength: -1, match: "Content-Length"},
		{name: "mismatched length", status: http.StatusOK, body: bodyFor(valid), contentLength: int64(len(valid) + 1), match: "Content-Length"},
		{name: "truncation", status: http.StatusOK, body: bodyFor(valid[:len(valid)-1]), contentLength: int64(len(valid)), match: "size"},
		{name: "overrun", status: http.StatusOK, body: bodyFor(append(append([]byte(nil), valid...), '!')), contentLength: int64(len(valid)), match: "size"},
		{name: "wrong digest", status: http.StatusOK, body: bodyFor(bytes.Repeat([]byte{'x'}, len(valid))), contentLength: int64(len(valid)), match: "SHA-256"},
		{name: "read error", status: http.StatusOK, body: &errorBody{err: errors.New("read failure")}, contentLength: int64(len(valid)), match: "stream"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := newClientUsing(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				response := onlineResponseWithBody(request, test.status, test.body, test.contentLength, test.encoding)
				if test.location != "" {
					response.Header.Set("Location", test.location)
				}
				return response, nil
			}), time.Second)
			destination, err := os.CreateTemp(t.TempDir(), "artifact-")
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			if err := client.FetchArtifact(context.Background(), artifact, destination); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("FetchArtifact error = %v, want %q", err, test.match)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestClientPropagatesArtifactWriteAndSyncErrors(t *testing.T) {
	body := []byte("artifact")
	digest := sha256.Sum256(body)
	artifact := releasetrust.Artifact{OS: "linux", Arch: "amd64", URL: "https://releases.example/artifact", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
	client := newClientUsing(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return onlineResponse(request, http.StatusOK, body, int64(len(body)), ""), nil
	}), time.Second)

	writeFailure := &testArtifactDestination{writeErr: errors.New("write failure")}
	if err := client.fetchArtifact(context.Background(), artifact, writeFailure); err == nil || !strings.Contains(err.Error(), "write failure") || writeFailure.synced {
		t.Fatalf("write failure result = %v, synced=%t", err, writeFailure.synced)
	}
	syncFailure := &testArtifactDestination{syncErr: errors.New("sync failure")}
	if err := client.fetchArtifact(context.Background(), artifact, syncFailure); err == nil || !strings.Contains(err.Error(), "sync failure") || !syncFailure.synced {
		t.Fatalf("sync failure result = %v, synced=%t", err, syncFailure.synced)
	}
}

func TestClientTimeoutCancellationAndHeaderSanitization(t *testing.T) {
	waitForContext := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client := newClientUsing(waitForContext, 10*time.Millisecond)
	if _, err := client.FetchBundle(context.Background(), "https://releases.example/channels/stable/bundle.json"); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("timeout returned %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client = newClientUsing(waitForContext, time.Second)
	if _, err := client.FetchBundle(ctx, "https://releases.example/channels/stable/bundle.json"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation returned %v", err)
	}

	valid, err := Encode(testBundle())
	if err != nil {
		t.Fatal(err)
	}
	client = newClientUsing(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return onlineResponse(request, http.StatusOK, valid, int64(len(valid)), "gzip\nforged-log-line"), nil
	}), time.Second)
	_, err = client.FetchBundle(context.Background(), "https://releases.example/channels/stable/bundle.json")
	if err == nil || strings.ContainsAny(err.Error(), "\r\n") || !strings.Contains(err.Error(), "forged-log-line") {
		t.Fatalf("multiline header error was not sanitized: %q", err)
	}
}

func TestProductionClientDisablesAmbientNetworkState(t *testing.T) {
	bundleRaw, err := Encode(testBundle())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
			t.Errorf("unsafe production request headers: %v", request.Header)
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(bundleRaw)))
		_, _ = writer.Write(bundleRaw)
	}))
	defer server.Close()

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyHit := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := proxy.Accept()
		if acceptErr == nil {
			proxyHit <- struct{}{}
			_ = connection.Close()
		}
	}()
	t.Setenv("HTTPS_PROXY", "http://"+proxy.Addr().String())
	t.Setenv("https_proxy", "http://"+proxy.Addr().String())

	httpClient := newProductionHTTPClient()
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("production transport type = %T", httpClient.Transport)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = roots
	client := &Client{http: httpClient}
	if _, err := client.FetchBundle(context.Background(), server.URL+"/bundle.json"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proxyHit:
		t.Fatal("production client used HTTPS_PROXY")
	default:
	}

	if transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 ||
		transport.MaxConnsPerHost != 1 || transport.ReadBufferSize != 32<<10 || transport.WriteBufferSize != 32<<10 {
		t.Fatalf("production transport is not hardened: %+v", transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
		len(transport.TLSClientConfig.NextProtos) != 1 || transport.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("production TLS policy = %+v", transport.TLSClientConfig)
	}
	if httpClient.Jar != nil || httpClient.Timeout <= 0 || httpClient.CheckRedirect == nil {
		t.Fatalf("production client policy = %+v", httpClient)
	}
	request, err := http.NewRequest(http.MethodGet, "https://releases.example/one", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpClient.CheckRedirect(request, []*http.Request{request}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy returned %v", err)
	}
}

type errorBody struct {
	err error
}

func (body *errorBody) Read([]byte) (int, error) { return 0, body.err }
func (body *errorBody) Close() error             { return nil }

type testArtifactDestination struct {
	bytes.Buffer
	writeErr error
	syncErr  error
	synced   bool
}

func (destination *testArtifactDestination) Write(raw []byte) (int, error) {
	if destination.writeErr != nil {
		return 0, destination.writeErr
	}
	return destination.Buffer.Write(raw)
}

func (destination *testArtifactDestination) Sync() error {
	destination.synced = true
	return destination.syncErr
}

func bodyFor(raw []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(raw))
}

func onlineResponse(request *http.Request, status int, body []byte, contentLength int64, encoding string) *http.Response {
	return onlineResponseWithBody(request, status, bodyFor(body), contentLength, encoding)
}

func onlineResponseWithBody(request *http.Request, status int, body io.ReadCloser, contentLength int64, encoding string) *http.Response {
	header := make(http.Header)
	if encoding != "" {
		header.Set("Content-Encoding", encoding)
	}
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header: header, Body: body, ContentLength: contentLength, Request: request,
	}
}
