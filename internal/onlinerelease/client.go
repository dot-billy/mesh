package onlinerelease

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	releasetrust "mesh/internal/release"
)

const (
	connectTimeout        = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 15 * time.Second
	totalDownloadTimeout  = 2 * time.Minute
	maxResponseHeaders    = 64 << 10
	onlineBundleAccept    = "application/json"
	artifactAccept        = "application/octet-stream"
	onlineUserAgent       = "mesh-install/online-release-v1"
)

type Client struct {
	http *http.Client
}

func NewClient() *Client {
	return &Client{http: newProductionHTTPClient()}
}

func newClientUsing(transport http.RoundTripper, timeout time.Duration) *Client {
	return &Client{http: &http.Client{
		Transport: transport,
		Timeout:   timeout,
		Jar:       nil,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func newProductionHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		ExpectContinueTimeout:  0,
		MaxResponseHeaderBytes: maxResponseHeaders,
		MaxConnsPerHost:        1,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		WriteBufferSize:        32 << 10,
		ReadBufferSize:         32 << 10,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   totalDownloadTimeout,
		Jar:       nil,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (client *Client) FetchBundle(ctx context.Context, address string) (Bundle, error) {
	canonical, err := CanonicalBundleURL(address)
	if err != nil {
		return Bundle{}, err
	}
	response, err := client.get(ctx, canonical, onlineBundleAccept)
	if err != nil {
		return Bundle{}, fmt.Errorf("request online release bundle: %w", err)
	}
	if response.Body == nil {
		return Bundle{}, errors.New("online release bundle response has no body")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Bundle{}, fmt.Errorf("online release bundle status is %d (%s), want 200", response.StatusCode, cleanHTTPText(response.Status))
	}
	if err := requireIdentityEncoding(response.Header); err != nil {
		return Bundle{}, fmt.Errorf("online release bundle %w", err)
	}
	if response.ContentLength < -1 || response.ContentLength > MaxEncodedBundleSize {
		return Bundle{}, fmt.Errorf("online release bundle Content-Length is %d, maximum is %d", response.ContentLength, MaxEncodedBundleSize)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxEncodedBundleSize+1))
	if err != nil {
		return Bundle{}, fmt.Errorf("read online release bundle: %s", cleanHTTPText(err.Error()))
	}
	if len(raw) > MaxEncodedBundleSize {
		return Bundle{}, fmt.Errorf("online release bundle size exceeds %d bytes", MaxEncodedBundleSize)
	}
	bundle, err := Parse(raw)
	if err != nil {
		return Bundle{}, fmt.Errorf("parse online release bundle: %w", err)
	}
	return bundle, nil
}

func (client *Client) FetchArtifact(ctx context.Context, artifact releasetrust.Artifact, destination *os.File) error {
	if destination == nil {
		return errors.New("artifact destination is nil")
	}
	return client.fetchArtifact(ctx, artifact, destination)
}

type artifactDestination interface {
	io.Writer
	Sync() error
}

func (client *Client) fetchArtifact(ctx context.Context, artifact releasetrust.Artifact, destination artifactDestination) error {
	if destination == nil {
		return errors.New("artifact destination is nil")
	}
	if err := releasetrust.ValidateArtifactReference(artifact); err != nil {
		return fmt.Errorf("invalid artifact reference: %w", err)
	}
	response, err := client.get(ctx, artifact.URL, artifactAccept)
	if err != nil {
		return fmt.Errorf("request authenticated artifact: %w", err)
	}
	if response.Body == nil {
		return errors.New("authenticated artifact response has no body")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("authenticated artifact status is %d (%s), want 200", response.StatusCode, cleanHTTPText(response.Status))
	}
	if err := requireIdentityEncoding(response.Header); err != nil {
		return fmt.Errorf("authenticated artifact %w", err)
	}
	if response.ContentLength != artifact.Size {
		return fmt.Errorf("authenticated artifact Content-Length is %d, want %d", response.ContentLength, artifact.Size)
	}
	expected, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(expected) != sha256.Size {
		return errors.New("internal validated artifact digest decoding failure")
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(response.Body, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("stream authenticated artifact: %s", cleanHTTPText(err.Error()))
	}
	if written != artifact.Size {
		return fmt.Errorf("authenticated artifact size is %d bytes, want %d", written, artifact.Size)
	}
	actual := hasher.Sum(nil)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return fmt.Errorf("authenticated artifact SHA-256 is %s, want %s", hex.EncodeToString(actual), artifact.SHA256)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync authenticated artifact: %w", err)
	}
	return nil
}

func (client *Client) get(ctx context.Context, address, accept string) (*http.Response, error) {
	if client == nil || client.http == nil {
		return nil, errors.New("online release HTTP client is nil")
	}
	if ctx == nil {
		return nil, errors.New("request context is nil")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fmt.Errorf("build GET request: %w", err)
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("User-Agent", onlineUserAgent)
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("HTTP transport returned no response")
	}
	return response, nil
}

func requireIdentityEncoding(header http.Header) error {
	values := header.Values("Content-Encoding")
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.TrimSpace(token) != "" && !strings.EqualFold(strings.TrimSpace(token), "identity") {
				return fmt.Errorf("Content-Encoding %q is not allowed", cleanHTTPText(value))
			}
		}
	}
	return nil
}

func cleanHTTPText(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
}
