package originaudit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mesh/internal/releaseorigin"
)

const (
	DefaultTimeout        = 10 * time.Minute
	MaximumTimeout        = time.Hour
	maximumCAFileSize     = 1 << 20
	maximumStatusBody     = 256
	maxResponseHeaders    = 64 << 10
	auditUserAgent        = "mesh-origin-audit/v1"
	channelCacheControl   = "public, max-age=30, must-revalidate, no-transform"
	immutableCacheControl = "public, max-age=31536000, immutable, no-transform"
)

type Config struct {
	GenerationPath string
	Origin         string
	CAFile         string
	Timeout        time.Duration
}

type certificateEvidence struct {
	sha256   string
	notAfter string
}

func Audit(ctx context.Context, config Config, clock func() time.Time) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, errors.New("release origin audit context is nil")
	}
	if clock == nil {
		return Receipt{}, errors.New("release origin audit clock is nil")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}
	if config.Timeout <= 0 || config.Timeout > MaximumTimeout {
		return Receipt{}, errors.New("release origin audit timeout must be positive and no more than one hour")
	}
	origin, err := canonicalOrigin(config.Origin)
	if err != nil {
		return Receipt{}, err
	}
	generationReceipt, index, err := releaseorigin.LoadGeneration(config.GenerationPath)
	if err != nil {
		return Receipt{}, fmt.Errorf("inspect expected release origin generation: %w", err)
	}
	roots, err := loadRoots(config.CAFile)
	if err != nil {
		return Receipt{}, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: min(config.Timeout, 10*time.Second), KeepAlive: -1}).DialContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:    min(config.Timeout, 10*time.Second),
		ResponseHeaderTimeout:  min(config.Timeout, 15*time.Second),
		MaxResponseHeaderBytes: maxResponseHeaders,
		MaxConnsPerHost:        1,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		WriteBufferSize:        32 << 10,
		ReadBufferSize:         32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		Jar:       nil,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("release origin audit redirects are not accepted")
		},
	}
	deadlineContext, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	var certificate certificateEvidence
	if err := verifyStatus(deadlineContext, client, origin+"/readyz", http.MethodGet, http.StatusOK, "ready", "", &certificate); err != nil {
		return Receipt{}, fmt.Errorf("verify release origin readiness: %w", err)
	}
	for _, object := range index.Objects {
		if err := verifyObject(deadlineContext, client, origin, object, &certificate); err != nil {
			return Receipt{}, err
		}
	}
	unlistedPath := "/mesh-origin-audit/" + generationReceipt.Generation
	if err := verifyStatus(deadlineContext, client, origin+unlistedPath, http.MethodGet, http.StatusNotFound, "not_found", "", &certificate); err != nil {
		return Receipt{}, fmt.Errorf("verify release origin unlisted route: %w", err)
	}
	if err := verifyStatus(deadlineContext, client, origin+index.Objects[0].Path, http.MethodPost, http.StatusMethodNotAllowed, "method_not_allowed", "GET, HEAD", &certificate); err != nil {
		return Receipt{}, fmt.Errorf("verify release origin write rejection: %w", err)
	}
	finalReceipt, err := releaseorigin.InspectGeneration(config.GenerationPath)
	if err != nil {
		return Receipt{}, fmt.Errorf("reinspect expected release origin generation: %w", err)
	}
	if finalReceipt != generationReceipt {
		return Receipt{}, errors.New("expected release origin generation changed during external audit")
	}
	checkedAt := clock()
	if checkedAt.IsZero() || checkedAt.Location() != time.UTC {
		return Receipt{}, errors.New("release origin audit time must be explicit UTC")
	}
	receipt := Receipt{
		Schema: ReceiptSchema, Generation: generationReceipt.Generation, IndexSHA256: generationReceipt.IndexSHA256,
		Origin: origin, CertificateSHA256: certificate.sha256, CertificateNotAfter: certificate.notAfter,
		CheckedAt: checkedAt.Format(time.RFC3339Nano), ObjectCount: generationReceipt.ObjectCount,
		TotalSize: generationReceipt.TotalSize, RequestCount: 2*generationReceipt.ObjectCount + 3,
	}
	if _, err := EncodeReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func canonicalOrigin(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", errors.New("release origin audit origin must be a canonical HTTPS base URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("release origin audit origin must be an exact HTTPS base URL without credentials, path, query, or fragment")
	}
	if parsed.Host != strings.ToLower(parsed.Host) || strings.HasSuffix(parsed.Hostname(), ".") || strings.Contains(parsed.Hostname(), "%") || parsed.String() != value {
		return "", errors.New("release origin audit origin host is not canonical")
	}
	return value, nil
}

func verifyObject(ctx context.Context, client *http.Client, origin string, object releaseorigin.Object, certificate *certificateEvidence) error {
	address := origin + object.Path
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		response, err := request(ctx, client, method, address, object.ContentType)
		if err != nil {
			return fmt.Errorf("request release origin object %q with %s: %w", object.Path, method, err)
		}
		if err := verifyCommonResponse(response, http.StatusOK, certificate); err != nil {
			_ = response.Body.Close()
			return fmt.Errorf("verify release origin object %q %s: %w", object.Path, method, err)
		}
		expectedCache := immutableCacheControl
		if object.Cache == releaseorigin.CacheChannel {
			expectedCache = channelCacheControl
		}
		if err := requireSingleHeader(response.Header, "Content-Type", object.ContentType); err != nil {
			_ = response.Body.Close()
			return fmt.Errorf("verify release origin object %q %s: %w", object.Path, method, err)
		}
		if err := requireSingleHeader(response.Header, "Cache-Control", expectedCache); err != nil {
			_ = response.Body.Close()
			return fmt.Errorf("verify release origin object %q %s: %w", object.Path, method, err)
		}
		if err := requireSingleHeader(response.Header, "ETag", `"sha256:`+object.SHA256+`"`); err != nil {
			_ = response.Body.Close()
			return fmt.Errorf("verify release origin object %q %s: %w", object.Path, method, err)
		}
		if err := requireSingleHeader(response.Header, "Content-Length", strconv.FormatInt(object.Size, 10)); err != nil || response.ContentLength != object.Size {
			_ = response.Body.Close()
			return fmt.Errorf("verify release origin object %q %s: invalid content length", object.Path, method)
		}
		if method == http.MethodHead {
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || len(raw) != 0 {
				return fmt.Errorf("verify release origin object %q HEAD: unexpected body", object.Path)
			}
			continue
		}
		expectedDigest, _ := hex.DecodeString(object.SHA256)
		hasher := sha256.New()
		written, readErr := io.Copy(hasher, io.LimitReader(response.Body, object.Size+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || written != object.Size {
			return fmt.Errorf("verify release origin object %q GET: read %d of %d bytes", object.Path, written, object.Size)
		}
		actualDigest := hasher.Sum(nil)
		if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
			return fmt.Errorf("verify release origin object %q GET: SHA-256 is %s, want %s", object.Path, hex.EncodeToString(actualDigest), object.SHA256)
		}
	}
	return nil
}

func verifyStatus(ctx context.Context, client *http.Client, address, method string, statusCode int, status, allow string, certificate *certificateEvidence) error {
	response, err := request(ctx, client, method, address, releaseorigin.ContentTypeJSON)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := verifyCommonResponse(response, statusCode, certificate); err != nil {
		return err
	}
	if err := requireSingleHeader(response.Header, "Content-Type", releaseorigin.ContentTypeJSON); err != nil {
		return err
	}
	if err := requireSingleHeader(response.Header, "Cache-Control", "no-store"); err != nil {
		return err
	}
	if allow != "" {
		if err := requireSingleHeader(response.Header, "Allow", allow); err != nil {
			return err
		}
	} else if response.Header.Get("Allow") != "" {
		return errors.New("unexpected Allow header")
	}
	expected := []byte("{\"status\":\"" + status + "\"}\n")
	if err := requireSingleHeader(response.Header, "Content-Length", strconv.Itoa(len(expected))); err != nil || response.ContentLength != int64(len(expected)) {
		return errors.New("status response Content-Length is not exact")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumStatusBody+1))
	if err != nil || subtle.ConstantTimeCompare(raw, expected) != 1 {
		return errors.New("status response body is not exact")
	}
	return nil
}

func request(ctx context.Context, client *http.Client, method, address, accept string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, address, nil)
	if err != nil {
		return nil, errors.New("construct release origin audit request")
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("User-Agent", auditUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("release origin audit transport returned an incomplete response")
	}
	return response, nil
}

func verifyCommonResponse(response *http.Response, expectedStatus int, certificate *certificateEvidence) error {
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("HTTP status is %d, want %d", response.StatusCode, expectedStatus)
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 {
		return errors.New("HTTP protocol is not 1.1")
	}
	if response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
		return errors.New("response lacks verified TLS evidence")
	}
	leaf := response.TLS.PeerCertificates[0]
	digest := sha256.Sum256(leaf.Raw)
	observed := certificateEvidence{sha256: hex.EncodeToString(digest[:]), notAfter: leaf.NotAfter.UTC().Format(time.RFC3339Nano)}
	if certificate.sha256 == "" {
		*certificate = observed
	} else if *certificate != observed {
		return errors.New("TLS leaf certificate changed during audit")
	}
	for name, value := range map[string]string{
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
	} {
		if err := requireSingleHeader(response.Header, name, value); err != nil {
			return err
		}
	}
	if len(response.TransferEncoding) != 0 || response.Header.Get("Content-Encoding") != "" || response.Header.Get("Location") != "" || response.Header.Get("Set-Cookie") != "" {
		return errors.New("response contains forbidden transfer or state headers")
	}
	return nil
}

func requireSingleHeader(header http.Header, name, expected string) error {
	values := header.Values(name)
	if len(values) != 1 || values[0] != expected {
		return fmt.Errorf("%s header is %q, want one exact %q", name, values, expected)
	}
	return nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("release origin audit CA file must be a clean absolute path")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximumCAFileSize {
		return nil, errors.New("release origin audit CA file must be one bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open release origin audit CA file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !sameFile(before, after) {
		return nil, errors.New("release origin audit CA file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumCAFileSize+1))
	if err != nil || len(raw) < 1 || len(raw) > maximumCAFileSize {
		return nil, errors.New("read bounded release origin audit CA file")
	}
	final, err := file.Stat()
	if err != nil || !sameFile(after, final) {
		return nil, errors.New("release origin audit CA file changed while reading")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errors.New("release origin audit CA file contains no trusted certificate")
	}
	return roots, nil
}

func sameFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
