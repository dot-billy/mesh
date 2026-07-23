//go:build linux

package originaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/onlinerelease"
	"mesh/internal/releaseorigin"
)

var auditTestNow = time.Date(2026, 7, 21, 16, 0, 0, 123456789, time.UTC)

type responseMutation func(request *http.Request, header http.Header, status *int, body *[]byte)

type auditFixture struct {
	config         Config
	generationPath string
	index          releaseorigin.Index
	server         *httptest.Server
}

func TestAuditExactPublicGenerationAndCanonicalReceipt(t *testing.T) {
	fixture := newAuditFixture(t, nil)
	receipt, err := Audit(context.Background(), fixture.config, func() time.Time { return auditTestNow })
	if err != nil {
		t.Fatal(err)
	}
	generation, err := releaseorigin.InspectGeneration(fixture.generationPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Generation != generation.Generation || receipt.IndexSHA256 != generation.IndexSHA256 || receipt.Origin != fixture.server.URL {
		t.Fatalf("unexpected audit binding: %#v", receipt)
	}
	if receipt.ObjectCount != len(fixture.index.Objects) || receipt.TotalSize != generation.TotalSize || receipt.RequestCount != 2*len(fixture.index.Objects)+3 {
		t.Fatalf("unexpected audit totals: %#v", receipt)
	}
	if receipt.CheckedAt != auditTestNow.Format(time.RFC3339Nano) || !validSHA256(receipt.CertificateSHA256) {
		t.Fatalf("unexpected audit time/certificate: %#v", receipt)
	}
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(raw)
	if err != nil || parsed != receipt {
		t.Fatalf("receipt round trip = %#v, %v", parsed, err)
	}
	outputPath := filepath.Join(t.TempDir(), "audit.json")
	if err := WriteNewReceipt(outputPath, raw); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("stored receipt = %q, %v", stored, err)
	}
	if err := WriteNewReceipt(outputPath, raw); err == nil {
		t.Fatal("audit receipt replacement accepted")
	}
	realParent := t.TempDir()
	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewReceipt(filepath.Join(linkedParent, "audit.json"), raw); err == nil {
		t.Fatal("audit receipt symlinked parent accepted")
	}
}

func TestAuditRejectsPublicRouteDriftWithoutReceipt(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutation responseMutation
	}{
		{
			name: "object body",
			mutation: func(request *http.Request, _ http.Header, _ *int, body *[]byte) {
				if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "mesh-linux-bundle.tar") && len(*body) > 0 {
					(*body)[0] ^= 0xff
				}
			},
		},
		{
			name: "cache policy",
			mutation: func(request *http.Request, header http.Header, _ *int, _ *[]byte) {
				if request.Method == http.MethodHead && strings.HasSuffix(request.URL.Path, "mesh-linux-bundle.tar") {
					header.Set("Cache-Control", "public, max-age=1")
				}
			},
		},
		{
			name: "etag",
			mutation: func(request *http.Request, header http.Header, _ *int, _ *[]byte) {
				if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "mesh-linux-bundle.tar") {
					header.Set("ETag", `"sha256:`+strings.Repeat("0", 64)+`"`)
				}
			},
		},
		{
			name: "readiness body",
			mutation: func(request *http.Request, header http.Header, _ *int, body *[]byte) {
				if request.URL.Path == "/readyz" {
					*body = []byte("{\"status\":\"ok\"}\n")
					header.Del("Content-Length")
				}
			},
		},
		{
			name: "unlisted exposure",
			mutation: func(request *http.Request, header http.Header, status *int, body *[]byte) {
				if strings.HasPrefix(request.URL.Path, "/mesh-origin-audit/") {
					*status = http.StatusOK
					*body = []byte("{\"status\":\"ready\"}\n")
					header.Del("Content-Length")
				}
			},
		},
		{
			name: "write accepted",
			mutation: func(request *http.Request, header http.Header, status *int, body *[]byte) {
				if request.Method == http.MethodPost {
					*status = http.StatusOK
					*body = []byte("{\"status\":\"ready\"}\n")
					header.Del("Content-Length")
				}
			},
		},
		{
			name: "redirect",
			mutation: func(request *http.Request, header http.Header, status *int, _ *[]byte) {
				if request.Method == http.MethodHead && strings.HasSuffix(request.URL.Path, "mesh-linux-bundle.tar") {
					*status = http.StatusFound
					header.Set("Location", "https://example.invalid/redirected")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditFixture(t, test.mutation)
			if receipt, err := Audit(context.Background(), fixture.config, func() time.Time { return auditTestNow }); err == nil || receipt != (Receipt{}) {
				t.Fatalf("drift audit = %#v, %v", receipt, err)
			}
		})
	}
}

func TestAuditRejectsLocalGenerationAndConfigurationAmbiguity(t *testing.T) {
	fixture := newAuditFixture(t, nil)
	artifactPath := objectPath(filepath.Join(fixture.generationPath, releaseorigin.GenerationRepoName), fixture.index.Objects[1].Path)
	if err := os.Chmod(artifactPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if receipt, err := Audit(context.Background(), fixture.config, func() time.Time { return auditTestNow }); err == nil || receipt != (Receipt{}) {
		t.Fatalf("writable local generation audit = %#v, %v", receipt, err)
	}

	for name, mutate := range map[string]func(*Config){
		"HTTP":         func(config *Config) { config.Origin = strings.Replace(config.Origin, "https://", "http://", 1) },
		"path":         func(config *Config) { config.Origin += "/readyz" },
		"query":        func(config *Config) { config.Origin += "?x=1" },
		"relative CA":  func(config *Config) { config.CAFile = "ca.pem" },
		"zero timeout": func(config *Config) { config.Timeout = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			fresh := newAuditFixture(t, nil)
			config := fresh.config
			mutate(&config)
			if receipt, err := Audit(context.Background(), config, func() time.Time { return auditTestNow }); err == nil || receipt != (Receipt{}) {
				t.Fatalf("ambiguous config audit = %#v, %v", receipt, err)
			}
		})
	}
	if receipt, err := Audit(nil, fixture.config, func() time.Time { return auditTestNow }); err == nil || receipt != (Receipt{}) {
		t.Fatalf("nil-context audit = %#v, %v", receipt, err)
	}
	if receipt, err := Audit(context.Background(), fixture.config, func() time.Time { return auditTestNow.In(time.FixedZone("offset", 0)) }); err == nil || receipt != (Receipt{}) {
		t.Fatalf("non-UTC-time audit = %#v, %v", receipt, err)
	}
	if receipt, err := Audit(context.Background(), fixture.config, nil); err == nil || receipt != (Receipt{}) {
		t.Fatalf("nil-clock audit = %#v, %v", receipt, err)
	}
}

func TestReceiptStrictCanonicalValidation(t *testing.T) {
	receipt := Receipt{
		Schema: ReceiptSchema, Generation: strings.Repeat("a", 64), IndexSHA256: strings.Repeat("a", 64),
		Origin: "https://origin.example", CertificateSHA256: strings.Repeat("b", 64),
		CertificateNotAfter: "2026-08-21T16:00:00Z", CheckedAt: "2026-07-21T16:00:00Z",
		ObjectCount: 2, TotalSize: 123, RequestCount: 7,
	}
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"missing newline": bytes.TrimSuffix(raw, []byte("\n")),
		"unknown field":   bytes.Replace(raw, []byte("}\n"), []byte(",\"unknown\":true}\n"), 1),
		"wrong count":     bytes.Replace(raw, []byte(`"request_count":7`), []byte(`"request_count":6`), 1),
		"expired":         bytes.Replace(raw, []byte("2026-08-21T16:00:00Z"), []byte("2026-06-21T16:00:00Z"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReceipt(candidate); err == nil {
				t.Fatal("inexact audit receipt accepted")
			}
		})
	}
}

func newAuditFixture(t *testing.T, mutation responseMutation) auditFixture {
	t.Helper()
	sourceRoot := t.TempDir()
	channelPath := "/channels/stable/bundle.json"
	artifactPath := "/releases/1.0.0/mesh-linux-bundle.tar"
	for _, path := range []string{channelPath, artifactPath} {
		if err := os.MkdirAll(filepath.Dir(objectPath(sourceRoot, path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundle, err := onlinerelease.Encode(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   []byte("channel\n"),
		ChannelSignatures: [][]byte{[]byte("channel-signature")},
		ReleaseManifest:   []byte("release\n"),
		ReleaseSignatures: [][]byte{[]byte("release-signature")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath(sourceRoot, channelPath), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath(sourceRoot, artifactPath), []byte("signed artifact bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := releaseorigin.BuildIndex(sourceRoot, []string{artifactPath, channelPath})
	if err != nil {
		t.Fatal(err)
	}
	indexRaw, err := releaseorigin.Encode(index)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(t.TempDir(), "origin-index.json")
	if err := releaseorigin.WriteNewIndex(indexPath, indexRaw); err != nil {
		t.Fatal(err)
	}
	generationsRoot := filepath.Join(t.TempDir(), "generations")
	if err := os.Mkdir(generationsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	_, generationPath, err := releaseorigin.PublishGeneration(sourceRoot, indexPath, generationsRoot)
	if err != nil {
		t.Fatal(err)
	}
	allowGenerationCleanup(t, generationPath)
	store, err := releaseorigin.OpenFiles(filepath.Join(generationPath, releaseorigin.GenerationRepoName), filepath.Join(generationPath, releaseorigin.GenerationIndexName))
	if err != nil {
		t.Fatal(err)
	}
	handler := store.Handler()
	if mutation != nil {
		handler = mutateResponses(handler, mutation)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = store.Close() })
	certificate := server.Certificate()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caRaw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caPath, caRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	return auditFixture{
		config:         Config{GenerationPath: generationPath, Origin: server.URL, CAFile: caPath, Timeout: 10 * time.Second},
		generationPath: generationPath, index: index, server: server,
	}
}

func mutateResponses(base http.Handler, mutation responseMutation) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder := httptest.NewRecorder()
		base.ServeHTTP(recorder, request)
		header := recorder.Header().Clone()
		status := recorder.Code
		body := append([]byte(nil), recorder.Body.Bytes()...)
		mutation(request, header, &status, &body)
		for name, values := range header {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(status)
		if request.Method != http.MethodHead {
			_, _ = writer.Write(body)
		}
	})
}

func objectPath(root, path string) string {
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, "/")))
}

func allowGenerationCleanup(t *testing.T, generationPath string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(generationPath, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
}

func TestAuditCertificateFingerprintMatchesLeaf(t *testing.T) {
	fixture := newAuditFixture(t, nil)
	receipt, err := Audit(context.Background(), fixture.config, func() time.Time { return auditTestNow })
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture.server.Certificate().Raw)
	if receipt.CertificateSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("certificate SHA-256 = %s", receipt.CertificateSHA256)
	}
}
