package originimage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var testTime = time.Date(2026, 7, 21, 20, 30, 0, 123456789, time.UTC)

type recordingRunner struct {
	raw        []byte
	err        error
	cosignPath string
	keyPath    string
	keyRaw     []byte
	image      string
}

func (runner *recordingRunner) Verify(_ context.Context, cosignPath, keyPath, image string) ([]byte, error) {
	runner.cosignPath = cosignPath
	runner.keyPath = keyPath
	runner.image = image
	runner.keyRaw, _ = os.ReadFile(keyPath)
	return runner.raw, runner.err
}

func TestParseReferenceRequiresExactRegistryRepositoryDigest(t *testing.T) {
	want := "registry.example.com:5443/mesh/release-origin@sha256:" + testDigest
	reference, err := ParseReference(want)
	if err != nil || reference.Canonical != want || reference.Repository != "registry.example.com:5443/mesh/release-origin" || reference.Digest != testDigest {
		t.Fatalf("ParseReference = %#v, %v", reference, err)
	}
	for _, value := range []string{
		"mesh/release-origin@sha256:" + testDigest,
		"registry.example.com/mesh/release-origin:latest",
		"registry.example.com/mesh/release-origin@sha256:" + strings.ToUpper(testDigest),
		"registry.example.com:0/mesh/release-origin@sha256:" + testDigest,
		"registry.example.com:65536/mesh/release-origin@sha256:" + testDigest,
		"registry.example.com/mesh//release-origin@sha256:" + testDigest,
		" registry.example.com/mesh/release-origin@sha256:" + testDigest,
	} {
		if _, err := ParseReference(value); err == nil {
			t.Fatalf("inexact image reference accepted: %q", value)
		}
	}
}

func TestVerifyBindsExactImageKeyCosignAndSignatures(t *testing.T) {
	directory := t.TempDir()
	keyRaw := []byte("-----BEGIN PUBLIC KEY-----\nexact independent key\n-----END PUBLIC KEY-----\n")
	keyPath := filepath.Join(directory, "cosign.pub")
	cosignPath := filepath.Join(directory, "cosign")
	if err := os.WriteFile(keyPath, keyRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	cosignRaw := []byte("exact cosign executable fixture\n")
	if err := os.WriteFile(cosignPath, cosignRaw, 0o555); err != nil {
		t.Fatal(err)
	}
	image := "registry.example.com/mesh/release-origin@sha256:" + testDigest
	runner := &recordingRunner{raw: cosignPayloads(testDigest, 2)}
	receipt, err := Verify(context.Background(), Config{
		Image: image, PublicKey: keyPath, CosignPath: cosignPath, Timeout: time.Minute,
	}, func() time.Time { return testTime }, runner)
	if err != nil {
		t.Fatal(err)
	}
	if runner.cosignPath != cosignPath || runner.image != image || !bytes.Equal(runner.keyRaw, keyRaw) {
		t.Fatalf("runner inputs = cosign %q image %q key %q", runner.cosignPath, runner.image, runner.keyRaw)
	}
	if _, err := os.Stat(runner.keyPath); !os.IsNotExist(err) {
		t.Fatalf("temporary key snapshot remains: %v", err)
	}
	wantKey := sha256.Sum256(keyRaw)
	wantCosign := sha256.Sum256(cosignRaw)
	if receipt.Schema != ReceiptSchema || receipt.Image != image || receipt.ManifestSHA256 != testDigest ||
		receipt.PublicKeySHA256 != hex.EncodeToString(wantKey[:]) || receipt.CosignSHA256 != hex.EncodeToString(wantCosign[:]) ||
		receipt.VerifiedAt != testTime.Format(time.RFC3339Nano) || receipt.SignatureCount != 2 {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(raw)
	if err != nil || parsed != receipt {
		t.Fatalf("receipt round trip = %#v, %v", parsed, err)
	}
	outputPath := filepath.Join(directory, "receipt.json")
	if err := WriteNewReceipt(outputPath, raw); err != nil {
		t.Fatal(err)
	}
	if stored, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("stored receipt = %q, %v", stored, err)
	}
	if err := WriteNewReceipt(outputPath, raw); err == nil {
		t.Fatal("receipt replacement accepted")
	}
}

func TestVerifyRejectsAmbiguityAndUnboundCosignOutput(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "cosign.pub")
	cosignPath := filepath.Join(directory, "cosign")
	if err := os.WriteFile(keyPath, []byte("public key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cosignPath, []byte("cosign\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	image := "registry.example.com/mesh/origin@sha256:" + testDigest
	base := Config{Image: image, PublicKey: keyPath, CosignPath: cosignPath, Timeout: time.Minute}
	wrongDigest := strings.Repeat("a", 64)
	for name, raw := range map[string][]byte{
		"empty":        nil,
		"not JSON":     []byte("no"),
		"empty list":   []byte("[]"),
		"wrong digest": cosignPayloads(wrongDigest, 1),
		"wrong type":   []byte(fmt.Sprintf(`[{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":"other"}}]`, testDigest)),
		"duplicate":    []byte(fmt.Sprintf(`[{"critical":{"image":{"docker-manifest-digest":"sha256:%s","docker-manifest-digest":"sha256:%s"},"type":"cosign container image signature"}}]`, testDigest, testDigest)),
	} {
		t.Run(name, func(t *testing.T) {
			runner := &recordingRunner{raw: raw}
			if receipt, err := Verify(context.Background(), base, func() time.Time { return testTime }, runner); err == nil || receipt != (Receipt{}) {
				t.Fatalf("Verify = %#v, %v", receipt, err)
			}
		})
	}

	for name, mutate := range map[string]func(*Config){
		"mutable image": func(config *Config) { config.Image = "registry.example.com/mesh/origin:latest" },
		"zero timeout":  func(config *Config) { config.Timeout = 0 },
		"relative key":  func(config *Config) { config.PublicKey = "cosign.pub" },
		"relative tool": func(config *Config) { config.CosignPath = "cosign" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if receipt, err := Verify(context.Background(), config, func() time.Time { return testTime }, &recordingRunner{raw: cosignPayloads(testDigest, 1)}); err == nil || receipt != (Receipt{}) {
				t.Fatalf("Verify = %#v, %v", receipt, err)
			}
		})
	}

	linkedKey := filepath.Join(directory, "linked.pub")
	if err := os.Symlink(keyPath, linkedKey); err != nil {
		t.Fatal(err)
	}
	linked := base
	linked.PublicKey = linkedKey
	if _, err := Verify(context.Background(), linked, func() time.Time { return testTime }, &recordingRunner{raw: cosignPayloads(testDigest, 1)}); err == nil {
		t.Fatal("symlinked trust anchor accepted")
	}

	realParent := t.TempDir()
	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	receipt, err := Verify(context.Background(), base, func() time.Time { return testTime }, &recordingRunner{raw: cosignPayloads(testDigest, 1)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := EncodeReceipt(receipt)
	if err := WriteNewReceipt(filepath.Join(linkedParent, "receipt.json"), raw); err == nil {
		t.Fatal("symlinked receipt parent accepted")
	}
}

func TestReceiptRejectsNonCanonicalBytes(t *testing.T) {
	receipt := Receipt{
		Schema: ReceiptSchema, Image: "registry.example.com/mesh/origin@sha256:" + testDigest,
		ManifestSHA256: testDigest, PublicKeySHA256: strings.Repeat("a", 64), CosignSHA256: strings.Repeat("b", 64),
		VerifiedAt: testTime.Format(time.RFC3339Nano), SignatureCount: 1,
	}
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"missing newline": bytes.TrimSuffix(raw, []byte("\n")),
		"unknown field":   bytes.Replace(raw, []byte("}\n"), []byte(",\"unknown\":true}\n"), 1),
		"wrong digest":    bytes.Replace(raw, []byte(`"manifest_sha256":"`+testDigest+`"`), []byte(`"manifest_sha256":"`+strings.Repeat("c", 64)+`"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReceipt(candidate); err == nil {
				t.Fatal("noncanonical receipt accepted")
			}
		})
	}
}

func cosignPayloads(digest string, count int) []byte {
	items := make([]string, count)
	for index := range items {
		items[index] = fmt.Sprintf(`{"critical":{"identity":{"docker-reference":"registry.example.com/mesh/origin"},"image":{"docker-manifest-digest":"sha256:%s"},"type":"cosign container image signature"},"optional":null}`, digest)
	}
	return []byte("[" + strings.Join(items, ",") + "]")
}
