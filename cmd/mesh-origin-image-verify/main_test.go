package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/originimage"
)

type commandRunner struct {
	raw []byte
}

func (runner commandRunner) Verify(_ context.Context, _, _, _ string) ([]byte, error) {
	return runner.raw, nil
}

func TestRunWritesExactCreateOnlyReceiptAfterVerification(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "cosign.pub")
	cosignPath := filepath.Join(directory, "cosign")
	outputPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(keyPath, []byte("public key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cosignPath, []byte("cosign binary\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	image := "registry.example.com/mesh/origin@sha256:" + digest
	payload := []byte(fmt.Sprintf(`[{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":"cosign container image signature"}}]`, digest))
	var stdout bytes.Buffer
	err := run([]string{"--image", image, "--key", keyPath, "--cosign", cosignPath, "--timeout", "1m", "--output", outputPath},
		&stdout, func() time.Time { return time.Date(2026, 7, 21, 21, 0, 0, 0, time.UTC) }, commandRunner{raw: payload})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(stored, stdout.Bytes()) {
		t.Fatalf("receipt/stdout mismatch: %q %q %v", stored, stdout.Bytes(), err)
	}
	if _, err := originimage.ParseReceipt(stored); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--image", image, "--key", keyPath, "--cosign", cosignPath, "--output", outputPath},
		&bytes.Buffer{}, func() time.Time { return time.Now().UTC() }, commandRunner{raw: payload}); err == nil {
		t.Fatal("existing receipt replacement accepted")
	}
}

func TestRunRejectsIncompleteAndAmbiguousArgumentsWithoutOutput(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"--image", "registry.example.com/mesh/origin:latest", "--key", "/key"},
		{"--image", "x", "--key", "/key", "extra"},
		{"--image", "x", "--key", "/key", "--output", ""},
	} {
		var output bytes.Buffer
		if err := run(arguments, &output, func() time.Time { return time.Now().UTC() }, commandRunner{}); err == nil || output.Len() != 0 {
			t.Fatalf("run(%q) = output %q, error %v", arguments, output.Bytes(), err)
		}
	}
}

func TestRunEmitsNoReceiptWhenCosignPayloadDoesNotBindImage(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "cosign.pub")
	cosignPath := filepath.Join(directory, "cosign")
	outputPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(keyPath, []byte("public key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cosignPath, []byte("cosign binary\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	wrong := strings.Repeat("b", 64)
	payload := []byte(fmt.Sprintf(`[{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":"cosign container image signature"}}]`, wrong))
	var stdout bytes.Buffer
	err := run([]string{
		"--image", "registry.example.com/mesh/origin@sha256:" + digest,
		"--key", keyPath, "--cosign", cosignPath, "--output", outputPath,
	}, &stdout, func() time.Time { return time.Now().UTC() }, commandRunner{raw: payload})
	if err == nil || stdout.Len() != 0 {
		t.Fatalf("unbound payload = output %q, error %v", stdout.Bytes(), err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed verification left a receipt: %v", statErr)
	}
}
