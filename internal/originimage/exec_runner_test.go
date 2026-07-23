//go:build !windows

package originimage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerUsesExactClaimCheckingArgumentsAndSnapshot(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "cosign.pub")
	cosignPath := filepath.Join(directory, "cosign")
	if err := os.WriteFile(keyPath, []byte("public key bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
[ "$#" -eq 7 ]
[ "$1" = "verify" ]
[ "$2" = "--key" ]
[ -f "$3" ]
[ "$(cat "$3")" = "public key bytes" ]
[ "$4" = "--check-claims=true" ]
[ "$5" = "--output" ]
[ "$6" = "json" ]
digest="${7##*@sha256:}"
printf '[{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":"cosign container image signature"}}]' "$digest"
`
	if err := os.WriteFile(cosignPath, []byte(script), 0o555); err != nil {
		t.Fatal(err)
	}
	image := "registry.example.com/mesh/origin@sha256:" + strings.Repeat("d", 64)
	receipt, err := Verify(context.Background(), Config{
		Image: image, PublicKey: keyPath, CosignPath: cosignPath, Timeout: time.Minute,
	}, func() time.Time { return testTime }, ExecRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Image != image || receipt.SignatureCount != 1 {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}
