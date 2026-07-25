//go:build linux

package linuxinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	releasetrust "mesh/internal/release"
)

func TestCaptureArtifactUsesPrivateUnlinkedSnapshot(t *testing.T) {
	body := []byte("threshold-authenticated bundle bytes")
	digest := sha256.Sum256(body)
	source := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(source, body, 0o644); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	captured, err := CaptureArtifact(source, releasetrust.Artifact{Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}, root)
	if err != nil {
		t.Fatal(err)
	}
	defer captured.Close()
	if _, err := captured.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("captured artifact descriptor remained writable")
	}
	if err := os.WriteFile(source, []byte("attacker replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(captured)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("captured bytes = %q, want %q", got, body)
	}
	entries, err := os.ReadDir(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("named private artifact residue remains: %v", entries)
	}
}

func TestCaptureArtifactRejectsHashMismatchAndSymlink(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	source := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(source, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureArtifact(source, releasetrust.Artifact{Size: 4, SHA256: string(make([]byte, 64))}, root); err == nil {
		t.Fatal("wrong artifact hash accepted")
	}
	link := source + ".link"
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureArtifact(link, releasetrust.Artifact{}, root); err == nil {
		t.Fatal("symlink artifact accepted")
	}
	entries, err := os.ReadDir(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed capture left residue: %v", entries)
	}
}

func TestCaptureArtifactRejectsPrivateRootWithSpecialBits(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, os.ModeSticky|0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	source := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(source, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("body"))
	if _, err := CaptureArtifact(source, releasetrust.Artifact{Size: 4, SHA256: hex.EncodeToString(digest[:])}, root); err == nil {
		t.Fatal("private root with special mode bits accepted")
	}
}
