//go:build linux || darwin

package postgresloadgate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateCanonicalLineAcceptsOnlyStablePrivateRegularFile(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid")
	if err := os.WriteFile(valid, []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readPrivateCanonicalLine(valid, "test secret")
	if err != nil || value != "secret-value" {
		t.Fatalf("valid private file value=%q err=%v", value, err)
	}
	if err := os.Chmod(valid, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCanonicalLine(valid, "test secret"); err != nil {
		t.Fatalf("0400 private file rejected: %v", err)
	}

	public := filepath.Join(directory, "public")
	if err := os.WriteFile(public, []byte("secret-value\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCanonicalLine(public, "test secret"); err == nil {
		t.Fatal("group-readable private file was accepted")
	}

	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCanonicalLine(symlink, "test secret"); err == nil {
		t.Fatal("symlink private file was accepted")
	}

	realParent := filepath.Join(directory, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	ancestorTarget := filepath.Join(realParent, "secret")
	if err := os.WriteFile(ancestorTarget, []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCanonicalLine(filepath.Join(linkedParent, "secret"), "test secret"); err == nil {
		t.Fatal("symlinked ancestor of private file was accepted")
	}

	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(valid, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCanonicalLine(valid, "test secret"); err == nil {
		t.Fatal("multi-link private file was accepted")
	}
}

func TestReadPrivateCanonicalLineRejectsSameSizeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("first-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readPrivateCanonicalLineWithHook(path, "test secret", func() {
		if writeErr := os.WriteFile(path, []byte("other-value\n"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if err == nil {
		t.Fatal("same-size mutation during private-file read was accepted")
	}
}
