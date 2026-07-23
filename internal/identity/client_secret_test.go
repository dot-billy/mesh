//go:build !windows

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOIDCClientSecretAcceptsPrivateSingleLinkFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client-secret")
			writeOIDCTestSecret(t, path, "correct-horse-battery-staple", mode)
			secret, err := LoadOIDCClientSecret(path)
			if err != nil || secret != "correct-horse-battery-staple" {
				t.Fatalf("secret=%q err=%v", secret, err)
			}
		})
	}
}

func TestLoadOIDCClientSecretRejectsUnsafeFilesAndContent(t *testing.T) {
	contents := map[string]string{
		"empty": "", "leading whitespace": " secret", "trailing whitespace": "secret ",
		"newline": "secret\n", "crlf": "secret\r\n", "nul": "secret\x00value", "control": "secret\tvalue",
	}
	for name, content := range contents {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client-secret")
			writeOIDCTestSecret(t, path, content, 0o600)
			if _, err := LoadOIDCClientSecret(path); err == nil {
				t.Fatal("unsafe client secret content was accepted")
			}
		})
	}

	t.Run("weak mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client-secret")
		writeOIDCTestSecret(t, path, "secret", 0o640)
		if _, err := LoadOIDCClientSecret(path); err == nil {
			t.Fatal("group-readable secret was accepted")
		}
	})
	t.Run("executable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client-secret")
		writeOIDCTestSecret(t, path, "secret", 0o700)
		if _, err := LoadOIDCClientSecret(path); err == nil {
			t.Fatal("executable secret was accepted")
		}
	})
	t.Run("hard link", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "client-secret")
		writeOIDCTestSecret(t, path, "secret", 0o600)
		if err := os.Link(path, filepath.Join(directory, "second-link")); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOIDCClientSecret(path); err == nil {
			t.Fatal("multiply-linked secret was accepted")
		}
	})
	t.Run("symlink file", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		writeOIDCTestSecret(t, target, "secret", 0o600)
		path := filepath.Join(directory, "client-secret")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOIDCClientSecret(path); err == nil {
			t.Fatal("symlink secret was accepted")
		}
	})
	t.Run("symlink directory", func(t *testing.T) {
		base := t.TempDir()
		realDirectory := filepath.Join(base, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		writeOIDCTestSecret(t, filepath.Join(realDirectory, "client-secret"), "secret", 0o600)
		link := filepath.Join(base, "link")
		if err := os.Symlink(realDirectory, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOIDCClientSecret(filepath.Join(link, "client-secret")); err == nil {
			t.Fatal("secret below symlink directory was accepted")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client-secret")
		writeOIDCTestSecret(t, path, strings.Repeat("x", maxOIDCClientSecretSize+1), 0o600)
		if _, err := LoadOIDCClientSecret(path); err == nil {
			t.Fatal("oversized secret was accepted")
		}
	})
	if _, err := LoadOIDCClientSecret("relative-secret"); err == nil {
		t.Fatal("relative secret path was accepted")
	}
}

func writeOIDCTestSecret(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
