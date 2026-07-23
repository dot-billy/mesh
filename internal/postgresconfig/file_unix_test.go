//go:build linux || darwin

package postgresconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateFilePolicy(t *testing.T) {
	clearPGEnvironment(t)

	t.Run("symlink", func(t *testing.T) {
		target := writeDSNFile(t, validTLSDsn, 0o600)
		link := filepath.Join(t.TempDir(), "postgres.dsn")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFile(link, Options{})
		requireStage(t, err, StageOpen)
	})

	t.Run("symlink parent", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(realDirectory, "postgres.dsn")
		if err := os.WriteFile(target, []byte(validTLSDsn), 0o600); err != nil {
			t.Fatal(err)
		}
		linkedDirectory := filepath.Join(root, "linked")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFile(filepath.Join(linkedDirectory, "postgres.dsn"), Options{})
		requireStage(t, err, StageOpen)
	})

	t.Run("hardlink", func(t *testing.T) {
		path := writeDSNFile(t, validTLSDsn, 0o600)
		if err := os.Link(path, filepath.Join(filepath.Dir(path), "second-name")); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFile(path, Options{})
		requireStage(t, err, StageMetadata)
	})

	for _, mode := range []os.FileMode{0o644, 0o640, 0o700, 0o500} {
		t.Run("mode "+mode.String(), func(t *testing.T) {
			path := writeDSNFile(t, validTLSDsn, mode)
			_, err := LoadFile(path, Options{})
			requireStage(t, err, StageMetadata)
		})
	}

	t.Run("oversize", func(t *testing.T) {
		path := writeDSNFile(t, strings.Repeat("x", MaxDSNFileBytes+1), 0o600)
		_, err := LoadFile(path, Options{})
		requireStage(t, err, StageMetadata)
	})

	t.Run("directory", func(t *testing.T) {
		_, err := LoadFile(t.TempDir(), Options{})
		requireStage(t, err, StageMetadata)
	})
}

func TestStableSameDescriptorReadRejectsMutation(t *testing.T) {
	clearPGEnvironment(t)
	path := writeDSNFile(t, validTLSDsn, 0o600)
	replacement := strings.Replace(validTLSDsn, "db.example.com", "xx.example.com", 1)
	if len(replacement) != len(validTLSDsn) {
		t.Fatal("test replacement must retain size")
	}

	_, err := loadFile(path, Options{}, func() {
		if writeErr := os.WriteFile(path, []byte(replacement), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	requireStage(t, err, StageRead)
}

func TestDSNLineFormat(t *testing.T) {
	clearPGEnvironment(t)
	cases := []struct {
		name     string
		contents string
	}{
		{"embedded newline", strings.Replace(validTLSDsn, "?", "\n?", 1)},
		{"two final newlines", validTLSDsn + "\n\n"},
		{"carriage return", validTLSDsn + "\r\n"},
		{"NUL", validTLSDsn + "\x00"},
		{"tab", strings.Replace(validTLSDsn, "mesh?", "mesh\t?", 1)},
		{"leading data separator", " " + validTLSDsn},
		{"trailing data separator", validTLSDsn + " "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFile(writeDSNFile(t, tc.contents, 0o600), Options{})
			requireStage(t, err, StageFormat)
		})
	}
}

func TestUnsafePathForms(t *testing.T) {
	clearPGEnvironment(t)
	validPath := writeDSNFile(t, validTLSDsn, 0o600)
	paths := []string{
		"relative/postgres.dsn",
		filepath.Join(filepath.Dir(validPath), ".", filepath.Base(validPath)),
		validPath + string(os.PathSeparator) + ".." + string(os.PathSeparator) + filepath.Base(validPath),
		validPath + "\x00suffix",
		"/" + strings.Repeat("x", maxPathBytes),
	}
	// filepath.Join cleans its input, so preserve an explicitly unclean path.
	paths[1] = filepath.Dir(validPath) + string(os.PathSeparator) + "." + string(os.PathSeparator) + filepath.Base(validPath)
	for _, path := range paths {
		_, err := LoadFile(path, Options{})
		requireStage(t, err, StagePath)
	}
}
