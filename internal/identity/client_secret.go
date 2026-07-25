package identity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxOIDCClientSecretSize = 4096

// LoadOIDCClientSecret reads a private, single-link regular file without
// accepting whitespace-normalized or line-oriented secret formats.
func LoadOIDCClientSecret(path string) (string, error) {
	if len(path) == 0 || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return "", errors.New("OIDC client secret path must be a clean absolute file path")
	}
	directory, fileName := filepath.Dir(path), filepath.Base(path)
	if err := rejectSymlinkPath(directory); err != nil {
		return "", err
	}
	beforeDirectory, err := os.Lstat(directory)
	if err != nil || beforeDirectory.Mode()&os.ModeSymlink != 0 || !beforeDirectory.IsDir() {
		return "", errors.New("OIDC client secret directory must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", fmt.Errorf("open OIDC client secret directory: %w", err)
	}
	defer root.Close()
	afterDirectory, err := root.Stat(".")
	if err != nil || !os.SameFile(beforeDirectory, afterDirectory) {
		return "", errors.New("OIDC client secret directory changed while opening")
	}
	before, err := root.Lstat(fileName)
	if err != nil {
		return "", fmt.Errorf("inspect OIDC client secret: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxOIDCClientSecretSize {
		return "", errors.New("OIDC client secret must be a bounded real regular file")
	}
	file, err := root.Open(fileName)
	if err != nil {
		return "", fmt.Errorf("open OIDC client secret: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return "", errors.New("OIDC client secret changed while opening")
	}
	if err := requirePrivateOIDCSecret(file, after); err != nil {
		return "", fmt.Errorf("OIDC client secret: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxOIDCClientSecretSize+1))
	if err != nil {
		return "", fmt.Errorf("read OIDC client secret: %w", err)
	}
	if len(raw) < 1 || len(raw) > maxOIDCClientSecretSize || !utf8.Valid(raw) {
		return "", errors.New("OIDC client secret is empty, oversized, or invalid UTF-8")
	}
	secret := string(raw)
	if !validBoundedText(secret, 1, maxOIDCClientSecretSize) || strings.ContainsAny(secret, "\x00\r\n") {
		return "", errors.New("OIDC client secret contains whitespace padding or prohibited control characters")
	}
	return secret, nil
}
