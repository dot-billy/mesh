package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	nebulacert "github.com/slackhq/nebula/cert"
)

type NebulaIssuer struct{ Binary string }

type CertificateIssuer interface {
	CreateCA(context.Context, string, string) (string, string, error)
	SignPublicKey(context.Context, string, string, string, string, string, string, string, time.Duration) (string, string, time.Time, error)
}

func canonicalNebulaPublicKeyPEM(raw string) (string, error) {
	if len(raw) < 40 || len(raw) > 4096 || !utf8.ValidString(raw) {
		return "", errors.New("Nebula public key is empty, oversized, or not valid UTF-8")
	}
	normalized := []byte(strings.TrimSpace(raw) + "\n")
	publicKey, remainder, curve, err := nebulacert.UnmarshalPublicKeyFromPEM(normalized)
	if err != nil {
		return "", fmt.Errorf("decode Nebula public key: %w", err)
	}
	canonical := nebulacert.MarshalPublicKeyToPEM(curve, publicKey)
	if len(canonical) == 0 || len(remainder) != 0 || !bytes.Equal(normalized, canonical) {
		return "", errors.New("Nebula public key must be exactly one canonical PEM block")
	}
	return string(canonical), nil
}

func (n NebulaIssuer) CreateCA(ctx context.Context, name, cidr string) (certificate, key string, err error) {
	dir, err := os.MkdirTemp("", "mesh-ca-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	crtPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := n.run(ctx, "ca", "-name", name, "-networks", cidr, "-duration", "87600h", "-out-crt", crtPath, "-out-key", keyPath); err != nil {
		return "", "", err
	}
	crt, err := os.ReadFile(crtPath)
	if err != nil {
		return "", "", err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", err
	}
	return string(crt), string(keyBytes), nil
}

func (n NebulaIssuer) SignPublicKey(ctx context.Context, caCert, caKey, publicKey, name, network, groups, unsafeNetworks string, ttl time.Duration) (certificate, fingerprint string, expiresAt time.Time, err error) {
	dir, err := os.MkdirTemp("", "mesh-sign-*")
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer os.RemoveAll(dir)
	paths := map[string]string{
		"caCert": filepath.Join(dir, "ca.crt"),
		"caKey":  filepath.Join(dir, "ca.key"),
		"pub":    filepath.Join(dir, "node.pub"),
		"crt":    filepath.Join(dir, "node.crt"),
	}
	for path, content := range map[string]string{paths["caCert"]: caCert, paths["caKey"]: caKey, paths["pub"]: publicKey} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return "", "", time.Time{}, err
		}
	}
	args := []string{"sign", "-ca-crt", paths["caCert"], "-ca-key", paths["caKey"], "-in-pub", paths["pub"], "-name", name, "-networks", network, "-duration", durationArg(ttl), "-out-crt", paths["crt"]}
	if groups != "" {
		args = append(args, "-groups", groups)
	}
	if unsafeNetworks != "" {
		args = append(args, "-unsafe-networks", unsafeNetworks)
	}
	if err := n.run(ctx, args...); err != nil {
		return "", "", time.Time{}, err
	}
	crt, err := os.ReadFile(paths["crt"])
	if err != nil {
		return "", "", time.Time{}, err
	}
	fingerprint, expiresAt, err = n.inspectCertificate(ctx, paths["crt"])
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(crt), fingerprint, expiresAt.UTC(), nil
}

func (n NebulaIssuer) inspectCertificate(ctx context.Context, path string) (string, time.Time, error) {
	cmd := exec.CommandContext(ctx, n.binary(), "print", "-json", "-path", path)
	out, err := cmd.Output()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("inspect certificate: %w", err)
	}
	var payload []struct {
		Fingerprint string `json:"fingerprint"`
		Details     struct {
			NotAfter time.Time `json:"notAfter"`
		} `json:"details"`
	}
	if err := json.Unmarshal(out, &payload); err == nil && len(payload) == 1 && payload[0].Fingerprint != "" && !payload[0].Details.NotAfter.IsZero() {
		return payload[0].Fingerprint, payload[0].Details.NotAfter.UTC(), nil
	}
	return "", time.Time{}, fmt.Errorf("inspect certificate: nebula-cert did not return a fingerprint and expiry")
}

func (n NebulaIssuer) run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, n.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("nebula-cert %s: %s", args[0], message)
	}
	return nil
}

func (n NebulaIssuer) binary() string {
	if n.Binary == "" {
		return "nebula-cert"
	}
	return n.Binary
}

func durationArg(d time.Duration) string { return fmt.Sprintf("%dh", int(d.Hours())) }
