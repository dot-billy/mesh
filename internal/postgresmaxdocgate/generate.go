//go:build linux && postgresmaxdocgate

package postgresmaxdocgate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"mesh/internal/backupio"
	"mesh/internal/control"
	"mesh/internal/identity"
)

const FixtureMetadataName = "fixture-metadata.json"

var maximumDocumentIdentityIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func Generate(ctx context.Context, options GenerateOptions) (FixtureMetadata, error) {
	if ctx == nil {
		return FixtureMetadata{}, errors.New("maximum-document generation context is required")
	}
	root, err := requirePrivateDirectory(options.OutputDirectory)
	if err != nil {
		return FixtureMetadata{}, err
	}
	sourceDir := filepath.Join(root, "source")
	secretsDir := filepath.Join(root, "secrets")
	controlWorkDir := filepath.Join(root, "control-work")
	for _, directory := range []string{sourceDir, secretsDir, controlWorkDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return FixtureMetadata{}, fmt.Errorf("create maximum-document fixture directory: %w", err)
		}
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return FixtureMetadata{}, errors.New("generate maximum-document master key")
	}
	defer clear(masterKey)
	adminRaw := make([]byte, 32)
	if _, err := rand.Read(adminRaw); err != nil {
		return FixtureMetadata{}, errors.New("generate maximum-document administrator token")
	}
	defer clear(adminRaw)
	masterText := base64.RawURLEncoding.EncodeToString(masterKey)
	adminText := base64.RawURLEncoding.EncodeToString(adminRaw)
	fixtureTime := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	masterPath := filepath.Join(secretsDir, "master.key")
	adminPath := filepath.Join(secretsDir, "admin.token")
	if err := writePrivateExclusive(masterPath, []byte(masterText+"\n")); err != nil {
		return FixtureMetadata{}, err
	}
	if err := writePrivateExclusive(adminPath, []byte(adminText+"\n")); err != nil {
		return FixtureMetadata{}, err
	}

	controlFixture, err := control.BuildMaximumDocumentFixture(ctx, control.MaximumDocumentFixtureOptions{
		Directory: controlWorkDir, MasterKey: masterKey, AdminToken: []byte(adminText), At: fixtureTime,
	})
	if err != nil {
		return FixtureMetadata{}, fmt.Errorf("build maximum control document: %w", err)
	}
	box, err := control.NewSecretBox(masterKey)
	if err != nil {
		return FixtureMetadata{}, err
	}
	identityFixture, err := identity.BuildMaximumDocumentFixture(ctx, identity.MaximumDocumentFixtureOptions{Sealer: box, At: fixtureTime})
	if err != nil {
		return FixtureMetadata{}, fmt.Errorf("build maximum identity document: %w", err)
	}
	controlPath := filepath.Join(sourceDir, backupio.ControlStateName)
	identityPath := filepath.Join(sourceDir, backupio.IdentityStateName)
	// Offline backup capture requires the same two pre-existing process-lock
	// inodes created by the production file stores. The generated source is
	// never opened by those stores, so create empty private lock files explicitly
	// and let backupio acquire them in its production control-then-identity order.
	for _, lockName := range []string{".mesh.lock", ".identity-state.json.lock"} {
		if err := writePrivateExclusive(filepath.Join(sourceDir, lockName), nil); err != nil {
			return FixtureMetadata{}, err
		}
	}
	if err := writePrivateExclusive(controlPath, controlFixture.ExactBytes); err != nil {
		return FixtureMetadata{}, err
	}
	if err := writePrivateExclusive(identityPath, identityFixture.ExactBytes); err != nil {
		return FixtureMetadata{}, err
	}

	controlHash := sha256.Sum256(controlFixture.ExactBytes)
	identityHash := sha256.Sum256(identityFixture.ExactBytes)
	metadata := FixtureMetadata{
		Schema: ReportSchema, CreatedAt: time.Now().UTC(),
		Control: ControlFixtureMetadata{
			CanonicalBytes: len(controlFixture.CanonicalBytes), ExactBytes: len(controlFixture.ExactBytes),
			PaddingBytes: len(controlFixture.ExactBytes) - len(controlFixture.CanonicalBytes),
			SHA256:       hex.EncodeToString(controlHash[:]), NetworkID: controlFixture.NetworkID,
			NetworkCount: controlFixture.NetworkCount, NetworkCIDR: controlFixture.NetworkCIDR,
			NodeCount: controlFixture.NodeCount, EnrollmentCount: controlFixture.EnrollmentCount,
			AuditCount: controlFixture.AuditCount, GroupCount: controlFixture.GroupCount,
			InboundRuleCount: controlFixture.InboundRuleCount, OutboundRuleCount: controlFixture.OutboundRuleCount,
			FirewallConfigRevision: controlFixture.FirewallConfigRevision,
		},
		Identity: IdentityFixtureMetadata{
			CanonicalBytes: len(identityFixture.CanonicalBytes), ExactBytes: len(identityFixture.ExactBytes),
			PaddingBytes:    len(identityFixture.ExactBytes) - len(identityFixture.CanonicalBytes),
			SHA256:          hex.EncodeToString(identityHash[:]),
			OIDCClaimsBytes: identityFixture.OIDCClaimsBytes, OIDCGroupCount: identityFixture.OIDCGroupCount,
			LoginAttemptCount: identityFixture.LoginAttemptCount, ExpiredLoginAttemptID: identityFixture.ExpiredLoginAttemptID,
			SessionCount: identityFixture.SessionCount, AuditCount: identityFixture.AuditCount, CleanupAt: identityFixture.CleanupAt,
			ExpiredSessionID: identityFixture.ExpiredSessionID, RevokeSessionID: identityFixture.RevokeSessionID,
		},
		Paths: FixturePaths{ControlState: controlPath, IdentityState: identityPath, MasterKey: masterPath, AdminToken: adminPath},
	}
	if err := validateFixtureMetadata(metadata); err != nil {
		return FixtureMetadata{}, err
	}
	if err := writeJSONExclusive(filepath.Join(root, FixtureMetadataName), metadata); err != nil {
		return FixtureMetadata{}, err
	}
	return metadata, nil
}

func validateFixtureMetadata(metadata FixtureMetadata) error {
	if metadata.Schema != ReportSchema || metadata.CreatedAt.IsZero() {
		return errors.New("maximum-document fixture metadata header is invalid")
	}
	if metadata.Control.ExactBytes != MaximumControlBytes || metadata.Identity.ExactBytes != MaximumIdentityBytes ||
		metadata.Control.CanonicalBytes < control.DefaultControlCanonicalMinimum || metadata.Control.CanonicalBytes > control.DefaultControlCanonicalMaximum ||
		metadata.Identity.CanonicalBytes < identity.DefaultIdentityCanonicalMinimum || metadata.Identity.CanonicalBytes > identity.DefaultIdentityCanonicalMaximum ||
		metadata.Control.PaddingBytes != metadata.Control.ExactBytes-metadata.Control.CanonicalBytes ||
		metadata.Identity.PaddingBytes != metadata.Identity.ExactBytes-metadata.Identity.CanonicalBytes ||
		metadata.Control.NetworkCount != 1 || metadata.Control.NetworkCIDR != "10.240.0.0/16" ||
		metadata.Control.NodeCount < 1 || metadata.Control.NodeCount > 65_525 || metadata.Control.EnrollmentCount != metadata.Control.NodeCount ||
		metadata.Control.AuditCount != metadata.Control.NodeCount+11 || metadata.Control.FirewallConfigRevision != 2 ||
		metadata.Control.GroupCount != 64 || metadata.Control.InboundRuleCount != 128 || metadata.Control.OutboundRuleCount != 128 ||
		metadata.Identity.OIDCClaimsBytes < 1 || metadata.Identity.OIDCClaimsBytes > identity.MaximumDocumentOIDCClaimsBytes ||
		metadata.Identity.OIDCGroupCount != identity.MaximumDocumentOIDCGroups || metadata.Identity.LoginAttemptCount != 1 ||
		!maximumDocumentIdentityIDPattern.MatchString(metadata.Identity.ExpiredLoginAttemptID) ||
		metadata.Identity.SessionCount < 2 || metadata.Identity.AuditCount != metadata.Identity.SessionCount ||
		metadata.Identity.ExpiredSessionID == metadata.Identity.RevokeSessionID || metadata.Identity.CleanupAt.IsZero() {
		return errors.New("maximum-document fixture metadata invariants are invalid")
	}
	for _, digest := range []string{metadata.Control.SHA256, metadata.Identity.SHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
			return errors.New("maximum-document fixture digest is invalid")
		}
	}
	return nil
}

func requirePrivateDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", errors.New("maximum-document output directory must be clean, absolute, and dedicated")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("maximum-document output directory must be a real mode-0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("maximum-document output directory must be owned by the current user")
	}
	return path, nil
}

func writePrivateExclusive(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private maximum-document file: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return errors.New("write private maximum-document file failed")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync private maximum-document file failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private maximum-document file failed")
	}
	ok = true
	return nil
}

func writeJSONExclusive(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writePrivateExclusive(path, raw)
}
