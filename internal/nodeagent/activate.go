package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"mesh/internal/control"
)

const (
	maxBundleFileSize         = control.MaxManagedConfigBytes
	maxRetainedBundleVersions = 5
)

var completeBundleFileNames = []string{
	"ca.crt",
	"config.signed.yml",
	"config.yml",
	"host.crt",
	"host.key",
	"host.pub",
	"metadata.json",
}

const rollbackTimeout = 30 * time.Second

const (
	managedDirectoryMarker = ".mesh-nodeagent-owned"
	managedDirectoryPrefix = "mesh-nodeagent-v2\n"
)

type Reloader interface {
	Reload(context.Context) error
}

type ReloadFunc func(context.Context) error

func (f ReloadFunc) Reload(ctx context.Context) error { return f(ctx) }

// Bundle contains both the signed desired config and every credential needed
// to validate, activate, and later renew a node without contacting the CA for
// private-key material.
type Bundle struct {
	NodeID                            string
	NetworkID                         string
	Revision                          int64
	IssuedAt                          time.Time
	Digest                            string
	Signature                         string
	CACertificateSHA256               string
	PreviousCACertificateSHA256       string
	CARotationRequired                bool
	CertificateProfileRenewalRequired bool
	CertificateFingerprint            string
	CertificateExpiresAt              time.Time
	CertificateRenewAfter             time.Time
	CertificateGeneration             int64
	PublicKeyHash                     string
	SignedConfig                      string
	CACertificate                     string
	Certificate                       string
	PrivateKey                        string
	PublicKey                         string
}

type Activation struct {
	VersionDir           string
	PreviousTarget       string
	CertificateExpiresAt time.Time
}

type bundleMetadata struct {
	NodeID                            string    `json:"node_id"`
	NetworkID                         string    `json:"network_id"`
	Revision                          int64     `json:"revision"`
	IssuedAt                          time.Time `json:"issued_at"`
	Digest                            string    `json:"digest"`
	Signature                         string    `json:"signature"`
	CACertificateSHA256               string    `json:"ca_sha256"`
	PreviousCACertificateSHA256       string    `json:"previous_ca_sha256,omitempty"`
	CARotationRequired                bool      `json:"ca_rotation_required,omitempty"`
	CertificateProfileRenewalRequired bool      `json:"certificate_profile_renewal_required,omitempty"`
	CertificateFingerprint            string    `json:"certificate_fingerprint"`
	CertificateExpiresAt              time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter             time.Time `json:"certificate_renew_after"`
	CertificateGeneration             int64     `json:"certificate_generation"`
	PublicKeyHash                     string    `json:"public_key_hash"`
}

// Activator stages immutable versions under OutputDir/versions and makes only
// OutputDir/current live. A failed reload atomically restores and reloads the
// previous target.
type Activator struct {
	OutputDir              string
	NodeID                 string
	NetworkID              string
	ConfigSigningPublicKey string
	CACertificateSHA256    string
	PublicKeyHash          string
	Validator              BundleValidator
	Reloader               Reloader
	syncFn                 func(string) error
	mu                     sync.Mutex
}

func (a *Activator) Apply(ctx context.Context, bundle Bundle) (Activation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := validateBundle(bundle, a.NodeID, a.NetworkID, a.ConfigSigningPublicKey, a.CACertificateSHA256, a.PublicKeyHash); err != nil {
		return Activation{}, err
	}
	if a.Reloader == nil {
		return Activation{}, errors.New("a Nebula reloader is required")
	}
	outputDir, err := filepath.Abs(a.OutputDir)
	if err != nil {
		return Activation{}, fmt.Errorf("resolve bundle output directory: %w", err)
	}
	outputDir = filepath.Clean(outputDir)
	if err := PreflightManagedOutput(outputDir); err != nil {
		return Activation{}, err
	}
	outputLock, err := acquireProcessLock(outputDir + ".lock")
	if err != nil {
		return Activation{}, fmt.Errorf("lock managed bundle output: %w", err)
	}
	defer outputLock.Close()
	// Repeat the non-destructive checks while holding the output lock. The
	// parent is owner-controlled, but this also closes accidental same-user
	// races between enrollment preflight and activation.
	if err := PreflightManagedOutput(outputDir); err != nil {
		return Activation{}, err
	}
	versionsDir := filepath.Join(outputDir, "versions")
	if err := secureManagedOutputDir(outputDir, a.NodeID, a.NetworkID); err != nil {
		return Activation{}, err
	}
	if err := secureChildDir(versionsDir); err != nil {
		return Activation{}, err
	}
	currentPath := filepath.Join(outputDir, "current")
	previousTarget, hadPrevious, err := inspectCurrentLink(currentPath, versionsDir)
	if err != nil {
		return Activation{}, err
	}
	// Prune before staging or changing the live symlink. Keeping one slot for
	// the bundle being published bounds successful activations at the retention
	// limit, while a cleanup failure leaves the running bundle untouched.
	if err := a.pruneVersionsBeforeActivation(versionsDir, currentPath, previousTarget, hadPrevious); err != nil {
		return Activation{}, err
	}
	stageDir, err := os.MkdirTemp(versionsDir, ".staging-")
	if err != nil {
		return Activation{}, fmt.Errorf("create staged Nebula bundle: %w", err)
	}
	if err := os.Chmod(stageDir, 0o700); err != nil {
		_ = os.RemoveAll(stageDir)
		return Activation{}, fmt.Errorf("secure staged Nebula bundle: %w", err)
	}
	removeStage := true
	defer func() {
		if removeStage {
			_ = os.RemoveAll(stageDir)
		}
	}()
	runtimeConfig, err := rewritePKIPaths(bundle.SignedConfig, filepath.Join(outputDir, "current"))
	if err != nil {
		return Activation{}, err
	}
	validationConfig, err := rewritePKIPaths(bundle.SignedConfig, stageDir)
	if err != nil {
		return Activation{}, err
	}
	files := map[string]string{
		"ca.crt":              bundle.CACertificate,
		"host.crt":            bundle.Certificate,
		"host.key":            bundle.PrivateKey,
		"host.pub":            bundle.PublicKey,
		"config.signed.yml":   bundle.SignedConfig,
		"config.yml":          runtimeConfig,
		"config.validate.yml": validationConfig,
	}
	for name, content := range files {
		if err := writeSyncedFile(filepath.Join(stageDir, name), []byte(content)); err != nil {
			return Activation{}, err
		}
	}
	validationPath := filepath.Join(stageDir, "config.validate.yml")
	certificateDetails, err := a.Validator.Validate(ctx, stageDir, validationPath)
	if err != nil {
		return Activation{}, err
	}
	if certificateDetails.Fingerprint != bundle.CertificateFingerprint || !certificateDetails.ExpiresAt.Equal(bundle.CertificateExpiresAt) {
		return Activation{}, errors.New("verified Nebula certificate does not match the signed artifact metadata")
	}
	metadata, err := json.Marshal(bundleMetadata{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID, Revision: bundle.Revision,
		IssuedAt: bundle.IssuedAt, Digest: bundle.Digest, Signature: bundle.Signature,
		CACertificateSHA256: bundle.CACertificateSHA256, PreviousCACertificateSHA256: bundle.PreviousCACertificateSHA256,
		CARotationRequired: bundle.CARotationRequired, CertificateProfileRenewalRequired: bundle.CertificateProfileRenewalRequired, CertificateFingerprint: bundle.CertificateFingerprint,
		CertificateExpiresAt: bundle.CertificateExpiresAt, CertificateRenewAfter: bundle.CertificateRenewAfter,
		CertificateGeneration: bundle.CertificateGeneration,
		PublicKeyHash:         bundle.PublicKeyHash,
	})
	if err != nil {
		return Activation{}, fmt.Errorf("encode bundle metadata: %w", err)
	}
	if err := writeSyncedFile(filepath.Join(stageDir, "metadata.json"), append(metadata, '\n')); err != nil {
		return Activation{}, err
	}
	if err := os.Remove(validationPath); err != nil {
		return Activation{}, fmt.Errorf("remove validation-only config: %w", err)
	}
	if err := a.syncDirectory(stageDir); err != nil {
		return Activation{}, err
	}
	suffix, err := GenerateBearer()
	if err != nil {
		return Activation{}, err
	}
	versionName := fmt.Sprintf("r%020d-%s-%s", bundle.Revision, bundle.Digest[:16], suffix[:12])
	versionDir := filepath.Join(versionsDir, versionName)
	if err := os.Rename(stageDir, versionDir); err != nil {
		return Activation{}, fmt.Errorf("publish staged Nebula bundle: %w", err)
	}
	removeStage = false
	if err := a.syncDirectory(versionsDir); err != nil {
		return Activation{}, err
	}
	relativeTarget, err := filepath.Rel(outputDir, versionDir)
	if err != nil {
		return Activation{}, fmt.Errorf("resolve live bundle target: %w", err)
	}
	if err := replaceSymlink(currentPath, relativeTarget); err != nil {
		return Activation{}, err
	}
	if err := a.syncDirectory(outputDir); err != nil {
		syncErr := fmt.Errorf("sync activated Nebula bundle: %w", err)
		rollbackErr := a.rollbackBounded(ctx, currentPath, outputDir, previousTarget, hadPrevious)
		if rollbackErr != nil {
			return Activation{}, errors.Join(syncErr, rollbackErr)
		}
		return Activation{}, syncErr
	}
	if err := a.Reloader.Reload(ctx); err != nil {
		reloadErr := fmt.Errorf("reload staged Nebula bundle: %w", err)
		rollbackErr := a.rollbackBounded(ctx, currentPath, outputDir, previousTarget, hadPrevious)
		if rollbackErr != nil {
			return Activation{}, errors.Join(reloadErr, rollbackErr)
		}
		return Activation{}, reloadErr
	}
	return Activation{VersionDir: versionDir, PreviousTarget: previousTarget, CertificateExpiresAt: certificateDetails.ExpiresAt}, nil
}

type retainedBundleVersion struct {
	name     string
	path     string
	modified time.Time
	current  bool
}

// pruneVersionsBeforeActivation retains the current version plus the newest
// complete inactive versions. Staging directories are deliberately ignored:
// they are crash journals, not published versions, and activation cleanup owns
// their lifecycle. Every published directory is validated before any removal
// begins so an unexpected entry fails closed without partially pruning a
// different, valid version.
func (a *Activator) pruneVersionsBeforeActivation(versionsDir, currentPath, currentTarget string, hasCurrent bool) error {
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return fmt.Errorf("inspect immutable Nebula bundle versions for retention: %w", err)
	}
	currentVersionPath := ""
	if hasCurrent {
		currentVersionPath = filepath.Clean(filepath.Join(filepath.Dir(currentPath), currentTarget))
	}
	versions := make([]retainedBundleVersion, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(versionsDir, entry.Name())
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return fmt.Errorf("inspect immutable Nebula bundle %q for retention: %w", entry.Name(), infoErr)
		}
		if validStagingName(entry.Name()) {
			if info.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(info) {
				return errors.New("managed bundle staging entry must be a private real directory")
			}
			continue
		}
		if !validVersionName(entry.Name()) || info.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(info) {
			return errors.New("managed bundle versions contain an invalid retention entry")
		}
		if err := validateCompleteVersionDirectory(path); err != nil {
			return fmt.Errorf("validate immutable Nebula bundle %q for retention: %w", entry.Name(), err)
		}
		versions = append(versions, retainedBundleVersion{
			name: entry.Name(), path: path, modified: info.ModTime(),
			current: hasCurrent && filepath.Clean(path) == currentVersionPath,
		})
	}
	if hasCurrent {
		found := false
		for _, version := range versions {
			if version.current {
				found = true
				break
			}
		}
		if !found {
			return errors.New("current Nebula bundle is not a validated immutable version")
		}
	}

	retainBeforeActivation := maxRetainedBundleVersions - 1
	if len(versions) <= retainBeforeActivation {
		return nil
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].modified.Equal(versions[j].modified) {
			return versions[i].name > versions[j].name
		}
		return versions[i].modified.After(versions[j].modified)
	})
	retained := make(map[string]bool, retainBeforeActivation)
	if hasCurrent {
		for _, version := range versions {
			if version.current {
				retained[version.path] = true
				break
			}
		}
	}
	for _, version := range versions {
		if len(retained) == retainBeforeActivation {
			break
		}
		retained[version.path] = true
	}
	for _, version := range versions {
		if retained[version.path] {
			continue
		}
		if version.current {
			return errors.New("refusing to prune the current Nebula bundle")
		}
		if err := removeCompleteVersionDirectory(version.path); err != nil {
			return fmt.Errorf("prune immutable Nebula bundle %q: %w", version.name, err)
		}
	}
	if err := a.syncDirectory(versionsDir); err != nil {
		return fmt.Errorf("sync pruned immutable Nebula bundle versions: %w", err)
	}
	return nil
}

func validateCompleteVersionDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect version directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(info) {
		return errors.New("version must be a private real directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inspect version contents: %w", err)
	}
	if len(entries) != len(completeBundleFileNames) {
		return errors.New("version does not contain the complete immutable bundle file set")
	}
	allowed := make(map[string]bool, len(completeBundleFileNames))
	for _, name := range completeBundleFileNames {
		allowed[name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return fmt.Errorf("version contains unexpected entry %q", entry.Name())
		}
		entryInfo, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil {
			return fmt.Errorf("inspect version entry %q: %w", entry.Name(), err)
		}
		if !privateRegularFile(entryInfo) {
			return fmt.Errorf("version entry %q must be a private regular file", entry.Name())
		}
	}
	metadataBytes, err := readSecureBundleFile(filepath.Join(path, "metadata.json"))
	if err != nil {
		return err
	}
	var metadata bundleMetadata
	decoder := json.NewDecoder(strings.NewReader(string(metadataBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return fmt.Errorf("decode bundle metadata: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode bundle metadata: %w", err)
	}
	if metadata.Revision < 1 || !validDigest(metadata.Digest) || metadata.CertificateGeneration < 1 ||
		metadata.IssuedAt.IsZero() || !validDigest(metadata.CACertificateSHA256) || !validDigest(metadata.CertificateFingerprint) ||
		metadata.CertificateExpiresAt.IsZero() || metadata.CertificateRenewAfter.IsZero() ||
		!metadata.CertificateRenewAfter.Before(metadata.CertificateExpiresAt) || !control.ValidTokenHash(metadata.PublicKeyHash) ||
		metadata.Signature == "" || !validIdentifier(metadata.NodeID) || !validIdentifier(metadata.NetworkID) {
		return errors.New("bundle metadata is incomplete or invalid")
	}
	expectedPrefix := fmt.Sprintf("r%020d-%s-", metadata.Revision, metadata.Digest[:16])
	if !strings.HasPrefix(filepath.Base(path), expectedPrefix) {
		return errors.New("version name does not match immutable bundle metadata")
	}
	return nil
}

func removeCompleteVersionDirectory(path string) error {
	// Revalidate immediately before deletion. Published bundles are flat, so
	// removing the known regular files individually never recursively follows a
	// directory or symlink supplied inside a version.
	if err := validateCompleteVersionDirectory(path); err != nil {
		return err
	}
	for _, name := range completeBundleFileNames {
		entryPath := filepath.Join(path, name)
		entryInfo, err := os.Lstat(entryPath)
		if err != nil {
			return fmt.Errorf("reinspect version entry %q: %w", name, err)
		}
		if !privateRegularFile(entryInfo) {
			return fmt.Errorf("version entry %q changed before removal", name)
		}
		if err := os.Remove(entryPath); err != nil {
			return fmt.Errorf("remove version entry %q: %w", name, err)
		}
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove empty version directory: %w", err)
	}
	return nil
}

func (a *Activator) rollbackBounded(ctx context.Context, currentPath, outputDir, previousTarget string, hadPrevious bool) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	return a.rollback(rollbackCtx, currentPath, outputDir, previousTarget, hadPrevious)
}

func (a *Activator) rollback(ctx context.Context, currentPath, outputDir, previousTarget string, hadPrevious bool) error {
	if hadPrevious {
		if err := replaceSymlink(currentPath, previousTarget); err != nil {
			return fmt.Errorf("restore previous Nebula bundle: %w", err)
		}
	} else if err := os.Remove(currentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove failed initial Nebula bundle: %w", err)
	}
	if err := a.syncDirectory(outputDir); err != nil {
		return fmt.Errorf("sync Nebula bundle rollback: %w", err)
	}
	if hadPrevious {
		if err := a.Reloader.Reload(ctx); err != nil {
			return fmt.Errorf("reload previous Nebula bundle: %w", err)
		}
	}
	return nil
}

func (a *Activator) CurrentBundle(ctx context.Context) (Bundle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	outputDir, err := filepath.Abs(a.OutputDir)
	if err != nil {
		return Bundle{}, fmt.Errorf("resolve bundle output directory: %w", err)
	}
	outputDir = filepath.Clean(outputDir)
	if err := validatePlatformPathSecurity(outputDir); err != nil {
		return Bundle{}, err
	}
	versionsDir := filepath.Join(outputDir, "versions")
	currentPath := filepath.Join(outputDir, "current")
	target, exists, err := inspectCurrentLink(currentPath, versionsDir)
	if err != nil {
		return Bundle{}, err
	}
	if !exists {
		return Bundle{}, errors.New("current Nebula bundle does not exist")
	}
	resolved := filepath.Join(filepath.Dir(currentPath), target)
	metadataBytes, err := readSecureBundleFile(filepath.Join(resolved, "metadata.json"))
	if err != nil {
		return Bundle{}, err
	}
	var metadata bundleMetadata
	decoder := json.NewDecoder(strings.NewReader(string(metadataBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return Bundle{}, fmt.Errorf("decode current bundle metadata: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Bundle{}, fmt.Errorf("decode current bundle metadata: %w", err)
	}
	contents := make(map[string]string, 6)
	for _, name := range []string{"config.signed.yml", "config.yml", "ca.crt", "host.crt", "host.key", "host.pub"} {
		content, err := readSecureBundleFile(filepath.Join(resolved, name))
		if err != nil {
			return Bundle{}, err
		}
		contents[name] = string(content)
	}
	bundle := Bundle{
		NodeID: metadata.NodeID, NetworkID: metadata.NetworkID, Revision: metadata.Revision,
		IssuedAt: metadata.IssuedAt, Digest: metadata.Digest, Signature: metadata.Signature,
		CACertificateSHA256: metadata.CACertificateSHA256, PreviousCACertificateSHA256: metadata.PreviousCACertificateSHA256,
		CARotationRequired: metadata.CARotationRequired, CertificateProfileRenewalRequired: metadata.CertificateProfileRenewalRequired, CertificateFingerprint: metadata.CertificateFingerprint,
		CertificateExpiresAt: metadata.CertificateExpiresAt, CertificateRenewAfter: metadata.CertificateRenewAfter,
		CertificateGeneration: metadata.CertificateGeneration,
		PublicKeyHash:         metadata.PublicKeyHash,
		SignedConfig:          contents["config.signed.yml"], CACertificate: contents["ca.crt"],
		Certificate: contents["host.crt"], PrivateKey: contents["host.key"], PublicKey: contents["host.pub"],
	}
	if err := validateBundle(bundle, a.NodeID, a.NetworkID, a.ConfigSigningPublicKey, a.CACertificateSHA256, a.PublicKeyHash); err != nil {
		return Bundle{}, fmt.Errorf("validate current Nebula bundle: %w", err)
	}
	expectedRuntimeConfig, err := rewritePKIPaths(bundle.SignedConfig, filepath.Join(filepath.Clean(outputDir), "current"))
	if err != nil {
		return Bundle{}, err
	}
	if contents["config.yml"] != expectedRuntimeConfig {
		return Bundle{}, errors.New("live Nebula config differs from the pinned signed config")
	}
	certificateDetails, err := a.Validator.Validate(ctx, resolved, filepath.Join(resolved, "config.yml"))
	if err != nil {
		return Bundle{}, fmt.Errorf("validate current Nebula runtime: %w", err)
	}
	if certificateDetails.Fingerprint != metadata.CertificateFingerprint || !certificateDetails.ExpiresAt.Equal(metadata.CertificateExpiresAt) {
		return Bundle{}, errors.New("current Nebula certificate does not match immutable signed metadata")
	}
	return bundle, nil
}

func validateBundle(bundle Bundle, nodeID, networkID, signingPublicKey, caCertificateSHA256, publicKeyHash string) error {
	if nodeID == "" || networkID == "" || signingPublicKey == "" || !validDigest(caCertificateSHA256) || !control.ValidTokenHash(publicKeyHash) {
		return errors.New("pinned node identity, config-signing key, CA certificate, and public key are required")
	}
	if bundle.NodeID != nodeID || bundle.NetworkID != networkID {
		return errors.New("bundle identity does not match the pinned node")
	}
	if bundle.Revision < 1 || !validDigest(bundle.Digest) {
		return errors.New("bundle revision or digest is invalid")
	}
	metadata := control.ConfigSignatureMetadata{
		NodeID: bundle.NodeID, NetworkID: bundle.NetworkID, Revision: bundle.Revision, IssuedAt: bundle.IssuedAt,
		CACertificateSHA256: bundle.CACertificateSHA256, PreviousCACertificateSHA256: bundle.PreviousCACertificateSHA256,
		CARotationRequired: bundle.CARotationRequired, CertificateProfileRenewalRequired: bundle.CertificateProfileRenewalRequired, CertificateFingerprint: bundle.CertificateFingerprint,
		CertificateExpiresAt: bundle.CertificateExpiresAt, CertificateRenewAfter: bundle.CertificateRenewAfter,
		CertificateGeneration: bundle.CertificateGeneration,
		PublicKeyHash:         bundle.PublicKeyHash,
	}
	if err := control.VerifyConfig(signingPublicKey, metadata, bundle.SignedConfig, bundle.Digest, bundle.Signature); err != nil {
		return fmt.Errorf("verify bundle config signature: %w", err)
	}
	if bundle.CACertificateSHA256 != caCertificateSHA256 || control.ConfigDigest(bundle.CACertificate) != caCertificateSHA256 {
		return errors.New("bundle CA certificate does not match the enrollment pin")
	}
	if bundle.PublicKeyHash != publicKeyHash || canonicalPublicKeyHash(bundle.PublicKey) != publicKeyHash {
		return errors.New("bundle public key does not match the enrollment pin")
	}
	for name, value := range map[string]string{
		"config": bundle.SignedConfig, "CA certificate": bundle.CACertificate,
		"node certificate": bundle.Certificate, "private key": bundle.PrivateKey, "public key": bundle.PublicKey,
	} {
		if value == "" {
			return fmt.Errorf("bundle %s is empty", name)
		}
		if len(value) > maxBundleFileSize {
			return fmt.Errorf("bundle %s exceeds size limit", name)
		}
	}
	return nil
}

func rewritePKIPaths(config, directory string) (string, error) {
	directory = filepath.ToSlash(directory)
	replacements := map[string]string{
		"/etc/nebula/ca.crt":   directory + "/ca.crt",
		"/etc/nebula/host.crt": directory + "/host.crt",
		"/etc/nebula/host.key": directory + "/host.key",
	}
	result := config
	for original, replacement := range replacements {
		if strings.Count(result, original) != 1 {
			return "", fmt.Errorf("signed config must contain exactly one %s path", original)
		}
		result = strings.Replace(result, original, replacement, 1)
	}
	return result, nil
}

func secureManagedOutputDir(path, nodeID, networkID string) error {
	path = filepath.Clean(path)
	if isProtectedOutputPath(path) {
		return errors.New("bundle output must be a dedicated leaf directory, not a filesystem or system root")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create managed bundle output directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect managed bundle output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(info) {
		return errors.New("bundle output must be an owned private real directory")
	}
	markerPath := filepath.Join(path, managedDirectoryMarker)
	markerValue := managedDirectoryPrefix + "node_id=" + nodeID + "\nnetwork_id=" + networkID + "\n"
	markerInfo, markerStatErr := os.Lstat(markerPath)
	if markerStatErr == nil && !privateRegularFile(markerInfo) {
		return errors.New("bundle ownership marker must be a private regular file")
	}
	if markerStatErr != nil && !errors.Is(markerStatErr, os.ErrNotExist) {
		return fmt.Errorf("inspect bundle ownership marker: %w", markerStatErr)
	}
	marker, markerErr := os.ReadFile(markerPath)
	if errors.Is(markerErr, os.ErrNotExist) {
		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return fmt.Errorf("inspect unmanaged bundle output directory: %w", readErr)
		}
		if len(entries) != 0 {
			return errors.New("refusing to manage a non-empty directory without the Mesh ownership marker")
		}
		if err := writeSyncedFile(markerPath, []byte(markerValue)); err != nil {
			return err
		}
	} else if markerErr != nil {
		return fmt.Errorf("read bundle ownership marker: %w", markerErr)
	} else if string(marker) != markerValue {
		return errors.New("bundle ownership marker is invalid")
	}
	return syncDir(path)
}

// PreflightManagedOutput performs the non-destructive path checks required
// before consuming a one-time enrollment token. A target must be unused or a
// structurally valid directory previously created by this agent (for crash
// recovery); Activator.Apply later binds its ownership marker to the enrolled
// node and network while holding the output lock.
func PreflightManagedOutput(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve bundle output directory: %w", err)
	}
	path = filepath.Clean(absPath)
	if err := validatePlatformPathSecurity(path); err != nil {
		return err
	}
	if isProtectedOutputPath(path) {
		return errors.New("bundle output must be a dedicated leaf directory, not a filesystem or system root")
	}
	if err := validateManagedOutputParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed bundle output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(info) {
		return errors.New("bundle output must be an owned private real directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inspect managed bundle output directory: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	allowed := map[string]bool{managedDirectoryMarker: true, "versions": true, "current": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return errors.New("bundle output must be unused or contain only a valid Mesh-managed layout")
		}
	}
	marker, err := readSecureBundleFile(filepath.Join(path, managedDirectoryMarker))
	if err != nil || !validManagedMarker(string(marker)) {
		return errors.New("bundle output ownership marker is invalid")
	}
	versionsDir := filepath.Join(path, "versions")
	versionsInfo, err := os.Lstat(versionsDir)
	if errors.Is(err, os.ErrNotExist) {
		if _, currentErr := os.Lstat(filepath.Join(path, "current")); !errors.Is(currentErr, os.ErrNotExist) {
			return errors.New("managed bundle output has a current link without a versions directory")
		}
		return nil
	}
	if err != nil || versionsInfo.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(versionsInfo) {
		return errors.New("managed versions directory must be an owned private real directory")
	}
	versions, err := os.ReadDir(versionsDir)
	if err != nil {
		return fmt.Errorf("inspect managed bundle versions: %w", err)
	}
	for _, version := range versions {
		versionInfo, infoErr := os.Lstat(filepath.Join(versionsDir, version.Name()))
		if infoErr != nil || (!validVersionName(version.Name()) && !validStagingName(version.Name())) || versionInfo.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(versionInfo) {
			return errors.New("managed bundle versions contain an invalid entry")
		}
	}
	currentPath := filepath.Join(path, "current")
	if _, err := os.Lstat(currentPath); err == nil {
		if _, _, err := inspectCurrentLink(currentPath, versionsDir); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current Nebula bundle: %w", err)
	}
	return nil
}

func validManagedMarker(marker string) bool {
	lines := strings.Split(marker, "\n")
	return len(lines) == 4 && lines[0]+"\n" == managedDirectoryPrefix &&
		strings.HasPrefix(lines[1], "node_id=") && validIdentifier(strings.TrimPrefix(lines[1], "node_id=")) &&
		strings.HasPrefix(lines[2], "network_id=") && validIdentifier(strings.TrimPrefix(lines[2], "network_id=")) && lines[3] == ""
}

func validVersionName(name string) bool {
	if len(name) != 51 || name[0] != 'r' || name[21] != '-' || name[38] != '-' {
		return false
	}
	for _, value := range name[1:21] {
		if value < '0' || value > '9' {
			return false
		}
	}
	for _, value := range name[22:38] {
		if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
			return false
		}
	}
	for _, value := range name[39:] {
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '-' || value == '_') {
			return false
		}
	}
	return true
}

func validStagingName(name string) bool {
	const prefix = ".staging-"
	if !strings.HasPrefix(name, prefix) || len(name) <= len(prefix) || len(name) > len(prefix)+64 {
		return false
	}
	for _, value := range name[len(prefix):] {
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '-' || value == '_') {
			return false
		}
	}
	return true
}

func validateManagedOutputParent(path string) error {
	parent := filepath.Clean(filepath.Dir(path))
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect bundle output parent directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !safeManagedParent(info) {
		return errors.New("bundle output parent must be an owned, non-writable real directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != parent {
		return errors.New("bundle output parent path cannot traverse symlinks")
	}
	return nil
}

func secureChildDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create secure bundle directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect secure bundle directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("bundle directory must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure bundle directory: %w", err)
	}
	return nil
}

func isProtectedOutputPath(path string) bool {
	volumeRoot := filepath.Clean(filepath.VolumeName(path) + string(filepath.Separator))
	if path == volumeRoot {
		return true
	}
	protected := map[string]bool{
		"/bin": true, "/boot": true, "/dev": true, "/etc": true, "/home": true,
		"/lib": true, "/lib64": true, "/opt": true, "/proc": true, "/root": true,
		"/run": true, "/sbin": true, "/srv": true, "/sys": true, "/tmp": true,
		"/usr": true, "/var": true,
	}
	return protected[filepath.ToSlash(path)]
}

func inspectCurrentLink(currentPath, versionsDir string) (target string, exists bool, err error) {
	info, err := os.Lstat(currentPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("inspect current Nebula bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false, errors.New("current Nebula bundle must be a symlink")
	}
	target, err = os.Readlink(currentPath)
	if err != nil {
		return "", false, fmt.Errorf("read current Nebula bundle: %w", err)
	}
	if filepath.IsAbs(target) {
		return "", false, errors.New("current Nebula bundle target must be relative")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(currentPath), target))
	inside, err := filepath.Rel(filepath.Clean(versionsDir), resolved)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", false, errors.New("current Nebula bundle points outside the versions directory")
	}
	if filepath.Dir(resolved) != filepath.Clean(versionsDir) {
		return "", false, errors.New("current Nebula bundle must point to one immutable version directory")
	}
	versionInfo, err := os.Lstat(resolved)
	if err != nil {
		return "", false, fmt.Errorf("inspect current Nebula version directory: %w", err)
	}
	if versionInfo.Mode()&os.ModeSymlink != 0 || !privateManagedDirectory(versionInfo) {
		return "", false, errors.New("current Nebula version must be a private real directory")
	}
	return target, true, nil
}

func replaceSymlink(linkPath, target string) error {
	random, err := GenerateBearer()
	if err != nil {
		return err
	}
	temporary := linkPath + ".next-" + random[:12]
	if err := os.Symlink(target, temporary); err != nil {
		return fmt.Errorf("create next Nebula bundle link: %w", err)
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, linkPath); err != nil {
		return fmt.Errorf("activate Nebula bundle: %w", err)
	}
	return nil
}

func writeSyncedFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create staged bundle file %s: %w", filepath.Base(path), err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("inspect staged bundle file %s: %w", filepath.Base(path), err)
	}
	if err := validateOpenedPrivateFile(file, info); err != nil {
		_ = file.Close()
		return fmt.Errorf("staged bundle file %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return fmt.Errorf("write staged bundle file %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync staged bundle file %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged bundle file %s: %w", filepath.Base(path), err)
	}
	return nil
}

func readSecureBundleFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect bundle file %s: %w", filepath.Base(path), err)
	}
	if !privateRegularFile(info) {
		return nil, fmt.Errorf("bundle file %s must be a private regular file", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle file %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("bundle file %s changed while opening", filepath.Base(path))
	}
	if err := validateOpenedPrivateFile(file, opened); err != nil {
		return nil, fmt.Errorf("bundle file %s: %w", filepath.Base(path), err)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBundleFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read bundle file %s: %w", filepath.Base(path), err)
	}
	if len(content) > maxBundleFileSize {
		return nil, fmt.Errorf("bundle file %s exceeds size limit", filepath.Base(path))
	}
	return content, nil
}

func (a *Activator) syncDirectory(path string) error {
	if a.syncFn != nil {
		return a.syncFn(path)
	}
	return syncDir(path)
}
