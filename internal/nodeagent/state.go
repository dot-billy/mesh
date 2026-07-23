package nodeagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/control"
)

const (
	// StateSchemaVersion is the durable state schema written by this agent.
	// Release identities declare this exact writer plus the inclusive schema
	// range they can read, allowing reversible upgrades to be proven pre-switch.
	StateSchemaVersion = agentstate.CurrentWriteVersion

	maxStateSize = 1 << 20
)

// State contains the node-scoped secret and the monotonic values that must
// survive agent and host restarts. It is deliberately small enough to persist
// atomically after every lifecycle operation.
type State struct {
	Version                                int       `json:"version"`
	ServerURL                              string    `json:"server_url"`
	Bearer                                 string    `json:"bearer"`
	PendingBearer                          string    `json:"pending_bearer,omitempty"`
	PendingRecoveryToken                   string    `json:"pending_recovery_token,omitempty"`
	PendingRecoveryAllowsGenerationAdvance bool      `json:"pending_recovery_allows_generation_advance,omitempty"`
	NodeID                                 string    `json:"node_id"`
	NetworkID                              string    `json:"network_id"`
	ConfigSigningPublicKey                 string    `json:"config_signing_public_key"`
	CACertificateSHA256                    string    `json:"ca_certificate_sha256"`
	PublicKeyHash                          string    `json:"public_key_hash"`
	AppliedConfigRevision                  int64     `json:"applied_config_revision"`
	AppliedConfigSHA256                    string    `json:"applied_config_sha256,omitempty"`
	LastSuccessfulConfigAt                 time.Time `json:"last_successful_config_at,omitempty"`
	CertificateFingerprint                 string    `json:"certificate_fingerprint,omitempty"`
	CertificateGeneration                  int64     `json:"certificate_generation"`
	CertificateExpiresAt                   time.Time `json:"certificate_expires_at"`
	CertificateRenewAfter                  time.Time `json:"certificate_renew_after"`
	AgentCredentialExpiresAt               time.Time `json:"agent_credential_expires_at"`
	AgentCredentialGeneration              int64     `json:"agent_credential_generation"`
	HeartbeatSequence                      int64     `json:"heartbeat_sequence"`
	BootID                                 string    `json:"boot_id"`
	OutputDir                              string    `json:"output_dir"`
}

// ProvisionalEnrollment is the crash journal that must be written before the
// one-time enrollment POST. Retrying reuses the exact bearer and public key,
// preserving the server's idempotency hash if the first response was lost.
type ProvisionalEnrollment struct {
	Version         int       `json:"version"`
	ServerURL       string    `json:"server_url"`
	EnrollmentToken string    `json:"enrollment_token"`
	Bearer          string    `json:"bearer"`
	PrivateKey      string    `json:"private_key"`
	PublicKey       string    `json:"public_key"`
	OutputDir       string    `json:"output_dir"`
	CreatedAt       time.Time `json:"created_at"`
}

func NewProvisionalEnrollment(serverURL, enrollmentToken, outputDir, privateKey, publicKey string) (ProvisionalEnrollment, error) {
	serverURL, err := normalizeServerURL(serverURL)
	if err != nil {
		return ProvisionalEnrollment{}, err
	}
	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return ProvisionalEnrollment{}, fmt.Errorf("resolve enrollment output directory: %w", err)
	}
	bearer, err := GenerateBearer()
	if err != nil {
		return ProvisionalEnrollment{}, err
	}
	journal := ProvisionalEnrollment{
		Version: StateSchemaVersion, ServerURL: serverURL, EnrollmentToken: strings.TrimSpace(enrollmentToken),
		Bearer: bearer, PrivateKey: privateKey, PublicKey: publicKey,
		OutputDir: filepath.Clean(absOutput), CreatedAt: time.Now().UTC(),
	}
	if err := journal.Validate(); err != nil {
		return ProvisionalEnrollment{}, err
	}
	return journal, nil
}

func (p ProvisionalEnrollment) Validate() error {
	if p.Version != StateSchemaVersion {
		return fmt.Errorf("unsupported provisional enrollment version %d", p.Version)
	}
	serverURL, err := normalizeServerURL(p.ServerURL)
	if err != nil || serverURL != p.ServerURL {
		return errors.New("provisional enrollment server URL is invalid")
	}
	if !control.ValidBearerToken(strings.TrimSpace(p.EnrollmentToken)) || !control.ValidBearerToken(strings.TrimSpace(p.Bearer)) {
		return errors.New("provisional enrollment credentials are missing")
	}
	if p.PrivateKey == "" || p.PublicKey == "" || len(p.PrivateKey) > maxBundleFileSize || len(p.PublicKey) > maxBundleFileSize {
		return errors.New("provisional enrollment keypair is missing or too large")
	}
	if !filepath.IsAbs(p.OutputDir) || filepath.Clean(p.OutputDir) != p.OutputDir || p.CreatedAt.IsZero() {
		return errors.New("provisional enrollment output or creation time is invalid")
	}
	return nil
}

// NewEnrollmentState builds the initially pinned state from a verified HTTPS
// endpoint and the enrollment response. The bearer must have been generated
// locally and only its hash sent with the enrollment request.
func NewEnrollmentState(serverURL, bearer, outputDir, publicKey string, bundle control.EnrollmentBundle) (State, error) {
	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return State{}, fmt.Errorf("resolve output directory: %w", err)
	}
	serverURL, err = normalizeServerURL(serverURL)
	if err != nil {
		return State{}, err
	}
	bootID, err := CurrentBootID()
	if err != nil {
		return State{}, err
	}
	state := State{
		Version:                   StateSchemaVersion,
		ServerURL:                 serverURL,
		Bearer:                    strings.TrimSpace(bearer),
		NodeID:                    bundle.NodeID,
		NetworkID:                 bundle.NetworkID,
		ConfigSigningPublicKey:    bundle.ConfigSigningPublicKey,
		CACertificateSHA256:       control.ConfigDigest(bundle.CA),
		PublicKeyHash:             canonicalPublicKeyHash(publicKey),
		CertificateFingerprint:    bundle.CertificateFingerprint,
		CertificateGeneration:     bundle.CertificateGeneration,
		CertificateExpiresAt:      bundle.CertificateExpiresAt,
		CertificateRenewAfter:     bundle.CertificateRenewAfter,
		AgentCredentialExpiresAt:  bundle.AgentCredentialExpiresAt,
		AgentCredentialGeneration: bundle.AgentCredentialGeneration,
		BootID:                    bootID,
		OutputDir:                 filepath.Clean(absOutput),
	}
	if bundle.Node.ID != state.NodeID || bundle.Node.NetworkID != state.NetworkID || bundle.CACertificateSHA256 != state.CACertificateSHA256 || bundle.PublicKeyHash != state.PublicKeyHash {
		return State{}, errors.New("enrollment identity, CA, or public key does not match its signed metadata")
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

// GenerateBearer returns a 256-bit node credential suitable for hashing with
// control.HashToken before enrollment or credential rotation.
func GenerateBearer() (string, error) {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("generate agent bearer: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// CurrentBootID returns the kernel boot identifier where available. The
// random fallback remains stable once State is saved and is safe on platforms
// without a kernel boot-id facility.
func CurrentBootID() (string, error) {
	if bootID, ok := systemBootID(); ok {
		return bootID, nil
	}
	random, err := GenerateBearer()
	if err != nil {
		return "", err
	}
	return "boot-" + random[:32], nil
}

func (s State) Validate() error {
	if s.Version != StateSchemaVersion {
		return fmt.Errorf("unsupported agent state version %d", s.Version)
	}
	serverURL, err := normalizeServerURL(s.ServerURL)
	if err != nil {
		return err
	}
	if serverURL != s.ServerURL {
		return errors.New("agent server URL is not canonical")
	}
	if !control.ValidBearerToken(s.Bearer) {
		return errors.New("agent bearer is missing or too short")
	}
	if s.PendingBearer != "" && !control.ValidBearerToken(s.PendingBearer) {
		return errors.New("pending agent bearer is too short")
	}
	if s.PendingBearer != "" && s.PendingBearer == s.Bearer {
		return errors.New("pending agent bearer must differ from the active bearer")
	}
	if s.PendingRecoveryToken != "" {
		if !control.ValidBearerToken(s.PendingRecoveryToken) {
			return errors.New("pending agent recovery token is invalid")
		}
		if s.PendingBearer == "" {
			return errors.New("pending agent recovery token requires a pending bearer")
		}
	}
	if s.PendingRecoveryAllowsGenerationAdvance && s.PendingRecoveryToken == "" {
		return errors.New("recovery generation advance is only valid for a pending agent recovery")
	}
	if !validIdentifier(s.NodeID) || !validIdentifier(s.NetworkID) {
		return errors.New("node and network IDs are required")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(s.ConfigSigningPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid pinned config-signing public key")
	}
	if !validDigest(s.CACertificateSHA256) {
		return errors.New("invalid pinned CA certificate digest")
	}
	if !control.ValidTokenHash(s.PublicKeyHash) {
		return errors.New("invalid pinned node public-key hash")
	}
	if s.AppliedConfigRevision < 0 || s.HeartbeatSequence < 0 {
		return errors.New("agent revisions and sequences cannot be negative")
	}
	if s.AppliedConfigRevision == 0 && s.AppliedConfigSHA256 != "" {
		return errors.New("config digest cannot be set without an applied revision")
	}
	if s.AppliedConfigRevision > 0 && !validDigest(s.AppliedConfigSHA256) {
		return errors.New("applied config digest is invalid")
	}
	if !validDigest(s.CertificateFingerprint) {
		return errors.New("certificate fingerprint is invalid")
	}
	if s.CertificateGeneration < 1 {
		return errors.New("certificate generation must be positive")
	}
	if s.CertificateExpiresAt.IsZero() || s.CertificateRenewAfter.IsZero() || !s.CertificateRenewAfter.Before(s.CertificateExpiresAt) {
		return errors.New("certificate expiry and signed renewal time are invalid")
	}
	if s.AgentCredentialExpiresAt.IsZero() {
		return errors.New("agent credential expiry is required")
	}
	if !validIdentifier(s.BootID) {
		return errors.New("boot ID is invalid")
	}
	if !filepath.IsAbs(s.OutputDir) || filepath.Clean(s.OutputDir) != s.OutputDir {
		return errors.New("output directory must be an absolute, clean path")
	}
	if s.AgentCredentialGeneration < 1 {
		return errors.New("agent credential generation must be positive")
	}
	return nil
}

func canonicalPublicKeyHash(publicKey string) string {
	return control.HashToken(strings.TrimSpace(publicKey) + "\n")
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func normalizeServerURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse agent server URL: %w", err)
	}
	if parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("agent server URL must contain only a scheme and host")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("agent server URL cannot contain a path")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) {
			return "", errors.New("agent server URL must use HTTPS except on loopback")
		}
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// StateStore persists the secret-bearing state using a 0600 temporary file,
// fsync, and atomic rename. One StateStore is safe for concurrent goroutines.
type StateStore struct {
	path string
	mu   sync.Mutex
}

func NewStateStore(path string) (*StateStore, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve agent state path: %w", err)
	}
	if filepath.Base(absPath) == "." || filepath.Base(absPath) == string(filepath.Separator) {
		return nil, errors.New("agent state path must name a file")
	}
	absPath = filepath.Clean(absPath)
	if err := validatePlatformPathSecurity(absPath); err != nil {
		return nil, err
	}
	return &StateStore{path: absPath}, nil
}

func (s *StateStore) Path() string { return s.path }

func (s *StateStore) AcquireProcessLock() (*ProcessLock, error) {
	if err := validatePrivateParent(s.path); err != nil {
		return nil, err
	}
	return acquireProcessLock(s.path + ".lock")
}

func (s *StateStore) SaveProvisionalEnrollment(journal ProvisionalEnrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return err
	}
	if err := journal.Validate(); err != nil {
		return err
	}
	path := s.path + ".enrollment.json"
	if existing, err := loadProvisionalEnrollment(path); err == nil {
		before, _ := json.Marshal(existing)
		after, _ := json.Marshal(journal)
		if string(before) == string(after) {
			return nil
		}
		return errors.New("a different provisional enrollment is already pending")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode provisional enrollment: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeAtomicPrivateFile(path, encoded); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (s *StateStore) LoadProvisionalEnrollment() (ProvisionalEnrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return ProvisionalEnrollment{}, err
	}
	return loadProvisionalEnrollment(s.path + ".enrollment.json")
}

func (s *StateStore) ClearProvisionalEnrollment() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return err
	}
	path := s.path + ".enrollment.json"
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove provisional enrollment journal: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

func loadProvisionalEnrollment(path string) (ProvisionalEnrollment, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ProvisionalEnrollment{}, err
	}
	if !privateRegularFile(info) || info.Size() > maxStateSize {
		return ProvisionalEnrollment{}, errors.New("provisional enrollment journal must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return ProvisionalEnrollment{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ProvisionalEnrollment{}, errors.New("provisional enrollment journal changed while opening")
	}
	if err := validateOpenedPrivateFile(file, opened); err != nil {
		return ProvisionalEnrollment{}, fmt.Errorf("provisional enrollment journal: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxStateSize+1))
	decoder.DisallowUnknownFields()
	var journal ProvisionalEnrollment
	if err := decoder.Decode(&journal); err != nil {
		return ProvisionalEnrollment{}, fmt.Errorf("decode provisional enrollment: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ProvisionalEnrollment{}, fmt.Errorf("decode provisional enrollment: %w", err)
	}
	if err := journal.Validate(); err != nil {
		return ProvisionalEnrollment{}, err
	}
	return journal, nil
}

func writeAtomicPrivateFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".mesh-private-*")
	if err != nil {
		return fmt.Errorf("create temporary private file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary private file: %w", err)
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil {
		return fmt.Errorf("inspect temporary private file: %w", err)
	}
	if err := validateOpenedPrivateFile(temporary, temporaryInfo); err != nil {
		return fmt.Errorf("temporary private file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary private file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary private file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary private file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit private file: %w", err)
	}
	keep = true
	return nil
}

// SaveRecoveryKeyPair retains the node-generated keypair independently of a
// live bundle so an authenticated bootstrap can recover an interrupted initial
// install or renewal. Existing keys are immutable and may only be re-saved if
// the bytes are identical.
func (s *StateStore) SaveRecoveryKeyPair(privateKey, publicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return err
	}
	if privateKey == "" || publicKey == "" || len(privateKey) > maxBundleFileSize || len(publicKey) > maxBundleFileSize {
		return errors.New("node recovery keypair is missing or too large")
	}
	for path, content := range map[string]string{s.path + ".host.key": privateKey, s.path + ".host.pub": publicKey} {
		if existing, err := readSecureBundleFile(path); err == nil {
			if string(existing) != content {
				return fmt.Errorf("refusing to replace existing node recovery key %s", filepath.Base(path))
			}
			continue
		} else if !errors.Is(rootPathError(err), os.ErrNotExist) {
			return err
		}
		if err := writeSyncedFile(path, []byte(content)); err != nil {
			return err
		}
	}
	return syncDir(filepath.Dir(s.path))
}

func (s *StateStore) LoadRecoveryKeyPair() (privateKey, publicKey string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return "", "", err
	}
	privateBytes, err := readSecureBundleFile(s.path + ".host.key")
	if err != nil {
		return "", "", err
	}
	publicBytes, err := readSecureBundleFile(s.path + ".host.pub")
	if err != nil {
		return "", "", err
	}
	return string(privateBytes), string(publicBytes), nil
}

func rootPathError(err error) error {
	for err != nil {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
	return nil
}

func (s *StateStore) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return State{}, err
	}
	return s.load()
}

func (s *StateStore) load() (State, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return State{}, fmt.Errorf("inspect agent state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return State{}, errors.New("agent state must be a regular file")
	}
	if !privateRegularFile(info) {
		return State{}, fmt.Errorf("agent state permissions must be 0600, got %04o", info.Mode().Perm())
	}
	if info.Size() > maxStateSize {
		return State{}, errors.New("agent state exceeds size limit")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return State{}, fmt.Errorf("open agent state: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return State{}, errors.New("agent state changed while opening")
	}
	if err := validateOpenedPrivateFile(file, opened); err != nil {
		return State{}, fmt.Errorf("agent state: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxStateSize+1))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode agent state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return State{}, fmt.Errorf("decode agent state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, fmt.Errorf("validate agent state: %w", err)
	}
	return state, nil
}

func (s *StateStore) Save(state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return err
	}
	if state.Version != 0 && state.Version != StateSchemaVersion {
		return fmt.Errorf("unsupported agent state version %d", state.Version)
	}
	state.Version = StateSchemaVersion
	if err := state.Validate(); err != nil {
		return fmt.Errorf("validate agent state: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create agent state directory: %w", err)
	}
	if info, err := os.Lstat(s.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("agent state must be a regular file")
		}
		if _, err := s.load(); err != nil {
			return fmt.Errorf("refusing to replace invalid agent state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect agent state: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".agent-state-*")
	if err != nil {
		return fmt.Errorf("create temporary agent state: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary agent state: %w", err)
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil {
		return fmt.Errorf("inspect temporary agent state: %w", err)
	}
	if err := validateOpenedPrivateFile(temporary, temporaryInfo); err != nil {
		return fmt.Errorf("temporary agent state: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync agent state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close agent state: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace agent state: %w", err)
	}
	keep = true
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("secure agent state: %w", err)
	}
	return syncDir(dir)
}

func validatePrivateParent(path string) error {
	parent := filepath.Clean(filepath.Dir(path))
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect agent state parent directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("agent state parent must be a real directory")
	}
	if err := validatePrivateStateParentPath(parent, info); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != parent {
		return errors.New("agent state parent path cannot traverse symlinks")
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
