package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"mesh/internal/buildinfo"
)

const (
	BootstrapManifestSchema            = "mesh-bootstrap-manifest-v1"
	MaxBootstrapArtifactSize     int64 = 128 << 20
	MaxBootstrapManifestLifetime       = 31 * 24 * time.Hour
)

var bootstrapGoVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.-]*)$`)

// BootstrapManifest is the root-role-authorized handoff for the separately
// authenticated first installer. The release URL is intentionally absent:
// transport is an untrusted courier and cannot become bootstrap authority.
type BootstrapManifest struct {
	Schema                   string                 `json:"schema"`
	Channel                  string                 `json:"channel"`
	RootVersion              uint64                 `json:"root_version"`
	ReleaseEpoch             uint64                 `json:"release_epoch"`
	RootSHA256               string                 `json:"root_sha256"`
	InstallerBootstrapSHA256 string                 `json:"installer_bootstrap_sha256"`
	IssuedAt                 string                 `json:"issued_at"`
	ExpiresAt                string                 `json:"expires_at"`
	Build                    buildinfo.IdentityInfo `json:"build"`
	GoVersion                string                 `json:"go_version"`
	Artifact                 BootstrapArtifact      `json:"artifact"`
}

type BootstrapArtifact struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ParsedBootstrapManifest struct {
	Document  BootstrapManifest
	IssuedAt  time.Time
	ExpiresAt time.Time
	SHA256    string
}

type VerifiedBootstrapManifest struct {
	ParsedBootstrapManifest
	SignerKeyIDs []string
}

// EncodeBootstrapManifest emits compact canonical JSON followed by one LF.
func EncodeBootstrapManifest(document BootstrapManifest) ([]byte, error) {
	if _, _, err := validateBootstrapManifest(document); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap manifest: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxManifestSize {
		return nil, fmt.Errorf("bootstrap manifest exceeds %d bytes", MaxManifestSize)
	}
	return raw, nil
}

// ParseBootstrapManifest accepts only the sole encoding emitted above and
// applies the fixed verification time supplied by the caller.
func ParseBootstrapManifest(raw []byte, now time.Time, clockSkew time.Duration) (ParsedBootstrapManifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestSize {
		return ParsedBootstrapManifest{}, fmt.Errorf("bootstrap manifest size must be between 1 and %d bytes", MaxManifestSize)
	}
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || raw[len(raw)-2] == '\n' {
		return ParsedBootstrapManifest{}, errors.New("bootstrap manifest must be compact JSON followed by exactly one LF")
	}
	top, err := exactObject(raw,
		"schema", "channel", "root_version", "release_epoch", "root_sha256",
		"installer_bootstrap_sha256", "issued_at", "expires_at", "build", "go_version", "artifact",
	)
	if err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap manifest: %w", err)
	}
	if err := requireFields(top,
		"schema", "channel", "root_version", "release_epoch", "root_sha256",
		"installer_bootstrap_sha256", "issued_at", "expires_at", "build", "go_version", "artifact",
	); err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap manifest: %w", err)
	}
	buildObject, err := exactObject(top["build"],
		"schema", "version", "commit", "build_time", "security_floor",
		"agent_state_read_min", "agent_state_read_max", "agent_state_write_version",
	)
	if err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap build identity: %w", err)
	}
	if err := requireFields(buildObject,
		"schema", "version", "commit", "build_time", "security_floor",
		"agent_state_read_min", "agent_state_read_max", "agent_state_write_version",
	); err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap build identity: %w", err)
	}
	artifactObject, err := exactObject(top["artifact"], "name", "os", "arch", "size", "sha256")
	if err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap artifact: %w", err)
	}
	if err := requireFields(artifactObject, "name", "os", "arch", "size", "sha256"); err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap artifact: %w", err)
	}
	var document BootstrapManifest
	if err := decodeStrict(raw, &document); err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("invalid bootstrap manifest: %w", err)
	}
	issuedAt, expiresAt, err := validateBootstrapManifest(document)
	if err != nil {
		return ParsedBootstrapManifest{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if clockSkew == 0 {
		clockSkew = 5 * time.Minute
	}
	if clockSkew < 0 {
		return ParsedBootstrapManifest{}, errors.New("bootstrap verification clock skew cannot be negative")
	}
	if issuedAt.After(now.Add(clockSkew)) {
		return ParsedBootstrapManifest{}, errors.New("bootstrap manifest issued_at is too far in the future")
	}
	if !now.Before(expiresAt) {
		return ParsedBootstrapManifest{}, fmt.Errorf("bootstrap manifest expired at %s", expiresAt.Format(time.RFC3339))
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return ParsedBootstrapManifest{}, fmt.Errorf("canonicalize bootstrap manifest: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return ParsedBootstrapManifest{}, errors.New("bootstrap manifest JSON is not in canonical encoding")
	}
	digest := sha256.Sum256(raw)
	return ParsedBootstrapManifest{
		Document: document, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		SHA256: hex.EncodeToString(digest[:]),
	}, nil
}

// VerifyBootstrapManifest authenticates an installer authorization with the
// version-1 root role. The root digest itself still has to arrive through the
// independent ceremony; a root cannot authenticate itself.
func VerifyBootstrapManifest(raw []byte, rawEnvelopes [][]byte, root ParsedRoot, now time.Time, clockSkew time.Duration) (VerifiedBootstrapManifest, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	trustedRoot, err := reparseTrustedRoot(root)
	if err != nil {
		return VerifiedBootstrapManifest{}, fmt.Errorf("trusted bootstrap root: %w", err)
	}
	if trustedRoot.Document.Version != 1 || trustedRoot.Document.ReleaseEpoch != 1 {
		return VerifiedBootstrapManifest{}, errors.New("bootstrap authorization requires release root version 1 and epoch 1")
	}
	if err := ValidateCurrentRoot(trustedRoot, now, clockSkew); err != nil {
		return VerifiedBootstrapManifest{}, fmt.Errorf("trusted bootstrap root: %w", err)
	}
	votes, err := collectSignatureVotes(raw, rawEnvelopes, trustedRoot.RootKeys)
	if err != nil {
		return VerifiedBootstrapManifest{}, fmt.Errorf("bootstrap signatures: %w", err)
	}
	signerIDs := sortedVoteIDs(votes.ByKind[BootstrapManifestKind])
	threshold := trustedRoot.Document.Roles.Root.Threshold
	if len(signerIDs) < threshold {
		thresholdErr := fmt.Errorf("root threshold %d not reached for bootstrap manifest: got %d distinct valid signatures", threshold, len(signerIDs))
		if votes.FirstInvalid != nil {
			return VerifiedBootstrapManifest{}, fmt.Errorf("%w; ignored invalid envelope: %v", thresholdErr, votes.FirstInvalid)
		}
		return VerifiedBootstrapManifest{}, thresholdErr
	}
	parsed, err := ParseBootstrapManifest(raw, now, clockSkew)
	if err != nil {
		return VerifiedBootstrapManifest{}, fmt.Errorf("authenticated bootstrap manifest semantics: %w", err)
	}
	document := parsed.Document
	if document.Channel != trustedRoot.Document.Channel || document.RootVersion != 1 || document.ReleaseEpoch != 1 || document.RootSHA256 != trustedRoot.SHA256 {
		return VerifiedBootstrapManifest{}, errors.New("bootstrap manifest does not bind the independently authenticated version-1 root")
	}
	if document.Build.SecurityFloor < trustedRoot.Document.MinimumSecurityFloor {
		return VerifiedBootstrapManifest{}, errors.New("bootstrap build security floor is below the trusted root floor")
	}
	if parsed.IssuedAt.Before(trustedRoot.IssuedAt) || parsed.ExpiresAt.After(trustedRoot.ExpiresAt) {
		return VerifiedBootstrapManifest{}, errors.New("bootstrap manifest validity is outside the trusted root validity")
	}
	return VerifiedBootstrapManifest{ParsedBootstrapManifest: parsed, SignerKeyIDs: append([]string(nil), signerIDs...)}, nil
}

func validateBootstrapManifest(document BootstrapManifest) (time.Time, time.Time, error) {
	if document.Schema != BootstrapManifestSchema {
		return time.Time{}, time.Time{}, fmt.Errorf("unsupported bootstrap manifest schema %q", document.Schema)
	}
	if !channelPattern.MatchString(document.Channel) {
		return time.Time{}, time.Time{}, errors.New("bootstrap channel is not canonical")
	}
	if document.RootVersion != 1 || document.ReleaseEpoch != 1 {
		return time.Time{}, time.Time{}, errors.New("bootstrap manifest requires root version 1 and release epoch 1")
	}
	if err := validateSHA256(document.RootSHA256); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap root_sha256: %w", err)
	}
	if err := validateSHA256(document.InstallerBootstrapSHA256); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("installer_bootstrap_sha256: %w", err)
	}
	if _, err := buildinfo.EncodeIdentity(document.Build); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap build identity: %w", err)
	}
	if !bootstrapGoVersionPattern.MatchString(document.GoVersion) || len(document.GoVersion) > 64 {
		return time.Time{}, time.Time{}, errors.New("bootstrap go_version is not canonical")
	}
	validPlatform := document.Artifact.OS == "linux" && document.Artifact.Name == "mesh-install" ||
		document.Artifact.OS == "windows" && document.Artifact.Name == "mesh-install-windows.exe"
	if !validPlatform || document.Artifact.Arch != "amd64" && document.Artifact.Arch != "arm64" {
		return time.Time{}, time.Time{}, errors.New("bootstrap artifact must be mesh-install for Linux or mesh-install-windows.exe for Windows on amd64 or arm64")
	}
	if document.Artifact.Size <= 0 || document.Artifact.Size > MaxBootstrapArtifactSize {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap artifact size must be between 1 and %d", MaxBootstrapArtifactSize)
	}
	if err := validateSHA256(document.Artifact.SHA256); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap artifact sha256: %w", err)
	}
	issuedAt, err := parseCanonicalTime(document.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap issued_at: %w", err)
	}
	expiresAt, err := parseCanonicalTime(document.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap expires_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return time.Time{}, time.Time{}, errors.New("bootstrap expires_at must be after issued_at")
	}
	if expiresAt.Sub(issuedAt) > MaxBootstrapManifestLifetime {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap manifest validity must not exceed %s", MaxBootstrapManifestLifetime)
	}
	buildTime, err := parseCanonicalTime(document.Build.BuildTime)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrap build_time: %w", err)
	}
	if buildTime.After(issuedAt) {
		return time.Time{}, time.Time{}, errors.New("bootstrap build_time must not be after issued_at")
	}
	return issuedAt, expiresAt, nil
}
