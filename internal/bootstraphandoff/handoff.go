// Package bootstraphandoff defines the one small document whose digest must be
// authenticated outside the installer origin. The document binds the exact
// version-1 root and the complete supported standalone-verifier package set. It is
// deliberately unsigned: its independent delivery is the trust boundary.
package bootstraphandoff

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
	releasetrust "mesh/internal/release"
)

const (
	LegacySchema           = "mesh-bootstrap-handoff-v1"
	Schema                 = "mesh-bootstrap-handoff-v2"
	MaxDocumentSize        = 64 << 10
	MaxValidity            = 31 * 24 * time.Hour
	RootName               = "root-v1.json"
	maxVerifierArchiveSize = 136 << 20
)

var (
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	channelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	goVersionRegex = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.-]*)$`)
)

type Document struct {
	Schema    string                 `json:"schema"`
	Channel   string                 `json:"channel"`
	IssuedAt  string                 `json:"issued_at"`
	ExpiresAt string                 `json:"expires_at"`
	Root      RootReference          `json:"root"`
	Build     buildinfo.IdentityInfo `json:"build"`
	GoVersion string                 `json:"go_version"`
	Verifiers []VerifierReference    `json:"verifiers"`
}

type RootReference struct {
	Name                 string `json:"name"`
	Version              uint64 `json:"version"`
	ReleaseEpoch         uint64 `json:"release_epoch"`
	MinimumSecurityFloor uint64 `json:"minimum_security_floor"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Size                 int64  `json:"size"`
	SHA256               string `json:"sha256"`
}

type VerifierReference struct {
	Name              string `json:"name"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	Size              int64  `json:"size"`
	SHA256            string `json:"sha256"`
	PackageJSONSHA256 string `json:"package_json_sha256"`
	VerifierSHA256    string `json:"verifier_sha256"`
}

// Resolution is the exact platform trust material derived only after the
// handoff digest, validity, canonical root, and platform selection pass.
type Resolution struct {
	HandoffSHA256 string
	RootSHA256    string
	Verifier      VerifierReference
	Build         buildinfo.IdentityInfo
	GoVersion     string
}

// Authenticate checks the independently supplied digest before interpreting
// the compact handoff, then requires its canonical schema and current validity.
// A zero Now uses the current UTC time.
func Authenticate(raw []byte, expectedSHA256 string, now time.Time) (Document, error) {
	if !digestPattern.MatchString(expectedSHA256) {
		return Document{}, errors.New("expected handoff SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if len(raw) == 0 || len(raw) > MaxDocumentSize {
		return Document{}, fmt.Errorf("bootstrap handoff size must be between 1 and %d bytes", MaxDocumentSize)
	}
	handoffDigest := sha256.Sum256(raw)
	if hex.EncodeToString(handoffDigest[:]) != expectedSHA256 {
		return Document{}, errors.New("bootstrap handoff differs from the independently authenticated digest")
	}
	document, err := Parse(raw)
	if err != nil {
		return Document{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	issuedAt, _ := parseTime(document.IssuedAt, "issued_at")
	expiresAt, _ := parseTime(document.ExpiresAt, "expires_at")
	if now.Before(issuedAt) {
		return Document{}, errors.New("bootstrap handoff is not valid yet")
	}
	if !now.Before(expiresAt) {
		return Document{}, errors.New("bootstrap handoff has expired")
	}
	return clone(document), nil
}

// Resolve authenticates the handoff, checks its exact root bytes, and selects
// one supported verifier package for the exact host platform.
func Resolve(raw []byte, expectedSHA256 string, rootRaw []byte, platformOS, arch string, now time.Time) (Resolution, error) {
	document, err := Authenticate(raw, expectedSHA256, now)
	if err != nil {
		return Resolution{}, err
	}
	if !supportedTarget(platformOS, arch) {
		return Resolution{}, errors.New("bootstrap handoff platform must be linux or windows with amd64 or arm64")
	}
	if int64(len(rootRaw)) != document.Root.Size {
		return Resolution{}, errors.New("bootstrap root size differs from the authenticated handoff")
	}
	rootDigest := sha256.Sum256(rootRaw)
	if hex.EncodeToString(rootDigest[:]) != document.Root.SHA256 {
		return Resolution{}, errors.New("bootstrap root digest differs from the authenticated handoff")
	}
	root, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		return Resolution{}, fmt.Errorf("parse handoff bootstrap root: %w", err)
	}
	if root.SHA256 != document.Root.SHA256 || root.Document.Channel != document.Channel ||
		root.Document.Version != document.Root.Version || root.Document.ReleaseEpoch != document.Root.ReleaseEpoch ||
		root.Document.MinimumSecurityFloor != document.Root.MinimumSecurityFloor ||
		root.Document.IssuedAt != document.Root.IssuedAt || root.Document.ExpiresAt != document.Root.ExpiresAt {
		return Resolution{}, errors.New("bootstrap root semantics differ from the authenticated handoff")
	}
	var selected VerifierReference
	found := false
	for _, verifier := range document.Verifiers {
		if verifier.OS == platformOS && verifier.Arch == arch {
			selected = verifier
			found = true
			break
		}
	}
	if !found {
		return Resolution{}, fmt.Errorf("bootstrap handoff schema %q does not authorize a verifier for %s/%s", document.Schema, platformOS, arch)
	}
	return Resolution{
		HandoffSHA256: expectedSHA256, RootSHA256: document.Root.SHA256,
		Verifier: selected, Build: document.Build, GoVersion: document.GoVersion,
	}, nil
}

func Encode(document Document) ([]byte, error) {
	if err := validate(document); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap handoff: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxDocumentSize {
		return nil, fmt.Errorf("bootstrap handoff exceeds %d bytes", MaxDocumentSize)
	}
	return raw, nil
}

func Parse(raw []byte) (Document, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentSize {
		return Document{}, fmt.Errorf("bootstrap handoff size must be between 1 and %d bytes", MaxDocumentSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Document{}, fmt.Errorf("invalid bootstrap handoff JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode bootstrap handoff: %w", err)
	}
	if err := validate(document); err != nil {
		return Document{}, err
	}
	canonical, err := Encode(document)
	if err != nil {
		return Document{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Document{}, errors.New("bootstrap handoff must be canonical compact JSON followed by one LF")
	}
	return clone(document), nil
}

func validate(document Document) error {
	if document.Schema != LegacySchema && document.Schema != Schema {
		return fmt.Errorf("unsupported bootstrap handoff schema %q", document.Schema)
	}
	if !channelPattern.MatchString(document.Channel) {
		return errors.New("bootstrap handoff channel is not canonical")
	}
	issuedAt, err := parseTime(document.IssuedAt, "issued_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseTime(document.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxValidity {
		return fmt.Errorf("bootstrap handoff validity must be positive and at most %s", MaxValidity)
	}
	if document.Root.Name != RootName || document.Root.Version != 1 || document.Root.ReleaseEpoch != 1 || document.Root.MinimumSecurityFloor == 0 {
		return errors.New("bootstrap handoff root reference is not canonical version 1, epoch 1")
	}
	rootIssuedAt, err := parseTime(document.Root.IssuedAt, "root.issued_at")
	if err != nil {
		return err
	}
	rootExpiresAt, err := parseTime(document.Root.ExpiresAt, "root.expires_at")
	if err != nil {
		return err
	}
	if rootIssuedAt.After(issuedAt) || rootExpiresAt.Before(expiresAt) || !rootExpiresAt.After(rootIssuedAt) {
		return errors.New("bootstrap handoff validity is outside its root reference")
	}
	if document.Root.Size <= 0 || document.Root.Size > releasetrust.MaxRootSize || !digestPattern.MatchString(document.Root.SHA256) {
		return errors.New("bootstrap handoff root size or SHA-256 is not canonical")
	}
	if _, err := buildinfo.EncodeIdentity(document.Build); err != nil {
		return fmt.Errorf("bootstrap handoff build identity: %w", err)
	}
	if document.Build.Version == "dev" || document.Build.SecurityFloor < document.Root.MinimumSecurityFloor {
		return errors.New("bootstrap handoff requires a production verifier at or above the root security floor")
	}
	buildTime, err := time.Parse(time.RFC3339, document.Build.BuildTime)
	if err != nil || buildTime.UTC().Format(time.RFC3339) != document.Build.BuildTime || buildTime.After(issuedAt) {
		return errors.New("bootstrap handoff build time is not canonical or follows issuance")
	}
	if !goVersionRegex.MatchString(document.GoVersion) || len(document.GoVersion) > 64 {
		return errors.New("bootstrap handoff Go version is not canonical")
	}
	targets := canonicalTargets(document.Schema)
	if len(document.Verifiers) != len(targets) {
		return fmt.Errorf("bootstrap handoff schema %q must contain exactly %d verifier packages", document.Schema, len(targets))
	}
	for index, target := range targets {
		verifier := document.Verifiers[index]
		if verifier.Name != VerifierName(target.OS, target.Arch) || verifier.OS != target.OS || verifier.Arch != target.Arch || verifier.Size <= 0 || verifier.Size > maxVerifierArchiveSize {
			return fmt.Errorf("bootstrap handoff verifier %d is not canonical %s/%s", index, target.OS, target.Arch)
		}
		if !digestPattern.MatchString(verifier.SHA256) || !digestPattern.MatchString(verifier.PackageJSONSHA256) || !digestPattern.MatchString(verifier.VerifierSHA256) {
			return fmt.Errorf("bootstrap handoff verifier %s/%s digests are not canonical", target.OS, target.Arch)
		}
	}
	return nil
}

func parseTime(value, name string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must be canonical UTC RFC3339 without fractional seconds", name)
	}
	return parsed.UTC(), nil
}

func VerifierName(platformOS, arch string) string {
	return "mesh-bootstrap-verifier-" + platformOS + "-" + arch + ".tar"
}

type target struct {
	OS   string
	Arch string
}

func canonicalTargets(schema string) []target {
	targets := []target{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}}
	if schema == Schema {
		targets = append(targets, target{OS: "windows", Arch: "amd64"}, target{OS: "windows", Arch: "arm64"})
	}
	return targets
}

func supportedTarget(platformOS, arch string) bool {
	return (platformOS == "linux" || platformOS == "windows") && (arch == "amd64" || arch == "arm64")
}

func clone(document Document) Document {
	result := document
	result.Verifiers = append([]VerifierReference(nil), document.Verifiers...)
	return result
}
