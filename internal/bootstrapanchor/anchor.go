// Package bootstrapanchor defines the small unsigned authority file that an
// operator transfers independently of the release origin and Mesh control
// plane. Its transport, not a signature in this package, grants authority.
package bootstrapanchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"mesh/internal/bootstraphandoff"
	releasetrust "mesh/internal/release"
)

const (
	LegacySchema    = "mesh-bootstrap-anchor-v1"
	Schema          = "mesh-bootstrap-anchor-v2"
	MaxDocumentSize = 8 << 10
	HandoffName     = "bootstrap-handoff.json"
)

var (
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	channelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type Document struct {
	Schema    string              `json:"schema"`
	Channel   string              `json:"channel"`
	Handoff   HandoffReference    `json:"handoff"`
	Root      RootReference       `json:"root"`
	Build     BuildReference      `json:"build"`
	Verifiers []VerifierReference `json:"verifiers"`
}

type HandoffReference struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type RootReference struct {
	Name         string `json:"name"`
	Version      uint64 `json:"version"`
	ReleaseEpoch uint64 `json:"release_epoch"`
	SHA256       string `json:"sha256"`
}

type BuildReference struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	SecurityFloor uint64 `json:"security_floor"`
}

type VerifierReference struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
}

type Resolution struct {
	AnchorSHA256  string
	HandoffSHA256 string
}

func Encode(document Document) ([]byte, error) {
	if err := validate(document); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap anchor: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxDocumentSize {
		return nil, fmt.Errorf("bootstrap anchor exceeds %d bytes", MaxDocumentSize)
	}
	return raw, nil
}

func Parse(raw []byte) (Document, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentSize {
		return Document{}, fmt.Errorf("bootstrap anchor size must be between 1 and %d bytes", MaxDocumentSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Document{}, fmt.Errorf("invalid bootstrap anchor JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode bootstrap anchor: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("bootstrap anchor contains trailing content")
	}
	if err := validate(document); err != nil {
		return Document{}, err
	}
	canonical, err := Encode(document)
	if err != nil {
		return Document{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Document{}, errors.New("bootstrap anchor must be canonical compact JSON followed by one LF")
	}
	return clone(document), nil
}

// Resolve accepts anchorRaw as independently transferred authority, then
// authenticates the courier handoff's exact bytes before interpreting it.
func Resolve(anchorRaw, handoffRaw []byte, now time.Time) (Resolution, error) {
	anchor, err := Parse(anchorRaw)
	if err != nil {
		return Resolution{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	issuedAt, _ := parseTime(anchor.Handoff.IssuedAt, "handoff.issued_at")
	expiresAt, _ := parseTime(anchor.Handoff.ExpiresAt, "handoff.expires_at")
	if now.Before(issuedAt) {
		return Resolution{}, errors.New("bootstrap anchor is not valid yet")
	}
	if !now.Before(expiresAt) {
		return Resolution{}, errors.New("bootstrap anchor has expired")
	}
	if int64(len(handoffRaw)) != anchor.Handoff.Size {
		return Resolution{}, errors.New("bootstrap handoff size differs from the independent anchor")
	}
	handoffDigest := sha256.Sum256(handoffRaw)
	handoffSHA := hex.EncodeToString(handoffDigest[:])
	if handoffSHA != anchor.Handoff.SHA256 {
		return Resolution{}, errors.New("bootstrap handoff differs from the independent anchor")
	}
	handoff, err := bootstraphandoff.Authenticate(handoffRaw, handoffSHA, now)
	if err != nil {
		return Resolution{}, err
	}
	if err := compare(anchor, handoff); err != nil {
		return Resolution{}, err
	}
	anchorDigest := sha256.Sum256(anchorRaw)
	return Resolution{AnchorSHA256: hex.EncodeToString(anchorDigest[:]), HandoffSHA256: handoffSHA}, nil
}

func validate(document Document) error {
	if document.Schema != LegacySchema && document.Schema != Schema {
		return fmt.Errorf("unsupported bootstrap anchor schema %q", document.Schema)
	}
	if !channelPattern.MatchString(document.Channel) {
		return errors.New("bootstrap anchor channel is not canonical")
	}
	if document.Handoff.Name != HandoffName || document.Handoff.Size < 1 || document.Handoff.Size > bootstraphandoff.MaxDocumentSize || !digestPattern.MatchString(document.Handoff.SHA256) {
		return errors.New("bootstrap anchor handoff reference is not canonical")
	}
	issuedAt, err := parseTime(document.Handoff.IssuedAt, "handoff.issued_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseTime(document.Handoff.ExpiresAt, "handoff.expires_at")
	if err != nil {
		return err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > bootstraphandoff.MaxValidity {
		return fmt.Errorf("bootstrap anchor validity must be positive and at most %s", bootstraphandoff.MaxValidity)
	}
	if document.Root.Name != bootstraphandoff.RootName || document.Root.Version != 1 || document.Root.ReleaseEpoch != 1 || !digestPattern.MatchString(document.Root.SHA256) {
		return errors.New("bootstrap anchor root reference is not canonical version 1, epoch 1")
	}
	if !versionPattern.MatchString(document.Build.Version) || document.Build.Version == "0.0.0" || !commitPattern.MatchString(document.Build.Commit) || document.Build.SecurityFloor == 0 {
		return errors.New("bootstrap anchor production build reference is not canonical")
	}
	targets := canonicalTargets(document.Schema)
	if len(document.Verifiers) != len(targets) {
		return fmt.Errorf("bootstrap anchor schema %q must contain exactly %d verifier packages", document.Schema, len(targets))
	}
	for index, target := range targets {
		verifier := document.Verifiers[index]
		if verifier.Name != bootstraphandoff.VerifierName(target.OS, target.Arch) || verifier.OS != target.OS || verifier.Arch != target.Arch || !digestPattern.MatchString(verifier.SHA256) {
			return fmt.Errorf("bootstrap anchor verifier %d is not canonical %s/%s", index, target.OS, target.Arch)
		}
	}
	return nil
}

func compare(anchor Document, handoff bootstraphandoff.Document) error {
	wantAnchorSchema := Schema
	if handoff.Schema == bootstraphandoff.LegacySchema {
		wantAnchorSchema = LegacySchema
	}
	if anchor.Schema != wantAnchorSchema {
		return errors.New("bootstrap anchor schema generation differs from the authenticated handoff")
	}
	if anchor.Channel != handoff.Channel || anchor.Handoff.Name != HandoffName ||
		anchor.Handoff.IssuedAt != handoff.IssuedAt || anchor.Handoff.ExpiresAt != handoff.ExpiresAt ||
		anchor.Root.Name != handoff.Root.Name || anchor.Root.Version != handoff.Root.Version ||
		anchor.Root.ReleaseEpoch != handoff.Root.ReleaseEpoch || anchor.Root.SHA256 != handoff.Root.SHA256 ||
		anchor.Build.Version != handoff.Build.Version || anchor.Build.Commit != handoff.Build.Commit ||
		anchor.Build.SecurityFloor != handoff.Build.SecurityFloor {
		return errors.New("bootstrap anchor review fields differ from the authenticated handoff")
	}
	for index := range anchor.Verifiers {
		left, right := anchor.Verifiers[index], handoff.Verifiers[index]
		if left.Name != right.Name || left.OS != right.OS || left.Arch != right.Arch || left.SHA256 != right.SHA256 {
			return errors.New("bootstrap anchor verifier fields differ from the authenticated handoff")
		}
	}
	return nil
}

func parseTime(value, label string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("bootstrap anchor %s must be canonical UTC RFC3339 without fractional seconds", label)
	}
	return parsed.UTC(), nil
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

func clone(document Document) Document {
	result := document
	result.Verifiers = append([]VerifierReference(nil), document.Verifiers...)
	return result
}
