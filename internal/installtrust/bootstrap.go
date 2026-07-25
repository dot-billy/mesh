package installtrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	releasetrust "mesh/internal/release"
)

const (
	bootstrapSchema         = "mesh-linux-installer-bootstrap-v2"
	maxDecodedBootstrapSize = 128 << 10
	maxEncodedBootstrapSize = 256 << 10

	BootstrapFramePrefix = "MESH_INSTALLER_TRUST_V2."
	BootstrapFrameSuffix = ".END_MESH_INSTALLER_TRUST_V2"
)

type encodedBootstrap struct {
	Schema             string `json:"schema"`
	InitialRoot        string `json:"initial_root"`
	InitialRootSHA256  string `json:"initial_root_sha256"`
	LegacyPolicySHA256 string `json:"legacy_policy_sha256"`
}

type BootstrapSpec struct {
	InitialRoot []byte
}

// Bootstrap is the immutable initial trust anchor carried by the separately
// authenticated installer binary.
type Bootstrap struct {
	InitialRoot        releasetrust.ParsedRoot
	InitialRootRaw     []byte
	InitialRootSHA256  string
	LegacyPolicySHA256 string
	SHA256             string
}

func EncodeBootstrap(spec BootstrapSpec) (string, Bootstrap, error) {
	parsed, err := releasetrust.ParseRoot(spec.InitialRoot)
	if err != nil {
		return "", Bootstrap{}, fmt.Errorf("initial release root: %w", err)
	}
	if parsed.Document.Version != 1 {
		return "", Bootstrap{}, errors.New("initial release root version must be 1")
	}
	if parsed.Document.ReleaseEpoch != 1 {
		return "", Bootstrap{}, errors.New("initial release epoch must be 1")
	}
	legacy, err := legacyPolicyForRoot(parsed)
	if err != nil {
		return "", Bootstrap{}, err
	}
	document := encodedBootstrap{
		Schema: bootstrapSchema, InitialRoot: base64.RawURLEncoding.EncodeToString(spec.InitialRoot),
		InitialRootSHA256: parsed.SHA256, LegacyPolicySHA256: legacy.SHA256,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", Bootstrap{}, fmt.Errorf("encode installer bootstrap: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxDecodedBootstrapSize {
		return "", Bootstrap{}, fmt.Errorf("installer bootstrap exceeds %d bytes", maxDecodedBootstrapSize)
	}
	frame := BootstrapFramePrefix + base64.RawURLEncoding.EncodeToString(raw) + BootstrapFrameSuffix
	if len(frame) > maxEncodedBootstrapSize {
		return "", Bootstrap{}, fmt.Errorf("encoded installer bootstrap exceeds %d bytes", maxEncodedBootstrapSize)
	}
	bootstrap, err := parseBootstrapDocument(raw)
	if err != nil {
		return "", Bootstrap{}, err
	}
	return frame, bootstrap, nil
}

func LoadBootstrap() (Bootstrap, error) {
	if Identity == DevelopmentPolicy {
		return Bootstrap{}, errors.New("no installer bootstrap root is compiled into this build")
	}
	return ParseBootstrapIdentity(Identity)
}

func ParseBootstrapIdentity(frame string) (Bootstrap, error) {
	if len(frame) == 0 || len(frame) > maxEncodedBootstrapSize || !strings.HasPrefix(frame, BootstrapFramePrefix) || !strings.HasSuffix(frame, BootstrapFrameSuffix) {
		return Bootstrap{}, errors.New("installer bootstrap does not have the exact v2 frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, BootstrapFramePrefix), BootstrapFrameSuffix)
	if encoded == "" {
		return Bootstrap{}, errors.New("installer bootstrap payload is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxDecodedBootstrapSize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Bootstrap{}, fmt.Errorf("installer bootstrap must be canonical unpadded base64url of 1 through %d bytes", maxDecodedBootstrapSize)
	}
	return parseBootstrapDocument(raw)
}

func parseBootstrapDocument(raw []byte) (Bootstrap, error) {
	if len(raw) == 0 || len(raw) > maxDecodedBootstrapSize {
		return Bootstrap{}, fmt.Errorf("installer bootstrap size must be between 1 and %d bytes", maxDecodedBootstrapSize)
	}
	var document encodedBootstrap
	if err := decodeStrictJSON(raw, &document); err != nil {
		return Bootstrap{}, fmt.Errorf("invalid installer bootstrap: %w", err)
	}
	if document.Schema != bootstrapSchema {
		return Bootstrap{}, fmt.Errorf("unsupported installer bootstrap schema %q", document.Schema)
	}
	rootRaw, err := decodeBootstrapRoot(document.InitialRoot)
	if err != nil {
		return Bootstrap{}, err
	}
	parsed, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial release root: %w", err)
	}
	if parsed.Document.Version != 1 || parsed.Document.ReleaseEpoch != 1 {
		return Bootstrap{}, errors.New("installer bootstrap requires root version 1 and release epoch 1")
	}
	if document.InitialRootSHA256 != parsed.SHA256 {
		return Bootstrap{}, errors.New("installer bootstrap initial-root digest does not match root bytes")
	}
	legacy, err := legacyPolicyForRoot(parsed)
	if err != nil {
		return Bootstrap{}, err
	}
	if document.LegacyPolicySHA256 != legacy.SHA256 {
		return Bootstrap{}, errors.New("installer bootstrap legacy-policy digest does not match initial release delegation")
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("canonicalize installer bootstrap: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return Bootstrap{}, errors.New("installer bootstrap JSON is not in canonical encoding")
	}
	digest := sha256.Sum256(raw)
	return cloneBootstrap(Bootstrap{
		InitialRoot: parsed, InitialRootRaw: rootRaw, InitialRootSHA256: parsed.SHA256,
		LegacyPolicySHA256: legacy.SHA256, SHA256: hex.EncodeToString(digest[:]),
	}), nil
}

func legacyPolicyForRoot(root releasetrust.ParsedRoot) (Policy, error) {
	byID := make(map[string]releasetrust.PublicKeyFile, len(root.Document.Keys))
	for _, file := range root.Document.Keys {
		byID[file.KeyID] = file
	}
	releaseFiles := make([]releasetrust.PublicKeyFile, len(root.Document.Roles.Release.KeyIDs))
	for index, keyID := range root.Document.Roles.Release.KeyIDs {
		file, ok := byID[keyID]
		if !ok {
			return Policy{}, fmt.Errorf("initial release role references missing key %s", keyID)
		}
		releaseFiles[index] = file
	}
	_, policy, err := Encode(PolicySpec{
		Channel: root.Document.Channel, SignatureThreshold: root.Document.Roles.Release.Threshold,
		MinimumSequence: root.Document.MinimumReleaseSequence, MinimumSecurityFloor: root.Document.MinimumSecurityFloor,
		TrustedKeys: releaseFiles,
	})
	if err != nil {
		return Policy{}, fmt.Errorf("derive legacy installer policy: %w", err)
	}
	return policy, nil
}

func decodeBootstrapRoot(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("installer bootstrap initial root is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > releasetrust.MaxRootSize || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("installer bootstrap initial root must be canonical unpadded base64url of 1 through %d bytes", releasetrust.MaxRootSize)
	}
	return raw, nil
}

func cloneBootstrap(source Bootstrap) Bootstrap {
	result := source
	result.InitialRootRaw = append([]byte(nil), source.InitialRootRaw...)
	result.InitialRoot.Document.Keys = append([]releasetrust.PublicKeyFile(nil), source.InitialRoot.Document.Keys...)
	result.InitialRoot.Document.Roles.Root.KeyIDs = append([]string(nil), source.InitialRoot.Document.Roles.Root.KeyIDs...)
	result.InitialRoot.Document.Roles.Release.KeyIDs = append([]string(nil), source.InitialRoot.Document.Roles.Release.KeyIDs...)
	result.InitialRoot.RootKeys = cloneBootstrapKeys(source.InitialRoot.RootKeys)
	result.InitialRoot.ReleaseKeys = cloneBootstrapKeys(source.InitialRoot.ReleaseKeys)
	return result
}

func cloneBootstrapKeys(source []releasetrust.TrustedKey) []releasetrust.TrustedKey {
	result := make([]releasetrust.TrustedKey, len(source))
	for index, key := range source {
		result[index] = releasetrust.TrustedKey{KeyID: key.KeyID, PublicKey: append([]byte(nil), key.PublicKey...)}
	}
	return result
}
