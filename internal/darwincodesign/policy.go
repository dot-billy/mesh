// Package darwincodesign owns the immutable Developer ID admission policy and
// native code-signature verification contract for macOS node executables.
package darwincodesign

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Schema            = "mesh-darwin-codesign-policy-v2"
	FramePrefix       = "MESH_DARWIN_CODESIGN_V2."
	FrameSuffix       = ".END_MESH_DARWIN_CODESIGN_V2"
	DevelopmentPolicy = "mesh-development-no-darwin-codesign-policy"

	MeshInstallRole = "mesh-install"
	MeshctlRole     = "meshctl"
	NebulaRole      = "nebula"
	NebulaCertRole  = "nebula-cert"

	maximumPolicyJSON  = 8 << 10
	maximumPolicyFrame = 16 << 10
)

var (
	teamIDPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Identity is replaced exactly once in production Darwin executables with:
//
//	-X mesh/internal/darwincodesign.Identity=<canonical frame>
//
// The unframed development sentinel makes omission statically detectable and
// can never be parsed as an admission policy.
var Identity = DevelopmentPolicy

type PolicySpec struct {
	TeamID                string
	MeshInstallIdentifier string
	MeshctlIdentifier     string
	NebulaIdentifier      string
	NebulaCertIdentifier  string
}

type policyDocument struct {
	Schema                string `json:"schema"`
	TeamID                string `json:"team_id"`
	MeshInstallIdentifier string `json:"mesh_install_identifier"`
	MeshctlIdentifier     string `json:"meshctl_identifier"`
	NebulaIdentifier      string `json:"nebula_identifier"`
	NebulaCertIdentifier  string `json:"nebula_cert_identifier"`
	RequireAppleAnchor    bool   `json:"require_apple_anchor"`
	RequireDeveloperID    bool   `json:"require_developer_id"`
	RequireStrict         bool   `json:"require_strict_verification"`
}

type Policy struct {
	TeamID                string
	MeshInstallIdentifier string
	MeshctlIdentifier     string
	NebulaIdentifier      string
	NebulaCertIdentifier  string
	SHA256                string
}

func EncodePolicy(spec PolicySpec) (string, Policy, error) {
	document := policyDocument{
		Schema: Schema, TeamID: spec.TeamID,
		MeshInstallIdentifier: spec.MeshInstallIdentifier,
		MeshctlIdentifier:     spec.MeshctlIdentifier, NebulaIdentifier: spec.NebulaIdentifier,
		NebulaCertIdentifier: spec.NebulaCertIdentifier,
		RequireAppleAnchor:   true, RequireDeveloperID: true, RequireStrict: true,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", Policy{}, fmt.Errorf("encode Darwin code-signing policy: %w", err)
	}
	if len(raw) > maximumPolicyJSON {
		return "", Policy{}, errors.New("Darwin code-signing policy exceeds its JSON size bound")
	}
	policy, err := parsePolicyDocument(raw)
	if err != nil {
		return "", Policy{}, err
	}
	frame := FramePrefix + base64.RawURLEncoding.EncodeToString(raw) + FrameSuffix
	if len(frame) > maximumPolicyFrame {
		return "", Policy{}, errors.New("Darwin code-signing policy exceeds its frame size bound")
	}
	return frame, policy, nil
}

func LoadPolicy() (Policy, error) {
	if Identity == DevelopmentPolicy {
		return Policy{}, errors.New("no Darwin code-signing admission policy is compiled into this build")
	}
	return ParsePolicyIdentity(Identity)
}

func ParsePolicyIdentity(frame string) (Policy, error) {
	if len(frame) == 0 || len(frame) > maximumPolicyFrame ||
		!strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return Policy{}, errors.New("Darwin code-signing policy does not have the exact v1 frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	if encoded == "" {
		return Policy{}, errors.New("Darwin code-signing policy payload is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximumPolicyJSON ||
		base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Policy{}, errors.New("Darwin code-signing policy must be canonical unpadded base64url")
	}
	return parsePolicyDocument(raw)
}

// Identifier returns the sole approved code identifier for one executable
// role. Unknown roles are never admitted.
func (policy Policy) Identifier(role string) (string, bool) {
	switch role {
	case MeshInstallRole:
		return policy.MeshInstallIdentifier, true
	case MeshctlRole:
		return policy.MeshctlIdentifier, true
	case NebulaRole:
		return policy.NebulaIdentifier, true
	case NebulaCertRole:
		return policy.NebulaCertIdentifier, true
	default:
		return "", false
	}
}

// Requirement derives rather than accepts arbitrary requirement language.
// Every substituted field has already passed a grammar that excludes quotes,
// whitespace, brackets, and operators.
func (policy Policy) Requirement(role string) (string, error) {
	identifier, ok := policy.Identifier(role)
	if !ok {
		return "", errors.New("Darwin code-signing executable role is unsupported")
	}
	if !teamIDPattern.MatchString(policy.TeamID) || !identifierPattern.MatchString(identifier) {
		return "", errors.New("Darwin code-signing policy is invalid")
	}
	return `anchor apple generic and identifier "` + identifier +
		`" and certificate 1[field.1.2.840.113635.100.6.2.6] exists` +
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` +
		` and certificate leaf[subject.OU] = "` + policy.TeamID + `"`, nil
}

func parsePolicyDocument(raw []byte) (Policy, error) {
	if len(raw) == 0 || len(raw) > maximumPolicyJSON || !utf8.Valid(raw) {
		return Policy{}, errors.New("Darwin code-signing policy JSON is empty, oversized, or invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document policyDocument
	if err := decoder.Decode(&document); err != nil {
		return Policy{}, fmt.Errorf("decode Darwin code-signing policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("Darwin code-signing policy contains trailing data")
	}
	if document.Schema != Schema || !document.RequireAppleAnchor ||
		!document.RequireDeveloperID || !document.RequireStrict {
		return Policy{}, errors.New("Darwin code-signing policy security contract is invalid")
	}
	if !teamIDPattern.MatchString(document.TeamID) {
		return Policy{}, errors.New("Darwin code-signing Team ID must be exactly 10 uppercase ASCII letters or digits")
	}
	identifiers := []string{
		document.MeshInstallIdentifier, document.MeshctlIdentifier,
		document.NebulaIdentifier, document.NebulaCertIdentifier,
	}
	seen := make(map[string]struct{}, len(identifiers))
	for index, identifier := range identifiers {
		if !identifierPattern.MatchString(identifier) || strings.Contains(identifier, "..") ||
			strings.HasSuffix(identifier, ".") {
			return Policy{}, fmt.Errorf("Darwin code-signing identifier %d is not canonical", index)
		}
		if _, duplicate := seen[identifier]; duplicate {
			return Policy{}, errors.New("Darwin executable code identifiers must be distinct")
		}
		seen[identifier] = struct{}{}
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Policy{}, errors.Join(err, errors.New("Darwin code-signing policy JSON is not canonical"))
	}
	digest := sha256.Sum256(raw)
	return Policy{
		TeamID:                document.TeamID,
		MeshInstallIdentifier: document.MeshInstallIdentifier,
		MeshctlIdentifier:     document.MeshctlIdentifier, NebulaIdentifier: document.NebulaIdentifier,
		NebulaCertIdentifier: document.NebulaCertIdentifier,
		SHA256:               hex.EncodeToString(digest[:]),
	}, nil
}
