// Package windowsauthenticode owns the immutable publisher policy and native
// Authenticode verification contract for Windows production executables.
package windowsauthenticode

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
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	Schema             = "mesh-windows-authenticode-policy-v1"
	FramePrefix        = "MESH_WINDOWS_AUTHENTICODE_V1."
	FrameSuffix        = ".END_MESH_WINDOWS_AUTHENTICODE_V1"
	DevelopmentPolicy  = "mesh-development-no-windows-authenticode-policy"
	RevocationMode     = "online-whole-chain"
	TimestampPolicy    = "lifetime-signing-required"
	DigestAlgorithm    = "sha256"
	maximumPolicyJSON  = 8 << 10
	maximumPolicyFrame = 16 << 10
	maximumPinsPerRole = 4
	MeshSignerRole     = "mesh"
	WintunSignerRole   = "wintun"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Identity is replaced exactly once in production Windows executables with:
//
//	-X mesh/internal/windowsauthenticode.Identity=<canonical frame>
//
// The unframed development sentinel makes omission statically detectable.
var Identity = DevelopmentPolicy

type PolicySpec struct {
	MeshSignerSPKISHA256   []string
	WintunSignerSPKISHA256 []string
}

type policyDocument struct {
	Schema                 string   `json:"schema"`
	DigestAlgorithm        string   `json:"digest_algorithm"`
	MeshSignerSPKISHA256   []string `json:"mesh_signer_spki_sha256"`
	RequireSingleSigner    bool     `json:"require_single_signer"`
	RevocationMode         string   `json:"revocation_mode"`
	TimestampPolicy        string   `json:"timestamp_policy"`
	WintunSignerSPKISHA256 []string `json:"wintun_signer_spki_sha256"`
}

type Policy struct {
	MeshSignerSPKISHA256   []string
	WintunSignerSPKISHA256 []string
	SHA256                 string
}

func EncodePolicy(spec PolicySpec) (string, Policy, error) {
	meshPins, err := canonicalPins(spec.MeshSignerSPKISHA256, MeshSignerRole)
	if err != nil {
		return "", Policy{}, err
	}
	wintunPins, err := canonicalPins(spec.WintunSignerSPKISHA256, WintunSignerRole)
	if err != nil {
		return "", Policy{}, err
	}
	document := policyDocument{
		Schema: Schema, DigestAlgorithm: DigestAlgorithm,
		MeshSignerSPKISHA256: meshPins, RequireSingleSigner: true,
		RevocationMode: RevocationMode, TimestampPolicy: TimestampPolicy,
		WintunSignerSPKISHA256: wintunPins,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", Policy{}, fmt.Errorf("encode Windows Authenticode policy: %w", err)
	}
	if len(raw) > maximumPolicyJSON {
		return "", Policy{}, errors.New("Windows Authenticode policy exceeds its JSON size bound")
	}
	policy, err := parsePolicyDocument(raw)
	if err != nil {
		return "", Policy{}, err
	}
	frame := FramePrefix + base64.RawURLEncoding.EncodeToString(raw) + FrameSuffix
	if len(frame) > maximumPolicyFrame {
		return "", Policy{}, errors.New("Windows Authenticode policy exceeds its frame size bound")
	}
	return frame, policy, nil
}

func LoadPolicy() (Policy, error) {
	if Identity == DevelopmentPolicy {
		return Policy{}, errors.New("no Windows Authenticode publisher policy is compiled into this build")
	}
	return ParsePolicyIdentity(Identity)
}

func ParsePolicyIdentity(frame string) (Policy, error) {
	if len(frame) == 0 || len(frame) > maximumPolicyFrame ||
		!strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return Policy{}, errors.New("Windows Authenticode policy does not have the exact v1 frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	if encoded == "" {
		return Policy{}, errors.New("Windows Authenticode policy payload is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximumPolicyJSON || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Policy{}, errors.New("Windows Authenticode policy must be canonical unpadded base64url")
	}
	return parsePolicyDocument(raw)
}

func (policy Policy) Allows(role, spkiSHA256 string) bool {
	var pins []string
	switch role {
	case MeshSignerRole:
		pins = policy.MeshSignerSPKISHA256
	case WintunSignerRole:
		pins = policy.WintunSignerSPKISHA256
	default:
		return false
	}
	index := sort.SearchStrings(pins, spkiSHA256)
	return index < len(pins) && pins[index] == spkiSHA256
}

func parsePolicyDocument(raw []byte) (Policy, error) {
	if len(raw) == 0 || len(raw) > maximumPolicyJSON || !utf8.Valid(raw) {
		return Policy{}, errors.New("Windows Authenticode policy JSON is empty, oversized, or invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document policyDocument
	if err := decoder.Decode(&document); err != nil {
		return Policy{}, fmt.Errorf("decode Windows Authenticode policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("Windows Authenticode policy contains trailing data")
	}
	if document.Schema != Schema || document.DigestAlgorithm != DigestAlgorithm ||
		document.RevocationMode != RevocationMode || document.TimestampPolicy != TimestampPolicy ||
		!document.RequireSingleSigner {
		return Policy{}, errors.New("Windows Authenticode policy security contract is invalid")
	}
	meshPins, err := validateCanonicalPins(document.MeshSignerSPKISHA256, MeshSignerRole)
	if err != nil {
		return Policy{}, err
	}
	wintunPins, err := validateCanonicalPins(document.WintunSignerSPKISHA256, WintunSignerRole)
	if err != nil {
		return Policy{}, err
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Policy{}, errors.Join(err, errors.New("Windows Authenticode policy JSON is not canonical"))
	}
	digest := sha256.Sum256(raw)
	return Policy{
		MeshSignerSPKISHA256:   append([]string(nil), meshPins...),
		WintunSignerSPKISHA256: append([]string(nil), wintunPins...),
		SHA256:                 hex.EncodeToString(digest[:]),
	}, nil
}

func canonicalPins(input []string, role string) ([]string, error) {
	pins := append([]string(nil), input...)
	sort.Strings(pins)
	return validateCanonicalPins(pins, role)
}

func validateCanonicalPins(pins []string, role string) ([]string, error) {
	if len(pins) == 0 || len(pins) > maximumPinsPerRole {
		return nil, fmt.Errorf("Windows Authenticode %s signer set must contain 1 through %d SPKI pins", role, maximumPinsPerRole)
	}
	for index, pin := range pins {
		if !digestPattern.MatchString(pin) {
			return nil, fmt.Errorf("Windows Authenticode %s signer pin %d is not canonical SHA-256", role, index)
		}
		if index > 0 && pins[index-1] >= pin {
			return nil, fmt.Errorf("Windows Authenticode %s signer pins must be unique and strictly sorted", role)
		}
	}
	return append([]string(nil), pins...), nil
}
