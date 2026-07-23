// Package installtrust owns the minimal installer's immutable release-trust
// bootstrap. This file retains the v1 policy parser for exact state migration;
// production installers use the versioned v2 root bootstrap and candidate
// release data cannot replace it.
package installtrust

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

	releasetrust "mesh/internal/release"
)

const (
	policySchema         = "mesh-linux-installer-trust-v1"
	maxDecodedPolicySize = 64 << 10
	maxEncodedPolicySize = 128 << 10

	FramePrefix       = "MESH_INSTALLER_TRUST_V1."
	FrameSuffix       = ".END_MESH_INSTALLER_TRUST_V1"
	DevelopmentPolicy = "mesh-development-no-installer-trust"
)

var channelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// Identity is the sole linker-set installer policy. Its development sentinel
// is deliberately not a valid frame so a production ELF contains exactly one
// statically inspectable policy even if the linker retains initialized bytes.
var Identity = DevelopmentPolicy

type encodedPolicy struct {
	Schema               string                       `json:"schema"`
	Channel              string                       `json:"channel"`
	SignatureThreshold   int                          `json:"signature_threshold"`
	MinimumSequence      uint64                       `json:"minimum_sequence"`
	MinimumSecurityFloor uint64                       `json:"minimum_security_floor"`
	TrustedKeys          []releasetrust.PublicKeyFile `json:"trusted_keys"`
}

// Policy is the installer-owned trust anchor and initial rollback floor.
type Policy struct {
	Channel              string
	SignatureThreshold   int
	MinimumSequence      uint64
	MinimumSecurityFloor uint64
	TrustedKeys          []releasetrust.TrustedKey
	SHA256               string
}

// PolicySpec is release-tooling input for the immutable installer trust
// policy. Encoding a policy does not make it trusted; only the separately
// authenticated mesh-install binary can establish that bootstrap trust.
type PolicySpec struct {
	Channel              string
	SignatureThreshold   int
	MinimumSequence      uint64
	MinimumSecurityFloor uint64
	TrustedKeys          []releasetrust.PublicKeyFile
}

// Encode returns the canonical frame suitable for the installer's sole linker
// value. Trusted keys are sorted by their derived key ID.
func Encode(spec PolicySpec) (string, Policy, error) {
	keys := append([]releasetrust.PublicKeyFile(nil), spec.TrustedKeys...)
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	document := encodedPolicy{
		Schema: policySchema, Channel: spec.Channel, SignatureThreshold: spec.SignatureThreshold,
		MinimumSequence: spec.MinimumSequence, MinimumSecurityFloor: spec.MinimumSecurityFloor,
		TrustedKeys: keys,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", Policy{}, fmt.Errorf("encode installer trust policy: %w", err)
	}
	policy, err := parsePolicy(raw)
	if err != nil {
		return "", Policy{}, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	frame := FramePrefix + encoded + FrameSuffix
	if len(frame) > maxEncodedPolicySize {
		return "", Policy{}, fmt.Errorf("encoded installer trust policy exceeds %d bytes", maxEncodedPolicySize)
	}
	return frame, policy, nil
}

// Load decodes a fresh policy value so callers cannot mutate global trust.
func Load() (Policy, error) {
	if Identity == DevelopmentPolicy {
		return Policy{}, errors.New("no installer trust policy is compiled into this build")
	}
	return ParseIdentity(Identity)
}

// ParseIdentity strictly decodes one canonical, statically inspectable policy
// frame. Parsing a frame does not itself make that policy trusted.
func ParseIdentity(frame string) (Policy, error) {
	if len(frame) == 0 || len(frame) > maxEncodedPolicySize || !strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return Policy{}, errors.New("installer trust policy does not have the exact frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	if encoded == "" {
		return Policy{}, errors.New("installer trust policy payload is empty")
	}
	if len(encoded) > maxEncodedPolicySize {
		return Policy{}, fmt.Errorf("encoded installer trust policy exceeds %d bytes", maxEncodedPolicySize)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxDecodedPolicySize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Policy{}, fmt.Errorf("installer trust policy must be canonical unpadded base64url of 1 through %d bytes", maxDecodedPolicySize)
	}
	return parsePolicy(raw)
}

func parsePolicy(raw []byte) (Policy, error) {
	if len(raw) == 0 || len(raw) > maxDecodedPolicySize {
		return Policy{}, fmt.Errorf("installer trust policy size must be between 1 and %d bytes", maxDecodedPolicySize)
	}
	var document encodedPolicy
	if err := decodeStrictJSON(raw, &document); err != nil {
		return Policy{}, fmt.Errorf("invalid installer trust policy: %w", err)
	}
	if document.Schema != policySchema {
		return Policy{}, fmt.Errorf("unsupported installer trust policy schema %q", document.Schema)
	}
	if !channelPattern.MatchString(document.Channel) {
		return Policy{}, errors.New("installer release channel is not canonical")
	}
	if document.SignatureThreshold < 2 {
		return Policy{}, errors.New("installer signature threshold must be at least 2")
	}
	if document.MinimumSequence == 0 || document.MinimumSecurityFloor == 0 {
		return Policy{}, errors.New("installer rollback and security floors must be positive")
	}
	if len(document.TrustedKeys) < document.SignatureThreshold || len(document.TrustedKeys) > releasetrust.MaxTrustedKeys {
		return Policy{}, fmt.Errorf("installer trust policy has %d keys for threshold %d", len(document.TrustedKeys), document.SignatureThreshold)
	}
	trusted := make([]releasetrust.TrustedKey, 0, len(document.TrustedKeys))
	seen := make(map[string]struct{}, len(document.TrustedKeys))
	previousKeyID := ""
	for index, keyFile := range document.TrustedKeys {
		keyRaw, err := json.Marshal(keyFile)
		if err != nil {
			return Policy{}, fmt.Errorf("marshal trusted key %d: %w", index, err)
		}
		key, err := releasetrust.ParseTrustedPublicKey(keyRaw)
		if err != nil {
			return Policy{}, fmt.Errorf("trusted key %d: %w", index, err)
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return Policy{}, fmt.Errorf("duplicate trusted key %s", key.KeyID)
		}
		if previousKeyID != "" && key.KeyID <= previousKeyID {
			return Policy{}, errors.New("trusted keys must be strictly sorted by key_id")
		}
		seen[key.KeyID] = struct{}{}
		previousKeyID = key.KeyID
		trusted = append(trusted, releasetrust.TrustedKey{KeyID: key.KeyID, PublicKey: append([]byte(nil), key.PublicKey...)})
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return Policy{}, fmt.Errorf("canonicalize installer trust policy: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return Policy{}, errors.New("installer trust policy JSON is not in canonical encoding")
	}
	digest := sha256.Sum256(raw)
	return Policy{
		Channel:              document.Channel,
		SignatureThreshold:   document.SignatureThreshold,
		MinimumSequence:      document.MinimumSequence,
		MinimumSecurityFloor: document.MinimumSecurityFloor,
		TrustedKeys:          trusted,
		SHA256:               hex.EncodeToString(digest[:]),
	}, nil
}

func decodeStrictJSON(raw []byte, output any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	if err := validateJSONSurrogates(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return nil
}

func consumeJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validateJSONSurrogates(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' || index+4 >= len(raw) {
				continue
			}
			value, ok := parseHexQuad(raw[index+1 : index+5])
			if !ok {
				continue
			}
			index += 4
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return errors.New("unpaired high UTF-16 surrogate escape")
				}
				low, ok := parseHexQuad(raw[index+3 : index+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired high UTF-16 surrogate escape")
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return errors.New("unpaired low UTF-16 surrogate escape")
			}
		}
	}
	return nil
}

func parseHexQuad(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, character := range raw {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
