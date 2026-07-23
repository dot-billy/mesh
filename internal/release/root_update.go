package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	RootUpdateSchema            = "mesh-release-root-update-v1"
	MaxRootUpdateSize           = 1 << 20
	MaxRootTransitionSignatures = 2 * MaxTrustedKeys
	MaxRootUpdatesPerInput      = 32
)

type RootUpdate struct {
	RootManifest []byte
	Signatures   [][]byte
}

type encodedRootUpdate struct {
	Schema       string   `json:"schema"`
	RootManifest string   `json:"root_manifest"`
	Signatures   []string `json:"signatures"`
}

type AppliedRootUpdate struct {
	Raw        []byte
	Transition VerifiedRootTransition
}

type RootChainResult struct {
	Root    ParsedRoot
	Applied []AppliedRootUpdate
}

// EncodeRootUpdate returns canonical compact JSON plus one LF. Signature
// envelopes are sorted by exact-byte SHA-256 without changing their bytes.
func EncodeRootUpdate(input RootUpdate) ([]byte, error) {
	value, err := canonicalRootUpdate(input)
	if err != nil {
		return nil, err
	}
	encoded := encodedRootUpdate{
		Schema: RootUpdateSchema, RootManifest: base64.RawURLEncoding.EncodeToString(value.RootManifest),
		Signatures: make([]string, len(value.Signatures)),
	}
	for index, signature := range value.Signatures {
		encoded.Signatures[index] = base64.RawURLEncoding.EncodeToString(signature)
	}
	raw, err := json.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("encode root update: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxRootUpdateSize {
		return nil, fmt.Errorf("root update exceeds %d bytes", MaxRootUpdateSize)
	}
	return raw, nil
}

func ParseRootUpdate(raw []byte) (RootUpdate, error) {
	if len(raw) == 0 || len(raw) > MaxRootUpdateSize {
		return RootUpdate{}, fmt.Errorf("root update size must be between 1 and %d bytes", MaxRootUpdateSize)
	}
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || raw[len(raw)-2] == '\n' {
		return RootUpdate{}, errors.New("root update must be compact JSON followed by exactly one LF")
	}
	object, err := exactObject(raw, "schema", "root_manifest", "signatures")
	if err != nil {
		return RootUpdate{}, fmt.Errorf("invalid root update: %w", err)
	}
	if err := requireFields(object, "schema", "root_manifest", "signatures"); err != nil {
		return RootUpdate{}, fmt.Errorf("invalid root update: %w", err)
	}
	var encoded encodedRootUpdate
	if err := decodeStrict(raw, &encoded); err != nil {
		return RootUpdate{}, fmt.Errorf("invalid root update: %w", err)
	}
	if encoded.Schema != RootUpdateSchema {
		return RootUpdate{}, fmt.Errorf("unsupported root update schema %q", encoded.Schema)
	}
	manifest, err := decodeRootUpdateBytes(encoded.RootManifest, "root manifest", MaxRootSize)
	if err != nil {
		return RootUpdate{}, err
	}
	if len(encoded.Signatures) == 0 || len(encoded.Signatures) > MaxRootTransitionSignatures {
		return RootUpdate{}, fmt.Errorf("root update signature count must be between 1 and %d", MaxRootTransitionSignatures)
	}
	signatures := make([][]byte, len(encoded.Signatures))
	for index, value := range encoded.Signatures {
		signature, err := decodeRootUpdateBytes(value, fmt.Sprintf("root signature %d", index), MaxEnvelopeSize)
		if err != nil {
			return RootUpdate{}, err
		}
		signatures[index] = signature
	}
	value, err := canonicalRootUpdate(RootUpdate{RootManifest: manifest, Signatures: signatures})
	if err != nil {
		return RootUpdate{}, err
	}
	canonical, err := EncodeRootUpdate(value)
	if err != nil {
		return RootUpdate{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return RootUpdate{}, errors.New("root update JSON is not in canonical encoding")
	}
	return cloneRootUpdate(value), nil
}

// EvaluateRootChain is the side-effect-free chain verifier. Persistence code
// may apply the same verified transitions one at a time; this function proves
// ordering, prefix, continuity, and final-root time semantics for one input.
func EvaluateRootChain(current ParsedRoot, rawUpdates [][]byte, now time.Time, clockSkew time.Duration) (RootChainResult, error) {
	trusted, err := reparseTrustedRoot(current)
	if err != nil {
		return RootChainResult{}, fmt.Errorf("current trusted root: %w", err)
	}
	if len(rawUpdates) > MaxRootUpdatesPerInput {
		return RootChainResult{}, fmt.Errorf("root update count must not exceed %d", MaxRootUpdatesPerInput)
	}
	type chainEntry struct {
		raw       []byte
		update    RootUpdate
		candidate ParsedRoot
	}
	entries := make([]chainEntry, len(rawUpdates))
	var previousInputVersion uint64
	for index, raw := range rawUpdates {
		update, err := ParseRootUpdate(raw)
		if err != nil {
			return RootChainResult{}, fmt.Errorf("root update %d: %w", index, err)
		}
		candidate, err := ParseRoot(update.RootManifest)
		if err != nil {
			return RootChainResult{}, fmt.Errorf("root update %d manifest: %w", index, err)
		}
		version := candidate.Document.Version
		if index != 0 && version <= previousInputVersion {
			return RootChainResult{}, errors.New("root update versions must be strictly increasing")
		}
		previousInputVersion = version
		entries[index] = chainEntry{raw: raw, update: update, candidate: candidate}
	}
	result := RootChainResult{Root: trusted}
	for index, entry := range entries {
		version := entry.candidate.Document.Version
		if version < result.Root.Document.Version {
			continue
		}
		if version == result.Root.Document.Version {
			if entry.candidate.SHA256 != result.Root.SHA256 {
				return RootChainResult{}, fmt.Errorf("root equivocation at version %d", version)
			}
			continue
		}
		transition, err := VerifyRootTransition(result.Root, entry.update.RootManifest, entry.update.Signatures)
		if err != nil {
			return RootChainResult{}, fmt.Errorf("root update %d transition: %w", index, err)
		}
		result.Root = transition.Root
		result.Applied = append(result.Applied, AppliedRootUpdate{
			Raw: append([]byte(nil), entry.raw...), Transition: transition,
		})
	}
	if err := ValidateCurrentRoot(result.Root, now, clockSkew); err != nil {
		return RootChainResult{}, err
	}
	return cloneRootChainResult(result), nil
}

func canonicalRootUpdate(input RootUpdate) (RootUpdate, error) {
	if len(input.RootManifest) == 0 || len(input.RootManifest) > MaxRootSize {
		return RootUpdate{}, fmt.Errorf("root manifest size must be between 1 and %d bytes", MaxRootSize)
	}
	if _, err := ParseRoot(input.RootManifest); err != nil {
		return RootUpdate{}, fmt.Errorf("root update manifest: %w", err)
	}
	if len(input.Signatures) == 0 || len(input.Signatures) > MaxRootTransitionSignatures {
		return RootUpdate{}, fmt.Errorf("root update signature count must be between 1 and %d", MaxRootTransitionSignatures)
	}
	result := cloneRootUpdate(input)
	seen := make(map[string]struct{}, len(result.Signatures))
	for index, signature := range result.Signatures {
		if len(signature) == 0 || len(signature) > MaxEnvelopeSize {
			return RootUpdate{}, fmt.Errorf("root signature %d size must be between 1 and %d bytes", index, MaxEnvelopeSize)
		}
		identity := string(signature)
		if _, duplicate := seen[identity]; duplicate {
			return RootUpdate{}, fmt.Errorf("duplicate root signature bytes at index %d", index)
		}
		seen[identity] = struct{}{}
	}
	sort.Slice(result.Signatures, func(left, right int) bool {
		leftDigest := sha256.Sum256(result.Signatures[left])
		rightDigest := sha256.Sum256(result.Signatures[right])
		if comparison := bytes.Compare(leftDigest[:], rightDigest[:]); comparison != 0 {
			return comparison < 0
		}
		return bytes.Compare(result.Signatures[left], result.Signatures[right]) < 0
	})
	return result, nil
}

func decodeRootUpdateBytes(value, label string, maximum int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s must not be empty", label)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url of 1 through %d decoded bytes", label, maximum)
	}
	return raw, nil
}

func cloneRootUpdate(source RootUpdate) RootUpdate {
	result := RootUpdate{RootManifest: append([]byte(nil), source.RootManifest...), Signatures: make([][]byte, len(source.Signatures))}
	for index, signature := range source.Signatures {
		result.Signatures[index] = append([]byte(nil), signature...)
	}
	return result
}

func cloneRootChainResult(source RootChainResult) RootChainResult {
	result := RootChainResult{Root: source.Root, Applied: make([]AppliedRootUpdate, len(source.Applied))}
	result.Root.Document = cloneRoot(source.Root.Document)
	result.Root.RootKeys = cloneTrustedKeys(source.Root.RootKeys)
	result.Root.ReleaseKeys = cloneTrustedKeys(source.Root.ReleaseKeys)
	for index, applied := range source.Applied {
		result.Applied[index] = AppliedRootUpdate{
			Raw: append([]byte(nil), applied.Raw...), Transition: applied.Transition,
		}
		result.Applied[index].Transition.Root.Document = cloneRoot(applied.Transition.Root.Document)
		result.Applied[index].Transition.Root.RootKeys = cloneTrustedKeys(applied.Transition.Root.RootKeys)
		result.Applied[index].Transition.Root.ReleaseKeys = cloneTrustedKeys(applied.Transition.Root.ReleaseKeys)
		result.Applied[index].Transition.PreviousSignerKeyIDs = append([]string(nil), applied.Transition.PreviousSignerKeyIDs...)
		result.Applied[index].Transition.NewSignerKeyIDs = append([]string(nil), applied.Transition.NewSignerKeyIDs...)
	}
	return result
}
