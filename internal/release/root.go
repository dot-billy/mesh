package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	RootSchema      = "mesh-release-root-v1"
	MaxRootSize     = 64 << 10
	MaxRootLifetime = 366 * 24 * time.Hour
)

// Root is the canonical release trust document. Root and release role key IDs
// are required to be disjoint, while Keys is their exact union.
type Root struct {
	Schema                 string          `json:"schema"`
	Version                uint64          `json:"version"`
	Channel                string          `json:"channel"`
	ReleaseEpoch           uint64          `json:"release_epoch"`
	MinimumReleaseSequence uint64          `json:"minimum_release_sequence"`
	MinimumSecurityFloor   uint64          `json:"minimum_security_floor"`
	IssuedAt               string          `json:"issued_at"`
	ExpiresAt              string          `json:"expires_at"`
	Keys                   []PublicKeyFile `json:"keys"`
	Roles                  RootRoles       `json:"roles"`
}

type RootRoles struct {
	Root    RootRole `json:"root"`
	Release RootRole `json:"release"`
}

type RootRole struct {
	Threshold int      `json:"threshold"`
	KeyIDs    []string `json:"key_ids"`
}

// ParsedRoot contains a structurally valid canonical document and fresh key
// slices for each authorized role.
type ParsedRoot struct {
	Document    Root
	SHA256      string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RootKeys    []TrustedKey
	ReleaseKeys []TrustedKey
}

// VerifiedRootTransition is one authenticated immediate successor. Signer ID
// slices are sorted and contain only distinct valid votes for the root role.
type VerifiedRootTransition struct {
	Root                 ParsedRoot
	PreviousSignerKeyIDs []string
	NewSignerKeyIDs      []string
}

// EncodeRoot returns the sole canonical root encoding without mutating any
// caller-owned slice. The encoding is compact JSON followed by exactly one LF.
func EncodeRoot(input Root) ([]byte, error) {
	document := cloneRoot(input)
	sort.Slice(document.Keys, func(left, right int) bool {
		return document.Keys[left].KeyID < document.Keys[right].KeyID
	})
	sort.Strings(document.Roles.Root.KeyIDs)
	sort.Strings(document.Roles.Release.KeyIDs)
	if _, err := validateRoot(document); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode release root: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxRootSize {
		return nil, fmt.Errorf("release root exceeds %d bytes", MaxRootSize)
	}
	return raw, nil
}

// ParseRoot accepts only the sole canonical encoding emitted by EncodeRoot.
func ParseRoot(raw []byte) (ParsedRoot, error) {
	if len(raw) == 0 || len(raw) > MaxRootSize {
		return ParsedRoot{}, fmt.Errorf("release root size must be between 1 and %d bytes", MaxRootSize)
	}
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || raw[len(raw)-2] == '\n' {
		return ParsedRoot{}, errors.New("release root must be compact JSON followed by exactly one LF")
	}
	object, err := exactObject(raw,
		"schema", "version", "channel", "release_epoch",
		"minimum_release_sequence", "minimum_security_floor",
		"issued_at", "expires_at", "keys", "roles",
	)
	if err != nil {
		return ParsedRoot{}, fmt.Errorf("invalid release root: %w", err)
	}
	if err := requireFields(object,
		"schema", "version", "channel", "release_epoch",
		"minimum_release_sequence", "minimum_security_floor",
		"issued_at", "expires_at", "keys", "roles",
	); err != nil {
		return ParsedRoot{}, fmt.Errorf("invalid release root: %w", err)
	}
	roles, err := exactObject(object["roles"], "root", "release")
	if err != nil {
		return ParsedRoot{}, fmt.Errorf("invalid release root roles: %w", err)
	}
	if err := requireFields(roles, "root", "release"); err != nil {
		return ParsedRoot{}, fmt.Errorf("invalid release root roles: %w", err)
	}
	for _, name := range []string{"root", "release"} {
		role, err := exactObject(roles[name], "threshold", "key_ids")
		if err != nil {
			return ParsedRoot{}, fmt.Errorf("invalid %s role: %w", name, err)
		}
		if err := requireFields(role, "threshold", "key_ids"); err != nil {
			return ParsedRoot{}, fmt.Errorf("invalid %s role: %w", name, err)
		}
	}
	var document Root
	if err := decodeStrict(raw, &document); err != nil {
		return ParsedRoot{}, fmt.Errorf("invalid release root: %w", err)
	}
	parsed, err := validateRoot(document)
	if err != nil {
		return ParsedRoot{}, err
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return ParsedRoot{}, fmt.Errorf("canonicalize release root: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return ParsedRoot{}, errors.New("release root JSON is not in canonical encoding")
	}
	return parsed, nil
}

// VerifyRootTransition authenticates one exact immediate successor with both
// the predecessor's root role and the candidate's own root role. Expiry is
// intentionally checked separately after a caller has processed every
// available sequential update, allowing an expired intermediate to rotate to
// a current root.
func VerifyRootTransition(previous ParsedRoot, candidateRaw []byte, rawEnvelopes [][]byte) (VerifiedRootTransition, error) {
	trustedPrevious, err := reparseTrustedRoot(previous)
	if err != nil {
		return VerifiedRootTransition{}, fmt.Errorf("previous trusted root: %w", err)
	}
	candidate, err := ParseRoot(candidateRaw)
	if err != nil {
		return VerifiedRootTransition{}, fmt.Errorf("candidate release root: %w", err)
	}
	if err := validateRootSuccessor(trustedPrevious.Document, candidate.Document); err != nil {
		return VerifiedRootTransition{}, err
	}

	previousVotes, err := collectSignatureVotes(candidateRaw, rawEnvelopes, trustedPrevious.RootKeys)
	if err != nil {
		return VerifiedRootTransition{}, fmt.Errorf("previous root signatures: %w", err)
	}
	previousIDs := sortedVoteIDs(previousVotes.ByKind[RootManifestKind])
	previousThreshold := trustedPrevious.Document.Roles.Root.Threshold
	if len(previousIDs) < previousThreshold {
		thresholdErr := fmt.Errorf("previous root threshold %d not reached: got %d distinct valid root signatures", previousThreshold, len(previousIDs))
		if previousVotes.FirstInvalid != nil {
			return VerifiedRootTransition{}, fmt.Errorf("%w; ignored invalid envelope: %v", thresholdErr, previousVotes.FirstInvalid)
		}
		return VerifiedRootTransition{}, thresholdErr
	}

	newVotes, err := collectSignatureVotes(candidateRaw, rawEnvelopes, candidate.RootKeys)
	if err != nil {
		return VerifiedRootTransition{}, fmt.Errorf("new root signatures: %w", err)
	}
	newIDs := sortedVoteIDs(newVotes.ByKind[RootManifestKind])
	newThreshold := candidate.Document.Roles.Root.Threshold
	if len(newIDs) < newThreshold {
		thresholdErr := fmt.Errorf("new root threshold %d not reached: got %d distinct valid root signatures", newThreshold, len(newIDs))
		if newVotes.FirstInvalid != nil {
			return VerifiedRootTransition{}, fmt.Errorf("%w; ignored invalid envelope: %v", thresholdErr, newVotes.FirstInvalid)
		}
		return VerifiedRootTransition{}, thresholdErr
	}
	return VerifiedRootTransition{
		Root: candidate, PreviousSignerKeyIDs: previousIDs, NewSignerKeyIDs: newIDs,
	}, nil
}

// ValidateRootSuccessor applies the non-cryptographic monotonic transition
// rules to two already canonical parsed roots. It is intended for offline
// authoring tools; only VerifyRootTransition establishes authority.
func ValidateRootSuccessor(previous, candidate ParsedRoot) error {
	trustedPrevious, err := reparseTrustedRoot(previous)
	if err != nil {
		return fmt.Errorf("previous trusted root: %w", err)
	}
	trustedCandidate, err := reparseTrustedRoot(candidate)
	if err != nil {
		return fmt.Errorf("candidate release root: %w", err)
	}
	return validateRootSuccessor(trustedPrevious.Document, trustedCandidate.Document)
}

// ValidateCurrentRoot applies the fixed-time issuance and expiry checks to the
// final root reached by an update attempt.
func ValidateCurrentRoot(root ParsedRoot, now time.Time, clockSkew time.Duration) error {
	trusted, err := reparseTrustedRoot(root)
	if err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("root verification time must be nonzero")
	}
	if clockSkew == 0 {
		clockSkew = 5 * time.Minute
	}
	if clockSkew < 0 {
		return errors.New("root verification clock skew cannot be negative")
	}
	now = now.UTC()
	if trusted.IssuedAt.After(now.Add(clockSkew)) {
		return fmt.Errorf("trusted root %d issued_at is too far in the future", trusted.Document.Version)
	}
	if !now.Before(trusted.ExpiresAt) {
		return fmt.Errorf("trusted root %d expired at %s", trusted.Document.Version, trusted.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func validateRootSuccessor(previous, candidate Root) error {
	if previous.Version == ^uint64(0) {
		return errors.New("trusted root version is terminal and cannot advance")
	}
	if candidate.Version != previous.Version+1 {
		return fmt.Errorf("candidate root version %d is not exact successor %d", candidate.Version, previous.Version+1)
	}
	if candidate.Channel != previous.Channel {
		return fmt.Errorf("candidate root channel %q differs from trusted channel %q", candidate.Channel, previous.Channel)
	}
	if candidate.MinimumSecurityFloor < previous.MinimumSecurityFloor {
		return fmt.Errorf("candidate root security floor %d is below trusted floor %d", candidate.MinimumSecurityFloor, previous.MinimumSecurityFloor)
	}
	if candidate.ReleaseEpoch < previous.ReleaseEpoch {
		return fmt.Errorf("candidate release epoch %d is below trusted epoch %d", candidate.ReleaseEpoch, previous.ReleaseEpoch)
	}
	if previous.ReleaseEpoch == ^uint64(0) {
		if candidate.ReleaseEpoch != previous.ReleaseEpoch {
			return errors.New("trusted release epoch is terminal and cannot advance")
		}
	} else if candidate.ReleaseEpoch > previous.ReleaseEpoch+1 {
		return fmt.Errorf("candidate release epoch %d skips trusted successor %d", candidate.ReleaseEpoch, previous.ReleaseEpoch+1)
	}
	if candidate.ReleaseEpoch == previous.ReleaseEpoch {
		if !sameRootRole(candidate.Roles.Release, previous.Roles.Release) {
			return errors.New("release role keys or threshold changed without advancing the release epoch")
		}
		if candidate.MinimumReleaseSequence < previous.MinimumReleaseSequence {
			return fmt.Errorf("candidate minimum release sequence %d is below trusted same-epoch floor %d", candidate.MinimumReleaseSequence, previous.MinimumReleaseSequence)
		}
	}
	return nil
}

func sameRootRole(left, right RootRole) bool {
	if left.Threshold != right.Threshold || len(left.KeyIDs) != len(right.KeyIDs) {
		return false
	}
	for index := range left.KeyIDs {
		if left.KeyIDs[index] != right.KeyIDs[index] {
			return false
		}
	}
	return true
}

func reparseTrustedRoot(input ParsedRoot) (ParsedRoot, error) {
	raw, err := EncodeRoot(input.Document)
	if err != nil {
		return ParsedRoot{}, err
	}
	parsed, err := ParseRoot(raw)
	if err != nil {
		return ParsedRoot{}, err
	}
	if input.SHA256 == "" || input.SHA256 != parsed.SHA256 {
		return ParsedRoot{}, errors.New("trusted root digest does not match its document")
	}
	return parsed, nil
}

func sortedVoteIDs(votes map[string]struct{}) []string {
	result := make([]string, 0, len(votes))
	for keyID := range votes {
		result = append(result, keyID)
	}
	sort.Strings(result)
	return result
}

func validateRoot(document Root) (ParsedRoot, error) {
	if document.Schema != RootSchema {
		return ParsedRoot{}, fmt.Errorf("unsupported release root schema %q", document.Schema)
	}
	if document.Version == 0 {
		return ParsedRoot{}, errors.New("release root version must be positive")
	}
	if !channelPattern.MatchString(document.Channel) {
		return ParsedRoot{}, errors.New("release root channel is not canonical")
	}
	if document.ReleaseEpoch == 0 {
		return ParsedRoot{}, errors.New("release epoch must be positive")
	}
	if document.MinimumReleaseSequence == 0 {
		return ParsedRoot{}, errors.New("minimum release sequence must be positive")
	}
	if document.MinimumSecurityFloor == 0 {
		return ParsedRoot{}, errors.New("minimum security floor must be positive")
	}
	issuedAt, err := parseCanonicalTime(document.IssuedAt)
	if err != nil {
		return ParsedRoot{}, fmt.Errorf("release root issued_at: %w", err)
	}
	expiresAt, err := parseCanonicalTime(document.ExpiresAt)
	if err != nil {
		return ParsedRoot{}, fmt.Errorf("release root expires_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return ParsedRoot{}, errors.New("release root expires_at must be after issued_at")
	}
	if expiresAt.Sub(issuedAt) > MaxRootLifetime {
		return ParsedRoot{}, fmt.Errorf("release root validity must not exceed %s", MaxRootLifetime)
	}
	if len(document.Keys) == 0 || len(document.Keys) > MaxTrustedKeys {
		return ParsedRoot{}, fmt.Errorf("release root key count must be between 1 and %d", MaxTrustedKeys)
	}

	keyByID := make(map[string]TrustedKey, len(document.Keys))
	previousKeyID := ""
	for index, file := range document.Keys {
		key, err := trustedKeyFromValue(file)
		if err != nil {
			return ParsedRoot{}, fmt.Errorf("release root key %d: %w", index, err)
		}
		if _, duplicate := keyByID[key.KeyID]; duplicate {
			return ParsedRoot{}, fmt.Errorf("duplicate release root key %s", key.KeyID)
		}
		if previousKeyID != "" && key.KeyID <= previousKeyID {
			return ParsedRoot{}, errors.New("release root keys must be strictly sorted by key_id")
		}
		previousKeyID = key.KeyID
		keyByID[key.KeyID] = cloneTrustedKey(key)
	}

	rootKeys, rootIDs, err := validateRootRole("root", document.Roles.Root, keyByID)
	if err != nil {
		return ParsedRoot{}, err
	}
	releaseKeys, releaseIDs, err := validateRootRole("release", document.Roles.Release, keyByID)
	if err != nil {
		return ParsedRoot{}, err
	}
	for keyID := range rootIDs {
		if _, overlap := releaseIDs[keyID]; overlap {
			return ParsedRoot{}, fmt.Errorf("key %s appears in both root and release roles", keyID)
		}
	}
	if len(rootIDs)+len(releaseIDs) != len(keyByID) {
		return ParsedRoot{}, errors.New("release root keys must be the exact union of root and release roles")
	}
	for keyID := range keyByID {
		if _, rootMember := rootIDs[keyID]; rootMember {
			continue
		}
		if _, releaseMember := releaseIDs[keyID]; !releaseMember {
			return ParsedRoot{}, fmt.Errorf("release root key %s is not assigned to a role", keyID)
		}
	}

	canonical, err := json.Marshal(document)
	if err != nil {
		return ParsedRoot{}, fmt.Errorf("hash release root: %w", err)
	}
	canonical = append(canonical, '\n')
	if len(canonical) > MaxRootSize {
		return ParsedRoot{}, fmt.Errorf("release root exceeds %d bytes", MaxRootSize)
	}
	digest := sha256.Sum256(canonical)
	return ParsedRoot{
		Document: cloneRoot(document), SHA256: hex.EncodeToString(digest[:]),
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
		RootKeys: cloneTrustedKeys(rootKeys), ReleaseKeys: cloneTrustedKeys(releaseKeys),
	}, nil
}

func validateRootRole(name string, role RootRole, keys map[string]TrustedKey) ([]TrustedKey, map[string]struct{}, error) {
	if role.Threshold < 2 {
		return nil, nil, fmt.Errorf("%s role threshold must be at least 2", name)
	}
	if len(role.KeyIDs) < role.Threshold {
		return nil, nil, fmt.Errorf("%s role threshold %d exceeds %d keys", name, role.Threshold, len(role.KeyIDs))
	}
	if len(role.KeyIDs) > MaxTrustedKeys {
		return nil, nil, fmt.Errorf("%s role key count must not exceed %d", name, MaxTrustedKeys)
	}
	trusted := make([]TrustedKey, 0, len(role.KeyIDs))
	seen := make(map[string]struct{}, len(role.KeyIDs))
	previous := ""
	for index, keyID := range role.KeyIDs {
		if !keyIDPattern.MatchString(keyID) {
			return nil, nil, fmt.Errorf("%s role key id %d is not canonical", name, index)
		}
		if previous != "" && keyID <= previous {
			return nil, nil, fmt.Errorf("%s role key ids must be strictly sorted", name)
		}
		previous = keyID
		key, ok := keys[keyID]
		if !ok {
			return nil, nil, fmt.Errorf("%s role references missing key %s", name, keyID)
		}
		if _, duplicate := seen[keyID]; duplicate {
			return nil, nil, fmt.Errorf("%s role contains duplicate key %s", name, keyID)
		}
		seen[keyID] = struct{}{}
		trusted = append(trusted, cloneTrustedKey(key))
	}
	return trusted, seen, nil
}

func cloneRoot(source Root) Root {
	clone := source
	clone.Keys = append([]PublicKeyFile(nil), source.Keys...)
	clone.Roles.Root.KeyIDs = append([]string(nil), source.Roles.Root.KeyIDs...)
	clone.Roles.Release.KeyIDs = append([]string(nil), source.Roles.Release.KeyIDs...)
	return clone
}

func cloneTrustedKey(source TrustedKey) TrustedKey {
	return TrustedKey{KeyID: source.KeyID, PublicKey: append([]byte(nil), source.PublicKey...)}
}

func cloneTrustedKeys(source []TrustedKey) []TrustedKey {
	result := make([]TrustedKey, len(source))
	for index, key := range source {
		result[index] = cloneTrustedKey(key)
	}
	return result
}
