package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	channelPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	platformPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
)

func ParseManifest(raw []byte, policy VerificationPolicy) (ParsedManifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestSize {
		return ParsedManifest{}, fmt.Errorf("manifest size must be between 1 and %d bytes", MaxManifestSize)
	}
	if err := validateJSONSyntax(raw); err != nil {
		return ParsedManifest{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return ParsedManifest{}, fmt.Errorf("manifest must be a JSON object")
	}
	schemaRaw, ok := top["schema"]
	if !ok {
		return ParsedManifest{}, fmt.Errorf("missing field %q", "schema")
	}
	var schema string
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		return ParsedManifest{}, fmt.Errorf("schema must be a string")
	}
	switch schema {
	case ChannelSchema:
		return parseChannelManifest(raw, policy, false)
	case ChannelSchemaV2:
		return parseChannelManifest(raw, policy, true)
	case ReleaseSchema:
		return parseReleaseManifest(raw, policy, false)
	case ReleaseSchemaV2:
		return parseReleaseManifest(raw, policy, true)
	default:
		return ParsedManifest{}, fmt.Errorf("unsupported manifest schema %q", schema)
	}
}

func parseChannelManifest(raw []byte, policy VerificationPolicy, versionTwo bool) (ParsedManifest, error) {
	fields := []string{"schema", "channel", "sequence", "minimum_security_floor", "issued_at", "expires_at", "release"}
	if versionTwo {
		fields = []string{"schema", "channel", "release_epoch", "sequence", "minimum_security_floor", "issued_at", "expires_at", "release"}
	}
	top, err := exactObject(raw, fields...)
	if err != nil {
		return ParsedManifest{}, err
	}
	if err := requireFields(top, fields...); err != nil {
		return ParsedManifest{}, err
	}
	reference, err := exactObject(top["release"], "version", "sequence", "manifest_url", "manifest_size", "manifest_sha256")
	if err != nil {
		return ParsedManifest{}, fmt.Errorf("release reference: %w", err)
	}
	if err := requireFields(reference, "version", "sequence", "manifest_url", "manifest_size", "manifest_sha256"); err != nil {
		return ParsedManifest{}, fmt.Errorf("release reference: %w", err)
	}
	var manifest ChannelManifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return ParsedManifest{}, err
	}
	expectedSchema := ChannelSchema
	if versionTwo {
		expectedSchema = ChannelSchemaV2
	}
	if manifest.Schema != expectedSchema {
		return ParsedManifest{}, fmt.Errorf("unsupported channel schema %q", manifest.Schema)
	}
	releaseEpoch, err := validateManifestReleaseEpoch(manifest.Schema, manifest.ReleaseEpoch, policy)
	if err != nil {
		return ParsedManifest{}, err
	}
	issuedAt, expiresAt, err := validateCommon(manifest.Channel, manifest.Sequence, manifest.MinimumSecurityFloor, manifest.IssuedAt, manifest.ExpiresAt, policy)
	if err != nil {
		return ParsedManifest{}, err
	}
	if err := validateVersion(manifest.Release.Version); err != nil {
		return ParsedManifest{}, fmt.Errorf("release version: %w", err)
	}
	if manifest.Release.Sequence == 0 || manifest.Release.Sequence != manifest.Sequence {
		return ParsedManifest{}, fmt.Errorf("release sequence must equal channel sequence")
	}
	if manifest.Release.ManifestSize <= 0 || manifest.Release.ManifestSize > MaxManifestSize {
		return ParsedManifest{}, fmt.Errorf("release manifest_size must be between 1 and %d", MaxManifestSize)
	}
	if err := validateSHA256(manifest.Release.ManifestSHA256); err != nil {
		return ParsedManifest{}, fmt.Errorf("release manifest_sha256: %w", err)
	}
	if err := validateHTTPSURL(manifest.Release.ManifestURL); err != nil {
		return ParsedManifest{}, fmt.Errorf("release manifest_url: %w", err)
	}
	return ParsedManifest{Kind: ChannelManifestKind, ReleaseEpoch: releaseEpoch, Channel: &manifest, IssuedAt: issuedAt, ExpiresAt: expiresAt}, nil
}

func parseReleaseManifest(raw []byte, policy VerificationPolicy, versionTwo bool) (ParsedManifest, error) {
	fields := []string{"schema", "channel", "version", "sequence", "minimum_security_floor", "issued_at", "expires_at", "artifacts"}
	if versionTwo {
		fields = []string{"schema", "channel", "release_epoch", "version", "sequence", "minimum_security_floor", "issued_at", "expires_at", "artifacts"}
	}
	top, err := exactObject(raw, fields...)
	if err != nil {
		return ParsedManifest{}, err
	}
	if err := requireFields(top, fields...); err != nil {
		return ParsedManifest{}, err
	}
	var artifactObjects []json.RawMessage
	if err := json.Unmarshal(top["artifacts"], &artifactObjects); err != nil {
		return ParsedManifest{}, fmt.Errorf("artifacts must be an array")
	}
	for index, artifactRaw := range artifactObjects {
		artifact, err := exactObject(artifactRaw, "os", "arch", "url", "size", "sha256")
		if err != nil {
			return ParsedManifest{}, fmt.Errorf("artifact %d: %w", index, err)
		}
		if err := requireFields(artifact, "os", "arch", "url", "size", "sha256"); err != nil {
			return ParsedManifest{}, fmt.Errorf("artifact %d: %w", index, err)
		}
	}
	var manifest ReleaseManifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return ParsedManifest{}, err
	}
	expectedSchema := ReleaseSchema
	if versionTwo {
		expectedSchema = ReleaseSchemaV2
	}
	if manifest.Schema != expectedSchema {
		return ParsedManifest{}, fmt.Errorf("unsupported release schema %q", manifest.Schema)
	}
	releaseEpoch, err := validateManifestReleaseEpoch(manifest.Schema, manifest.ReleaseEpoch, policy)
	if err != nil {
		return ParsedManifest{}, err
	}
	issuedAt, expiresAt, err := validateCommon(manifest.Channel, manifest.Sequence, manifest.MinimumSecurityFloor, manifest.IssuedAt, manifest.ExpiresAt, policy)
	if err != nil {
		return ParsedManifest{}, err
	}
	if err := validateVersion(manifest.Version); err != nil {
		return ParsedManifest{}, fmt.Errorf("version: %w", err)
	}
	if len(manifest.Artifacts) == 0 {
		return ParsedManifest{}, fmt.Errorf("release must contain at least one artifact")
	}
	platforms := make(map[string]struct{}, len(manifest.Artifacts))
	var selected *Artifact
	for index := range manifest.Artifacts {
		artifact := manifest.Artifacts[index]
		if err := ValidateArtifactReference(artifact); err != nil {
			return ParsedManifest{}, fmt.Errorf("artifact %d %w", index, err)
		}
		platform := artifact.OS + "\x00" + artifact.Arch
		if _, duplicate := platforms[platform]; duplicate {
			return ParsedManifest{}, fmt.Errorf("duplicate artifact platform %s/%s", artifact.OS, artifact.Arch)
		}
		platforms[platform] = struct{}{}
		if policy.PlatformOS != "" && policy.PlatformArch != "" && artifact.OS == policy.PlatformOS && artifact.Arch == policy.PlatformArch {
			copy := artifact
			selected = &copy
		}
	}
	if (policy.PlatformOS == "") != (policy.PlatformArch == "") {
		return ParsedManifest{}, fmt.Errorf("platform OS and architecture must be supplied together")
	}
	if policy.PlatformOS != "" && selected == nil {
		return ParsedManifest{}, fmt.Errorf("release has no artifact for %s/%s", policy.PlatformOS, policy.PlatformArch)
	}
	return ParsedManifest{Kind: ReleaseManifestKind, ReleaseEpoch: releaseEpoch, Release: &manifest, IssuedAt: issuedAt, ExpiresAt: expiresAt, SelectedArtifact: selected}, nil
}

func validateManifestReleaseEpoch(schema string, declared uint64, policy VerificationPolicy) (uint64, error) {
	var epoch uint64
	switch schema {
	case ChannelSchema, ReleaseSchema:
		epoch = 1
		rootAware := policy.ExpectedReleaseEpoch != 0 || policy.MinimumReleaseEpoch != 0
		if rootAware && !policy.AllowLegacyEpochOne {
			return 0, errors.New("legacy v1 release metadata requires the explicit initial-root epoch-1 bridge")
		}
	case ChannelSchemaV2, ReleaseSchemaV2:
		if declared == 0 {
			return 0, errors.New("release_epoch must be positive")
		}
		epoch = declared
	default:
		return 0, fmt.Errorf("unsupported release metadata schema %q", schema)
	}
	if policy.MinimumReleaseEpoch != 0 && epoch < policy.MinimumReleaseEpoch {
		return 0, fmt.Errorf("release epoch %d is below persisted epoch %d", epoch, policy.MinimumReleaseEpoch)
	}
	if policy.ExpectedReleaseEpoch != 0 && epoch != policy.ExpectedReleaseEpoch {
		return 0, fmt.Errorf("release epoch %d does not match trusted root epoch %d", epoch, policy.ExpectedReleaseEpoch)
	}
	return epoch, nil
}

func validateCommon(channel string, sequence, securityFloor uint64, issuedText, expiresText string, policy VerificationPolicy) (time.Time, time.Time, error) {
	if !channelPattern.MatchString(channel) {
		return time.Time{}, time.Time{}, fmt.Errorf("channel is not canonical")
	}
	if policy.ExpectedChannel != "" && channel != policy.ExpectedChannel {
		return time.Time{}, time.Time{}, fmt.Errorf("channel %q does not match expected channel %q", channel, policy.ExpectedChannel)
	}
	if sequence == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("sequence must be positive")
	}
	if sequence < policy.MinimumSequence {
		return time.Time{}, time.Time{}, fmt.Errorf("sequence %d is below replay floor %d", sequence, policy.MinimumSequence)
	}
	if securityFloor == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("minimum_security_floor must be positive")
	}
	if securityFloor < policy.MinimumSecurityFloor {
		return time.Time{}, time.Time{}, fmt.Errorf("security floor %d is below persisted floor %d", securityFloor, policy.MinimumSecurityFloor)
	}
	if policy.SupportedSecurityFloor != 0 && securityFloor > policy.SupportedSecurityFloor {
		return time.Time{}, time.Time{}, fmt.Errorf("manifest requires security floor %d but verifier supports %d", securityFloor, policy.SupportedSecurityFloor)
	}
	issuedAt, err := parseCanonicalTime(issuedText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("issued_at: %w", err)
	}
	expiresAt, err := parseCanonicalTime(expiresText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("expires_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return time.Time{}, time.Time{}, fmt.Errorf("expires_at must be after issued_at")
	}
	now := policy.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	skew := policy.ClockSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	if skew < 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("clock skew cannot be negative")
	}
	if issuedAt.After(now.Add(skew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("manifest issued_at is too far in the future")
	}
	if !now.Before(expiresAt) {
		return time.Time{}, time.Time{}, fmt.Errorf("manifest expired at %s", expiresAt.Format(time.RFC3339))
	}
	return issuedAt, expiresAt, nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("must be canonical UTC RFC3339 without fractional seconds")
	}
	return parsed.UTC(), nil
}

func validateVersion(version string) error {
	if version == "" || len(version) > 128 {
		return fmt.Errorf("must be a non-empty SemVer string of at most 128 characters")
	}
	if strings.Count(version, "+") > 1 {
		return fmt.Errorf("invalid SemVer build metadata")
	}
	mainAndBuild := strings.SplitN(version, "+", 2)
	if len(mainAndBuild) == 2 && !validIdentifiers(mainAndBuild[1], false) {
		return fmt.Errorf("invalid SemVer build metadata")
	}
	mainAndPre := strings.SplitN(mainAndBuild[0], "-", 2)
	core := strings.Split(mainAndPre[0], ".")
	if len(core) != 3 {
		return fmt.Errorf("version must contain major.minor.patch")
	}
	for _, number := range core {
		if !validNumericIdentifier(number) {
			return fmt.Errorf("version core numbers must be canonical")
		}
	}
	if len(mainAndPre) == 2 && !validIdentifiers(mainAndPre[1], true) {
		return fmt.Errorf("invalid SemVer prerelease")
	}
	return nil
}

func validIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" || !identifierPattern.MatchString(part) {
			return false
		}
		if rejectNumericLeadingZero && allDigits(part) && !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validNumericIdentifier(value string) bool {
	if value == "" || !allDigits(value) {
		return false
	}
	return len(value) == 1 || value[0] != '0'
}

func allDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}

func validateSHA256(value string) error {
	if !sha256Pattern.MatchString(value) {
		return fmt.Errorf("must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func validateHTTPSURL(value string) error {
	for _, character := range value {
		if unicode.IsSpace(character) {
			return fmt.Errorf("must not contain whitespace")
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" || !strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf("must be an absolute HTTPS URL without user information or fragment")
	}
	port, present := explicitURLPort(parsed.Host)
	if present {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return fmt.Errorf("URL port must be a decimal number from 1 through 65535")
		}
	}
	return nil
}

func explicitURLPort(host string) (string, bool) {
	if strings.HasPrefix(host, "[") {
		closing := strings.LastIndexByte(host, ']')
		if closing < 0 || closing+1 == len(host) {
			return "", false
		}
		if host[closing+1] == ':' {
			return host[closing+2:], true
		}
		return "", false
	}
	if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		return host[colon+1:], true
	}
	return "", false
}

func SignManifest(kind ManifestKind, rawManifest []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if kind != RootManifestKind && kind != BootstrapManifestKind && kind != ChannelManifestKind && kind != ReleaseManifestKind {
		return nil, fmt.Errorf("unsupported manifest type %q", kind)
	}
	maximum := MaxManifestSize
	if kind == RootManifestKind {
		maximum = MaxRootSize
	}
	if len(rawManifest) == 0 || len(rawManifest) > maximum {
		return nil, fmt.Errorf("manifest size must be between 1 and %d bytes", maximum)
	}
	declaredKind, err := declaredManifestKind(rawManifest)
	if err != nil {
		return nil, err
	}
	if declaredKind != kind {
		return nil, fmt.Errorf("manifest declares type %s, not %s", declaredKind, kind)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := KeyID(publicKey)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, signatureMessage(kind, rawManifest))
	envelope := SignatureEnvelope{
		Schema:       SignatureEnvelopeSchema,
		ManifestType: string(kind),
		KeyID:        keyID,
		Signature:    base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxEnvelopeSize {
		return nil, fmt.Errorf("signature envelope exceeds %d bytes", MaxEnvelopeSize)
	}
	return encoded, nil
}

func declaredManifestKind(raw []byte) (ManifestKind, error) {
	if err := validateJSONSyntax(raw); err != nil {
		return "", err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return "", fmt.Errorf("manifest must be a JSON object")
	}
	var schema string
	if err := json.Unmarshal(top["schema"], &schema); err != nil {
		return "", fmt.Errorf("manifest schema must be a string")
	}
	switch schema {
	case RootSchema:
		return RootManifestKind, nil
	case BootstrapManifestSchema:
		return BootstrapManifestKind, nil
	case ChannelSchema, ChannelSchemaV2:
		return ChannelManifestKind, nil
	case ReleaseSchema, ReleaseSchemaV2:
		return ReleaseManifestKind, nil
	default:
		return "", fmt.Errorf("unsupported manifest schema %q", schema)
	}
}

func parseSignatureEnvelope(raw []byte) (SignatureEnvelope, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeSize {
		return SignatureEnvelope{}, nil, fmt.Errorf("signature envelope size must be between 1 and %d bytes", MaxEnvelopeSize)
	}
	object, err := exactObject(raw, "schema", "manifest_type", "key_id", "signature")
	if err != nil {
		return SignatureEnvelope{}, nil, err
	}
	if err := requireFields(object, "schema", "manifest_type", "key_id", "signature"); err != nil {
		return SignatureEnvelope{}, nil, err
	}
	var envelope SignatureEnvelope
	if err := decodeStrict(raw, &envelope); err != nil {
		return SignatureEnvelope{}, nil, err
	}
	if envelope.Schema != SignatureEnvelopeSchema {
		return SignatureEnvelope{}, nil, fmt.Errorf("unsupported signature envelope schema %q", envelope.Schema)
	}
	if envelope.ManifestType != string(RootManifestKind) && envelope.ManifestType != string(BootstrapManifestKind) && envelope.ManifestType != string(ChannelManifestKind) && envelope.ManifestType != string(ReleaseManifestKind) {
		return SignatureEnvelope{}, nil, fmt.Errorf("unsupported signature manifest_type %q", envelope.ManifestType)
	}
	if !keyIDPattern.MatchString(envelope.KeyID) {
		return SignatureEnvelope{}, nil, fmt.Errorf("signature key id is not canonical")
	}
	signature, err := decodeCanonicalBase64(envelope.Signature, ed25519.SignatureSize, "signature")
	if err != nil {
		return SignatureEnvelope{}, nil, err
	}
	return envelope, signature, nil
}

func VerifyManifest(rawManifest []byte, rawEnvelopes [][]byte, trustedKeys []TrustedKey, policy VerificationPolicy) (VerifiedManifest, error) {
	// Do not parse attacker-controlled candidate semantics until a trusted
	// threshold has authenticated the exact bounded bytes. The only candidate
	// check before that point is the hard allocation/work bound.
	if len(rawManifest) == 0 || len(rawManifest) > MaxManifestSize {
		return VerifiedManifest{}, fmt.Errorf("manifest size must be between 1 and %d bytes", MaxManifestSize)
	}
	if policy.SupportedSecurityFloor == 0 {
		return VerifiedManifest{}, fmt.Errorf("supported security floor must be positive for verification")
	}
	threshold := policy.Threshold
	if threshold == 0 {
		threshold = DefaultThreshold
	}
	if threshold < 1 {
		return VerifiedManifest{}, fmt.Errorf("signature threshold must be positive")
	}
	// Treat envelopes as independent votes. An attacker who can append an
	// envelope must not be able to veto an otherwise valid threshold with a
	// malformed, unknown, duplicated, invalid, or minority wrong-kind vote.
	// We therefore count only distinct, cryptographically valid trusted keys in
	// each manifest-type bucket and decide after examining the bounded input.
	votes, err := collectSignatureVotes(rawManifest, rawEnvelopes, trustedKeys)
	if err != nil {
		return VerifiedManifest{}, err
	}
	if votes.TrustedCount < threshold {
		return VerifiedManifest{}, fmt.Errorf("signature threshold %d exceeds %d distinct trusted keys", threshold, votes.TrustedCount)
	}
	thresholdKinds := make([]ManifestKind, 0, 2)
	for _, kind := range []ManifestKind{ChannelManifestKind, ReleaseManifestKind} {
		if len(votes.ByKind[kind]) >= threshold {
			thresholdKinds = append(thresholdKinds, kind)
		}
	}
	if len(thresholdKinds) == 0 {
		err := fmt.Errorf("no manifest type reached signature threshold %d (channel=%d, release=%d)", threshold, len(votes.ByKind[ChannelManifestKind]), len(votes.ByKind[ReleaseManifestKind]))
		if votes.FirstInvalid != nil {
			return VerifiedManifest{}, fmt.Errorf("%w; ignored invalid envelope: %v", err, votes.FirstInvalid)
		}
		return VerifiedManifest{}, err
	}
	if len(thresholdKinds) != 1 {
		return VerifiedManifest{}, fmt.Errorf("ambiguous authenticated manifest type: channel and release each reached signature threshold %d", threshold)
	}
	agreedKind := thresholdKinds[0]
	parsed, err := ParseManifest(rawManifest, policy)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("authenticated manifest semantics: %w", err)
	}
	if parsed.Kind != agreedKind {
		return VerifiedManifest{}, fmt.Errorf("authenticated signatures declare %s but manifest schema declares %s", agreedKind, parsed.Kind)
	}
	verified := make([]string, 0, len(votes.ByKind[agreedKind]))
	for keyID := range votes.ByKind[agreedKind] {
		verified = append(verified, keyID)
	}
	sort.Strings(verified)
	return VerifiedManifest{ParsedManifest: parsed, SignerKeyIDs: verified}, nil
}

type signatureVotes struct {
	ByKind       map[ManifestKind]map[string]struct{}
	TrustedCount int
	FirstInvalid error
}

// collectSignatureVotes performs all bounded envelope and trusted-key work but
// does not apply a role threshold. Callers decide which manifest kind and
// threshold establish authority.
func collectSignatureVotes(rawManifest []byte, rawEnvelopes [][]byte, trustedKeys []TrustedKey) (signatureVotes, error) {
	if len(rawEnvelopes) > MaxSignatureEnvelopes {
		return signatureVotes{}, fmt.Errorf("signature envelope count must not exceed %d", MaxSignatureEnvelopes)
	}
	if len(trustedKeys) > MaxTrustedKeys {
		return signatureVotes{}, fmt.Errorf("trusted key count must not exceed %d", MaxTrustedKeys)
	}
	trusted := make(map[string]ed25519.PublicKey, len(trustedKeys))
	for index, key := range trustedKeys {
		if !keyIDPattern.MatchString(key.KeyID) || len(key.PublicKey) != ed25519.PublicKeySize {
			return signatureVotes{}, fmt.Errorf("trusted key %d is invalid", index)
		}
		derived, err := KeyID(key.PublicKey)
		if err != nil || derived != key.KeyID {
			return signatureVotes{}, fmt.Errorf("trusted key %d id does not match key material", index)
		}
		if _, duplicate := trusted[key.KeyID]; duplicate {
			return signatureVotes{}, fmt.Errorf("duplicate trusted key %s", key.KeyID)
		}
		trusted[key.KeyID] = append(ed25519.PublicKey(nil), key.PublicKey...)
	}
	result := signatureVotes{
		ByKind: map[ManifestKind]map[string]struct{}{
			RootManifestKind:      make(map[string]struct{}),
			BootstrapManifestKind: make(map[string]struct{}),
			ChannelManifestKind:   make(map[string]struct{}),
			ReleaseManifestKind:   make(map[string]struct{}),
		},
		TrustedCount: len(trusted),
	}
	for index, rawEnvelope := range rawEnvelopes {
		envelope, signature, err := parseSignatureEnvelope(rawEnvelope)
		if err != nil {
			if result.FirstInvalid == nil {
				result.FirstInvalid = fmt.Errorf("signature envelope %d: %w", index, err)
			}
			continue
		}
		publicKey, isTrusted := trusted[envelope.KeyID]
		if !isTrusted {
			continue
		}
		envelopeKind := ManifestKind(envelope.ManifestType)
		if _, duplicate := result.ByKind[envelopeKind][envelope.KeyID]; duplicate {
			continue
		}
		if !ed25519.Verify(publicKey, signatureMessage(envelopeKind, rawManifest), signature) {
			if result.FirstInvalid == nil {
				result.FirstInvalid = fmt.Errorf("invalid signature from trusted key %s in envelope %d", envelope.KeyID, index)
			}
			continue
		}
		result.ByKind[envelopeKind][envelope.KeyID] = struct{}{}
	}
	return result, nil
}

func signatureMessage(kind ManifestKind, rawManifest []byte) []byte {
	const domain = "mesh-release-detached-signature-v1"
	message := make([]byte, 0, len(domain)+1+8+len(kind)+8+len(rawManifest))
	message = append(message, domain...)
	message = append(message, 0)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(kind)))
	message = append(message, length[:]...)
	message = append(message, kind...)
	binary.BigEndian.PutUint64(length[:], uint64(len(rawManifest)))
	message = append(message, length[:]...)
	message = append(message, rawManifest...)
	return message
}

// VerifyChannelRelease verifies both threshold signature sets and then proves
// the exact release bytes are the bytes pinned by the channel manifest.
func VerifyChannelRelease(channelRaw []byte, channelEnvelopes [][]byte, releaseRaw []byte, releaseEnvelopes [][]byte, trustedKeys []TrustedKey, policy VerificationPolicy) (VerifiedManifest, VerifiedManifest, error) {
	channelPolicy := policy
	channelPolicy.PlatformOS = ""
	channelPolicy.PlatformArch = ""
	verifiedChannel, err := VerifyManifest(channelRaw, channelEnvelopes, trustedKeys, channelPolicy)
	if err != nil {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("channel manifest: %w", err)
	}
	if verifiedChannel.Kind != ChannelManifestKind {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("first manifest is not a channel manifest")
	}
	verifiedRelease, err := VerifyManifest(releaseRaw, releaseEnvelopes, trustedKeys, policy)
	if err != nil {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("release manifest: %w", err)
	}
	if verifiedRelease.Kind != ReleaseManifestKind {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("second manifest is not a release manifest")
	}
	reference := verifiedChannel.Channel.Release
	if int64(len(releaseRaw)) != reference.ManifestSize {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("release manifest size does not match channel reference")
	}
	digest := sha256.Sum256(releaseRaw)
	expected, _ := hex.DecodeString(reference.ManifestSHA256)
	if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("release manifest SHA-256 does not match channel reference")
	}
	manifest := verifiedRelease.Release
	if manifest.Channel != verifiedChannel.Channel.Channel || manifest.Version != reference.Version || manifest.Sequence != reference.Sequence || manifest.MinimumSecurityFloor != verifiedChannel.Channel.MinimumSecurityFloor || verifiedRelease.ReleaseEpoch != verifiedChannel.ReleaseEpoch {
		return VerifiedManifest{}, VerifiedManifest{}, fmt.Errorf("release manifest identity does not match channel reference")
	}
	return verifiedChannel, verifiedRelease, nil
}
