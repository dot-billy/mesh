package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)

func TestVerifyReleaseThresholdAndExactArtifact(t *testing.T) {
	artifactBytes := []byte("trusted release artifact\n")
	raw := marshalRelease(t, releaseForArtifact(artifactBytes))
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, raw, privateKeys)
	verified, err := VerifyManifest(raw, signatures, keys, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Kind != ReleaseManifestKind || len(verified.SignerKeyIDs) != 2 || verified.SelectedArtifact == nil {
		t.Fatalf("unexpected verification result: %+v", verified)
	}
	if err := VerifyArtifact(bytes.NewReader(artifactBytes), *verified.SelectedArtifact); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"truncated": artifactBytes[:len(artifactBytes)-1],
		"appended":  append(append([]byte(nil), artifactBytes...), 'x'),
		"tampered":  append([]byte("X"), artifactBytes[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyArtifact(bytes.NewReader(content), *verified.SelectedArtifact); err == nil {
				t.Fatal("invalid artifact verified")
			}
		})
	}
}

func TestVerifyArtifactFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires platform privileges")
	}
	content := []byte("artifact")
	manifest := releaseForArtifact(content)
	directory := t.TempDir()
	target := filepath.Join(directory, "artifact")
	link := filepath.Join(directory, "artifact-link")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactFile(link, manifest.Artifacts[0]); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink artifact returned %v", err)
	}
}

func TestThresholdRequiresDistinctTrustedSigners(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, raw, privateKeys)
	if _, err := VerifyManifest(raw, signatures[:1], keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("one signature returned %v", err)
	}
	if _, err := VerifyManifest(raw, [][]byte{signatures[0], signatures[0]}, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("duplicate signature returned %v", err)
	}
	if _, err := VerifyManifest(raw, signatures, []TrustedKey{keys[0], keys[0]}, basePolicy()); err == nil || !strings.Contains(err.Error(), "duplicate trusted key") {
		t.Fatalf("duplicate trusted key returned %v", err)
	}
	unknownKeys, unknownPrivate := makeKeys(t, 1)
	unknownSignature := signWithKeys(t, ReleaseManifestKind, raw, unknownPrivate)[0]
	if _, err := VerifyManifest(raw, append(signatures[:1], unknownSignature), append(keys, unknownKeys...), VerificationPolicy{
		Now: testNow, Threshold: 2, MinimumSecurityFloor: 1, SupportedSecurityFloor: 1, PlatformOS: "linux", PlatformArch: "amd64",
	}); err != nil {
		t.Fatalf("two distinct trusted signers should verify: %v", err)
	}
}

func TestThresholdAuthenticatesRawBytesBeforeSemanticParsing(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	semanticallyInvalid := bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, semanticallyInvalid, privateKeys)
	if _, err := VerifyManifest(semanticallyInvalid, signatures[:1], keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "threshold") || strings.Contains(err.Error(), "semantics") {
		t.Fatalf("pre-threshold semantic candidate returned %v", err)
	}
	if _, err := VerifyManifest(semanticallyInvalid, signatures, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "authenticated manifest semantics") || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("authenticated invalid semantics returned %v", err)
	}
}

func TestThresholdKindMustMatchParsedSchema(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 2)
	channelEnvelope := signedTestEnvelope(t, ChannelManifestKind, raw, privateKeys[0])
	releaseEnvelope := signedTestEnvelope(t, ReleaseManifestKind, raw, privateKeys[1])
	if _, err := VerifyManifest(raw, [][]byte{channelEnvelope, releaseEnvelope}, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("mixed trusted manifest types returned %v", err)
	}
	secondChannelEnvelope := signedTestEnvelope(t, ChannelManifestKind, raw, privateKeys[1])
	if _, err := VerifyManifest(raw, [][]byte{channelEnvelope, secondChannelEnvelope}, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "signatures declare channel") {
		t.Fatalf("signature/schema type mismatch returned %v", err)
	}
}

func TestThresholdIgnoresNonContributingEnvelopeExtras(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 3)
	good := signWithKeys(t, ReleaseManifestKind, raw, privateKeys[:2])
	_, unknownPrivateKeys := makeKeys(t, 1)
	unknown := signWithKeys(t, ReleaseManifestKind, raw, unknownPrivateKeys)[0]
	invalidTrusted := signedTestEnvelope(t, ReleaseManifestKind, raw, privateKeys[2])
	var invalidEnvelope SignatureEnvelope
	if err := json.Unmarshal(invalidTrusted, &invalidEnvelope); err != nil {
		t.Fatal(err)
	}
	invalidSignature, err := base64.RawURLEncoding.DecodeString(invalidEnvelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	invalidSignature[0] ^= 0xff
	invalidEnvelope.Signature = base64.RawURLEncoding.EncodeToString(invalidSignature)
	invalidTrusted, err = json.Marshal(invalidEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	wrongKind := signedTestEnvelope(t, ChannelManifestKind, raw, privateKeys[2])

	tests := map[string][][]byte{
		"malformed":              {[]byte(`{"broken"`)},
		"unknown signer":         {unknown},
		"duplicate":              {good[0]},
		"invalid trusted signer": {invalidTrusted},
		"minority wrong kind":    {wrongKind},
		"all extras":             {[]byte(`{"broken"`), unknown, good[0], invalidTrusted, wrongKind},
	}
	for name, extras := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := append(append([][]byte(nil), good...), extras...)
			verified, err := VerifyManifest(raw, candidate, keys, basePolicy())
			if err != nil {
				t.Fatalf("valid threshold was vetoed: %v", err)
			}
			if verified.Kind != ReleaseManifestKind || len(verified.SignerKeyIDs) != 2 {
				t.Fatalf("unexpected result: %+v", verified)
			}
		})
	}
}

func TestThresholdRejectsAmbiguousKinds(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 4)
	envelopes := [][]byte{
		signedTestEnvelope(t, ReleaseManifestKind, raw, privateKeys[0]),
		signedTestEnvelope(t, ReleaseManifestKind, raw, privateKeys[1]),
		signedTestEnvelope(t, ChannelManifestKind, raw, privateKeys[2]),
		signedTestEnvelope(t, ChannelManifestKind, raw, privateKeys[3]),
	}
	if _, err := VerifyManifest(raw, envelopes, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous thresholds returned %v", err)
	}
}

func TestSignaturesBindDomainAndExactRawBytes(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, raw, privateKeys)
	tampered := append(append([]byte(nil), raw...), '\n')
	if _, err := VerifyManifest(tampered, signatures, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("whitespace-tampered bytes returned %v", err)
	}
	keyID, err := KeyID(privateKeys[0].Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	domainEnvelope := SignatureEnvelope{
		Schema: SignatureEnvelopeSchema, ManifestType: string(ReleaseManifestKind), KeyID: keyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKeys[0], signatureMessage(ChannelManifestKind, raw))),
	}
	domainSignature, err := json.Marshal(domainEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(raw, [][]byte{domainSignature}, keys[:1], policyWithThreshold(1)); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("cross-domain signature returned %v", err)
	}
}

func TestManifestStrictJSONAndBounds(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	mutations := map[string][]byte{
		"unknown top field":  bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"case changed field": bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1),
		"duplicate field":    bytes.Replace(raw, []byte(`"channel":"stable"`), []byte(`"channel":"stable","channel":"stable"`), 1),
		"unknown artifact":   bytes.Replace(raw, []byte(`"os":"linux"`), []byte(`"extra":false,"os":"linux"`), 1),
		"trailing value":     append(append([]byte(nil), raw...), []byte(` {}`)...),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest(mutated, basePolicy()); err == nil {
				t.Fatal("ambiguous manifest parsed")
			}
		})
	}
	oversize := bytes.Repeat([]byte{' '}, MaxManifestSize+1)
	if _, err := ParseManifest(oversize, basePolicy()); err == nil || !strings.Contains(err.Error(), "manifest size") {
		t.Fatalf("oversize manifest returned %v", err)
	}
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, raw, privateKeys)
	signatures[0] = append(signatures[0], bytes.Repeat([]byte{' '}, MaxEnvelopeSize-len(signatures[0])+1)...)
	if _, err := VerifyManifest(raw, signatures, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "envelope size") {
		t.Fatalf("oversize envelope returned %v", err)
	}
	if _, err := VerifyManifest(raw, make([][]byte, MaxSignatureEnvelopes+1), keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "envelope count") {
		t.Fatalf("excess envelope count returned %v", err)
	}
	if _, err := VerifyManifest(raw, signatures, make([]TrustedKey, MaxTrustedKeys+1), basePolicy()); err == nil || !strings.Contains(err.Error(), "trusted key count") {
		t.Fatalf("excess trusted-key count returned %v", err)
	}
}

func TestStrictJSONRejectsNonCanonicalUnicode(t *testing.T) {
	tests := map[string][]byte{
		"invalid raw UTF-8":       {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"unpaired high surrogate": []byte(`{"x":"\uD800"}`),
		"unpaired low surrogate":  []byte(`{"x":"\uDC00"}`),
		"two high surrogates":     []byte(`{"x":"\uD800\uD801"}`),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateJSONSyntax(raw); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
				t.Fatalf("invalid Unicode returned %v", err)
			}
		})
	}
	for name, raw := range map[string][]byte{
		"valid surrogate pair": []byte(`{"emoji":"\uD83D\uDE00"}`),
		"escaped literal":      []byte(`{"literal":"\\uD800"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJSONSyntax(raw); err != nil {
				t.Fatalf("valid Unicode rejected: %v", err)
			}
		})
	}
}

func TestVerifyManifestRequiresSupportedSecurityFloor(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 2)
	policy := basePolicy()
	policy.SupportedSecurityFloor = 0
	if _, err := VerifyManifest(raw, signWithKeys(t, ReleaseManifestKind, raw, privateKeys), keys, policy); err == nil || !strings.Contains(err.Error(), "supported security floor") {
		t.Fatalf("missing supported floor returned %v", err)
	}
}

func TestExpiryReplaySecurityFloorAndPlatformPolicy(t *testing.T) {
	base := releaseForArtifact([]byte("artifact"))
	tests := []struct {
		name   string
		change func(*ReleaseManifest)
		policy VerificationPolicy
		match  string
	}{
		{name: "expired", change: func(m *ReleaseManifest) { m.ExpiresAt = testNow.Format(time.RFC3339) }, policy: basePolicy(), match: "expired"},
		{name: "future", change: func(m *ReleaseManifest) { m.IssuedAt = testNow.Add(6 * time.Minute).Format(time.RFC3339) }, policy: basePolicy(), match: "future"},
		{name: "replay floor", change: func(*ReleaseManifest) {}, policy: policyChange(basePolicy(), func(p *VerificationPolicy) { p.MinimumSequence = 8 }), match: "replay floor"},
		{name: "downgrade floor", change: func(*ReleaseManifest) {}, policy: policyChange(basePolicy(), func(p *VerificationPolicy) { p.MinimumSecurityFloor = 2; p.SupportedSecurityFloor = 2 }), match: "persisted floor"},
		{name: "unsupported floor", change: func(m *ReleaseManifest) { m.MinimumSecurityFloor = 2 }, policy: basePolicy(), match: "supports 1"},
		{name: "missing platform", change: func(*ReleaseManifest) {}, policy: policyChange(basePolicy(), func(p *VerificationPolicy) { p.PlatformArch = "arm64" }), match: "no artifact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			manifest.Artifacts = append([]Artifact(nil), base.Artifacts...)
			test.change(&manifest)
			if _, err := ParseManifest(marshalRelease(t, manifest), test.policy); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("returned %v, want match %q", err, test.match)
			}
		})
	}
}

func TestArtifactAndURLValidation(t *testing.T) {
	base := releaseForArtifact([]byte("artifact"))
	tests := []struct {
		name   string
		change func(*ReleaseManifest)
	}{
		{name: "zero size", change: func(m *ReleaseManifest) { m.Artifacts[0].Size = 0 }},
		{name: "oversize artifact", change: func(m *ReleaseManifest) { m.Artifacts[0].Size = MaxArtifactSize + 1 }},
		{name: "uppercase digest", change: func(m *ReleaseManifest) { m.Artifacts[0].SHA256 = strings.ToUpper(m.Artifacts[0].SHA256) }},
		{name: "http URL", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "http://releases.example/meshctl" }},
		{name: "URL credentials", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://user@releases.example/meshctl" }},
		{name: "interior ASCII space", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://releases.example/mesh ctl" }},
		{name: "interior NBSP", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://releases.example/mesh\u00a0ctl" }},
		{name: "zero port", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://releases.example:0/meshctl" }},
		{name: "oversize port", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://releases.example:65536/meshctl" }},
		{name: "empty port", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://releases.example:/meshctl" }},
		{name: "nonnumeric port", change: func(m *ReleaseManifest) { m.Artifacts[0].URL = "https://releases.example:tls/meshctl" }},
		{name: "duplicate platform", change: func(m *ReleaseManifest) { m.Artifacts = append(m.Artifacts, m.Artifacts[0]) }},
		{name: "invalid platform", change: func(m *ReleaseManifest) { m.Artifacts[0].OS = "Linux" }},
		{name: "invalid version", change: func(m *ReleaseManifest) { m.Version = "01.2.3" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			manifest.Artifacts = append([]Artifact(nil), base.Artifacts...)
			test.change(&manifest)
			if _, err := ParseManifest(marshalRelease(t, manifest), basePolicy()); err == nil {
				t.Fatal("invalid release parsed")
			}
		})
	}
	for _, value := range []string{"https://releases.example:65535/meshctl", "https://releases.example/mesh%20ctl"} {
		if err := validateHTTPSURL(value); err != nil {
			t.Fatalf("valid URL %q rejected: %v", value, err)
		}
	}
}

func TestValidateArtifactReference(t *testing.T) {
	content := []byte("artifact")
	valid := releaseForArtifact(content).Artifacts[0]
	if err := ValidateArtifactReference(valid); err != nil {
		t.Fatalf("valid artifact reference rejected: %v", err)
	}
	tests := []struct {
		name   string
		change func(*Artifact)
		match  string
	}{
		{name: "empty OS", change: func(value *Artifact) { value.OS = "" }, match: "platform"},
		{name: "noncanonical architecture", change: func(value *Artifact) { value.Arch = "AMD64" }, match: "platform"},
		{name: "zero size", change: func(value *Artifact) { value.Size = 0 }, match: "size"},
		{name: "oversize", change: func(value *Artifact) { value.Size = MaxArtifactSize + 1 }, match: "size"},
		{name: "uppercase digest", change: func(value *Artifact) { value.SHA256 = strings.ToUpper(value.SHA256) }, match: "sha256"},
		{name: "short digest", change: func(value *Artifact) { value.SHA256 = value.SHA256[:62] }, match: "sha256"},
		{name: "HTTP URL", change: func(value *Artifact) { value.URL = "http://releases.example/artifact" }, match: "URL"},
		{name: "URL credentials", change: func(value *Artifact) { value.URL = "https://user@releases.example/artifact" }, match: "URL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := valid
			test.change(&artifact)
			if err := ValidateArtifactReference(artifact); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("validation returned %v, want %q", err, test.match)
			}
		})
	}
}

func TestChannelPinsExactReleaseBytesAndIdentity(t *testing.T) {
	releaseRaw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	digest := sha256.Sum256(releaseRaw)
	channel := ChannelManifest{
		Schema: ChannelSchema, Channel: "stable", Sequence: 7, MinimumSecurityFloor: 1,
		IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		Release: ReleaseReference{Version: "1.2.3", Sequence: 7, ManifestURL: "https://releases.example/1.2.3/release.json", ManifestSize: int64(len(releaseRaw)), ManifestSHA256: hex.EncodeToString(digest[:])},
	}
	channelRaw, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	keys, privateKeys := makeKeys(t, 2)
	channelSigs := signWithKeys(t, ChannelManifestKind, channelRaw, privateKeys)
	releaseSigs := signWithKeys(t, ReleaseManifestKind, releaseRaw, privateKeys)
	if _, _, err := VerifyChannelRelease(channelRaw, channelSigs, releaseRaw, releaseSigs, keys, basePolicy()); err != nil {
		t.Fatal(err)
	}
	tamperedRelease := append(append([]byte(nil), releaseRaw...), '\n')
	tamperedSigs := signWithKeys(t, ReleaseManifestKind, tamperedRelease, privateKeys)
	if _, _, err := VerifyChannelRelease(channelRaw, channelSigs, tamperedRelease, tamperedSigs, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("republished release bytes returned %v", err)
	}
}

func TestV2ChannelReleaseBindsReleaseEpoch(t *testing.T) {
	release := releaseForArtifact([]byte("artifact"))
	release.Schema = ReleaseSchemaV2
	release.ReleaseEpoch = 2
	releaseRaw := marshalRelease(t, release)
	digest := sha256.Sum256(releaseRaw)
	channel := ChannelManifest{
		Schema: ChannelSchemaV2, Channel: "stable", ReleaseEpoch: 2,
		Sequence: 7, MinimumSecurityFloor: 1,
		IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		Release: ReleaseReference{Version: "1.2.3", Sequence: 7, ManifestURL: "https://releases.example/1.2.3/release.json", ManifestSize: int64(len(releaseRaw)), ManifestSHA256: hex.EncodeToString(digest[:])},
	}
	channelRaw, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	keys, privateKeys := makeKeys(t, 2)
	policy := basePolicy()
	policy.ExpectedReleaseEpoch = 2
	policy.MinimumReleaseEpoch = 2
	verifiedChannel, verifiedRelease, err := VerifyChannelRelease(
		channelRaw, signWithKeys(t, ChannelManifestKind, channelRaw, privateKeys),
		releaseRaw, signWithKeys(t, ReleaseManifestKind, releaseRaw, privateKeys),
		keys, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedChannel.ReleaseEpoch != 2 || verifiedRelease.ReleaseEpoch != 2 {
		t.Fatalf("verified epochs = %d/%d", verifiedChannel.ReleaseEpoch, verifiedRelease.ReleaseEpoch)
	}

	wrongChannel := channel
	wrongChannel.ReleaseEpoch = 1
	wrongRaw, err := json.Marshal(wrongChannel)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyChannelRelease(
		wrongRaw, signWithKeys(t, ChannelManifestKind, wrongRaw, privateKeys),
		releaseRaw, signWithKeys(t, ReleaseManifestKind, releaseRaw, privateKeys), keys, policy,
	); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("wrong channel epoch returned %v", err)
	}

	zeroEpoch := release
	zeroEpoch.ReleaseEpoch = 0
	if _, err := ParseManifest(marshalRelease(t, zeroEpoch), policy); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("zero v2 epoch returned %v", err)
	}
}

func TestLegacyV1EpochRequiresExplicitInitialRootBridge(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	rootAware := basePolicy()
	rootAware.ExpectedReleaseEpoch = 1
	rootAware.MinimumReleaseEpoch = 1
	if _, err := ParseManifest(raw, rootAware); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("implicit legacy epoch returned %v", err)
	}
	rootAware.AllowLegacyEpochOne = true
	parsed, err := ParseManifest(raw, rootAware)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ReleaseEpoch != 1 {
		t.Fatalf("legacy epoch = %d", parsed.ReleaseEpoch)
	}
	rootAware.ExpectedReleaseEpoch = 2
	rootAware.MinimumReleaseEpoch = 2
	if _, err := ParseManifest(raw, rootAware); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("legacy metadata crossed epoch boundary: %v", err)
	}
	if _, err := ParseManifest(raw, basePolicy()); err != nil {
		t.Fatalf("pre-root verifier compatibility changed: %v", err)
	}
}

func TestV2EpochFloorAllowsSequenceResetOnlyInNewEpoch(t *testing.T) {
	release := releaseForArtifact([]byte("artifact"))
	release.Schema = ReleaseSchemaV2
	release.ReleaseEpoch = 2
	release.Sequence = 1
	policy := basePolicy()
	policy.ExpectedReleaseEpoch = 2
	policy.MinimumReleaseEpoch = 2
	policy.MinimumSequence = 1
	if _, err := ParseManifest(marshalRelease(t, release), policy); err != nil {
		t.Fatalf("new epoch sequence reset failed: %v", err)
	}
	policy.MinimumSequence = 2
	if _, err := ParseManifest(marshalRelease(t, release), policy); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("same-epoch sequence replay returned %v", err)
	}
	oldEpoch := release
	oldEpoch.ReleaseEpoch = 1
	policy.MinimumSequence = 1
	if _, err := ParseManifest(marshalRelease(t, oldEpoch), policy); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("old epoch crossed floor: %v", err)
	}
}

func TestKeyFilesRequireCanonicalIdentityAndStrictSchema(t *testing.T) {
	privateFile, privateKey, err := GeneratePrivateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	publicFile, err := PublicKeyFileFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalPublicKeyFile(publicFile)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := ParseTrustedPublicKey(raw)
	if err != nil || trusted.KeyID != privateFile.KeyID {
		t.Fatalf("parse public key: %v, %+v", err, trusted)
	}
	for name, mutated := range map[string][]byte{
		"unknown":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		"duplicate": bytes.Replace(raw, []byte(`"key_id":`), []byte(`"key_id":"bad","key_id":`), 1),
		"padded":    bytes.Replace(raw, []byte(publicFile.PublicKey), []byte(publicFile.PublicKey+"="), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTrustedPublicKey(mutated); err == nil {
				t.Fatal("invalid public key parsed")
			}
		})
	}
}

func TestTrustedSignatureTamperingFails(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, raw, privateKeys)
	var envelope SignatureEnvelope
	if err := json.Unmarshal(signatures[0], &envelope); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0] ^= 0xff
	envelope.Signature = base64.RawURLEncoding.EncodeToString(decoded)
	signatures[0], _ = json.Marshal(envelope)
	if _, err := VerifyManifest(raw, signatures, keys, basePolicy()); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("tampered signature returned %v", err)
	}
}

func TestSignatureEnvelopeStrictSchema(t *testing.T) {
	raw := marshalRelease(t, releaseForArtifact([]byte("artifact")))
	keys, privateKeys := makeKeys(t, 2)
	signatures := signWithKeys(t, ReleaseManifestKind, raw, privateKeys)
	mutations := map[string][]byte{
		"unknown":   bytes.Replace(signatures[0], []byte(`"schema":`), []byte(`"unknown":false,"schema":`), 1),
		"duplicate": bytes.Replace(signatures[0], []byte(`"key_id":`), []byte(`"key_id":"bad","key_id":`), 1),
		"trailing":  append(append([]byte(nil), signatures[0]...), []byte(` {}`)...),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := [][]byte{mutated, signatures[1]}
			if _, err := VerifyManifest(raw, candidate, keys, basePolicy()); err == nil {
				t.Fatal("invalid signature envelope verified")
			}
		})
	}
	if _, err := SignManifest(ChannelManifestKind, raw, privateKeys[0]); err == nil || !strings.Contains(err.Error(), "declares type") {
		t.Fatalf("mismatched signing domain returned %v", err)
	}
}

func TestValidateStrictJSONRejectsAmbiguousSyntax(t *testing.T) {
	valid := []byte(`{"schema":"example","value":[1,true,null]}`)
	if err := ValidateStrictJSON(valid); err != nil {
		t.Fatalf("valid strict JSON: %v", err)
	}
	for name, raw := range map[string][]byte{
		"duplicate":      []byte(`{"schema":"a","schema":"b"}`),
		"trailing":       []byte(`{"schema":"a"}{}`),
		"invalid utf8":   {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"high surrogate": []byte(`{"x":"\ud800"}`),
		"low surrogate":  []byte(`{"x":"\udc00"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateStrictJSON(raw); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}

func releaseForArtifact(content []byte) ReleaseManifest {
	digest := sha256.Sum256(content)
	return ReleaseManifest{
		Schema: ReleaseSchema, Channel: "stable", Version: "1.2.3", Sequence: 7, MinimumSecurityFloor: 1,
		IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		Artifacts: []Artifact{{OS: "linux", Arch: "amd64", URL: "https://releases.example/meshctl-linux-amd64", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}},
	}
}

func marshalRelease(t *testing.T, manifest ReleaseManifest) []byte {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func makeKeys(t *testing.T, count int) ([]TrustedKey, []ed25519.PrivateKey) {
	t.Helper()
	trusted := make([]TrustedKey, 0, count)
	privateKeys := make([]ed25519.PrivateKey, 0, count)
	for range count {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := KeyID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, TrustedKey{KeyID: keyID, PublicKey: publicKey})
		privateKeys = append(privateKeys, privateKey)
	}
	t.Cleanup(func() {
		for _, key := range privateKeys {
			clear(key)
		}
	})
	return trusted, privateKeys
}

func signWithKeys(t *testing.T, kind ManifestKind, raw []byte, privateKeys []ed25519.PrivateKey) [][]byte {
	t.Helper()
	signatures := make([][]byte, 0, len(privateKeys))
	for _, privateKey := range privateKeys {
		envelope, err := SignManifest(kind, raw, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, envelope)
	}
	return signatures
}

func signedTestEnvelope(t *testing.T, kind ManifestKind, raw []byte, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	keyID, err := KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	envelope := SignatureEnvelope{
		Schema: SignatureEnvelopeSchema, ManifestType: string(kind), KeyID: keyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signatureMessage(kind, raw))),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func basePolicy() VerificationPolicy {
	return VerificationPolicy{Now: testNow, MinimumSecurityFloor: 1, SupportedSecurityFloor: 1, PlatformOS: "linux", PlatformArch: "amd64"}
}

func policyWithThreshold(threshold int) VerificationPolicy {
	policy := basePolicy()
	policy.Threshold = threshold
	return policy
}

func policyChange(policy VerificationPolicy, change func(*VerificationPolicy)) VerificationPolicy {
	change(&policy)
	return policy
}
