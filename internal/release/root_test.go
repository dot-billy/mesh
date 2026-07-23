package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVerifyRootTransitionRequiresOldAndNewThresholds(t *testing.T) {
	previousDocument, oldRootPrivate, oldReleasePrivate := testRootAuthority(t)
	previousRaw, err := EncodeRoot(previousDocument)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := ParseRoot(previousRaw)
	if err != nil {
		t.Fatal(err)
	}
	candidateDocument, newRootPrivate, _ := testSuccessorRoot(t, previousDocument, true, false)
	candidateRaw, err := EncodeRoot(candidateDocument)
	if err != nil {
		t.Fatal(err)
	}
	oldSignatures := signWithKeys(t, RootManifestKind, candidateRaw, oldRootPrivate)
	newSignatures := signWithKeys(t, RootManifestKind, candidateRaw, newRootPrivate)

	verified, err := VerifyRootTransition(previous, candidateRaw, append(oldSignatures, newSignatures...))
	if err != nil {
		t.Fatal(err)
	}
	if verified.Root.Document.Version != 2 || verified.Root.Document.ReleaseEpoch != 1 ||
		len(verified.PreviousSignerKeyIDs) != 2 || len(verified.NewSignerKeyIDs) != 2 {
		t.Fatalf("unexpected transition: %+v", verified)
	}

	if _, err := VerifyRootTransition(previous, candidateRaw, append(oldSignatures[:1], newSignatures...)); err == nil || !strings.Contains(err.Error(), "previous root threshold") {
		t.Fatalf("insufficient previous signatures returned %v", err)
	}
	if _, err := VerifyRootTransition(previous, candidateRaw, append(oldSignatures, newSignatures[:1]...)); err == nil || !strings.Contains(err.Error(), "new root threshold") {
		t.Fatalf("insufficient new signatures returned %v", err)
	}
	wrongRole := signWithKeys(t, RootManifestKind, candidateRaw, oldReleasePrivate)
	if _, err := VerifyRootTransition(previous, candidateRaw, append(wrongRole, newSignatures...)); err == nil || !strings.Contains(err.Error(), "previous root threshold") {
		t.Fatalf("release-role root votes returned %v", err)
	}
	withExtras := append(append(append([][]byte(nil), oldSignatures...), newSignatures...), []byte(`{"broken"`), oldSignatures[0])
	if _, err := VerifyRootTransition(previous, candidateRaw, withExtras); err != nil {
		t.Fatalf("invalid extras vetoed valid root transition: %v", err)
	}
}

func TestVerifyRootTransitionRetainedKeysCountForBothRoles(t *testing.T) {
	previousDocument, rootPrivate, _ := testRootAuthority(t)
	previousRaw, err := EncodeRoot(previousDocument)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := ParseRoot(previousRaw)
	if err != nil {
		t.Fatal(err)
	}
	candidateDocument, _, _ := testSuccessorRoot(t, previousDocument, false, false)
	candidateRaw, err := EncodeRoot(candidateDocument)
	if err != nil {
		t.Fatal(err)
	}
	signatures := signWithKeys(t, RootManifestKind, candidateRaw, rootPrivate)
	verified, err := VerifyRootTransition(previous, candidateRaw, append(signatures, signatures[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(verified.PreviousSignerKeyIDs, verified.NewSignerKeyIDs) || len(verified.NewSignerKeyIDs) != 2 {
		t.Fatalf("retained signer result: %+v", verified)
	}
}

func TestVerifyRootTransitionEnforcesMonotonicSemantics(t *testing.T) {
	baseDocument, oldRootPrivate, _ := testRootAuthority(t)
	baseDocument.MinimumReleaseSequence = 3
	baseDocument.MinimumSecurityFloor = 2
	baseRaw, err := EncodeRoot(baseDocument)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseRoot(baseRaw)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*Root){
		"version gap":                        func(root *Root) { root.Version = 3 },
		"channel change":                     func(root *Root) { root.Channel = "beta" },
		"security floor decrease":            func(root *Root) { root.MinimumSecurityFloor = 1 },
		"epoch jump":                         func(root *Root) { root.ReleaseEpoch = 3 },
		"same epoch sequence floor decrease": func(root *Root) { root.MinimumReleaseSequence = 2 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate, _, _ := testSuccessorRoot(t, baseDocument, false, false)
			mutate(&candidate)
			candidateRaw, err := EncodeRoot(candidate)
			if err != nil {
				t.Fatal(err)
			}
			signatures := signWithKeys(t, RootManifestKind, candidateRaw, oldRootPrivate)
			if _, err := VerifyRootTransition(base, candidateRaw, signatures); err == nil {
				t.Fatal("invalid transition verified")
			}
		})
	}

	changedRelease, _, _ := testSuccessorRoot(t, baseDocument, false, true)
	changedRelease.ReleaseEpoch = baseDocument.ReleaseEpoch
	changedRaw, err := EncodeRoot(changedRelease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRootTransition(base, changedRaw, signWithKeys(t, RootManifestKind, changedRaw, oldRootPrivate)); err == nil || !strings.Contains(err.Error(), "release role") {
		t.Fatalf("same-epoch release-role change returned %v", err)
	}

	rotatedRelease, _, _ := testSuccessorRoot(t, baseDocument, false, true)
	rotatedRelease.MinimumReleaseSequence = 1
	rotatedRaw, err := EncodeRoot(rotatedRelease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRootTransition(base, rotatedRaw, signWithKeys(t, RootManifestKind, rotatedRaw, oldRootPrivate)); err != nil {
		t.Fatalf("new-epoch release rotation failed: %v", err)
	}
}

func TestVerifyRootTransitionRejectsVersionOverflow(t *testing.T) {
	previousDocument, rootPrivate, _ := testRootAuthority(t)
	previousDocument.Version = math.MaxUint64
	previousRaw, err := EncodeRoot(previousDocument)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := ParseRoot(previousRaw)
	if err != nil {
		t.Fatal(err)
	}
	candidate := cloneRootForTest(t, previousDocument)
	candidateRaw, err := EncodeRoot(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRootTransition(previous, candidateRaw, signWithKeys(t, RootManifestKind, candidateRaw, rootPrivate)); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("version overflow returned %v", err)
	}
}

func TestCurrentRootTimeAllowsExpiredIntermediateButRejectsExpiredFinal(t *testing.T) {
	previousDocument, rootPrivate, _ := testRootAuthority(t)
	previousDocument.ExpiresAt = "2026-07-21T12:00:00Z"
	previousRaw, err := EncodeRoot(previousDocument)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := ParseRoot(previousRaw)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, _ := testSuccessorRoot(t, previousDocument, false, false)
	candidate.IssuedAt = "2026-07-21T12:00:00Z"
	candidate.ExpiresAt = "2026-07-22T12:00:00Z"
	candidateRaw, err := EncodeRoot(candidate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRootTransition(previous, candidateRaw, signWithKeys(t, RootManifestKind, candidateRaw, rootPrivate))
	if err != nil {
		t.Fatalf("expired intermediate did not authenticate successor: %v", err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	if err := ValidateCurrentRoot(verified.Root, now, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired final root returned %v", err)
	}
	if err := ValidateCurrentRoot(verified.Root, time.Date(2026, 7, 22, 11, 0, 0, 0, time.UTC), 5*time.Minute); err != nil {
		t.Fatalf("current root rejected: %v", err)
	}
	future := cloneRootForTest(t, candidate)
	future.Version++
	future.IssuedAt = "2026-07-22T12:10:01Z"
	future.ExpiresAt = "2026-07-23T12:10:01Z"
	futureRaw, err := EncodeRoot(future)
	if err != nil {
		t.Fatal(err)
	}
	futureVerified, err := VerifyRootTransition(verified.Root, futureRaw, signWithKeys(t, RootManifestKind, futureRaw, rootPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCurrentRoot(futureVerified.Root, time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC), 5*time.Minute); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future final root returned %v", err)
	}
}

func TestRootSignaturesUseDistinctExactByteDomain(t *testing.T) {
	document, rootPrivate, _ := testRootAuthority(t)
	raw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := SignManifest(RootManifestKind, raw, rootPrivate[0])
	if err != nil {
		t.Fatal(err)
	}
	envelope, signature, err := parseSignatureEnvelope(envelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.ManifestType != string(RootManifestKind) {
		t.Fatalf("manifest type = %q", envelope.ManifestType)
	}
	publicKey := rootPrivate[0].Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, signatureMessage(RootManifestKind, raw), signature) {
		t.Fatal("root signature did not verify in root domain")
	}
	if ed25519.Verify(publicKey, signatureMessage(ChannelManifestKind, raw), signature) ||
		ed25519.Verify(publicKey, signatureMessage(ReleaseManifestKind, raw), signature) {
		t.Fatal("root signature crossed into release metadata domain")
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 1
	if ed25519.Verify(publicKey, signatureMessage(RootManifestKind, tampered), signature) {
		t.Fatal("root signature accepted changed bytes")
	}

	parsedKind, err := declaredManifestKind(raw)
	if err != nil || parsedKind != RootManifestKind {
		t.Fatalf("declared root kind = %q, %v", parsedKind, err)
	}
	if _, err := SignManifest(ChannelManifestKind, raw, rootPrivate[0]); err == nil || !strings.Contains(err.Error(), "declares") {
		t.Fatalf("root signed as channel returned %v", err)
	}
}

func TestOrdinaryManifestVerificationDoesNotTreatRootVotesAsReleaseAuthority(t *testing.T) {
	document, rootPrivate, _ := testRootAuthority(t)
	raw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	signatures := signWithKeys(t, RootManifestKind, raw, rootPrivate)
	parsed, err := ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(raw, signatures, parsed.RootKeys, policyWithThreshold(2)); err == nil || !strings.Contains(err.Error(), "no manifest type") {
		t.Fatalf("ordinary manifest verification returned %v", err)
	}
}

func TestRootSignatureEnvelopeBoundsAndDistinctVotes(t *testing.T) {
	document, rootPrivate, _ := testRootAuthority(t)
	raw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	signatures := signWithKeys(t, RootManifestKind, raw, rootPrivate)
	votes, err := collectSignatureVotes(raw, [][]byte{signatures[0], signatures[0], []byte(`{"broken"`), signatures[1]}, parsed.RootKeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(votes.ByKind[RootManifestKind]) != 2 || votes.FirstInvalid == nil {
		t.Fatalf("unexpected root votes: %+v", votes)
	}
	oversize := append(append([]byte(nil), signatures[0]...), bytes.Repeat([]byte{' '}, MaxEnvelopeSize-len(signatures[0])+1)...)
	if _, _, err := parseSignatureEnvelope(oversize); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversize root envelope returned %v", err)
	}
	var envelope SignatureEnvelope
	if err := json.Unmarshal(signatures[0], &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.KeyID = "ed25519-sha256:" + strings.Repeat("0", 64)
	badKeyID, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	badKeyID = append(badKeyID, '\n')
	if _, _, err := parseSignatureEnvelope(badKeyID); err != nil {
		// The ID is syntactically canonical. It is unknown rather than malformed,
		// so it must parse and simply contribute no trusted vote.
		t.Fatalf("canonical unknown key ID did not parse: %v", err)
	}
	unknownVotes, err := collectSignatureVotes(raw, [][]byte{badKeyID}, parsed.RootKeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknownVotes.ByKind[RootManifestKind]) != 0 {
		t.Fatal("unknown root signer became a vote")
	}
}

func TestRootCanonicalRoundTripAndDefensiveCopies(t *testing.T) {
	document := testRoot(t)
	originalKeys := append([]PublicKeyFile(nil), document.Keys...)
	originalRootIDs := append([]string(nil), document.Roles.Root.KeyIDs...)

	raw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		t.Fatalf("root is not compact JSON followed by one LF: %q", raw)
	}
	if bytes.ContainsAny(bytes.TrimSuffix(raw, []byte{'\n'}), " \t\r\n") {
		t.Fatalf("root contains insignificant whitespace: %q", raw)
	}
	if !slices.Equal(document.Keys, originalKeys) || !slices.Equal(document.Roles.Root.KeyIDs, originalRootIDs) {
		t.Fatal("EncodeRoot mutated caller-owned ordering")
	}

	parsed, err := ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Document.Schema != RootSchema || parsed.Document.Version != 1 || parsed.Document.ReleaseEpoch != 1 {
		t.Fatalf("unexpected parsed root: %+v", parsed.Document)
	}
	if len(parsed.RootKeys) != 2 || len(parsed.ReleaseKeys) != 2 || len(parsed.SHA256) != 64 {
		t.Fatalf("unexpected parsed authority: %+v", parsed)
	}
	reencoded, err := EncodeRoot(parsed.Document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Fatalf("root round trip changed bytes\nwant=%s\n got=%s", raw, reencoded)
	}

	parsed.Document.Keys[0].PublicKey = "poisoned"
	parsed.Document.Roles.Root.KeyIDs[0] = "poisoned"
	parsed.RootKeys[0].PublicKey[0] ^= 0xff
	if parsed.ReleaseKeys[0].PublicKey[0] == parsed.RootKeys[0].PublicKey[0] && parsed.ReleaseKeys[0].KeyID == parsed.RootKeys[0].KeyID {
		t.Fatal("parsed role keys unexpectedly alias")
	}
	again, err := ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again.Document.Keys[0].PublicKey == "poisoned" || again.Document.Roles.Root.KeyIDs[0] == "poisoned" {
		t.Fatal("caller mutation poisoned later parsing")
	}
}

func TestRootRejectsInvalidRolesAndKeyMembership(t *testing.T) {
	tests := map[string]func(*Root){
		"root threshold below two":    func(root *Root) { root.Roles.Root.Threshold = 1 },
		"release threshold below two": func(root *Root) { root.Roles.Release.Threshold = 1 },
		"threshold above key count":   func(root *Root) { root.Roles.Root.Threshold = 3 },
		"overlapping roles": func(root *Root) {
			root.Roles.Release.KeyIDs[0] = root.Roles.Root.KeyIDs[0]
		},
		"missing role key": func(root *Root) {
			root.Roles.Root.KeyIDs[0] = "ed25519-sha256:" + strings.Repeat("0", 64)
		},
		"unreferenced key":  func(root *Root) { root.Roles.Release.KeyIDs = root.Roles.Release.KeyIDs[:1] },
		"duplicate key":     func(root *Root) { root.Keys[1] = root.Keys[0] },
		"duplicate role id": func(root *Root) { root.Roles.Root.KeyIDs[1] = root.Roles.Root.KeyIDs[0] },
		"wrong key id":      func(root *Root) { root.Keys[0].KeyID = "ed25519-sha256:" + strings.Repeat("0", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			document := testRoot(t)
			mutate(&document)
			if _, err := EncodeRoot(document); err == nil {
				t.Fatal("invalid root encoded")
			}
		})
	}
}

func TestRootRejectsInvalidIdentityAndValidityWindow(t *testing.T) {
	tests := map[string]func(*Root){
		"zero version":        func(root *Root) { root.Version = 0 },
		"zero epoch":          func(root *Root) { root.ReleaseEpoch = 0 },
		"zero sequence floor": func(root *Root) { root.MinimumReleaseSequence = 0 },
		"zero security floor": func(root *Root) { root.MinimumSecurityFloor = 0 },
		"invalid channel":     func(root *Root) { root.Channel = "Stable" },
		"noncanonical issued": func(root *Root) { root.IssuedAt = "2026-07-20T12:00:00+00:00" },
		"fractional expiry":   func(root *Root) { root.ExpiresAt = "2026-07-21T12:00:00.000Z" },
		"expiry before issue": func(root *Root) { root.ExpiresAt = root.IssuedAt },
		"valid too long": func(root *Root) {
			root.ExpiresAt = mustRootTime(t, root.IssuedAt).Add(MaxRootLifetime + time.Second).Format(time.RFC3339)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			document := testRoot(t)
			mutate(&document)
			if _, err := EncodeRoot(document); err == nil {
				t.Fatal("invalid root encoded")
			}
		})
	}
}

func TestRootParserRequiresExactCanonicalDocument(t *testing.T) {
	raw, err := EncodeRoot(testRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"unknown field":      bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"duplicate field":    bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"unknown role":       bytes.Replace(raw, []byte(`"roles":{`), []byte(`"roles":{"other":{"threshold":2,"key_ids":[]},`), 1),
		"trailing value":     append(append([]byte(nil), raw...), []byte(`{}`)...),
		"leading whitespace": append([]byte{' '}, raw...),
		"missing newline":    bytes.TrimSuffix(raw, []byte{'\n'}),
		"extra newline":      append(append([]byte(nil), raw...), '\n'),
		"invalid utf8":       {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"unpaired surrogate": []byte(`{"schema":"mesh-release-root-v1","x":"\uD800"}`),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRoot(mutated); err == nil {
				t.Fatal("noncanonical root parsed")
			}
		})
	}
	oversize := bytes.Repeat([]byte{'x'}, MaxRootSize+1)
	if _, err := ParseRoot(oversize); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversize root returned %v", err)
	}
}

func testRoot(t *testing.T) Root {
	t.Helper()
	document, _, _ := testRootAuthority(t)
	return document
}

func testRootAuthority(t *testing.T) (Root, []ed25519.PrivateKey, []ed25519.PrivateKey) {
	t.Helper()
	keys, privateKeys := makeKeys(t, 4)
	files := make([]PublicKeyFile, len(keys))
	for index, key := range keys {
		files[index] = PublicKeyFile{
			Schema: PublicKeySchema, KeyID: key.KeyID,
			PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey),
		}
	}
	// Deliberately provide unsorted caller-owned slices. EncodeRoot canonicalizes
	// fresh copies and must not mutate them.
	document := Root{
		Schema: RootSchema, Version: 1, Channel: "stable", ReleaseEpoch: 1,
		MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
		IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z",
		Keys: []PublicKeyFile{files[3], files[1], files[0], files[2]},
		Roles: RootRoles{
			Root:    RootRole{Threshold: 2, KeyIDs: []string{files[1].KeyID, files[0].KeyID}},
			Release: RootRole{Threshold: 2, KeyIDs: []string{files[3].KeyID, files[2].KeyID}},
		},
	}
	return document, privateKeys[:2], privateKeys[2:]
}

func testSuccessorRoot(t *testing.T, previous Root, replaceRoot, replaceRelease bool) (Root, []ed25519.PrivateKey, []ed25519.PrivateKey) {
	t.Helper()
	byID := make(map[string]PublicKeyFile, len(previous.Keys))
	for _, key := range previous.Keys {
		byID[key.KeyID] = key
	}
	roleFiles := func(role RootRole) []PublicKeyFile {
		files := make([]PublicKeyFile, len(role.KeyIDs))
		for index, keyID := range role.KeyIDs {
			files[index] = byID[keyID]
		}
		return files
	}
	rootFiles := roleFiles(previous.Roles.Root)
	releaseFiles := roleFiles(previous.Roles.Release)
	var rootPrivate, releasePrivate []ed25519.PrivateKey
	if replaceRoot {
		keys, privateKeys := makeKeys(t, 2)
		rootFiles = publicFilesForTest(keys)
		rootPrivate = privateKeys
	}
	if replaceRelease {
		keys, privateKeys := makeKeys(t, 2)
		releaseFiles = publicFilesForTest(keys)
		releasePrivate = privateKeys
	}
	candidate := Root{
		Schema: RootSchema, Version: previous.Version + 1, Channel: previous.Channel,
		ReleaseEpoch: previous.ReleaseEpoch, MinimumReleaseSequence: previous.MinimumReleaseSequence,
		MinimumSecurityFloor: previous.MinimumSecurityFloor,
		IssuedAt:             "2026-07-21T12:00:00Z", ExpiresAt: "2027-07-21T12:00:00Z",
		Keys: append(append([]PublicKeyFile(nil), releaseFiles...), rootFiles...),
		Roles: RootRoles{
			Root:    RootRole{Threshold: previous.Roles.Root.Threshold, KeyIDs: keyIDsForTest(rootFiles)},
			Release: RootRole{Threshold: previous.Roles.Release.Threshold, KeyIDs: keyIDsForTest(releaseFiles)},
		},
	}
	if replaceRelease {
		candidate.ReleaseEpoch++
	}
	return candidate, rootPrivate, releasePrivate
}

func publicFilesForTest(keys []TrustedKey) []PublicKeyFile {
	files := make([]PublicKeyFile, len(keys))
	for index, key := range keys {
		files[index] = PublicKeyFile{
			Schema: PublicKeySchema, KeyID: key.KeyID,
			PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey),
		}
	}
	return files
}

func keyIDsForTest(keys []PublicKeyFile) []string {
	result := make([]string, len(keys))
	for index, key := range keys {
		result[index] = key.KeyID
	}
	return result
}

func mustRootTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func cloneRootForTest(t *testing.T, source Root) Root {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone Root
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
