package onlinerelease

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	releasetrust "mesh/internal/release"
)

func testBundle() Bundle {
	return Bundle{
		ChannelManifest:   []byte(`{"schema":"mesh-channel-manifest-v1"}`),
		ChannelSignatures: [][]byte{[]byte(`{"manifest_type":"channel","signature":"a"}`)},
		ReleaseManifest:   []byte(`{"schema":"mesh-release-manifest-v1"}`),
		ReleaseSignatures: [][]byte{[]byte(`{"manifest_type":"release","signature":"b"}`)},
	}
}

func TestBundleV2CarriesExactRootUpdatesAndV1MeansEmptyChain(t *testing.T) {
	updates := testRootUpdates(t, 2)
	want := testBundle()
	want.RootUpdates = updates
	raw, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RootUpdates) != 2 || !bytes.Equal(got.RootUpdates[0], updates[0]) || !bytes.Equal(got.RootUpdates[1], updates[1]) {
		t.Fatal("v2 bundle changed root-update bytes")
	}
	got.RootUpdates[0][0] ^= 1
	again, err := Parse(raw)
	if err != nil || !bytes.Equal(again.RootUpdates[0], updates[0]) {
		t.Fatalf("caller mutation poisoned parsed root updates: %v", err)
	}

	legacy := testBundle()
	legacy.RootUpdates = nil
	legacyRaw, err := encodeForSchema(legacy, SchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	legacyParsed, err := Parse(legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	if legacyParsed.RootUpdates != nil {
		t.Fatalf("v1 bundle did not decode as an absent root chain: %#v", legacyParsed.RootUpdates)
	}

	outOfOrder := testBundle()
	outOfOrder.RootUpdates = [][]byte{updates[1], updates[0]}
	if _, err := Encode(outOfOrder); err == nil || !strings.Contains(err.Error(), "continue") {
		t.Fatalf("out-of-order roots returned %v", err)
	}
	duplicate := testBundle()
	duplicate.RootUpdates = [][]byte{updates[0], append([]byte(nil), updates[0]...)}
	if _, err := Encode(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate root version returned %v", err)
	}
	tooMany := testBundle()
	tooMany.RootUpdates = make([][]byte, releasetrust.MaxRootUpdatesPerInput+1)
	if _, err := Encode(tooMany); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("too many roots returned %v", err)
	}
}

func testRootUpdates(t *testing.T, count int) [][]byte {
	t.Helper()
	files := make([]releasetrust.PublicKeyFile, 4)
	privateKeys := make([]ed25519.PrivateKey, 4)
	for index := range files {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := releasetrust.KeyID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		files[index] = releasetrust.PublicKeyFile{Schema: releasetrust.PublicKeySchema, KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
		privateKeys[index] = privateKey
	}
	t.Cleanup(func() {
		for _, key := range privateKeys {
			clear(key)
		}
	})
	updates := make([][]byte, count)
	for index := range count {
		document := releasetrust.Root{
			Schema: releasetrust.RootSchema, Version: uint64(index + 2), Channel: "stable", ReleaseEpoch: 1,
			MinimumReleaseSequence: 1, MinimumSecurityFloor: 1,
			IssuedAt: "2026-07-20T12:00:00Z", ExpiresAt: "2027-07-20T12:00:00Z", Keys: files,
			Roles: releasetrust.RootRoles{
				Root:    releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[0].KeyID, files[1].KeyID}},
				Release: releasetrust.RootRole{Threshold: 2, KeyIDs: []string{files[2].KeyID, files[3].KeyID}},
			},
		}
		rootRaw, err := releasetrust.EncodeRoot(document)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := releasetrust.SignManifest(releasetrust.RootManifestKind, rootRaw, privateKeys[0])
		if err != nil {
			t.Fatal(err)
		}
		updates[index], err = releasetrust.EncodeRootUpdate(releasetrust.RootUpdate{RootManifest: rootRaw, Signatures: [][]byte{signature}})
		if err != nil {
			t.Fatal(err)
		}
	}
	return updates
}

func TestBundleExactCanonicalRoundTrip(t *testing.T) {
	want := testBundle()
	raw, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		t.Fatalf("bundle is not one compact JSON line: %q", raw)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.ChannelManifest, want.ChannelManifest) ||
		!bytes.Equal(got.ReleaseManifest, want.ReleaseManifest) ||
		!bytes.Equal(got.ChannelSignatures[0], want.ChannelSignatures[0]) ||
		!bytes.Equal(got.ReleaseSignatures[0], want.ReleaseSignatures[0]) {
		t.Fatalf("round trip changed bytes: %#v", got)
	}
	got.ChannelManifest[0] ^= 1
	got.ChannelSignatures[0][0] ^= 1
	again, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got.ChannelManifest, again.ChannelManifest) || bytes.Equal(got.ChannelSignatures[0], again.ChannelSignatures[0]) {
		t.Fatal("Parse did not return fresh ownership")
	}
}

func TestBundleRejectsAmbiguousOrNoncanonicalDocuments(t *testing.T) {
	base, err := Encode(testBundle())
	if err != nil {
		t.Fatal(err)
	}
	var paddedDocument encodedBundle
	if err := json.Unmarshal(base, &paddedDocument); err != nil {
		t.Fatal(err)
	}
	paddedDocument.ChannelManifest += "="
	padded, err := json.Marshal(paddedDocument)
	if err != nil {
		t.Fatal(err)
	}
	padded = append(padded, '\n')

	invalid := map[string][]byte{
		"empty":           nil,
		"unknown field":   bytes.Replace(base, []byte(`"schema":`), []byte(`"extra":true,"schema":`), 1),
		"duplicate field": bytes.Replace(base, []byte(`"schema":`), []byte(`"schema":"mesh-online-release-bundle-v1","schema":`), 1),
		"padded base64":   padded,
		"leading space":   append([]byte(" "), base...),
		"trailing value":  append(append([]byte(nil), base...), []byte("{}")...),
		"missing newline": bytes.TrimSuffix(base, []byte{'\n'}),
		"extra newline":   append(append([]byte(nil), base...), '\n'),
		"wrong schema":    bytes.Replace(base, []byte(Schema), []byte("mesh-online-release-bundle-v3"), 1),
		"invalid utf8":    append([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, '\n'),
		"oversize":        bytes.Repeat([]byte{'x'}, MaxEncodedBundleSize+1),
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

func TestBundleEnforcesEveryInnerBoundAndCollision(t *testing.T) {
	for _, role := range []string{"channel", "release"} {
		t.Run(role+" empty signatures", func(t *testing.T) {
			value := testBundle()
			if role == "channel" {
				value.ChannelSignatures = nil
			} else {
				value.ReleaseSignatures = nil
			}
			if _, err := Encode(value); err == nil {
				t.Fatal("empty signatures accepted")
			}
		})
	}

	value := testBundle()
	value.ChannelManifest = bytes.Repeat([]byte{'m'}, releasetrust.MaxManifestSize+1)
	if _, err := Encode(value); err == nil || !strings.Contains(err.Error(), "channel manifest") {
		t.Fatalf("oversized manifest error = %v", err)
	}

	value = testBundle()
	value.ReleaseManifest = nil
	if _, err := Encode(value); err == nil || !strings.Contains(err.Error(), "release manifest") {
		t.Fatalf("empty manifest error = %v", err)
	}

	value = testBundle()
	value.ReleaseSignatures = make([][]byte, releasetrust.MaxSignatureEnvelopes+1)
	for index := range value.ReleaseSignatures {
		value.ReleaseSignatures[index] = []byte{byte(index), byte(index >> 8)}
	}
	if _, err := Encode(value); err == nil {
		t.Fatal("too many signatures accepted")
	}

	value = testBundle()
	value.ChannelSignatures[0] = bytes.Repeat([]byte{'s'}, releasetrust.MaxEnvelopeSize+1)
	if _, err := Encode(value); err == nil || !strings.Contains(err.Error(), "channel signature 0") {
		t.Fatalf("oversized signature error = %v", err)
	}

	value = testBundle()
	value.ReleaseSignatures[0] = append([]byte(nil), value.ChannelSignatures[0]...)
	if _, err := Encode(value); err == nil || !strings.Contains(err.Error(), "byte-identical") {
		t.Fatalf("cross-role collision error = %v", err)
	}

	value = testBundle()
	value.ChannelSignatures = append(value.ChannelSignatures, append([]byte(nil), value.ChannelSignatures[0]...))
	if _, err := Encode(value); err == nil || !strings.Contains(err.Error(), "byte-identical") {
		t.Fatalf("same-role collision error = %v", err)
	}
}
