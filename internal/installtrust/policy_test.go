package installtrust

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	releasetrust "mesh/internal/release"
)

func TestLoadFailsClosedWithoutCompiledPolicy(t *testing.T) {
	withEncodedPolicy(t, "")
	if _, err := Load(); err == nil {
		t.Fatal("empty compiled policy accepted")
	}
}

func TestLoadValidPolicyAndDeepCopies(t *testing.T) {
	encoded := validEncodedPolicy(t, 2, nil)
	withEncodedPolicy(t, encoded)
	first, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if first.Channel != "stable" || first.SignatureThreshold != 2 || first.MinimumSequence != 1 || first.MinimumSecurityFloor != 1 || len(first.TrustedKeys) != 2 || len(first.SHA256) != 64 {
		t.Fatalf("unexpected policy: %+v", first)
	}
	first.TrustedKeys[0].PublicKey[0] ^= 0xff
	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if first.TrustedKeys[0].PublicKey[0] == second.TrustedKeys[0].PublicKey[0] {
		t.Fatal("caller mutation poisoned compiled trust")
	}
}

func TestLoadRejectsMalformedPolicies(t *testing.T) {
	valid := decodedPolicy(t, validEncodedPolicy(t, 2, nil))
	tests := map[string]string{
		"bad-base64":  "!",
		"padded":      validEncodedPolicy(t, 2, nil) + "=",
		"duplicate":   encodePolicyBytes([]byte(strings.Replace(string(valid), `"schema":`, `"schema":"duplicate","schema":`, 1))),
		"unknown":     encodePolicyBytes([]byte(strings.Replace(string(valid), `"schema":`, `"unknown":true,"schema":`, 1))),
		"trailing":    encodePolicyBytes(append(append([]byte(nil), valid...), []byte(` {}`)...)),
		"surrogate":   encodePolicyBytes([]byte(strings.Replace(string(valid), `"channel":"stable"`, `"channel":"\ud800"`, 1))),
		"threshold-1": validEncodedPolicy(t, 1, nil),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			withEncodedPolicy(t, encoded)
			if _, err := Load(); err == nil {
				t.Fatal("malformed policy accepted")
			}
		})
	}
}

func TestLoadRejectsDuplicateTrustedKeys(t *testing.T) {
	key := newPublicKeyFile(t)
	withEncodedPolicy(t, validEncodedPolicy(t, 2, []releasetrust.PublicKeyFile{key, key}))
	if _, err := Load(); err == nil {
		t.Fatal("duplicate trusted keys accepted")
	}
}

func TestLoadRejectsNoncanonicalJSONAndKeyOrdering(t *testing.T) {
	valid := decodedPolicy(t, validEncodedPolicy(t, 2, nil))
	withEncodedPolicy(t, encodePolicyBytes(append([]byte{' '}, valid...)))
	if _, err := Load(); err == nil {
		t.Fatal("noncanonical policy whitespace accepted")
	}
	keys := []releasetrust.PublicKeyFile{newPublicKeyFile(t), newPublicKeyFile(t)}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID > keys[j].KeyID })
	withEncodedPolicy(t, validEncodedPolicyUnsorted(t, 2, keys))
	if _, err := Load(); err == nil {
		t.Fatal("noncanonical trusted-key order accepted")
	}
}

func TestEncodeProducesLoadableCanonicalSortedPolicy(t *testing.T) {
	keys := []releasetrust.PublicKeyFile{newPublicKeyFile(t), newPublicKeyFile(t), newPublicKeyFile(t)}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID > keys[j].KeyID })
	encoded, encodedPolicy, err := Encode(PolicySpec{
		Channel: "stable", SignatureThreshold: 2, MinimumSequence: 9,
		MinimumSecurityFloor: 3, TrustedKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	withEncodedPolicy(t, encoded)
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SHA256 != encodedPolicy.SHA256 || loaded.MinimumSequence != 9 || loaded.MinimumSecurityFloor != 3 || len(loaded.TrustedKeys) != 3 {
		t.Fatalf("encoded policy changed on load: %+v versus %+v", encodedPolicy, loaded)
	}
	for index := 1; index < len(loaded.TrustedKeys); index++ {
		if loaded.TrustedKeys[index-1].KeyID >= loaded.TrustedKeys[index].KeyID {
			t.Fatal("encoded trusted keys are not strictly sorted")
		}
	}
}

func validEncodedPolicy(t *testing.T, threshold int, supplied []releasetrust.PublicKeyFile) string {
	t.Helper()
	keys := supplied
	if keys == nil {
		keys = []releasetrust.PublicKeyFile{newPublicKeyFile(t), newPublicKeyFile(t)}
	}
	keys = append([]releasetrust.PublicKeyFile(nil), keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	return validEncodedPolicyUnsorted(t, threshold, keys)
}

func validEncodedPolicyUnsorted(t *testing.T, threshold int, keys []releasetrust.PublicKeyFile) string {
	t.Helper()
	document := encodedPolicy{
		Schema: policySchema, Channel: "stable", SignatureThreshold: threshold,
		MinimumSequence: 1, MinimumSecurityFloor: 1, TrustedKeys: keys,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encodePolicyBytes(raw)
}

func newPublicKeyFile(t *testing.T) releasetrust.PublicKeyFile {
	t.Helper()
	_, privateKey, err := releasetrust.GeneratePrivateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	publicKey, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func decodedPolicy(t *testing.T, encoded string) []byte {
	t.Helper()
	if !strings.HasPrefix(encoded, FramePrefix) || !strings.HasSuffix(encoded, FrameSuffix) {
		t.Fatal("policy test frame is invalid")
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(encoded, FramePrefix), FrameSuffix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func encodePolicyBytes(raw []byte) string {
	return FramePrefix + base64.RawURLEncoding.EncodeToString(raw) + FrameSuffix
}

func withEncodedPolicy(t *testing.T, encoded string) {
	t.Helper()
	original := Identity
	Identity = encoded
	t.Cleanup(func() { Identity = original })
}
