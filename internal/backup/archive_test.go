package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"crypto/hkdf"
)

var testCaptureTime = time.Date(2026, 7, 19, 17, 42, 9, 987654321, time.FixedZone("EDT", -4*60*60))

func testRootKey() []byte {
	return bytes.Repeat([]byte{0xa7}, 32)
}

func testSource() Source {
	return Source{
		StateJSON:         []byte("{\"version\":1,\"networks\":[],\"audit\":[]}\n"),
		IdentityStateJSON: []byte("{\"schema\":\"identity-state-v2\",\"sessions\":[],\"audit\":[]}\n"),
		MasterKey:         bytes.Repeat([]byte{0x5c}, 32),
		AdminToken:        []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijk"),
		ControlVersion:    1,
		IdentitySchema:    "identity-state-v2",
	}
}

func testCodec(t *testing.T) *Codec {
	t.Helper()
	entropy := make([]byte, 16+32)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	codec, err := NewCodecForTesting(bytes.NewReader(entropy), func() time.Time { return testCaptureTime })
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func sealFixture(t *testing.T) ([]byte, Manifest) {
	t.Helper()
	envelope, manifest, err := testCodec(t).Seal(testRootKey(), testSource())
	if err != nil {
		t.Fatal(err)
	}
	return envelope, manifest
}

func TestEnvelopeGoldenPrefixAndRoundTrip(t *testing.T) {
	envelope, sealedManifest := sealFixture(t)
	wantPrefix := []byte{'M', 'E', 'S', 'H', '-', 'B', 'A', 'C', 'K', 'U', 'P', '-', 'V', '1', 0, 0}
	if !bytes.Equal(envelope[:fixedHeaderSize], wantPrefix) {
		t.Fatalf("prefix=%x want=%x", envelope[:fixedHeaderSize], wantPrefix)
	}
	if len(envelope) > MaxArchiveSize {
		t.Fatalf("envelope size=%d", len(envelope))
	}
	if got := binary.BigEndian.Uint64(envelope[fixedHeaderSize+saltSize : envelopeHeadSize]); got != uint64(len(envelope)-envelopeHeadSize) {
		t.Fatalf("declared ciphertext=%d actual=%d", got, len(envelope)-envelopeHeadSize)
	}
	if sealedManifest.Schema != ManifestSchema || sealedManifest.BackupID != "0102030405060708090a0b0c0d0e0f10" || sealedManifest.CapturedAt != "2026-07-19T21:42:09Z" {
		t.Fatalf("unexpected manifest: %+v", sealedManifest)
	}
	contents, err := Open(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	source := testSource()
	if !bytes.Equal(contents.StateJSON, source.StateJSON) || !bytes.Equal(contents.IdentityStateJSON, source.IdentityStateJSON) || !bytes.Equal(contents.MasterKey, source.MasterKey) || !bytes.Equal(contents.AdminToken, source.AdminToken) {
		t.Fatalf("round trip differs: %+v", contents)
	}
	if !manifestsEqual(contents.Manifest, sealedManifest) {
		t.Fatalf("open manifest differs\nopen=%+v\nseal=%+v", contents.Manifest, sealedManifest)
	}
	inspected, err := Inspect(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !manifestsEqual(inspected, sealedManifest) {
		t.Fatalf("inspect manifest differs: %+v", inspected)
	}
}

func TestFixedManifestContract(t *testing.T) {
	envelope, manifest := sealFixture(t)
	wantRequirements := []string{
		"backup-key-custody",
		"identity-policy-and-public-url",
		"oidc-client-secret-if-configured",
		"tls-or-trusted-proxy-configuration",
		"service-definition-and-trusted-binaries",
		"external-monotonic-backup-catalog",
	}
	if !slicesEqual(manifest.ExternalRequirements, wantRequirements) {
		t.Fatalf("requirements=%q", manifest.ExternalRequirements)
	}
	wantNames := []string{"state.json", "identity-state.json", "master.key", "admin.token"}
	for index, entry := range manifest.Entries {
		if entry.Name != wantNames[index] || entry.Mode != "0600" || len(entry.SHA256) != 64 || strings.ToLower(entry.SHA256) != entry.SHA256 {
			t.Fatalf("entry %d=%+v", index, entry)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			t.Fatalf("entry %d digest: %v", index, err)
		}
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeManifest(canonical)
	if err != nil || !manifestsEqual(decoded, manifest) {
		t.Fatalf("canonical decode=%+v err=%v", decoded, err)
	}
	plaintext, err := decryptEnvelope(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	_, _, bodies := splitTestPlaintext(t, plaintext)
	source := testSource()
	wantMaster := base64.RawURLEncoding.EncodeToString(source.MasterKey) + "\n"
	if string(bodies[2]) != wantMaster || len(bodies[2]) != 44 {
		t.Fatalf("master key body=%q", bodies[2])
	}
	if string(bodies[3]) != string(source.AdminToken)+"\n" {
		t.Fatalf("admin token body is not exact canonical token plus LF")
	}
}

func TestWrongKeyAndKeySeparation(t *testing.T) {
	envelope, _ := sealFixture(t)
	wrong := bytes.Repeat([]byte{0xa6}, 32)
	if _, err := Open(wrong, envelope); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key error=%v", err)
	}
	if _, err := Open(testSource().MasterKey, envelope); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("master key was not separated from backup root: %v", err)
	}
	salt := bytes.Repeat([]byte{0x33}, 32)
	archiveKey, err := hkdf.Key(sha256.New, testRootKey(), salt, backupKDFInfo, 32)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := hkdf.Key(sha256.New, testRootKey(), salt, "mesh-control-secretbox-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(archiveKey, testRootKey()) || bytes.Equal(archiveKey, otherKey) {
		t.Fatal("HKDF did not separate the archive key")
	}
}

func TestEveryEnvelopeByteTamperFails(t *testing.T) {
	envelope, _ := sealFixture(t)
	for index := range envelope {
		tampered := bytes.Clone(envelope)
		tampered[index] ^= 0x01
		if _, err := Open(testRootKey(), tampered); err == nil {
			t.Fatalf("tamper at byte %d was accepted", index)
		}
	}
}

func TestTruncationTrailingAndLengthBounds(t *testing.T) {
	envelope, _ := sealFixture(t)
	for _, length := range []int{0, 1, fixedHeaderSize - 1, fixedHeaderSize, envelopeHeadSize - 1, envelopeHeadSize, len(envelope) - 1} {
		if _, err := Open(testRootKey(), envelope[:length]); err == nil {
			t.Fatalf("truncation at %d accepted", length)
		}
	}
	if _, err := Open(testRootKey(), append(bytes.Clone(envelope), 0)); err == nil {
		t.Fatal("trailing envelope byte accepted")
	}
	for _, declared := range []uint64{0, gcmOverhead - 1, uint64(MaxArchiveSize - envelopeHeadSize + 1), ^uint64(0)} {
		malformed := bytes.Clone(envelope)
		binary.BigEndian.PutUint64(malformed[fixedHeaderSize+saltSize:envelopeHeadSize], declared)
		if _, err := Open(testRootKey(), malformed); err == nil {
			t.Fatalf("declared length %d accepted", declared)
		}
	}
	tooLarge := make([]byte, MaxArchiveSize+1)
	copy(tooLarge, envelope)
	if _, err := Open(testRootKey(), tooLarge); err == nil {
		t.Fatal("oversized envelope accepted")
	}
}

func TestNilAndInvalidCodecInputs(t *testing.T) {
	var codec *Codec
	if _, _, err := codec.Seal(testRootKey(), testSource()); err == nil {
		t.Fatal("nil codec Seal succeeded")
	}
	if _, err := codec.Open(testRootKey(), []byte("archive")); err == nil {
		t.Fatal("nil codec Open succeeded")
	}
	if _, err := codec.Inspect(testRootKey(), []byte("archive")); err == nil {
		t.Fatal("nil codec Inspect succeeded")
	}
	if _, err := NewCodecForTesting(nil, time.Now); err == nil {
		t.Fatal("nil entropy accepted")
	}
	if _, err := NewCodecForTesting(bytes.NewReader(nil), nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	for _, size := range []int{0, 31, 33} {
		if _, _, err := testCodec(t).Seal(make([]byte, size), testSource()); err == nil {
			t.Fatalf("root key size %d accepted", size)
		}
		if _, err := Open(make([]byte, size), make([]byte, envelopeHeadSize+gcmOverhead)); err == nil {
			t.Fatalf("Open root key size %d accepted", size)
		}
	}
}

func TestSourceValidationAndBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Source)
	}{
		{name: "empty state", mutate: func(source *Source) { source.StateJSON = nil }},
		{name: "empty identity", mutate: func(source *Source) { source.IdentityStateJSON = nil }},
		{name: "short master", mutate: func(source *Source) { source.MasterKey = make([]byte, 31) }},
		{name: "long master", mutate: func(source *Source) { source.MasterKey = make([]byte, 33) }},
		{name: "short admin", mutate: func(source *Source) { source.AdminToken = bytes.Repeat([]byte{'a'}, 31) }},
		{name: "long admin", mutate: func(source *Source) { source.AdminToken = bytes.Repeat([]byte{'a'}, 4097) }},
		{name: "space admin", mutate: func(source *Source) { source.AdminToken[4] = ' ' }},
		{name: "control admin", mutate: func(source *Source) { source.AdminToken[4] = '\n' }},
		{name: "unicode admin", mutate: func(source *Source) { source.AdminToken = []byte(strings.Repeat("a", 31) + "é") }},
		{name: "zero version", mutate: func(source *Source) { source.ControlVersion = 0 }},
		{name: "uppercase schema", mutate: func(source *Source) { source.IdentitySchema = "Identity-State-v2" }},
		{name: "long schema", mutate: func(source *Source) { source.IdentitySchema = "a" + strings.Repeat("b", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := testSource()
			test.mutate(&source)
			if _, _, err := testCodec(t).Seal(testRootKey(), source); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	tooLargeState := testSource()
	tooLargeState.StateJSON = make([]byte, MaxControlStateSize+1)
	if _, _, err := testCodec(t).Seal(testRootKey(), tooLargeState); err == nil {
		t.Fatal("oversized control state accepted")
	}
	tooLargeIdentity := testSource()
	tooLargeIdentity.IdentityStateJSON = make([]byte, MaxIdentityStateSize+1)
	if _, _, err := testCodec(t).Seal(testRootKey(), tooLargeIdentity); err == nil {
		t.Fatal("oversized identity state accepted")
	}
	for _, size := range []int{32, 4096} {
		source := testSource()
		source.AdminToken = bytes.Repeat([]byte{'x'}, size)
		envelope, _, err := testCodec(t).Seal(testRootKey(), source)
		if err != nil {
			t.Fatalf("valid admin token size %d: %v", size, err)
		}
		opened, err := Open(testRootKey(), envelope)
		if err != nil || !bytes.Equal(opened.AdminToken, source.AdminToken) {
			t.Fatalf("round-trip admin token size %d: %v", size, err)
		}
	}
}

func TestSealEntropyFailures(t *testing.T) {
	for _, available := range []int{0, 15, 16, 47} {
		codec, err := NewCodecForTesting(bytes.NewReader(make([]byte, available)), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := codec.Seal(testRootKey(), testSource()); err == nil {
			t.Fatalf("entropy length %d accepted", available)
		}
	}
}

func TestRandomNonceWithRepeatableMetadataAndSalt(t *testing.T) {
	entropy := make([]byte, 48)
	clock := func() time.Time { return testCaptureTime }
	firstCodec, _ := NewCodecForTesting(bytes.NewReader(entropy), clock)
	secondCodec, _ := NewCodecForTesting(bytes.NewReader(entropy), clock)
	first, firstManifest, err := firstCodec.Seal(testRootKey(), testSource())
	if err != nil {
		t.Fatal(err)
	}
	second, secondManifest, err := secondCodec.Seal(testRootKey(), testSource())
	if err != nil {
		t.Fatal(err)
	}
	if !manifestsEqual(firstManifest, secondManifest) || !bytes.Equal(first[fixedHeaderSize:envelopeHeadSize], second[fixedHeaderSize:envelopeHeadSize]) {
		t.Fatal("repeatable test metadata did not produce matching authenticated headers")
	}
	if bytes.Equal(first[envelopeHeadSize:], second[envelopeHeadSize:]) {
		t.Fatal("GCM random nonces produced identical ciphertext messages")
	}
	if bytes.Equal(first[envelopeHeadSize:envelopeHeadSize+12], second[envelopeHeadSize:envelopeHeadSize+12]) {
		t.Fatal("GCM prepended identical random nonces")
	}
}

func TestDetachedInputsAndOutputs(t *testing.T) {
	source := testSource()
	want := testSource()
	envelope, manifest, err := testCodec(t).Seal(testRootKey(), source)
	if err != nil {
		t.Fatal(err)
	}
	clear(source.StateJSON)
	clear(source.IdentityStateJSON)
	clear(source.MasterKey)
	clear(source.AdminToken)
	manifest.ExternalRequirements[0] = "mutated"
	manifest.Entries[0].Name = "mutated"

	contents, err := Open(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents.StateJSON, want.StateJSON) || !bytes.Equal(contents.IdentityStateJSON, want.IdentityStateJSON) || !bytes.Equal(contents.MasterKey, want.MasterKey) || !bytes.Equal(contents.AdminToken, want.AdminToken) {
		t.Fatal("Seal retained source or returned aliases")
	}
	originalEnvelope := bytes.Clone(envelope)
	contents.Manifest.ExternalRequirements[0] = "changed"
	contents.Manifest.Entries[0].Name = "changed"
	clear(contents.StateJSON)
	clear(contents.IdentityStateJSON)
	clear(contents.MasterKey)
	clear(contents.AdminToken)
	if !bytes.Equal(envelope, originalEnvelope) {
		t.Fatal("Open outputs alias the envelope")
	}
	inspected, err := Inspect(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Entries[0].Name != "state.json" || inspected.ExternalRequirements[0] != "backup-key-custody" {
		t.Fatalf("manifest aliases escaped: %+v", inspected)
	}
	firstRequirements := FixedExternalRequirements()
	firstRequirements[0] = "changed"
	if FixedExternalRequirements()[0] != "backup-key-custody" {
		t.Fatal("fixed external requirements returned an alias")
	}
}

func TestAuthenticatedMalformedManifestsAreRejected(t *testing.T) {
	envelope, _ := sealFixture(t)
	plaintext, err := decryptEnvelope(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	manifest, raw, bodies := splitTestPlaintext(t, plaintext)

	tests := []struct {
		name string
		raw  func() []byte
	}{
		{name: "noncanonical whitespace", raw: func() []byte { return append([]byte(" "), raw...) }},
		{name: "duplicate", raw: func() []byte {
			return bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schema":"mesh-backup-manifest-v1","schema":`), 1)
		}},
		{name: "unknown", raw: func() []byte { return bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"unknown":true,"schema":`), 1) }},
		{name: "trailing document", raw: func() []byte { return append(bytes.Clone(raw), []byte(`{}`)...) }},
		{name: "bad schema", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.Schema = "mesh-backup-manifest-v2"
			return mustJSON(t, copy)
		}},
		{name: "uppercase id", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.BackupID = strings.ToUpper(copy.BackupID)
			return mustJSON(t, copy)
		}},
		{name: "short id", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.BackupID = copy.BackupID[:31]
			return mustJSON(t, copy)
		}},
		{name: "fractional time", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.CapturedAt = "2026-07-19T21:42:09.000Z"
			return mustJSON(t, copy)
		}},
		{name: "offset time", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.CapturedAt = "2026-07-19T17:42:09-04:00"
			return mustJSON(t, copy)
		}},
		{name: "zero version", raw: func() []byte { copy := cloneManifest(manifest); copy.ControlVersion = 0; return mustJSON(t, copy) }},
		{name: "bad identity schema", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.IdentitySchema = "Identity-State-v2"
			return mustJSON(t, copy)
		}},
		{name: "nil external", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.ExternalRequirements = nil
			return mustJSON(t, copy)
		}},
		{name: "external reordered", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.ExternalRequirements[0], copy.ExternalRequirements[1] = copy.ExternalRequirements[1], copy.ExternalRequirements[0]
			return mustJSON(t, copy)
		}},
		{name: "entry reordered", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.Entries[0], copy.Entries[1] = copy.Entries[1], copy.Entries[0]
			return mustJSON(t, copy)
		}},
		{name: "entry renamed", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.Entries[0].Name = "control.json"
			return mustJSON(t, copy)
		}},
		{name: "entry mode", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.Entries[0].Mode = "0640"
			return mustJSON(t, copy)
		}},
		{name: "uppercase digest", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.Entries[0].SHA256 = strings.ToUpper(copy.Entries[0].SHA256)
			return mustJSON(t, copy)
		}},
		{name: "missing entry", raw: func() []byte {
			copy := cloneManifest(manifest)
			copy.Entries = copy.Entries[:3]
			return mustJSON(t, copy)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forged := sealTestPlaintext(t, joinTestPlaintext(test.raw(), bodies...))
			if _, err := Open(testRootKey(), forged); err == nil {
				t.Fatal("authenticated malformed manifest accepted")
			}
			if _, err := Inspect(testRootKey(), forged); err == nil {
				t.Fatal("Inspect accepted authenticated malformed manifest")
			}
		})
	}
}

func TestManifestJSONNestingDepthIsBounded(t *testing.T) {
	deep := []byte(`{"unknown":` + strings.Repeat("[", maxJSONNestingDepth+2) + `null` + strings.Repeat("]", maxJSONNestingDepth+2) + `}`)
	if err := rejectDuplicateJSONNames(deep); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("deep JSON error=%v", err)
	}

	envelope, _ := sealFixture(t)
	plaintext, err := decryptEnvelope(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	_, _, bodies := splitTestPlaintext(t, plaintext)
	forged := sealTestPlaintext(t, joinTestPlaintext(deep, bodies...))
	if _, err := Open(testRootKey(), forged); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("authenticated deep manifest error=%v", err)
	}
}

func TestAuthenticatedMalformedBodiesAreRejected(t *testing.T) {
	envelope, _ := sealFixture(t)
	plaintext, err := decryptEnvelope(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	manifest, _, bodies := splitTestPlaintext(t, plaintext)

	t.Run("digest mismatch", func(t *testing.T) {
		changed := cloneBodies(bodies)
		changed[0][0] ^= 1
		forged := sealTestPlaintext(t, joinTestPlaintext(mustJSON(t, manifest), changed...))
		if _, err := Open(testRootKey(), forged); err == nil {
			t.Fatal("digest mismatch accepted")
		}
	})
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "master missing newline", body: bytes.Repeat([]byte{'A'}, 44)},
		{name: "master invalid base64", body: append(bytes.Repeat([]byte{'!'}, 43), '\n')},
		{name: "admin control", body: append(append(bytes.Repeat([]byte{'a'}, 31), '\n'), '\n')},
		{name: "admin unicode", body: append([]byte(strings.Repeat("a", 31)+"é"), '\n')},
		{name: "admin space", body: append(append(bytes.Repeat([]byte{'a'}, 31), ' '), '\n')},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedManifest := cloneManifest(manifest)
			changedBodies := cloneBodies(bodies)
			index := 2
			if strings.HasPrefix(test.name, "admin") {
				index = 3
			}
			changedBodies[index] = bytes.Clone(test.body)
			changedManifest.Entries[index].Size = uint64(len(test.body))
			digest := sha256.Sum256(test.body)
			changedManifest.Entries[index].SHA256 = hex.EncodeToString(digest[:])
			forged := sealTestPlaintext(t, joinTestPlaintext(mustJSON(t, changedManifest), changedBodies...))
			if _, err := Open(testRootKey(), forged); err == nil {
				t.Fatal("noncanonical credential body accepted")
			}
		})
	}
}

func TestAuthenticatedPlaintextFramingErrors(t *testing.T) {
	for _, plaintext := range [][]byte{
		nil,
		{0, 0, 0},
		{0, 0, 0, 0},
		{0, 1, 0, 1},
	} {
		if _, err := Open(testRootKey(), sealTestPlaintext(t, plaintext)); err == nil {
			t.Fatalf("plaintext %x accepted", plaintext)
		}
	}
	oversizedManifest := make([]byte, 4)
	binary.BigEndian.PutUint32(oversizedManifest, maxManifestSize+1)
	if _, err := Open(testRootKey(), sealTestPlaintext(t, oversizedManifest)); err == nil {
		t.Fatal("oversized manifest declaration accepted")
	}
	envelope, _ := sealFixture(t)
	plaintext, err := decryptEnvelope(testRootKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	if _, err := Open(testRootKey(), sealTestPlaintext(t, append(bytes.Clone(plaintext), 0))); err == nil {
		t.Fatal("trailing plaintext accepted")
	}
}

func TestOpenRandomInputsNeverPanics(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for iteration := 0; iteration < 5000; iteration++ {
		data := make([]byte, random.IntN(4096))
		for index := range data {
			data[index] = byte(random.Uint32())
		}
		key := make([]byte, random.IntN(65))
		for index := range key {
			key[index] = byte(random.Uint32())
		}
		_, _ = Open(key, data)
		_, _ = Inspect(key, data)
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 32), []byte("not an archive"))
	f.Fuzz(func(t *testing.T, key, envelope []byte) {
		_, _ = Open(key, envelope)
	})
}

func sealTestPlaintext(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	if len(plaintext)+gcmOverhead > MaxArchiveSize-envelopeHeadSize {
		t.Fatal("test plaintext is too large")
	}
	header := make([]byte, envelopeHeadSize)
	copy(header, envelopeMagic[:])
	for index := fixedHeaderSize; index < fixedHeaderSize+saltSize; index++ {
		header[index] = byte(index)
	}
	binary.BigEndian.PutUint64(header[fixedHeaderSize+saltSize:], uint64(len(plaintext)+gcmOverhead))
	aead, key, err := archiveAEAD(testRootKey(), header[fixedHeaderSize:fixedHeaderSize+saltSize])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	ciphertext := aead.Seal(nil, nil, plaintext, header)
	return append(header, ciphertext...)
}

func splitTestPlaintext(t *testing.T, plaintext []byte) (Manifest, []byte, [][]byte) {
	t.Helper()
	manifestLength := int(binary.BigEndian.Uint32(plaintext[:4]))
	raw := bytes.Clone(plaintext[4 : 4+manifestLength])
	manifest, err := decodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	bodies := make([][]byte, 4)
	offset := 4 + manifestLength
	for index, entry := range manifest.Entries {
		end := offset + int(entry.Size)
		bodies[index] = bytes.Clone(plaintext[offset:end])
		offset = end
	}
	return manifest, raw, bodies
}

func joinTestPlaintext(rawManifest []byte, bodies ...[]byte) []byte {
	total := 4 + len(rawManifest)
	for _, body := range bodies {
		total += len(body)
	}
	plaintext := make([]byte, total)
	binary.BigEndian.PutUint32(plaintext[:4], uint32(len(rawManifest)))
	offset := 4 + copy(plaintext[4:], rawManifest)
	for _, body := range bodies {
		offset += copy(plaintext[offset:], body)
	}
	return plaintext
}

func cloneBodies(bodies [][]byte) [][]byte {
	clone := make([][]byte, len(bodies))
	for index := range bodies {
		clone[index] = bytes.Clone(bodies[index])
	}
	return clone
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func manifestsEqual(left, right Manifest) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
