package release

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRootUpdateCanonicalRoundTripAndBounds(t *testing.T) {
	_, updates, _ := testRootChain(t, 1, false)
	value, err := ParseRootUpdate(updates[0])
	if err != nil {
		t.Fatal(err)
	}
	originalFirst := append([]byte(nil), value.Signatures[0]...)
	raw, err := EncodeRootUpdate(RootUpdate{
		RootManifest: append([]byte(nil), value.RootManifest...),
		Signatures:   reverseByteSlicesForTest(value.Signatures),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, updates[0]) {
		t.Fatalf("signature order changed canonical update\nwant=%s\n got=%s", updates[0], raw)
	}
	if raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		t.Fatalf("root update is not compact JSON plus LF: %q", raw)
	}
	value.RootManifest[0] ^= 1
	value.Signatures[0][0] ^= 1
	again, err := ParseRootUpdate(updates[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Signatures[0], originalFirst) {
		t.Fatal("caller mutation poisoned root update parsing")
	}

	duplicate := RootUpdate{RootManifest: again.RootManifest, Signatures: [][]byte{again.Signatures[0], again.Signatures[0]}}
	if _, err := EncodeRootUpdate(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate signatures returned %v", err)
	}
	if _, err := EncodeRootUpdate(RootUpdate{RootManifest: again.RootManifest}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("empty signatures returned %v", err)
	}
	tooMany := make([][]byte, MaxRootTransitionSignatures+1)
	for index := range tooMany {
		tooMany[index] = []byte(`{}`)
	}
	if _, err := EncodeRootUpdate(RootUpdate{RootManifest: again.RootManifest, Signatures: tooMany}); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("signature count returned %v", err)
	}
	oversize := bytes.Repeat([]byte{'x'}, MaxRootUpdateSize+1)
	if _, err := ParseRootUpdate(oversize); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversize update returned %v", err)
	}
}

func TestRootUpdateRejectsAmbiguousOrNoncanonicalDocuments(t *testing.T) {
	_, updates, _ := testRootChain(t, 1, false)
	raw := updates[0]
	mutations := map[string][]byte{
		"unknown":         bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"duplicate":       bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"mesh-release-root-update-v1","schema":`), 1),
		"trailing":        append(append([]byte(nil), raw...), []byte(`{}`)...),
		"missing newline": bytes.TrimSuffix(raw, []byte{'\n'}),
		"extra newline":   append(append([]byte(nil), raw...), '\n'),
		"invalid utf8":    {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	}
	var encoded map[string]any
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatal(err)
	}
	encoded["root_manifest"] = base64.URLEncoding.EncodeToString([]byte("padded"))
	mutations["padded base64"] = mustJSONForRootUpdateTest(t, encoded)
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRootUpdate(mutated); err == nil {
				t.Fatal("ambiguous root update parsed")
			}
		})
	}
}

func TestEvaluateRootChainAppliesSequentialUpdatesAndOldPrefix(t *testing.T) {
	initial, updates, roots := testRootChain(t, 2, false)
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	result, err := EvaluateRootChain(initial, updates, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Root.Document.Version != 3 || len(result.Applied) != 2 {
		t.Fatalf("unexpected chain result: %+v", result)
	}
	fromSecond, err := EvaluateRootChain(roots[0], updates, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if fromSecond.Root.Document.Version != 3 || len(fromSecond.Applied) != 1 {
		t.Fatalf("old-prefix result: %+v", fromSecond)
	}
	current, err := EvaluateRootChain(roots[1], updates, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if current.Root.Document.Version != 3 || len(current.Applied) != 0 {
		t.Fatalf("current-prefix result: %+v", current)
	}
}

func TestEvaluateRootChainRejectsGapOrderEquivocationAndCount(t *testing.T) {
	initial, updates, roots := testRootChain(t, 2, false)
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if _, err := EvaluateRootChain(initial, updates[1:], now, 0); err == nil || !strings.Contains(err.Error(), "successor") {
		t.Fatalf("gap returned %v", err)
	}
	if _, err := EvaluateRootChain(initial, [][]byte{updates[1], updates[0]}, now, 0); err == nil || !strings.Contains(err.Error(), "increasing") {
		t.Fatalf("reordered chain returned %v", err)
	}
	if _, err := EvaluateRootChain(initial, make([][]byte, MaxRootUpdatesPerInput+1), now, 0); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("excess chain returned %v", err)
	}

	current := roots[0]
	different := cloneRootForTest(t, current.Document)
	different.MinimumReleaseSequence++
	differentRaw, err := EncodeRoot(different)
	if err != nil {
		t.Fatal(err)
	}
	update := RootUpdate{RootManifest: differentRaw, Signatures: ParseRootUpdateForTest(t, updates[0]).Signatures}
	differentUpdate, err := EncodeRootUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateRootChain(current, [][]byte{differentUpdate}, now, 0); err == nil || !strings.Contains(err.Error(), "equivocation") {
		t.Fatalf("same-version difference returned %v", err)
	}
}

func TestEvaluateRootChainAllowsExpiredIntermediateButRequiresCurrentFinal(t *testing.T) {
	initial, updates, roots := testRootChain(t, 2, true)
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if !roots[0].ExpiresAt.Before(now) {
		t.Fatal("fixture intermediate root is not expired")
	}
	result, err := EvaluateRootChain(initial, updates, now, 5*time.Minute)
	if err != nil || result.Root.Document.Version != 3 {
		t.Fatalf("expired intermediate catch-up returned %+v, %v", result, err)
	}
	if _, err := EvaluateRootChain(initial, updates[:1], now, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired final root returned %v", err)
	}
}

func testRootChain(t *testing.T, count int, expireIntermediate bool) (ParsedRoot, [][]byte, []ParsedRoot) {
	t.Helper()
	document, rootPrivate, _ := testRootAuthority(t)
	initialRaw, err := EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ParseRoot(initialRaw)
	if err != nil {
		t.Fatal(err)
	}
	initial := current
	updates := make([][]byte, 0, count)
	roots := make([]ParsedRoot, 0, count)
	for index := 0; index < count; index++ {
		candidate, _, _ := testSuccessorRoot(t, current.Document, false, false)
		issued := time.Date(2026, 7, 21+index, 12, 0, 0, 0, time.UTC)
		candidate.IssuedAt = issued.Format(time.RFC3339)
		candidate.ExpiresAt = issued.Add(48 * time.Hour).Format(time.RFC3339)
		if expireIntermediate && index == 0 {
			candidate.ExpiresAt = issued.Add(24 * time.Hour).Format(time.RFC3339)
		}
		candidateRaw, err := EncodeRoot(candidate)
		if err != nil {
			t.Fatal(err)
		}
		signatures := signWithKeys(t, RootManifestKind, candidateRaw, rootPrivate)
		updateRaw, err := EncodeRootUpdate(RootUpdate{RootManifest: candidateRaw, Signatures: signatures})
		if err != nil {
			t.Fatal(err)
		}
		transition, err := VerifyRootTransition(current, candidateRaw, signatures)
		if err != nil {
			t.Fatal(err)
		}
		current = transition.Root
		updates = append(updates, updateRaw)
		roots = append(roots, current)
	}
	return initial, updates, roots
}

func reverseByteSlicesForTest(source [][]byte) [][]byte {
	result := make([][]byte, len(source))
	for index := range source {
		result[len(source)-1-index] = append([]byte(nil), source[index]...)
	}
	return result
}

func mustJSONForRootUpdateTest(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func ParseRootUpdateForTest(t *testing.T, raw []byte) RootUpdate {
	t.Helper()
	value, err := ParseRootUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
