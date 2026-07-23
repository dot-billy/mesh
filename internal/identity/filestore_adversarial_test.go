//go:build !windows

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreRejectsSymlinksAndWeakModes(t *testing.T) {
	t.Run("symlink directory component", func(t *testing.T) {
		base := t.TempDir()
		realDirectory := filepath.Join(base, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(realDirectory, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(filepath.Join(link, "identity.json"), newTestSealer(t)); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("symlink directory error = %v", err)
		}
	})
	t.Run("symlink prefix has no directory creation side effect", func(t *testing.T) {
		base := t.TempDir()
		target := t.TempDir()
		link := filepath.Join(base, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(filepath.Join(link, "must-not-exist", "identity.json"), newTestSealer(t)); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("symlink directory error = %v", err)
		}
		if _, err := os.Lstat(filepath.Join(target, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("identity open mutated symlink target: %v", err)
		}
	})
	t.Run("symlink state", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte(`{"schema":"identity-state-v1","login_attempts":[],"sessions":[],"break_glass_codes":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "identity.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("symlink identity state was accepted")
		}
	})
	t.Run("weak directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "weak")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(filepath.Join(directory, "identity.json"), newTestSealer(t)); err == nil {
			t.Fatal("group-readable identity directory was accepted")
		}
	})
	t.Run("weak state", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("group-readable identity state was accepted")
		}
	})
}

func TestFileStoreRejectsUnknownTrailingOversizedAndRelativeState(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "unknown field", raw: []byte(`{"schema":"identity-state-v1","login_attempts":[],"sessions":[],"break_glass_codes":[],"unknown":true}`)},
		{name: "trailing data", raw: []byte(`{"schema":"identity-state-v1","login_attempts":[],"sessions":[],"break_glass_codes":[]} {}`)},
		{name: "wrong schema", raw: []byte(`{"schema":"identity-state-v2","login_attempts":[],"sessions":[],"break_glass_codes":[]}`)},
		{name: "null array", raw: []byte(`{"schema":"identity-state-v1","login_attempts":null,"sessions":[],"break_glass_codes":[]}`)},
		{name: "duplicate key", raw: []byte(`{"schema":"identity-state-v1","schema":"identity-state-v1","login_attempts":[],"sessions":[],"break_glass_codes":[]}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.json")
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
				t.Fatal("malformed identity state was accepted")
			}
		})
	}
	oversized := filepath.Join(t.TempDir(), "identity.json")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxIdentityStateSize + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err := OpenFileStore(oversized, newTestSealer(t)); err == nil {
		t.Fatal("oversized identity state was accepted")
	}
	if _, err := OpenFileStore("relative/identity.json", newTestSealer(t)); err == nil {
		t.Fatal("relative identity state path was accepted")
	}
}

func TestFileStoreRejectsDuplicateCredentialHashesAndTamperedOIDCPayload(t *testing.T) {
	t.Run("duplicate hash", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		now := identityTestTime()
		first, err := store.CreateSession(context.Background(), testCreateSessionInput(t, "session_1", now))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		state := dumpIdentityState(t, path)
		duplicate := cloneSession(first)
		duplicate.ID = "session_2"
		duplicate.CSRFHash, _ = HashOpaqueToken(mustToken(t))
		state.Sessions = append(state.Sessions, duplicate)
		writePrivateJSON(t, path, state)
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil || !strings.Contains(err.Error(), "reuses a credential hash") {
			t.Fatalf("duplicate credential error = %v", err)
		}
	})
	t.Run("tampered sealed transaction", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		store := openTestStore(t, path)
		now := identityTestTime()
		input := LoginAttemptInput{ID: "login_1", TransactionToken: mustToken(t), StateToken: mustToken(t), Nonce: mustToken(t), PKCEVerifier: mustToken(t), ReturnPath: "/", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
		if err := store.CreateLoginAttempt(context.Background(), input); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		state := dumpIdentityState(t, path)
		state.LoginAttempts[0].SealedOIDCPayload = base64LikeTamper(state.LoginAttempts[0].SealedOIDCPayload)
		writePrivateJSON(t, path, state)
		if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
			t.Fatal("tampered OIDC transaction was accepted")
		}
	})
}

func TestFileStoreRejectsRawOrMalformedNestedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	state := map[string]any{
		"schema":            identityStateSchema,
		"login_attempts":    []any{},
		"sessions":          []any{map[string]any{"id": "session_1", "raw_token": mustToken(t)}},
		"break_glass_codes": []any{},
	}
	writePrivateJSON(t, path, state)
	if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
		t.Fatal("unknown raw credential field was accepted")
	}
}

func TestFileStoreRecordBoundsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	state := identityState{Schema: identityStateSchema, LoginAttempts: make([]persistedLoginAttempt, maxLoginAttempts+1), Sessions: []Session{}, BreakGlassCodes: []BreakGlassCode{}, Audit: []IdentityAuditEvent{}}
	writePrivateJSON(t, path, state)
	if _, err := OpenFileStore(path, newTestSealer(t)); err == nil || !strings.Contains(err.Error(), "record-count") {
		t.Fatalf("record bound error = %v", err)
	}
}

func TestFileStorePersistsStrictJSONWithoutRawCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	store := openTestStore(t, path)
	now := identityTestTime()
	input := testCreateSessionInput(t, "session_json", now)
	if _, err := store.CreateSession(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	code := BreakGlassCodeInput{ID: "bg_json", Token: mustToken(t), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateBreakGlassCode(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{input.Token, input.CSRFToken, code.Token} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw credential leaked to strict JSON")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decoded identityState
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != identityStateSchema || len(decoded.Sessions) != 1 || len(decoded.BreakGlassCodes) != 1 {
		t.Fatalf("persisted state = %#v", decoded)
	}
}

func base64LikeTamper(value string) string {
	if value == "" {
		return "A"
	}
	replacement := byte('A')
	if value[0] == replacement {
		replacement = 'B'
	}
	return string(replacement) + value[1:]
}

func TestFileStoreRejectsNoncanonicalTimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	now := identityTestTime()
	principal, err := NewLegacyPrincipal(now)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, _ := HashOpaqueToken(mustToken(t))
	csrfHash, _ := HashOpaqueToken(mustToken(t))
	local := time.FixedZone("offset", 3600)
	session := Session{
		ID: "session_time", TokenHash: tokenHash, CSRFHash: csrfHash, Principal: principal,
		PolicyFingerprint: strings.Repeat("a", 64), AuthMethod: "legacy_token", CreatedAt: now.In(local), LastSeenAt: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), Version: 1,
	}
	writePrivateJSON(t, path, identityState{Schema: identityStateSchema, LoginAttempts: []persistedLoginAttempt{}, Sessions: []Session{session}, BreakGlassCodes: []BreakGlassCode{}, Audit: []IdentityAuditEvent{}})
	if _, err := OpenFileStore(path, newTestSealer(t)); err == nil {
		t.Fatal("non-UTC persisted timestamp was accepted")
	}
}
