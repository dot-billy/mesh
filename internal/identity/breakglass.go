package identity

import (
	"errors"
	"strings"
)

const BreakGlassCredentialPrefix = "mesh-bg-v1"

// BreakGlassCredential is split so the code ID can be used for indexed lookup
// while only the hash of Token is retained by the identity store.
type BreakGlassCredential struct {
	ID    string
	Token string
}

// NewBreakGlassCredential is primarily useful to non-browser clients and
// tests. The browser management flow generates both random values locally so
// the complete credential is never returned by the server.
func NewBreakGlassCredential() (BreakGlassCredential, string, error) {
	idToken, err := NewOpaqueToken()
	if err != nil {
		return BreakGlassCredential{}, "", err
	}
	secret, err := NewOpaqueToken()
	if err != nil {
		return BreakGlassCredential{}, "", err
	}
	credential := BreakGlassCredential{ID: "bg_" + idToken, Token: secret}
	return credential, credential.String(), nil
}

func ParseBreakGlassCredential(input string) (BreakGlassCredential, error) {
	parts := strings.Split(input, ".")
	if len(parts) != 3 || parts[0] != BreakGlassCredentialPrefix || !strings.HasPrefix(parts[1], "bg_") {
		return BreakGlassCredential{}, errors.New("invalid break-glass credential")
	}
	idToken := strings.TrimPrefix(parts[1], "bg_")
	if !ValidOpaqueToken(idToken) || !ValidOpaqueToken(parts[2]) {
		return BreakGlassCredential{}, errors.New("invalid break-glass credential")
	}
	return BreakGlassCredential{ID: parts[1], Token: parts[2]}, nil
}

func (c BreakGlassCredential) String() string {
	if !strings.HasPrefix(c.ID, "bg_") || !ValidOpaqueToken(strings.TrimPrefix(c.ID, "bg_")) || !ValidOpaqueToken(c.Token) {
		return ""
	}
	return BreakGlassCredentialPrefix + "." + c.ID + "." + c.Token
}
