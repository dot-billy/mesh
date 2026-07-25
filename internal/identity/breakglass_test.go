package identity

import (
	"strings"
	"testing"
)

func TestBreakGlassCredentialRoundTripAndStrictParsing(t *testing.T) {
	credential, combined, err := NewBreakGlassCredential()
	if err != nil {
		t.Fatal(err)
	}
	if combined == "" || combined != credential.String() || !strings.HasPrefix(combined, BreakGlassCredentialPrefix+".bg_") {
		t.Fatalf("generated credential = %q, %#v", combined, credential)
	}
	parsed, err := ParseBreakGlassCredential(combined)
	if err != nil || parsed != credential {
		t.Fatalf("parsed credential = %#v, %v", parsed, err)
	}

	invalid := []string{
		"", " " + combined, combined + " ", strings.ToUpper(BreakGlassCredentialPrefix) + strings.TrimPrefix(combined, BreakGlassCredentialPrefix),
		strings.Replace(combined, ".bg_", ".", 1), combined + ".extra",
		BreakGlassCredentialPrefix + ".bg_short." + credential.Token,
		BreakGlassCredentialPrefix + "." + credential.ID + ".short",
	}
	for _, candidate := range invalid {
		if parsed, err := ParseBreakGlassCredential(candidate); err == nil || parsed != (BreakGlassCredential{}) {
			t.Fatalf("invalid credential %q parsed as %#v, %v", candidate, parsed, err)
		}
	}
}
