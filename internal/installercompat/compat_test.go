package installercompat

import (
	"encoding/base64"
	"testing"
)

func TestCurrentFrameIsCanonicalAndMatchesImplementation(t *testing.T) {
	want := Supported()
	encoded, err := EncodeIdentity(want)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != currentFrame || Identity != currentFrame {
		t.Fatal("compiled installer-state compatibility frame drifted from its canonical source contract")
	}
	got, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if got != want || !got.Reads(2) || !got.Reads(3) || got.Reads(1) || got.Reads(4) {
		t.Fatalf("unexpected current compatibility: %+v", got)
	}
}

func TestParseIdentityRejectsAmbiguousAndInvalidContracts(t *testing.T) {
	valid, err := EncodeIdentity(Supported())
	if err != nil {
		t.Fatal(err)
	}
	rawFrame := func(raw string) string {
		return FramePrefix + base64.RawURLEncoding.EncodeToString([]byte(raw)) + FrameSuffix
	}
	cases := []string{
		"", "unframed", valid + "x",
		rawFrame(`{"schema":"mesh-installer-state-compatibility-v1","read_min":2,"read_min":2,"read_max":3,"write_version":3}`),
		rawFrame(`{"schema":"mesh-installer-state-compatibility-v1","read_min":2,"read_max":3,"write_version":3,"extra":true}`),
		rawFrame(`{"read_min":2,"schema":"mesh-installer-state-compatibility-v1","read_max":3,"write_version":3}`),
		rawFrame(`{"schema":"mesh-installer-state-compatibility-v1","read_min":4,"read_max":3,"write_version":3}`),
		rawFrame(`{"schema":"mesh-installer-state-compatibility-v1","read_min":2,"read_max":3,"write_version":4}`),
	}
	for index, value := range cases {
		if _, err := ParseIdentity(value); err == nil {
			t.Fatalf("case %d accepted invalid compatibility", index)
		}
	}

	previous := Identity
	different := Supported()
	different.ReadMaximum = 4
	Identity, err = EncodeIdentity(different)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Identity = previous })
	if _, err := Current(); err == nil {
		t.Fatal("runtime accepted a frame that differs from its implementation")
	}
}
