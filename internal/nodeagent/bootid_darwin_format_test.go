package nodeagent

import (
	"encoding/binary"
	"testing"
)

func TestParseDarwinBootTimeAcceptsExactNativeTimeval(t *testing.T) {
	raw := darwinBootTimeFixture(1_752_883_200, 456_789)
	want := "darwin-boot-1752883200-456789"
	for _, candidate := range [][]byte{raw, raw[:len(raw)-1]} {
		if got, ok := parseDarwinBootTime(candidate); !ok || got != want {
			t.Fatalf("parseDarwinBootTime(%d bytes) = %q, %t; want %q, true", len(candidate), got, ok, want)
		}
	}
}

func TestParseDarwinBootTimeRejectsMalformedKernelValues(t *testing.T) {
	valid := darwinBootTimeFixture(1_752_883_200, 456_789)
	tests := map[string][]byte{
		"empty":            nil,
		"short":            valid[:14],
		"long":             append(append([]byte(nil), valid...), 0),
		"zero-seconds":     darwinBootTimeFixture(0, 1),
		"negative-seconds": darwinBootTimeFixture(-1, 1),
		"usec-overflow":    darwinBootTimeFixture(1, 1_000_000),
		"negative-usec":    darwinBootTimeFixture(1, -1),
	}
	badPadding := append([]byte(nil), valid...)
	badPadding[15] = 1
	tests["nonzero-padding"] = badPadding
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if got, ok := parseDarwinBootTime(raw); ok || got != "" {
				t.Fatalf("malformed Darwin boottime accepted as %q", got)
			}
		})
	}
}

func darwinBootTimeFixture(seconds int64, microseconds int32) []byte {
	raw := make([]byte, darwinTimevalSize)
	binary.LittleEndian.PutUint64(raw[0:8], uint64(seconds))
	binary.LittleEndian.PutUint32(raw[8:12], uint32(microseconds))
	return raw
}
