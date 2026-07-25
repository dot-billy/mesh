package runtimeobserver

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const sharedFixtureNonce = "0123456789abcdef0123456789abcdef"

func TestSharedNebulaObserverProtocolFixtures(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate shared fixtures")
	}
	fixtureDirectory := filepath.Join(filepath.Dir(sourceFile), "..", "..", "third_party", "nebula-observer", "fixtures")

	validRequest, err := os.ReadFile(filepath.Join(fixtureDirectory, "request-valid.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeRequestLine(validRequest)
	if err != nil || request.Nonce != sharedFixtureNonce {
		t.Fatalf("valid request = %#v, %v", request, err)
	}
	invalidRequests, err := filepath.Glob(filepath.Join(fixtureDirectory, "request-invalid-*.jsonl"))
	if err != nil || len(invalidRequests) == 0 {
		t.Fatalf("invalid request fixtures = %v, %v", invalidRequests, err)
	}
	for _, path := range invalidRequests {
		line, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequestLine(line); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s error = %v, want ErrProtocol", filepath.Base(path), err)
		}
	}

	validation, err := NewValidationContext(netip.MustParsePrefix("10.42.0.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	validSnapshot, err := os.ReadFile(filepath.Join(fixtureDirectory, "snapshot-empty-valid.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshotLine(validSnapshot, sharedFixtureNonce, validation); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	invalidSnapshots, err := filepath.Glob(filepath.Join(fixtureDirectory, "snapshot-invalid-*.jsonl"))
	if err != nil || len(invalidSnapshots) == 0 {
		t.Fatalf("invalid snapshot fixtures = %v, %v", invalidSnapshots, err)
	}
	for _, path := range invalidSnapshots {
		line, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSnapshotLine(line, sharedFixtureNonce, validation); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s error = %v, want ErrProtocol", filepath.Base(path), err)
		}
	}
}
