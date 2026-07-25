package main

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func darwinProcArgsFixture(argc int32, executable string, padding int, arguments ...string) []byte {
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, uint32(argc))
	raw = append(raw, executable...)
	raw = append(raw, 0)
	raw = append(raw, make([]byte, padding)...)
	for _, argument := range arguments {
		raw = append(raw, argument...)
		raw = append(raw, 0)
	}
	return append(raw, []byte("UNTRUSTED_ENV=value\x00")...)
}

func TestParseDarwinProcessArgumentsAcceptsExactArgvAndIgnoresEnvironment(t *testing.T) {
	raw := darwinProcArgsFixture(3, "/opt/mesh/releases/v1/bin/nebula", 3,
		"/opt/mesh/current/bin/nebula", "-config", "/private/var/db/mesh-agent/runtime/current/config.yml")
	executable, arguments, err := parseDarwinProcessArguments(raw)
	if err != nil {
		t.Fatal(err)
	}
	if executable != "/opt/mesh/releases/v1/bin/nebula" {
		t.Fatalf("executable = %q", executable)
	}
	want := []string{"/opt/mesh/current/bin/nebula", "-config", "/private/var/db/mesh-agent/runtime/current/config.yml"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %q, want %q", arguments, want)
	}
}

func TestParseDarwinProcessArgumentsRejectsAmbiguity(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "short", raw: []byte{1, 0, 0, 0}, want: "bound"},
		{name: "zero-argc", raw: darwinProcArgsFixture(0, "/opt/mesh/nebula", 0), want: "argc"},
		{name: "relative-executable", raw: darwinProcArgsFixture(1, "nebula", 0, "nebula"), want: "executable"},
		{name: "unclean-executable", raw: darwinProcArgsFixture(1, "/opt/mesh/../mesh/nebula", 0, "/opt/mesh/nebula"), want: "executable"},
		{name: "missing-argv", raw: append([]byte{2, 0, 0, 0}, []byte("/opt/mesh/nebula\x00/opt/mesh/nebula\x00")...), want: "argument 1"},
		{name: "unterminated-executable", raw: append([]byte{1, 0, 0, 0}, []byte("/opt/mesh/nebula")...), want: "executable"},
		{name: "oversized", raw: make([]byte, maxDarwinProcessArgBytes+1), want: "bound"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseDarwinProcessArguments(test.raw)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parse error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestParseDarwinProcessArgumentsTreatsArgcAsTheKernelBoundary(t *testing.T) {
	raw := darwinProcArgsFixture(1, "/opt/mesh/nebula", 0, "/opt/mesh/nebula")
	binary.LittleEndian.PutUint32(raw[:4], 2)
	_, arguments, err := parseDarwinProcessArguments(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/opt/mesh/nebula", "UNTRUSTED_ENV=value"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %q, want %q", arguments, want)
	}
	// The process proof compares this result with the exact launch vector, so a
	// forged or unstable argc cannot authenticate the child.
}

func TestValidateDarwinProcessArgumentsRequiresExactExecutableAndLaunchVector(t *testing.T) {
	resolved := "/opt/mesh/releases/v1/bin/nebula"
	expected := []string{
		"/opt/mesh/current/bin/nebula", "-config",
		"/private/var/db/mesh-agent/runtime/current/config.yml",
	}
	valid := darwinProcArgsFixture(3, resolved, 2, expected...)
	if err := validateDarwinProcessArguments(valid, resolved, expected); err != nil {
		t.Fatal(err)
	}

	wrongExecutable := darwinProcArgsFixture(3, "/tmp/nebula", 0, expected...)
	if err := validateDarwinProcessArguments(wrongExecutable, resolved, expected); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("wrong executable validation error = %v", err)
	}
	wgArgs := darwinProcArgsFixture(3, resolved, 0,
		expected[0], "-config", "/tmp/config.yml")
	if err := validateDarwinProcessArguments(wgArgs, resolved, expected); err == nil || !strings.Contains(err.Error(), "argument vector") {
		t.Fatalf("wrong argument validation error = %v", err)
	}
	inflatedArgc := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(inflatedArgc[:4], 4)
	if err := validateDarwinProcessArguments(inflatedArgc, resolved, expected); err == nil || !strings.Contains(err.Error(), "argument vector") {
		t.Fatalf("inflated argc validation error = %v", err)
	}
}
