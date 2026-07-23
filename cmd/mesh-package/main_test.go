package main

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"mesh/internal/linuxbundle"
	"mesh/internal/verifierbundle"
	"mesh/internal/windowsbundle"
)

func TestBuildLinuxCommand(t *testing.T) {
	var captured linuxbundle.BuildOptions
	builder := func(options linuxbundle.BuildOptions) (linuxbundle.BuildResult, error) {
		captured = options
		return linuxbundle.BuildResult{
			OutputPath: "/tmp/mesh.tar", Size: 42, SHA256: strings.Repeat("a", 64),
			PackageJSONSHA256: strings.Repeat("b", 64),
			Package:           linuxbundle.Package{Target: linuxbundle.Target{OS: "linux", Arch: "amd64"}},
		}, nil
	}
	args := []string{
		"build-linux", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--mesh-install", "/in/mesh-install", "--meshctl", "/in/meshctl",
		"--nebula-dir", "/in/nebula", "--output", "/tmp/mesh.tar",
	}
	var output bytes.Buffer
	if err := run(args, &output, builder); err != nil {
		t.Fatal(err)
	}
	want := linuxbundle.BuildOptions{
		Version: "1.2.3", Commit: strings.Repeat("c", 40), SourceDateEpoch: 1752883200,
		SecurityFloor: 2, Arch: "amd64", MeshInstallPath: "/in/mesh-install",
		MeshctlPath: "/in/meshctl", NebulaDirectory: "/in/nebula", OutputPath: "/tmp/mesh.tar",
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("builder options = %+v, want %+v", captured, want)
	}
	if !strings.Contains(output.String(), "No software was installed or started") || !strings.Contains(output.String(), strings.Repeat("b", 64)) {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestBuildLinuxCommandRejectsInvalidInputs(t *testing.T) {
	valid := []string{
		"build-linux", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--mesh-install", "/in/mesh-install", "--meshctl", "/in/meshctl",
		"--nebula-dir", "/in/nebula", "--output", "/tmp/mesh.tar",
	}
	called := false
	builder := func(linuxbundle.BuildOptions) (linuxbundle.BuildResult, error) {
		called = true
		return linuxbundle.BuildResult{}, nil
	}
	cases := [][]string{
		nil,
		{"other"},
		valid[:len(valid)-2],
		append(append([]string(nil), valid...), "extra"),
		replaceArgument(valid, "1752883200", "01752883200"),
		replaceArgument(valid, "2", "0"),
	}
	for _, args := range cases {
		called = false
		if err := run(args, io.Discard, builder); err == nil {
			t.Fatalf("invalid args accepted: %v", args)
		}
		if called {
			t.Fatalf("builder called for invalid args: %v", args)
		}
	}
}

func TestBuildLinuxCommandPropagatesBuilderFailure(t *testing.T) {
	args := []string{
		"build-linux", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--mesh-install", "a", "--meshctl", "b", "--nebula-dir", "c", "--output", "d",
	}
	want := errors.New("build failed")
	err := run(args, io.Discard, func(linuxbundle.BuildOptions) (linuxbundle.BuildResult, error) {
		return linuxbundle.BuildResult{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestBuildWindowsCommand(t *testing.T) {
	var captured windowsbundle.BuildOptions
	builder := func(options windowsbundle.BuildOptions) (windowsbundle.BuildResult, error) {
		captured = options
		return windowsbundle.BuildResult{
			OutputPath: "/tmp/mesh-windows.tar", Size: 84, SHA256: strings.Repeat("d", 64),
			PackageJSONSHA256: strings.Repeat("e", 64),
			Package:           windowsbundle.Package{Target: windowsbundle.Target{OS: "windows", Arch: "arm64"}},
		}, nil
	}
	args := []string{
		"build-windows", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "arm64",
		"--meshctl", "/in/meshctl.exe", "--nebula-dir", "/in/nebula", "--nebula-runtime-dir", "/in/runtime", "--output", "/tmp/mesh-windows.tar",
	}
	var output bytes.Buffer
	if err := runWithBuilders(args, &output, nil, builder); err != nil {
		t.Fatal(err)
	}
	want := windowsbundle.BuildOptions{
		Version: "1.2.3", Commit: strings.Repeat("c", 40), SourceDateEpoch: 1752883200,
		SecurityFloor: 2, Arch: "arm64", MeshctlPath: "/in/meshctl.exe",
		NebulaDirectory: "/in/nebula", NebulaRuntimeDirectory: "/in/runtime", OutputPath: "/tmp/mesh-windows.tar",
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("builder options = %+v, want %+v", captured, want)
	}
	message := output.String()
	for _, exactBoundary := range []string{
		"Windows node staging bundle", "No software was installed",
		"no service was created or started", "no DACL was applied", strings.Repeat("e", 64),
	} {
		if !strings.Contains(message, exactBoundary) {
			t.Fatalf("output %q does not contain %q", message, exactBoundary)
		}
	}
}

func TestBuildWindowsCommandRejectsInvalidInputs(t *testing.T) {
	valid := []string{
		"build-windows", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--meshctl", "/in/meshctl.exe", "--nebula-dir", "/in/nebula", "--nebula-runtime-dir", "/in/runtime", "--output", "/tmp/mesh-windows.tar",
	}
	called := false
	builder := func(windowsbundle.BuildOptions) (windowsbundle.BuildResult, error) {
		called = true
		return windowsbundle.BuildResult{}, nil
	}
	cases := [][]string{
		valid[:len(valid)-2],
		append(append([]string(nil), valid...), "extra"),
		replaceArgument(valid, "1752883200", "01752883200"),
		replaceArgument(valid, "2", "0"),
		append(append([]string(nil), valid...), "--mesh-install", "/in/mesh-install.exe"),
	}
	for _, args := range cases {
		called = false
		if err := runWithBuilders(args, io.Discard, nil, builder); err == nil {
			t.Fatalf("invalid args accepted: %v", args)
		}
		if called {
			t.Fatalf("builder called for invalid args: %v", args)
		}
	}
	if err := runWithBuilders(valid, io.Discard, nil, nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing Windows builder error = %v", err)
	}
}

func TestBuildWindowsCommandPropagatesBuilderFailure(t *testing.T) {
	args := []string{
		"build-windows", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--meshctl", "a.exe", "--nebula-dir", "b", "--nebula-runtime-dir", "runtime", "--output", "c.tar",
	}
	want := errors.New("Windows build failed")
	err := runWithBuilders(args, io.Discard, nil, func(windowsbundle.BuildOptions) (windowsbundle.BuildResult, error) {
		return windowsbundle.BuildResult{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestBuildWindowsSignedCommand(t *testing.T) {
	var captured windowsbundle.SignedBuildOptions
	builder := func(options windowsbundle.SignedBuildOptions) (windowsbundle.BuildResult, error) {
		captured = options
		return windowsbundle.BuildResult{
			OutputPath: "/out/final.tar", Size: 123, SHA256: strings.Repeat("a", 64),
			PackageJSONSHA256: strings.Repeat("b", 64),
			Package:           windowsbundle.Package{Target: windowsbundle.Target{OS: "windows", Arch: "amd64"}},
		}, nil
	}
	args := []string{
		"build-windows-signed", "--unsigned-bundle", "/in/unsigned.tar",
		"--meshctl", "/in/meshctl.exe", "--nebula", "/in/nebula.exe", "--nebula-cert", "/in/nebula-cert.exe",
		"--authenticode-receipt", "/in/auth.json", "--expected-authenticode-policy-sha256", strings.Repeat("c", 64),
		"--output", "/out/final.tar",
	}
	var output bytes.Buffer
	if err := buildWindowsSigned(args, &output, builder); err != nil {
		t.Fatal(err)
	}
	want := windowsbundle.SignedBuildOptions{
		UnsignedBundlePath: "/in/unsigned.tar", SignedMeshctlPath: "/in/meshctl.exe",
		SignedNebulaPath: "/in/nebula.exe", SignedNebulaCertPath: "/in/nebula-cert.exe",
		AuthenticodeReceiptPath: "/in/auth.json", ExpectedPolicySHA256: strings.Repeat("c", 64),
		OutputPath: "/out/final.tar",
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("builder options = %+v, want %+v", captured, want)
	}
	for _, boundary := range []string{"final signed Windows node bundle", "native Authenticode receipt", "no software was installed", strings.Repeat("b", 64)} {
		if !strings.Contains(output.String(), boundary) {
			t.Fatalf("output %q does not contain %q", output.String(), boundary)
		}
	}
}

func TestBuildWindowsSignedCommandRejectsIncompleteInput(t *testing.T) {
	called := false
	builder := func(windowsbundle.SignedBuildOptions) (windowsbundle.BuildResult, error) {
		called = true
		return windowsbundle.BuildResult{}, nil
	}
	err := buildWindowsSigned([]string{"build-windows-signed", "--unsigned-bundle", "/in/unsigned.tar"}, io.Discard, builder)
	if err == nil || !strings.Contains(err.Error(), "--meshctl is required") {
		t.Fatalf("incomplete input error = %v", err)
	}
	if called {
		t.Fatal("builder called for incomplete input")
	}
}

func TestBuildBootstrapVerifierCommand(t *testing.T) {
	var captured verifierbundle.BuildOptions
	builder := func(options verifierbundle.BuildOptions) (verifierbundle.BuildResult, error) {
		captured = options
		return verifierbundle.BuildResult{
			OutputPath: "/tmp/verifier.tar", Size: 8192, SHA256: strings.Repeat("f", 64),
			PackageJSONSHA256: strings.Repeat("e", 64),
			Package:           verifierbundle.Package{Target: verifierbundle.Target{OS: "linux", Arch: "amd64"}},
		}, nil
	}
	args := []string{
		"build-bootstrap-verifier", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--verifier", "/in/mesh-bootstrap-verify", "--output", "/tmp/verifier.tar",
	}
	var output bytes.Buffer
	if err := runWithAllBuilders(args, &output, nil, nil, builder); err != nil {
		t.Fatal(err)
	}
	want := verifierbundle.BuildOptions{
		Version: "1.2.3", Commit: strings.Repeat("c", 40), SourceDateEpoch: 1752883200,
		SecurityFloor: 2, OS: "linux", Arch: "amd64", VerifierPath: "/in/mesh-bootstrap-verify", OutputPath: "/tmp/verifier.tar",
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("builder options = %+v, want %+v", captured, want)
	}
	for _, text := range []string{"standalone bootstrap verifier", "not signed, installed, or trusted", "independent operator channel", strings.Repeat("e", 64)} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("output %q does not contain %q", output.String(), text)
		}
	}
}

func TestBuildBootstrapVerifierCommandRejectsInvalidInputs(t *testing.T) {
	valid := []string{
		"build-bootstrap-verifier", "--version", "1.2.3", "--commit", strings.Repeat("c", 40),
		"--source-date-epoch", "1752883200", "--security-floor", "2", "--arch", "amd64",
		"--verifier", "/in/verifier", "--output", "/tmp/verifier.tar",
	}
	called := false
	builder := func(verifierbundle.BuildOptions) (verifierbundle.BuildResult, error) {
		called = true
		return verifierbundle.BuildResult{}, nil
	}
	for _, args := range [][]string{
		valid[:len(valid)-2],
		append(append([]string(nil), valid...), "extra"),
		replaceArgument(valid, "1752883200", "01752883200"),
		replaceArgument(valid, "2", "0"),
	} {
		called = false
		if err := runWithAllBuilders(args, io.Discard, nil, nil, builder); err == nil {
			t.Fatalf("invalid args accepted: %v", args)
		}
		if called {
			t.Fatalf("builder called for invalid args: %v", args)
		}
	}
	if err := runWithAllBuilders(valid, io.Discard, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing verifier builder error = %v", err)
	}
}

func replaceArgument(input []string, old, replacement string) []string {
	clone := append([]string(nil), input...)
	for index := range clone {
		if clone[index] == old {
			clone[index] = replacement
			break
		}
	}
	return clone
}
