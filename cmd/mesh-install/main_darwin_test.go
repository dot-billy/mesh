//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"mesh/internal/buildinfo"
	"mesh/internal/darwincodesign"
	"mesh/internal/darwininstall"
	"mesh/internal/darwinnodepackage"
)

func TestDarwinCommandDispatchUsesExactArgumentsAndContext(t *testing.T) {
	originalOnline := applyDarwinOnline
	originalSnapshot := applyDarwinSnapshot
	originalRecover := recoverDarwin
	originalActivate := activateDarwin
	originalUninstall := uninstallDarwin
	originalRollback := rollbackDarwin
	t.Cleanup(func() {
		applyDarwinOnline = originalOnline
		applyDarwinSnapshot = originalSnapshot
		recoverDarwin = originalRecover
		activateDarwin = originalActivate
		uninstallDarwin = originalUninstall
		rollbackDarwin = originalRollback
	})

	type contextKey struct{}
	wantContext := context.WithValue(context.Background(), contextKey{}, "exact")
	var calls []string
	result := darwininstall.DarwinInstallResult{
		Operation: darwininstall.JournalOperationActivate,
		Release:   darwininstall.AuthenticatedDarwinRelease{Version: "1.2.3"},
	}
	checkContext := func(ctx context.Context) {
		t.Helper()
		if ctx != wantContext {
			t.Fatal("Darwin command changed the caller context")
		}
	}
	applyDarwinOnline = func(ctx context.Context, value string) (darwininstall.DarwinInstallResult, error) {
		checkContext(ctx)
		calls = append(calls, "online:"+value)
		return result, nil
	}
	applyDarwinSnapshot = func(ctx context.Context, value string) (darwininstall.DarwinInstallResult, error) {
		checkContext(ctx)
		calls = append(calls, "snapshot:"+value)
		return result, nil
	}
	recoverDarwin = func(ctx context.Context) (darwininstall.DarwinInstallResult, error) {
		checkContext(ctx)
		calls = append(calls, "recover")
		return result, nil
	}
	activateDarwin = func(ctx context.Context) (darwininstall.DarwinInstallResult, error) {
		checkContext(ctx)
		calls = append(calls, "activate")
		return result, nil
	}
	uninstallResult := darwininstall.DarwinRuntimeUninstallResult{
		Schema:             darwininstall.DarwinRuntimeUninstallResultSchema,
		Operation:          "uninstall-runtime",
		RuntimeDeactivated: true,
	}
	uninstallDarwin = func(ctx context.Context) (darwininstall.DarwinRuntimeUninstallResult, error) {
		checkContext(ctx)
		calls = append(calls, "uninstall-runtime")
		return uninstallResult, nil
	}
	rollbackDarwin = func(ctx context.Context, value string) (darwininstall.DarwinInstallResult, error) {
		checkContext(ctx)
		calls = append(calls, "rollback:"+value)
		return result, nil
	}

	for _, args := range [][]string{
		{"install-online", "https://releases.example/channels/stable/bundle.json"},
		{"install", "/private/var/tmp/mesh-snapshot"},
		{"recover"},
		{"activate"},
		{"rollback", "e00000000000000000001-s00000000000000000002-r0123456789abcdef-a0123456789abcdef"},
	} {
		var output bytes.Buffer
		if err := runContext(wantContext, args, &output); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var decoded darwininstall.DarwinInstallResult
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatalf("%v: decode result: %v", args, err)
		}
		if !reflect.DeepEqual(decoded, result) {
			t.Fatalf("%v: result = %#v, want %#v", args, decoded, result)
		}
	}
	var uninstallOutput bytes.Buffer
	if err := runContext(wantContext, []string{"uninstall-runtime"}, &uninstallOutput); err != nil {
		t.Fatal(err)
	}
	var decodedUninstall darwininstall.DarwinRuntimeUninstallResult
	if err := json.Unmarshal(uninstallOutput.Bytes(), &decodedUninstall); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodedUninstall, uninstallResult) {
		t.Fatalf("uninstall result = %#v, want %#v", decodedUninstall, uninstallResult)
	}
	wantCalls := []string{
		"online:https://releases.example/channels/stable/bundle.json",
		"snapshot:/private/var/tmp/mesh-snapshot",
		"recover",
		"activate",
		"rollback:e00000000000000000001-s00000000000000000002-r0123456789abcdef-a0123456789abcdef",
		"uninstall-runtime",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("Darwin dispatch calls = %q, want %q", calls, wantCalls)
	}
}

func TestDarwinCompiledPackagePostinstallUsesOnlyPolicyPaths(t *testing.T) {
	originalPolicy := loadDarwinNodePackagePolicy
	originalVerify := verifyDarwinPackageBootstrap
	originalApply := applyDarwinPackageSnapshot
	t.Cleanup(func() {
		loadDarwinNodePackagePolicy = originalPolicy
		verifyDarwinPackageBootstrap = originalVerify
		applyDarwinPackageSnapshot = originalApply
	})
	_, policy, err := darwinnodepackage.EncodePolicy(darwinnodepackage.PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	loadDarwinNodePackagePolicy = func() (darwinnodepackage.Policy, error) {
		return policy, nil
	}
	verifyDarwinPackageBootstrap = func(path, role string) (darwincodesign.Verification, error) {
		if path != policy.InstalledBootstrapPath || role != darwincodesign.MeshInstallRole {
			t.Fatalf("verify path=%q role=%q", path, role)
		}
		return darwincodesign.Verification{
			Role: role, Identifier: "io.mesh.node.mesh-install",
			TeamID: "AB12CD34EF", PolicySHA256: "policy",
		}, nil
	}
	wantContext := context.WithValue(context.Background(), struct{}{}, "package")
	want := darwininstall.DarwinInstallResult{
		Operation: darwininstall.JournalOperationActivate,
		Release:   darwininstall.AuthenticatedDarwinRelease{Version: "1.2.3"},
	}
	applyDarwinPackageSnapshot = func(ctx context.Context, path string) (darwininstall.DarwinInstallResult, error) {
		if ctx != wantContext || path != policy.PackageSnapshotPath {
			t.Fatalf("apply context=%v path=%q", ctx, path)
		}
		return want, nil
	}
	if err := runPlatformPackagePostinstallContext(
		wantContext,
		[]string{"/private/tmp/MeshNode.pkg", "/tmp", "/", "/"},
		io.Discard,
	); err == nil || !strings.Contains(err.Error(), "differs from compiled policy") {
		t.Fatalf("wrong package install location returned %v", err)
	}
	var output bytes.Buffer
	if err := runPlatformPackagePostinstallContext(
		wantContext,
		[]string{
			"/private/tmp/MeshNode.pkg",
			"/Library/Application Support/Mesh",
			"/",
			"/",
		},
		&output,
	); err != nil {
		t.Fatal(err)
	}
	var got darwininstall.DarwinInstallResult
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result=%+v want=%+v", got, want)
	}
}

func TestDarwinPackagePostinstallFailsBeforePathUseWithoutPolicy(t *testing.T) {
	originalPolicy := loadDarwinNodePackagePolicy
	originalVerify := verifyDarwinPackageBootstrap
	t.Cleanup(func() {
		loadDarwinNodePackagePolicy = originalPolicy
		verifyDarwinPackageBootstrap = originalVerify
	})
	loadDarwinNodePackagePolicy = func() (darwinnodepackage.Policy, error) {
		return darwinnodepackage.Policy{}, errors.New("development sentinel")
	}
	verifyDarwinPackageBootstrap = func(string, string) (darwincodesign.Verification, error) {
		t.Fatal("bootstrap verification ran without a package policy")
		return darwincodesign.Verification{}, nil
	}
	if err := runPlatformPackagePostinstallContext(
		context.Background(),
		[]string{
			"/private/tmp/MeshNode.pkg",
			"/Library/Application Support/Mesh",
			"/",
			"/",
		},
		io.Discard,
	); err == nil || !strings.Contains(err.Error(), "development sentinel") {
		t.Fatalf("missing policy returned %v", err)
	}
	for _, args := range [][]string{
		nil,
		{"/private/tmp/MeshNode.pkg"},
		{"relative.pkg", "/Library/Application Support/Mesh", "/", "/"},
		{"/private/tmp/MeshNode", "/Library/Application Support/Mesh", "/", "/"},
		{"/private/tmp/MeshNode.pkg", "/tmp", "/", "/"},
		{"/private/tmp/MeshNode.pkg", "/Library/Application Support/Mesh", "/tmp", "/"},
		{"/private/tmp/MeshNode.pkg", "/Library/Application Support/Mesh", "/", "/tmp"},
		{"/private/tmp/MeshNode.pkg", "/Library/Application Support/Mesh", "/", "/", "extra"},
	} {
		if err := runPlatformPackagePostinstallContext(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("invalid package invocation %q accepted", args)
		}
	}
}

func TestDarwinCommandErrorWritesNoSuccessJSON(t *testing.T) {
	original := applyDarwinOnline
	t.Cleanup(func() { applyDarwinOnline = original })
	want := errors.New("injected Darwin install failure")
	applyDarwinOnline = func(context.Context, string) (darwininstall.DarwinInstallResult, error) {
		return darwininstall.DarwinInstallResult{AlreadyActive: true}, want
	}
	var output bytes.Buffer
	err := runContext(context.Background(), []string{"install-online", "https://releases.example/channels/stable/bundle.json"}, &output)
	if !errors.Is(err, want) || output.Len() != 0 {
		t.Fatalf("error = %v, output = %q", err, output.String())
	}
}

func TestDarwinRuntimeUninstallErrorWritesNoSuccessJSON(t *testing.T) {
	original := uninstallDarwin
	t.Cleanup(func() { uninstallDarwin = original })
	want := errors.New("injected Darwin runtime-uninstall failure")
	uninstallDarwin = func(context.Context) (darwininstall.DarwinRuntimeUninstallResult, error) {
		return darwininstall.DarwinRuntimeUninstallResult{RuntimeDeactivated: true}, want
	}
	var output bytes.Buffer
	err := runContext(context.Background(), []string{"uninstall-runtime"}, &output)
	if !errors.Is(err, want) || output.Len() != 0 {
		t.Fatalf("error = %v, output = %q", err, output.String())
	}
}

func TestDarwinVersion(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	var got buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var identity map[string]any
	if err := json.Unmarshal(output.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity["darwin_code_signing_policy_sha256"] != "" ||
		identity["darwin_node_package_policy_sha256"] != "" {
		t.Fatalf("development build exposed production policy digests: %+v", identity)
	}
	current, err := buildinfo.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != current.Version || got.SecurityFloor == 0 ||
		got.AgentStateReadMin != current.AgentStateReadMin ||
		got.AgentStateReadMax != current.AgentStateReadMax ||
		got.AgentStateWriteVersion != current.AgentStateWriteVersion {
		t.Fatalf("unexpected build identity: %+v", got)
	}
}

func TestDarwinUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{},
		{"install-online"},
		{"install-online", "https://releases.example/one", "https://releases.example/two"},
		{"install-online", "--bundle-url", "https://releases.example/one"},
		{"install"},
		{"install", "/tmp/snapshot", "extra"},
		{"recover", "extra"},
		{"activate", "extra"},
		{"uninstall-runtime", "extra"},
		{"rollback"},
		{"rollback", "target", "extra"},
		{"version", "extra"},
		{"unknown"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Fatalf("args %v accepted", args)
		}
	}
	if err := runContext(nil, []string{"recover"}, io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := runContext(context.Background(), []string{"recover"}, nil); err == nil {
		t.Fatal("nil output accepted")
	}
}
