package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"mesh/internal/buildinfo"
	"mesh/internal/linuxinstall"
)

func TestInstallOnlineDispatchesExactURLAndWritesExistingResult(t *testing.T) {
	original := applyOnline
	t.Cleanup(func() { applyOnline = original })
	wantURL := "https://releases.example/channels/stable/bundle.json"
	wantContext := context.WithValue(context.Background(), struct{}{}, "exact")
	applyOnline = func(gotContext context.Context, got string) (linuxinstall.InstallResult, error) {
		if gotContext != wantContext {
			t.Fatal("install-online changed the caller context")
		}
		if got != wantURL {
			t.Fatalf("URL = %q, want %q", got, wantURL)
		}
		return linuxinstall.InstallResult{Operation: linuxinstall.OperationActivate, FirstInstall: true}, nil
	}
	var output bytes.Buffer
	if err := runContext(wantContext, []string{"install-online", wantURL}, &output); err != nil {
		t.Fatal(err)
	}
	var got linuxinstall.InstallResult
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Operation != linuxinstall.OperationActivate || !got.FirstInstall {
		t.Fatalf("result = %#v", got)
	}
}

func TestInstallOnlineErrorWritesNoSuccessJSON(t *testing.T) {
	original := applyOnline
	t.Cleanup(func() { applyOnline = original })
	want := errors.New("injected online install failure")
	applyOnline = func(context.Context, string) (linuxinstall.InstallResult, error) {
		return linuxinstall.InstallResult{AlreadyActive: true}, want
	}
	var output bytes.Buffer
	err := runContext(context.Background(), []string{"install-online", "https://releases.example/channels/stable/bundle.json"}, &output)
	if !errors.Is(err, want) || output.Len() != 0 {
		t.Fatalf("error = %v, output = %q", err, output.String())
	}
}

func TestVersion(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	var got buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	current, err := buildinfo.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != current.Version || got.SecurityFloor == 0 || got.AgentStateReadMin != current.AgentStateReadMin ||
		got.AgentStateReadMax != current.AgentStateReadMax || got.AgentStateWriteVersion != current.AgentStateWriteVersion {
		t.Fatalf("unexpected build identity: %+v", got)
	}
}

func TestUsage(t *testing.T) {
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
		{"rollback"},
		{"rollback", "target", "extra"},
		{"version", "extra"},
		{"unknown"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Fatalf("args %v accepted", args)
		}
	}
}
