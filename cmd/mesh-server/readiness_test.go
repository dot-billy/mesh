package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"mesh/internal/control"
	"mesh/internal/identity"
)

func TestRuntimeReadinessCheckRequiresDurableStoresAndCurrentCredentialBinding(t *testing.T) {
	directory := t.TempDir()
	controlPath := filepath.Join(directory, "state.json")
	controlStore, err := control.OpenStore(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlStore.Close() })
	master := bytes.Repeat([]byte{0x61}, 32)
	box, err := control.NewSecretBox(master)
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.OpenFileStore(filepath.Join(directory, "identity-state.json"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	service := control.NewService(controlStore, box, control.NebulaIssuer{})
	masterVerifier, err := control.DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'A'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	check := runtimeReadinessCheck(controlStore, identityStore, service, masterVerifier, adminVerifier)

	before, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(context.Background()); !errors.Is(err, control.ErrConflict) {
		t.Fatalf("unbound schema-v1 state was ready: %v", err)
	}
	after, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("readiness migrated or otherwise mutated an unbound state")
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNetworkRelaySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureCARotationSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallRolloutSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallPauseSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteTransferSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRouteProfileEditSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRoutePolicySchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureNativeDNSSchema(); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureFirewallScopeSchema(); err != nil {
		t.Fatal(err)
	}
	if err := check(context.Background()); err != nil {
		t.Fatalf("fully initialized runtime was not ready: %v", err)
	}

	wrongAdmin, err := control.DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'B'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeReadinessCheck(controlStore, identityStore, service, masterVerifier, wrongAdmin)(context.Background()); !errors.Is(err, control.ErrConflict) {
		t.Fatalf("mismatched administrator binding was ready: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := check(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness returned %v, want context cancellation", err)
	}
	if err := identityStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := check(context.Background()); !errors.Is(err, identity.ErrClosed) {
		t.Fatalf("closed identity store was ready: %v", err)
	}
}

func TestRuntimeReadinessCheckRejectsMissingDependencies(t *testing.T) {
	if err := runtimeReadinessCheck(nil, nil, nil, "", "")(context.Background()); err == nil {
		t.Fatal("missing runtime dependencies were ready")
	}
}

type fakeRuntimeTelemetryReadiness struct {
	calls int
	err   error
}

func (check *fakeRuntimeTelemetryReadiness) CheckReadiness() error {
	check.calls++
	return check.err
}

func TestRuntimeTelemetryReadinessComposesAfterAuthoritativeStores(t *testing.T) {
	baseCalls := 0
	baseErr := errors.New("authoritative state unavailable")
	telemetryErr := errors.New("telemetry state unavailable")
	telemetry := &fakeRuntimeTelemetryReadiness{err: telemetryErr}
	check := runtimeTelemetryReadinessCheck(func(context.Context) error {
		baseCalls++
		return baseErr
	}, telemetry)
	if err := check(context.Background()); !errors.Is(err, baseErr) || baseCalls != 1 || telemetry.calls != 0 {
		t.Fatalf("base failure err=%v base_calls=%d telemetry_calls=%d", err, baseCalls, telemetry.calls)
	}

	check = runtimeTelemetryReadinessCheck(func(context.Context) error {
		baseCalls++
		return nil
	}, telemetry)
	if err := check(context.Background()); !errors.Is(err, telemetryErr) || telemetry.calls != 1 {
		t.Fatalf("telemetry failure err=%v calls=%d", err, telemetry.calls)
	}
	telemetry.err = nil
	if err := check(context.Background()); err != nil || telemetry.calls != 2 {
		t.Fatalf("composed readiness err=%v calls=%d", err, telemetry.calls)
	}
	if err := runtimeTelemetryReadinessCheck(nil, nil)(context.Background()); err == nil {
		t.Fatal("missing telemetry readiness dependencies were accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before := baseCalls
	if err := check(cancelled); !errors.Is(err, context.Canceled) || baseCalls != before {
		t.Fatalf("cancelled readiness err=%v base_calls=%d", err, baseCalls)
	}
}
