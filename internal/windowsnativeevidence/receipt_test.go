package windowsnativeevidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"mesh/internal/bootstrapverify"
)

func TestNativeEvidenceCanonicalPairBinding(t *testing.T) {
	bootstrap := fixtureBootstrapReceipt()
	runtime := fixtureRuntimeReceipt()
	parsedBootstrap, err := ParseBootstrapReceipt(encodeFixture(t, bootstrap))
	if err != nil {
		t.Fatal(err)
	}
	parsedRuntime, err := ParseRuntimeReceipt(encodeFixture(t, runtime))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 21, 22, 0, 0, 0, time.UTC)
	if err := MatchPair(now, parsedBootstrap, parsedRuntime, "amd64", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if err := MatchPair(now, parsedBootstrap, parsedRuntime, "amd64", strings.Repeat("f", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)); err == nil {
		t.Fatal("native evidence matched a different Authenticode policy")
	}
}

func TestNativeEvidenceRejectsDriftAndStaleness(t *testing.T) {
	validRuntime := encodeFixture(t, fixtureRuntimeReceipt())
	for name, mutation := range map[string]func([]byte) []byte{
		"noncanonical": func(raw []byte) []byte { return append([]byte(" "), raw...) },
		"unknown": func(raw []byte) []byte {
			var document map[string]any
			_ = json.Unmarshal(raw, &document)
			document["unknown"] = true
			result, _ := json.Marshal(document)
			return append(result, '\n')
		},
		"same bundle": func(raw []byte) []byte {
			var receipt RuntimeReceipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.UpgradeBundleSHA256 = receipt.BundleSHA256
			return encodeFixture(t, receipt)
		},
		"proof drift": func(raw []byte) []byte {
			var receipt RuntimeReceipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.Proofs[0] = "different"
			return encodeFixture(t, receipt)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRuntimeReceipt(mutation(bytes.Clone(validRuntime))); err == nil {
				t.Fatal("drifted native runtime receipt was accepted")
			}
		})
	}
	bootstrap, err := ParseBootstrapReceipt(encodeFixture(t, fixtureBootstrapReceipt()))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := ParseRuntimeReceipt(validRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if err := MatchPair(time.Date(2026, 7, 23, 0, 0, 1, 0, time.UTC), bootstrap, runtime, "amd64", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)); err == nil || !strings.Contains(err.Error(), "older than 24 hours") {
		t.Fatalf("stale native evidence returned %v", err)
	}
}

func fixtureBootstrapReceipt() BootstrapReceipt {
	receipt := BootstrapReceipt{
		Schema: BootstrapSchema, Architecture: "amd64", VerifiedAt: "2026-07-21T21:00:00Z",
		VerifierPackageSHA256: strings.Repeat("1", 64), VerifierSHA256: strings.Repeat("2", 64),
		AnchorSHA256: strings.Repeat("3", 64), HandoffSHA256: strings.Repeat("4", 64),
		RootSHA256: strings.Repeat("5", 64), InstallerSHA256: strings.Repeat("b", 64),
		Proofs: append([]string(nil), bootstrapProofs...), SourceSHA256: fixtureSources(bootstrapSources),
	}
	receipt.Verification = bootstrapverify.Result{
		Schema: bootstrapverify.AnchorResultSchema, AnchorSHA256: receipt.AnchorSHA256,
		HandoffSHA256: receipt.HandoffSHA256, VerifierPackageSHA256: receipt.VerifierPackageSHA256,
		RootSHA256: receipt.RootSHA256, ManifestSHA256: strings.Repeat("6", 64),
		InstallerSHA256: receipt.InstallerSHA256, InstallerBootstrapSHA256: strings.Repeat("7", 64),
		AuthenticodePolicySHA256: strings.Repeat("a", 64), AuthenticodeSignerSPKI: strings.Repeat("8", 64),
		AuthenticodeCertificate: strings.Repeat("9", 64), Version: "1.2.3", OS: "windows", Arch: "amd64",
		SignerKeyIDs: []string{strings.Repeat("e", 64), strings.Repeat("f", 64)},
	}
	return receipt
}

func fixtureRuntimeReceipt() RuntimeReceipt {
	return RuntimeReceipt{
		Schema: RuntimeSchema, Architecture: "amd64", GoVersion: "go version go1.26.5 windows/amd64",
		NativeFaultGate: "1", BundlePath: `C:\proof\initial.tar`, BundleSHA256: strings.Repeat("c", 64),
		UpgradeBundlePath: `C:\proof\upgrade.tar`, UpgradeBundleSHA256: strings.Repeat("d", 64),
		PolicySHA256: strings.Repeat("a", 64), NativeDNSLocalIP: "10.42.0.9",
		StartedAt: "2026-07-21T21:10:00Z", VerifiedAt: "2026-07-21T21:20:00Z",
		Proofs: append([]string(nil), runtimeProofs...), SourceSHA256: fixtureSources(runtimeSources),
	}
}

func fixtureSources(names []string) map[string]string {
	result := make(map[string]string, len(names))
	for _, name := range names {
		result[name] = strings.Repeat("1", 64)
	}
	return result
}

func encodeFixture(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}
