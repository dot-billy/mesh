//go:build darwin

package darwininstall

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"mesh/internal/nodeagent"
)

func TestProductionDarwinEnrollmentBindingRequiresExactCompletedState(t *testing.T) {
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	authority := validAuthenticatedDarwinRelease(1, 2, 1, "a", "b")
	digest := strings.Repeat("c", 64)
	fingerprint := strings.Repeat("d", 64)
	state := nodeagent.State{
		Version:                   nodeagent.StateSchemaVersion,
		ServerURL:                 "https://mesh.example",
		Bearer:                    base64.RawURLEncoding.EncodeToString(bytesOf(1)),
		NodeID:                    "node-1",
		NetworkID:                 "network-1",
		ConfigSigningPublicKey:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CACertificateSHA256:       strings.Repeat("e", 64),
		PublicKeyHash:             base64.RawURLEncoding.EncodeToString(bytesOf(2)),
		AppliedConfigRevision:     7,
		AppliedConfigSHA256:       digest,
		LastSuccessfulConfigAt:    now.Add(-time.Minute),
		CertificateFingerprint:    fingerprint,
		CertificateGeneration:     3,
		CertificateExpiresAt:      now.Add(time.Hour),
		CertificateRenewAfter:     now.Add(30 * time.Minute),
		AgentCredentialExpiresAt:  now.Add(2 * time.Hour),
		AgentCredentialGeneration: 2,
		BootID:                    "boot-1",
		OutputDir:                 ProductionDarwinAgentOutputDirectory,
	}
	bundle := nodeagent.Bundle{
		NodeID: state.NodeID, NetworkID: state.NetworkID,
		Revision: state.AppliedConfigRevision, Digest: state.AppliedConfigSHA256,
		CACertificateSHA256: state.CACertificateSHA256, PublicKeyHash: state.PublicKeyHash,
		CertificateFingerprint: state.CertificateFingerprint,
		CertificateGeneration:  state.CertificateGeneration,
		CertificateExpiresAt:   state.CertificateExpiresAt,
		CertificateRenewAfter:  state.CertificateRenewAfter,
	}
	if err := validateProductionDarwinEnrollmentBinding(authority, state, bundle, now); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*AuthenticatedDarwinRelease, *nodeagent.State, *nodeagent.Bundle, *time.Time){
		"other output": func(_ *AuthenticatedDarwinRelease, state *nodeagent.State, _ *nodeagent.Bundle, _ *time.Time) {
			state.OutputDir = "/private/var/db/other/runtime"
		},
		"pending recovery": func(_ *AuthenticatedDarwinRelease, state *nodeagent.State, _ *nodeagent.Bundle, _ *time.Time) {
			state.PendingBearer = base64.RawURLEncoding.EncodeToString(bytesOf(3))
			state.PendingRecoveryToken = base64.RawURLEncoding.EncodeToString(bytesOf(4))
		},
		"bundle drift": func(_ *AuthenticatedDarwinRelease, _ *nodeagent.State, bundle *nodeagent.Bundle, _ *time.Time) {
			bundle.Revision++
		},
		"no signed success": func(_ *AuthenticatedDarwinRelease, state *nodeagent.State, _ *nodeagent.Bundle, _ *time.Time) {
			state.LastSuccessfulConfigAt = time.Time{}
		},
		"expired certificate": func(_ *AuthenticatedDarwinRelease, _ *nodeagent.State, bundle *nodeagent.Bundle, now *time.Time) {
			*now = bundle.CertificateExpiresAt
		},
		"expired agent credential": func(_ *AuthenticatedDarwinRelease, state *nodeagent.State, _ *nodeagent.Bundle, now *time.Time) {
			*now = state.AgentCredentialExpiresAt
		},
		"unsupported state schema": func(authority *AuthenticatedDarwinRelease, _ *nodeagent.State, _ *nodeagent.Bundle, _ *time.Time) {
			authority.AgentStateReadMin++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidateAuthority := authority
			candidateState := state
			candidateBundle := bundle
			candidateNow := now
			mutate(&candidateAuthority, &candidateState, &candidateBundle, &candidateNow)
			if err := validateProductionDarwinEnrollmentBinding(candidateAuthority, candidateState, candidateBundle, candidateNow); err == nil {
				t.Fatal("unsafe Darwin enrollment binding was accepted")
			}
		})
	}
}

func bytesOf(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestDarwinInstallerValidationRunnerAcceptsOnlyExactCommands(t *testing.T) {
	runner := darwinInstallerValidationRunner{
		nebula:     "/opt/mesh/releases/exact/bin/nebula",
		nebulaCert: "/opt/mesh/releases/exact/bin/nebula-cert",
	}
	versionDirectory := ProductionDarwinAgentOutputDirectory + "/versions/r00000000000000000001-0123456789abcdef-exact"
	for _, test := range []struct {
		name       string
		executable string
		arguments  []string
		output     bool
	}{
		{name: "nebula version", executable: runner.nebula, arguments: []string{"-version"}, output: true},
		{name: "nebula config", executable: runner.nebula, arguments: []string{"-test", "-config", versionDirectory + "/config.yml"}},
		{name: "certificate verify", executable: runner.nebulaCert, arguments: []string{"verify", "-ca", versionDirectory + "/ca.crt", "-crt", versionDirectory + "/host.crt"}},
		{name: "certificate print", executable: runner.nebulaCert, arguments: []string{"print", "-json", "-path", versionDirectory + "/host.crt"}, output: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runner.validate(test.executable, test.arguments, test.output); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, test := range map[string]struct {
		executable string
		arguments  []string
		output     bool
	}{
		"other executable": {executable: "/tmp/nebula", arguments: []string{"-version"}, output: true},
		"extra flag":       {executable: runner.nebula, arguments: []string{"-version", "--verbose"}, output: true},
		"other config":     {executable: runner.nebula, arguments: []string{"-test", "-config", "/tmp/config.yml"}},
		"mixed certificate directories": {
			executable: runner.nebulaCert,
			arguments:  []string{"verify", "-ca", versionDirectory + "/ca.crt", "-crt", ProductionDarwinAgentOutputDirectory + "/versions/other/host.crt"},
		},
		"quiet print": {executable: runner.nebulaCert, arguments: []string{"print", "-json", "-path", versionDirectory + "/host.crt"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runner.validate(test.executable, test.arguments, test.output); err == nil {
				t.Fatal("out-of-contract Darwin enrollment validation command was accepted")
			}
		})
	}
}
