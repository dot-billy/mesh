package linuxbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/nebulaobserverartifact"
	systemdassets "mesh/packaging/systemd"
	nebulasource "mesh/third_party/nebula"
)

type contentKind uint8

const (
	kindMeshInstall contentKind = iota + 1
	kindMeshctl
	kindNebula
	kindNebulaCert
	kindEmbedded
)

type contentExpectation struct {
	mode   uint32
	size   int64
	sha256 string
	bytes  []byte
	kind   contentKind
}

type bundlePolicy struct {
	arch        string
	nebula      NebulaIdentity
	expectation map[string]contentExpectation
}

func productionPolicy(arch string) (bundlePolicy, error) {
	if !supportedArch(arch) {
		return bundlePolicy{}, fmt.Errorf("unsupported Linux architecture %q", arch)
	}
	observerPolicy, observerPolicyDigest, err := nebulaobserverartifact.EmbeddedPolicy()
	if err != nil {
		return bundlePolicy{}, err
	}
	target, err := observerPolicy.Select(arch)
	if err != nil {
		return bundlePolicy{}, err
	}
	policy := bundlePolicy{
		arch: arch,
		nebula: NebulaIdentity{
			Version: observerPolicy.Version, UpstreamCommit: observerPolicy.Commit,
			UpstreamLockSHA256: observerPolicy.UpstreamLockSHA256, ObserverLockSHA256: observerPolicyDigest,
			SourceTreeSHA256: observerPolicy.SourceTreeSHA256, PatchedTreeSHA256: observerPolicy.PatchedTreeSHA256,
			PatchSetSHA256: observerPolicy.PatchSetSHA256, GoVersion: observerPolicy.Toolchain,
		},
		expectation: map[string]contentExpectation{
			"bin/mesh-install": {mode: 0o555, kind: kindMeshInstall},
			"bin/meshctl":      {mode: 0o555, kind: kindMeshctl},
		},
	}
	for _, entry := range target.Entries {
		path := ""
		kind := kindNebula
		switch entry.Name {
		case "nebula":
			path = "bin/nebula"
		case "nebula-cert":
			path = "bin/nebula-cert"
			kind = kindNebulaCert
		default:
			return bundlePolicy{}, fmt.Errorf("Linux Nebula lock contains unexpected entry %q", entry.Name)
		}
		policy.expectation[path] = contentExpectation{
			mode: entry.Mode, size: entry.Size, sha256: entry.SHA256, kind: kind,
		}
	}
	embedded := map[string][]byte{
		"lib/systemd/system/mesh-agent.service":                          systemdassets.MeshAgentService(),
		"lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf":  systemdassets.TimeoutAbortCompatibilityMask(),
		"lib/systemd/system/mesh-nebula.service":                         systemdassets.MeshNebulaService(),
		"lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf": systemdassets.TimeoutAbortCompatibilityMask(),
		"share/doc/mesh/systemd/README.md":                               systemdassets.README(),
		"share/licenses/nebula/LICENSE":                                  nebulasource.V1103License(),
	}
	for path, content := range embedded {
		digest := sha256.Sum256(content)
		policy.expectation[path] = contentExpectation{
			mode: 0o444, size: int64(len(content)), sha256: hex.EncodeToString(digest[:]),
			bytes: append([]byte(nil), content...), kind: kindEmbedded,
		}
	}
	if len(policy.expectation) != len(payloadSpecs) {
		return bundlePolicy{}, errors.New("compiled Linux bundle policy is incomplete")
	}
	return policy, nil
}

func (policy bundlePolicy) validateMetadata(metadata Package) error {
	if metadata.Target.OS != "linux" || metadata.Target.Arch != policy.arch || metadata.Nebula != policy.nebula {
		return errors.New("package metadata does not match the compiled Linux dependency policy")
	}
	entries := entryMap(metadata.Entries)
	for _, spec := range payloadSpecs {
		entry, ok := entries[spec.path]
		expectation, expected := policy.expectation[spec.path]
		if !ok || !expected {
			return fmt.Errorf("compiled policy is missing payload %q", spec.path)
		}
		if entry.Mode != expectation.mode {
			return fmt.Errorf("payload %q mode does not match compiled policy", spec.path)
		}
		if expectation.size != 0 && (entry.Size != expectation.size || entry.SHA256 != expectation.sha256) {
			return fmt.Errorf("payload %q identity does not match compiled policy", spec.path)
		}
	}
	return nil
}

func (policy bundlePolicy) validateContent(path string, content []byte, metadata Package) error {
	expectation, ok := policy.expectation[path]
	if !ok {
		return fmt.Errorf("payload %q is outside the compiled policy", path)
	}
	entry := entryMap(metadata.Entries)[path]
	if int64(len(content)) != entry.Size {
		return fmt.Errorf("payload %q size changed", path)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != entry.SHA256 {
		return fmt.Errorf("payload %q SHA-256 changed", path)
	}
	meshIdentity := meshbuildinfo.IdentityInfo{
		Schema: meshbuildinfo.Schema, Version: metadata.Version, Commit: metadata.Commit,
		BuildTime: metadata.BuildTime, SecurityFloor: metadata.SecurityFloor,
		AgentStateReadMin: metadata.AgentStateReadMin, AgentStateReadMax: metadata.AgentStateReadMax,
		AgentStateWriteVersion: metadata.AgentStateWriteVersion,
	}
	switch expectation.kind {
	case kindMeshInstall:
		goVersion, err := verifyMeshBinary(content, "mesh/cmd/mesh-install", policy.arch, meshIdentity)
		if err != nil {
			return fmt.Errorf("validate bin/mesh-install: %w", err)
		}
		if goVersion != metadata.GoVersion {
			return errors.New("bin/mesh-install Go version does not match package.json")
		}
		installerTrust, err := inspectInstallerTrustBootstrapBytes(content)
		if err != nil {
			return fmt.Errorf("validate bin/mesh-install trust bootstrap: %w", err)
		}
		if installerTrust.InitialRootSHA256 != metadata.InstallerBootstrapRootSHA256 {
			return errors.New("bin/mesh-install bootstrap root does not match package.json")
		}
		if metadata.Schema == Schema {
			compatibility, err := inspectInstallerCompatibilityBytes(content)
			if err != nil {
				return fmt.Errorf("validate bin/mesh-install compatibility: %w", err)
			}
			if compatibility.ReadMinimum != metadata.InstallerStateReadMin ||
				compatibility.ReadMaximum != metadata.InstallerStateReadMax ||
				compatibility.WriteVersion != metadata.InstallerStateWriteVersion {
				return errors.New("bin/mesh-install compatibility does not match package.json")
			}
		}
	case kindMeshctl:
		goVersion, err := verifyMeshBinary(content, "mesh/cmd/meshctl", policy.arch, meshIdentity)
		if err != nil {
			return fmt.Errorf("validate bin/meshctl: %w", err)
		}
		if goVersion != metadata.GoVersion {
			return errors.New("bin/meshctl Go version does not match package.json")
		}
		if err := rejectInstallerTrustFramesBytes(content); err != nil {
			return fmt.Errorf("validate bin/meshctl trust separation: %w", err)
		}
		if err := rejectInstallerCompatibilityFramesBytes(content); err != nil {
			return fmt.Errorf("validate bin/meshctl compatibility separation: %w", err)
		}
	case kindNebula, kindNebulaCert:
		name := "nebula"
		if expectation.kind == kindNebulaCert {
			name = "nebula-cert"
		}
		if err := nebulaobserverartifact.VerifyBinary(content, policy.arch, name); err != nil {
			return fmt.Errorf("validate %s: %w", path, err)
		}
	case kindEmbedded:
		if string(content) != string(expectation.bytes) {
			return fmt.Errorf("payload %q differs from the reviewed embedded asset", path)
		}
	default:
		return fmt.Errorf("payload %q has an unsupported compiled content kind", path)
	}
	return nil
}
