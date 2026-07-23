package darwinbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/nebulaobserverartifact"
	"mesh/packaging/launchd"
	nebulasource "mesh/third_party/nebula"
)

type contentKind uint8

const (
	kindMeshctl contentKind = iota + 1
	kindNebula
	kindNebulaCert
	kindEmbedded
)

type contentExpectation struct {
	archiveMode uint32
	size        int64
	sha256      string
	bytes       []byte
	kind        contentKind
}

type bundlePolicy struct {
	arch        string
	runtime     RuntimeIdentity
	expectation map[string]contentExpectation
	inputs      map[string]string
}

func productionPolicy(arch string) (bundlePolicy, error) {
	if !supportedArch(arch) {
		return bundlePolicy{}, fmt.Errorf("unsupported Darwin architecture %q", arch)
	}
	observerPolicy, observerDigest, err := nebulaobserverartifact.EmbeddedPolicy()
	if err != nil {
		return bundlePolicy{}, err
	}
	darwinDigest, err := nebulaobserverartifact.DarwinPolicyDigest()
	if err != nil {
		return bundlePolicy{}, err
	}
	darwinTarget, err := nebulaobserverartifact.DarwinTargetLock(arch)
	if err != nil {
		return bundlePolicy{}, err
	}
	policy := bundlePolicy{
		arch: arch,
		runtime: RuntimeIdentity{
			Version: observerPolicy.Version, Commit: observerPolicy.Commit,
			UpstreamLockSHA256:    observerPolicy.UpstreamLockSHA256,
			SourceBuildLockSHA256: observerDigest, DarwinBuildLockSHA256: darwinDigest,
			SourceTreeSHA256: observerPolicy.SourceTreeSHA256, PatchedTreeSHA256: observerPolicy.PatchedTreeSHA256,
			PatchSetSHA256: observerPolicy.PatchSetSHA256, GoVersion: observerPolicy.Toolchain,
		},
		expectation: map[string]contentExpectation{
			"bin/meshctl": {archiveMode: 0o555, kind: kindMeshctl},
		},
		inputs: map[string]string{
			"bin/meshctl": "",
		},
	}
	for _, entry := range darwinTarget.Entries {
		bundlePath := "bin/" + entry.Name
		kind := kindNebula
		if entry.Name == "nebula-cert" {
			kind = kindNebulaCert
		}
		policy.expectation[bundlePath] = contentExpectation{
			archiveMode: 0o555, size: entry.Size, sha256: entry.SHA256, kind: kind,
		}
		policy.inputs[bundlePath] = entry.Name
	}
	for name, content := range map[string][]byte{
		"Library/LaunchDaemons/io.mesh.node-agent.plist": launchd.NodeAgentPlist(),
		"share/doc/mesh/launchd/README.md":               launchd.README(),
	} {
		digest := sha256.Sum256(content)
		policy.expectation[name] = contentExpectation{
			archiveMode: 0o444, size: int64(len(content)), sha256: hex.EncodeToString(digest[:]),
			bytes: append([]byte(nil), content...), kind: kindEmbedded,
		}
	}
	license := nebulasource.V1103License()
	licenseDigest := sha256.Sum256(license)
	policy.expectation["share/licenses/nebula/LICENSE"] = contentExpectation{
		archiveMode: 0o444, size: int64(len(license)), sha256: hex.EncodeToString(licenseDigest[:]),
		bytes: append([]byte(nil), license...), kind: kindEmbedded,
	}
	if len(policy.expectation) != len(payloadSpecs(arch)) || len(policy.inputs) != 3 {
		return bundlePolicy{}, errors.New("compiled Darwin staging-bundle policy is incomplete")
	}
	return policy, nil
}

func (policy bundlePolicy) validateMetadata(metadata Package) error {
	if metadata.Target.OS != "darwin" || metadata.Target.Arch != policy.arch || metadata.Runtime != policy.runtime {
		return errors.New("package metadata does not match the compiled Darwin dependency policy")
	}
	entries := entryMap(metadata.Entries)
	for _, spec := range payloadSpecs(policy.arch) {
		entry, ok := entries[spec.path]
		expectation, expected := policy.expectation[spec.path]
		if !ok || !expected {
			return fmt.Errorf("compiled policy is missing payload %q", spec.path)
		}
		if entry.ArchiveMode != expectation.archiveMode {
			return fmt.Errorf("payload %q archive mode does not match compiled policy", spec.path)
		}
		if expectation.size != 0 && (entry.Size != expectation.size || entry.SHA256 != expectation.sha256) {
			return fmt.Errorf("payload %q identity does not match compiled policy", spec.path)
		}
	}
	return nil
}

func (policy bundlePolicy) validateContent(name string, content []byte, metadata Package) error {
	expectation, ok := policy.expectation[name]
	if !ok {
		return fmt.Errorf("payload %q is outside the compiled policy", name)
	}
	entry := entryMap(metadata.Entries)[name]
	if int64(len(content)) != entry.Size {
		return fmt.Errorf("payload %q size changed", name)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != entry.SHA256 {
		return fmt.Errorf("payload %q SHA-256 changed", name)
	}
	meshIdentity := meshbuildinfo.IdentityInfo{
		Schema: meshbuildinfo.Schema, Version: metadata.Version, Commit: metadata.Commit,
		BuildTime: metadata.BuildTime, SecurityFloor: metadata.SecurityFloor,
		AgentStateReadMin: metadata.AgentStateReadMin, AgentStateReadMax: metadata.AgentStateReadMax,
		AgentStateWriteVersion: metadata.AgentStateWriteVersion,
	}
	switch expectation.kind {
	case kindMeshctl:
		goVersion, err := verifyMeshBinary(content, "mesh/cmd/meshctl", policy.arch, meshIdentity)
		if err != nil {
			return fmt.Errorf("validate bin/meshctl: %w", err)
		}
		if goVersion != metadata.GoVersion {
			return errors.New("bin/meshctl Go version does not match package.json")
		}
	case kindNebula, kindNebulaCert:
		if err := nebulaobserverartifact.VerifyDarwinBinary(content, policy.arch, path.Base(name)); err != nil {
			return fmt.Errorf("validate %s: %w", name, err)
		}
	case kindEmbedded:
		if !bytesEqual(content, expectation.bytes) {
			return fmt.Errorf("payload %q differs from the reviewed embedded asset", name)
		}
	default:
		return fmt.Errorf("payload %q has an unsupported compiled content kind", name)
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
