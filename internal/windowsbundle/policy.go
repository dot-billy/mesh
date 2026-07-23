package windowsbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/nebulaartifact"
	"mesh/internal/nebulaobserverartifact"
	"mesh/internal/windowsauthenticode"
	nebulasource "mesh/third_party/nebula"
)

type contentKind uint8

const (
	kindMeshctl contentKind = iota + 1
	kindNebula
	kindNebulaCert
	kindWintunDLL
	kindLockedNotice
	kindEmbedded
)

type contentExpectation struct {
	archiveMode       uint32
	size              int64
	sha256            string
	bytes             []byte
	kind              contentKind
	binaryExpectation *nebulaartifact.BinaryExpectation
}

type bundlePolicy struct {
	arch        string
	nebula      NebulaIdentity
	runtime     RuntimeIdentity
	expectation map[string]contentExpectation
	inputs      map[string]string
}

func productionPolicy(arch string) (bundlePolicy, error) {
	if !supportedArch(arch) {
		return bundlePolicy{}, fmt.Errorf("unsupported Windows architecture %q", arch)
	}
	lock, err := nebulaartifact.EmbeddedLock()
	if err != nil {
		return bundlePolicy{}, err
	}
	artifact, err := lock.Select("windows", arch)
	if err != nil {
		return bundlePolicy{}, err
	}
	lockDigest := sha256.Sum256(nebulasource.V1103Lock())
	observerPolicy, observerDigest, err := nebulaobserverartifact.EmbeddedPolicy()
	if err != nil {
		return bundlePolicy{}, err
	}
	windowsDigest, err := nebulaobserverartifact.WindowsPolicyDigest()
	if err != nil {
		return bundlePolicy{}, err
	}
	windowsTarget, err := nebulaobserverartifact.WindowsTargetLock(arch)
	if err != nil {
		return bundlePolicy{}, err
	}
	policy := bundlePolicy{
		arch: arch,
		nebula: NebulaIdentity{
			Version: lock.Version, LockSHA256: hex.EncodeToString(lockDigest[:]),
			AssetID: artifact.AssetID, AssetName: artifact.Name,
			ArchiveSize: artifact.Size, ArchiveSHA256: artifact.SHA256,
		},
		runtime: RuntimeIdentity{
			Version: observerPolicy.Version, Commit: observerPolicy.Commit,
			UpstreamLockSHA256:    observerPolicy.UpstreamLockSHA256,
			SourceBuildLockSHA256: observerDigest, WindowsBuildLockSHA256: windowsDigest,
			SourceTreeSHA256: observerPolicy.SourceTreeSHA256, PatchedTreeSHA256: observerPolicy.PatchedTreeSHA256,
			PatchSetSHA256: observerPolicy.PatchSetSHA256, GoVersion: observerPolicy.Toolchain,
		},
		expectation: map[string]contentExpectation{
			"bin/meshctl.exe": {archiveMode: 0o555, kind: kindMeshctl},
		},
		inputs: map[string]string{
			"bin/meshctl.exe": "",
		},
	}
	wanted := map[string]struct {
		bundlePath string
		kind       contentKind
	}{
		"nebula.exe":                      {bundlePath: "bin/nebula.exe", kind: kindNebula},
		"nebula-cert.exe":                 {bundlePath: "bin/nebula-cert.exe", kind: kindNebulaCert},
		"dist/windows/wintun/README.md":   {bundlePath: "bin/dist/windows/wintun/README.md", kind: kindLockedNotice},
		"dist/windows/wintun/LICENSE.txt": {bundlePath: "bin/dist/windows/wintun/LICENSE.txt", kind: kindLockedNotice},
		"dist/windows/wintun/bin/" + arch + "/wintun.dll": {
			bundlePath: "bin/dist/windows/wintun/bin/" + arch + "/wintun.dll", kind: kindWintunDLL,
		},
	}
	seen := make(map[string]bool, len(wanted))
	for _, entry := range artifact.Entries {
		target, ok := wanted[entry.Name]
		if !ok {
			continue
		}
		if seen[entry.Name] || entry.Type != "file" || entry.Size <= 0 || !digestPattern.MatchString(entry.SHA256) {
			return bundlePolicy{}, fmt.Errorf("Windows Nebula lock entry %q is not one exact file", entry.Name)
		}
		seen[entry.Name] = true
		mode := uint32(0o444)
		var binary *nebulaartifact.BinaryExpectation
		if target.kind == kindNebula || target.kind == kindNebulaCert {
			mode = 0o555
			if entry.Binary == nil {
				return bundlePolicy{}, fmt.Errorf("Windows Nebula lock entry %q has no executable identity", entry.Name)
			}
			copy := *entry.Binary
			copy.Targets = append([]nebulaartifact.Target(nil), entry.Binary.Targets...)
			binary = &copy
		}
		policy.expectation[target.bundlePath] = contentExpectation{
			archiveMode: mode, size: entry.Size, sha256: entry.SHA256,
			kind: target.kind, binaryExpectation: binary,
		}
		policy.inputs[target.bundlePath] = path.Clean(entry.Name)
	}
	for source := range wanted {
		if !seen[source] {
			return bundlePolicy{}, fmt.Errorf("Windows Nebula lock is missing required entry %q", source)
		}
	}
	for _, entry := range windowsTarget.Entries {
		bundlePath := "bin/" + entry.Name
		expectation, ok := policy.expectation[bundlePath]
		if !ok {
			return bundlePolicy{}, fmt.Errorf("Windows runtime policy is missing bundle path %q", bundlePath)
		}
		expectation.size = entry.Size
		expectation.sha256 = entry.SHA256
		expectation.binaryExpectation = nil
		policy.expectation[bundlePath] = expectation
		policy.inputs[bundlePath] = entry.Name
	}
	license := nebulasource.V1103License()
	licenseDigest := sha256.Sum256(license)
	policy.expectation["share/licenses/nebula/LICENSE"] = contentExpectation{
		archiveMode: 0o444, size: int64(len(license)), sha256: hex.EncodeToString(licenseDigest[:]),
		bytes: append([]byte(nil), license...), kind: kindEmbedded,
	}
	if len(policy.expectation) != len(payloadSpecs(arch)) || len(policy.inputs) != len(payloadSpecs(arch))-1 {
		return bundlePolicy{}, errors.New("compiled Windows staging-bundle policy is incomplete")
	}
	return policy, nil
}

func (policy bundlePolicy) validateMetadata(metadata Package) error {
	if metadata.Target.OS != "windows" || metadata.Target.Arch != policy.arch || metadata.Nebula != policy.nebula || metadata.Runtime != policy.runtime {
		return errors.New("package metadata does not match the compiled Windows dependency policy")
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
		if expectation.size != 0 {
			if metadata.Schema == SignedSchema && (expectation.kind == kindNebula || expectation.kind == kindNebulaCert) {
				if entry.Size <= expectation.size || entry.Size > expectation.size+(4<<20) {
					return fmt.Errorf("signed payload %q size is outside the certificate-envelope bound", spec.path)
				}
			} else if entry.Size != expectation.size || entry.SHA256 != expectation.sha256 {
				return fmt.Errorf("payload %q identity does not match compiled policy", spec.path)
			}
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
		if metadata.Schema == SignedSchema {
			if _, err := windowsauthenticode.InspectPEEnvelope(content); err != nil {
				return fmt.Errorf("validate bin/meshctl.exe Authenticode envelope: %w", err)
			}
		}
		goVersion, err := verifyMeshBinary(content, "mesh/cmd/meshctl", policy.arch, meshIdentity)
		if err != nil {
			return fmt.Errorf("validate bin/meshctl.exe: %w", err)
		}
		if goVersion != metadata.GoVersion {
			return errors.New("bin/meshctl.exe Go version does not match package.json")
		}
	case kindNebula, kindNebulaCert:
		var err error
		if metadata.Schema == SignedSchema {
			_, err = nebulaobserverartifact.VerifySignedWindowsBinary(content, policy.arch, path.Base(name))
		} else {
			err = nebulaobserverartifact.VerifyWindowsBinary(content, policy.arch, path.Base(name))
		}
		if err != nil {
			return fmt.Errorf("validate %s: %w", name, err)
		}
	case kindWintunDLL:
		if err := verifyWintunDLL(content, policy.arch); err != nil {
			return fmt.Errorf("validate %s: %w", name, err)
		}
		if metadata.Schema == SignedSchema {
			if _, err := windowsauthenticode.InspectPEEnvelope(content); err != nil {
				return fmt.Errorf("validate %s Authenticode envelope: %w", name, err)
			}
		}
	case kindLockedNotice:
		// The exact size and digest checks above bind these bytes to the lock.
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
