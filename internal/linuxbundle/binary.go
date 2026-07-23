package linuxbundle

import (
	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/installerinspect"
	"mesh/internal/installtrust"
)

// InstallerInspection remains the release-package-facing name for the shared
// read-only installer inspection result.
type InstallerInspection = installerinspect.Inspection

func InspectInstallerBinary(content []byte, arch string) (InstallerInspection, error) {
	return installerinspect.Inspect(content, arch)
}

func verifyMeshBinary(content []byte, mainPath, arch string, expected meshbuildinfo.IdentityInfo) (string, error) {
	return installerinspect.VerifyMeshBinary(content, mainPath, arch, expected)
}

func inspectMeshIdentityBytes(content []byte) (meshbuildinfo.IdentityInfo, error) {
	return installerinspect.InspectMeshIdentity(content)
}

func inspectInstallerTrustBootstrapBytes(content []byte) (installtrust.Bootstrap, error) {
	return installerinspect.InspectTrustBootstrap(content)
}

func rejectInstallerTrustFramesBytes(content []byte) error {
	return installerinspect.RejectTrustFrames(content)
}

func inspectInstallerCompatibilityBytes(content []byte) (installercompat.Contract, error) {
	return installerinspect.InspectCompatibility(content)
}

func rejectInstallerCompatibilityFramesBytes(content []byte) error {
	return installerinspect.RejectCompatibilityFrames(content)
}
