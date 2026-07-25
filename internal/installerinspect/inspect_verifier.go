package installerinspect

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"

	meshbuildinfo "mesh/internal/buildinfo"
	"mesh/internal/installercompat"
	"mesh/internal/installtrust"
	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsinstallercompat"
)

// VerifierInspection is the static production identity of the narrow
// standalone bootstrap verifier. Unlike an installer inspection, it also
// proves that no canonical installer trust or state-compatibility frame is
// linked into the executable.
type VerifierInspection struct {
	Identity     meshbuildinfo.IdentityInfo
	Authenticode windowsauthenticode.Policy
	GoVersion    string
}

// InspectVerifier applies the platform-specific executable, Go-build,
// production-identity, and capability-separation contract without executing
// the candidate.
func InspectVerifier(content []byte, platformOS, arch string) (VerifierInspection, error) {
	switch platformOS {
	case "linux":
		identity, err := InspectMeshIdentity(content)
		if err != nil {
			return VerifierInspection{}, err
		}
		goVersion, err := VerifyMeshBinary(content, "mesh/cmd/mesh-bootstrap-verify", arch, identity)
		if err != nil {
			return VerifierInspection{}, err
		}
		if err := RejectTrustFrames(content); err != nil {
			return VerifierInspection{}, err
		}
		if err := RejectCompatibilityFrames(content); err != nil {
			return VerifierInspection{}, err
		}
		return VerifierInspection{Identity: identity, GoVersion: goVersion}, nil
	case "windows":
		return inspectWindowsVerifier(content, arch)
	default:
		return VerifierInspection{}, fmt.Errorf("unsupported standalone verifier platform %q", platformOS)
	}
}

func inspectWindowsVerifier(content []byte, arch string) (result VerifierInspection, returnErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = VerifierInspection{}
			returnErr = fmt.Errorf("parse Windows standalone verifier PE: malformed input (%T)", recovered)
		}
	}()
	if arch != "amd64" && arch != "arm64" {
		return result, errors.New("Windows standalone verifier architecture must be amd64 or arm64")
	}
	if len(content) == 0 || int64(len(content)) > maximumExecutableSize {
		return result, errors.New("Windows standalone verifier executable size is outside the supported bound")
	}
	parsed, err := pe.NewFile(bytes.NewReader(content))
	if err != nil {
		return result, fmt.Errorf("parse Windows standalone verifier PE: %w", err)
	}
	defer parsed.Close()
	if err := validateWindowsPEExecutable(parsed, arch, "standalone verifier"); err != nil {
		return result, err
	}
	sections, err := windowsReadOnlySections(parsed)
	if err != nil {
		return result, err
	}
	identities := collectWindowsFrames(sections, []byte(meshbuildinfo.FramePrefix), []byte(meshbuildinfo.FrameSuffix), 8<<10, meshbuildinfo.ParseIdentity)
	if len(identities) != 1 {
		return result, fmt.Errorf("Windows standalone verifier PE contains %d canonical build identities in read-only sections, want exactly one", len(identities))
	}
	bootstraps := collectWindowsFrames(sections, []byte(installtrust.BootstrapFramePrefix), []byte(installtrust.BootstrapFrameSuffix), 256<<10, installtrust.ParseBootstrapIdentity)
	legacy := collectWindowsFrames(sections, []byte(installtrust.FramePrefix), []byte(installtrust.FrameSuffix), 128<<10, installtrust.ParseIdentity)
	linuxContracts := collectWindowsFrames(sections, []byte(installercompat.FramePrefix), []byte(installercompat.FrameSuffix), 4<<10, installercompat.ParseIdentity)
	windowsContracts := collectWindowsFrames(sections, []byte(windowsinstallercompat.FramePrefix), []byte(windowsinstallercompat.FrameSuffix), 4<<10, windowsinstallercompat.ParseIdentity)
	if len(bootstraps) != 0 || len(legacy) != 0 || len(linuxContracts) != 0 || len(windowsContracts) != 0 {
		return result, fmt.Errorf("Windows standalone verifier PE contains %d v2 bootstraps, %d v1 policies, %d Linux compatibility frames, and %d Windows compatibility frames, want none", len(bootstraps), len(legacy), len(linuxContracts), len(windowsContracts))
	}
	authenticodePolicies := collectWindowsFrames(sections, []byte(windowsauthenticode.FramePrefix), []byte(windowsauthenticode.FrameSuffix), 16<<10, windowsauthenticode.ParsePolicyIdentity)
	if len(authenticodePolicies) != 1 {
		return result, fmt.Errorf("Windows standalone verifier PE contains %d canonical Authenticode publisher policies, want exactly one", len(authenticodePolicies))
	}
	goVersion, err := verifyWindowsGoBuildForMain(content, "mesh/cmd/mesh-bootstrap-verify", arch, identities[0])
	if err != nil {
		return result, err
	}
	return VerifierInspection{Identity: identities[0], Authenticode: authenticodePolicies[0], GoVersion: goVersion}, nil
}
